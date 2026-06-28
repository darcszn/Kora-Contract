#![no_std]

use kora_shared::{
    audit::{AdminActionType, AdminAuditEntry, AuditSource, MAX_AUDIT_LOG_SIZE},
    errors::KoraError,
    events,
    reentrancy::ReentrancyGuard,
    types::SmeProfile,
    validation::{require_exact_length, require_valid_risk_score, UPGRADE_TIMELOCK_DELAY},
};
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Bytes, BytesN, Env, Vec};

// ── TTL constants (in ledgers; ~5s per ledger on Stellar) ────────────────────
/// ~30 days worth of ledgers for persistent SME/verifier data
const PERSISTENT_TTL_THRESHOLD: u32 = 518_400;
const PERSISTENT_TTL_BUMP: u32 = 518_400;

/// Minimum seconds between consecutive updates to the same debtor's score by the same verifier.
/// Prevents rapid manipulation immediately before a funding or default decision.
pub const MIN_SCORE_UPDATE_INTERVAL: u64 = 3_600; // 1 hour

// ── Storage Keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    InvoiceNft, // authorized caller for increment_invoice_count
    StakingToken, // token contract for verifier stakes
    MinimumStake, // minimum stake amount required to become verifier
    SlashPercentage, // percentage of stake to slash on default (basis points)
    Verifier(Address),
    VerifierStake(Address), // amount of tokens staked by verifier
    VerifierReputation(Address), // reputation score of verifier
    SmeProfile(Address),
    DebtorScore(Bytes), // keyed by debtor_hash (SHA-256 of PII)
    /// Ledger timestamp of the last set_debtor_score call per (verifier, debtor_hash).
    DebtorScoreLastUpdate(Address, Bytes),
    UpgradeProposal,
    // ── Audit log ─────────────────────────────────────────────────────────────
    /// Next write position in the audit ring buffer (0..MAX_AUDIT_LOG_SIZE).
    AuditLogHead,
    /// Total admin actions ever recorded (monotonic; not capped at ring size).
    AuditLogTotal,
    /// An audit log entry at ring-buffer position `n`.
    AuditEntry(u64),
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct RiskRegistryContract;

#[contractimpl]
impl RiskRegistryContract {
    /// One-time initialization. Sets admin, authorized invoice_nft, and staking parameters.
    pub fn initialize(
        env: Env,
        admin: Address,
        invoice_nft: Address,
        staking_token: Address,
        minimum_stake: i128,
        slash_percentage_bps: u32,
    ) -> Result<(), KoraError> {
        if env.storage().persistent().has(&DataKey::Admin) {
            return Err(KoraError::AlreadyInitialized);
        }
        kora_shared::validation::require_not_self(&env, &admin)?;
        env.storage().persistent().set(&DataKey::Admin, &admin);
        Self::bump_persistent(&env, &DataKey::Admin);
        env.storage()
            .persistent()
            .set(&DataKey::InvoiceNft, &invoice_nft);
        env.storage()
            .persistent()
            .set(&DataKey::StakingToken, &staking_token);
        env.storage()
            .persistent()
            .set(&DataKey::MinimumStake, &minimum_stake);
        env.storage()
            .persistent()
            .set(&DataKey::SlashPercentage, &slash_percentage_bps);
        events::registry_initialized(&env, &admin, &invoice_nft);
        Ok(())
    }

    /// Transfer admin role to a new address. Current admin only.
    pub fn transfer_admin(env: Env, admin: Address, new_admin: Address) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        env.storage().persistent().set(&DataKey::Admin, &new_admin);
        Self::bump_persistent(&env, &DataKey::Admin);
        events::admin_transferred(&env, &admin, &new_admin);
        Self::append_audit_entry(&env, &admin, AdminActionType::RegistryTransferAdmin);
        Ok(())
    }

    // ── Verifier management ───────────────────────────────────────────────────

    /// Admin adds a trusted verifier with required staking deposit.
    pub fn add_verifier(env: Env, admin: Address, verifier: Address, stake_amount: i128) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        kora_shared::validation::require_not_self(&env, &verifier)?;

        let minimum_stake: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::MinimumStake)
            .ok_or(KoraError::NotInitialized)?;

        if stake_amount < minimum_stake {
            return Err(KoraError::InsufficientFunds);
        }

        let token_addr: Address = env
            .storage()
            .persistent()
            .get(&DataKey::StakingToken)
            .ok_or(KoraError::NotInitialized)?;

        let token_client = soroban_sdk::token::Client::new(&env, &token_addr);
        token_client.transfer(&verifier, &env.current_contract_address(), &stake_amount);

        env.storage()
            .persistent()
            .set(&DataKey::Verifier(verifier.clone()), &true);
        env.storage()
            .persistent()
            .set(&DataKey::VerifierStake(verifier.clone()), &stake_amount);
        env.storage()
            .persistent()
            .set(&DataKey::VerifierReputation(verifier.clone()), &100u32);
        Self::bump_persistent(&env, &DataKey::Verifier(verifier.clone()));
        Self::bump_persistent(&env, &DataKey::VerifierStake(verifier.clone()));
        Self::bump_persistent(&env, &DataKey::VerifierReputation(verifier.clone()));
        events::verifier_added(&env, &admin, &verifier);
        Self::append_audit_entry(&env, &admin, AdminActionType::AddVerifier);
        Ok(())
    }

    /// Admin removes a verifier and returns their stake.
    pub fn remove_verifier(env: Env, admin: Address, verifier: Address) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        // Only remove if it actually exists — avoids a no-op silently succeeding
        if !env
            .storage()
            .persistent()
            .get::<_, bool>(&DataKey::Verifier(verifier.clone()))
            .unwrap_or(false)
        {
            return Err(KoraError::NotVerifier);
        }

        let stake: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::VerifierStake(verifier.clone()))
            .unwrap_or(0);

        if stake > 0 {
            let token_addr: Address = env
                .storage()
                .persistent()
                .get(&DataKey::StakingToken)
                .ok_or(KoraError::NotInitialized)?;
            let token_client = soroban_sdk::token::Client::new(&env, &token_addr);
            token_client.transfer(&env.current_contract_address(), &verifier, &stake);
        }

        env.storage()
            .persistent()
            .remove(&DataKey::Verifier(verifier.clone()));
        env.storage()
            .persistent()
            .remove(&DataKey::VerifierStake(verifier.clone()));
        env.storage()
            .persistent()
            .remove(&DataKey::VerifierReputation(verifier.clone()));
        events::verifier_removed(&env, &admin, &verifier);
        Self::append_audit_entry(&env, &admin, AdminActionType::RemoveVerifier);
        Ok(())
    }

    // ── SME management ────────────────────────────────────────────────────────

    /// Verifier registers and scores an SME. Fails if SME is already registered.
    pub fn register_sme(
        env: Env,
        verifier: Address,
        sme: Address,
        risk_score: u32,
        compliance_attested: bool,
    ) -> Result<(), KoraError> {
        verifier.require_auth();
        Self::require_verifier(&env, &verifier)?;
        require_valid_risk_score(risk_score)?;

        // Guard against silent re-registration that would reset defaults/invoice counts
        if env
            .storage()
            .persistent()
            .has(&DataKey::SmeProfile(sme.clone()))
        {
            return Err(KoraError::AlreadyInitialized);
        }

        let profile = SmeProfile {
            address: sme.clone(),
            verified: true,
            verifier: verifier.clone(),
            risk_score,
            total_invoices: 0,
            defaults: 0,
            registered_at: env.ledger().timestamp(),
            compliance_attested,
            credit_limit: 0,
        };

        env.storage()
            .persistent()
            .set(&DataKey::SmeProfile(sme.clone()), &profile);
        Self::bump_persistent(&env, &DataKey::SmeProfile(sme.clone()));
        events::sme_registered(&env, &verifier, &sme, risk_score);
        Ok(())
    }

    /// Update SME risk score. Verifier only.
    pub fn update_sme_score(
        env: Env,
        verifier: Address,
        sme: Address,
        new_score: u32,
    ) -> Result<(), KoraError> {
        verifier.require_auth();
        Self::require_verifier(&env, &verifier)?;
        require_valid_risk_score(new_score)?;

        let _guard = ReentrancyGuard::new(&env)?;

        let mut profile: SmeProfile = env
            .storage()
            .persistent()
            .get(&DataKey::SmeProfile(sme.clone()))
            .ok_or(KoraError::SMENotRegistered)?;

        profile.risk_score = new_score;
        env.storage()
            .persistent()
            .set(&DataKey::SmeProfile(sme.clone()), &profile);
        Self::bump_persistent(&env, &DataKey::SmeProfile(sme.clone()));
        events::sme_score_updated(&env, &verifier, &sme, new_score);
        Ok(())
    }

    /// Set (or update) an SME's aggregate credit limit. Verifier only.
    /// A limit of 0 means no limit is enforced.
    pub fn set_credit_limit(
        env: Env,
        verifier: Address,
        sme: Address,
        credit_limit: i128,
    ) -> Result<(), KoraError> {
        verifier.require_auth();
        Self::require_verifier(&env, &verifier)?;
        if credit_limit < 0 {
            return Err(KoraError::InvalidAmount);
        }

        let mut profile: SmeProfile = env
            .storage()
            .persistent()
            .get(&DataKey::SmeProfile(sme.clone()))
            .ok_or(KoraError::SMENotRegistered)?;

        profile.credit_limit = credit_limit;
        env.storage()
            .persistent()
            .set(&DataKey::SmeProfile(sme.clone()), &profile);
        Self::bump_persistent(&env, &DataKey::SmeProfile(sme.clone()));
        events::sme_credit_limit_set(&env, &verifier, &sme, credit_limit);
        Ok(())
    }

    /// Increment invoice count for an SME.
    /// Restricted to the invoice_nft contract address set at initialization.
    pub fn increment_invoice_count(
        env: Env,
        caller: Address,
        sme: Address,
    ) -> Result<(), KoraError> {
        caller.require_auth();
        Self::require_invoice_nft(&env, &caller)?;

        let mut profile: SmeProfile = env
            .storage()
            .persistent()
            .get(&DataKey::SmeProfile(sme.clone()))
            .ok_or(KoraError::SMENotRegistered)?;

        profile.total_invoices = profile
            .total_invoices
            .checked_add(1)
            .ok_or(KoraError::ArithmeticOverflow)?;

        env.storage()
            .persistent()
            .set(&DataKey::SmeProfile(sme.clone()), &profile);
        Self::bump_persistent(&env, &DataKey::SmeProfile(sme.clone()));
        events::sme_invoice_count_incremented(&env, &sme, profile.total_invoices);
        Ok(())
    }

    /// Record a default against an SME. Admin only. Slashes verifier's stake and reputation.
    pub fn record_default(env: Env, admin: Address, sme: Address) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        let _guard = ReentrancyGuard::new(&env)?;

        let mut profile: SmeProfile = env
            .storage()
            .persistent()
            .get(&DataKey::SmeProfile(sme.clone()))
            .ok_or(KoraError::SMENotRegistered)?;

        profile.defaults = profile
            .defaults
            .checked_add(1)
            .ok_or(KoraError::ArithmeticOverflow)?;

        let verifier = profile.verifier.clone();
        let slash_percentage: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::SlashPercentage)
            .ok_or(KoraError::NotInitialized)?;

        let current_stake: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::VerifierStake(verifier.clone()))
            .unwrap_or(0);

        if current_stake > 0 {
            let slash_amount = (current_stake as u128 * slash_percentage as u128 / 10_000) as i128;
            let remaining_stake = current_stake.checked_sub(slash_amount)
                .ok_or(KoraError::ArithmeticUnderflow)?;

            env.storage()
                .persistent()
                .set(&DataKey::VerifierStake(verifier.clone()), &remaining_stake);
            Self::bump_persistent(&env, &DataKey::VerifierStake(verifier.clone()));
        }

        let current_reputation: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::VerifierReputation(verifier.clone()))
            .unwrap_or(100);

        let new_reputation = current_reputation.saturating_sub(10);
        env.storage()
            .persistent()
            .set(&DataKey::VerifierReputation(verifier.clone()), &new_reputation);
        Self::bump_persistent(&env, &DataKey::VerifierReputation(verifier.clone()));

        env.storage()
            .persistent()
            .set(&DataKey::SmeProfile(sme.clone()), &profile);
        Self::bump_persistent(&env, &DataKey::SmeProfile(sme.clone()));
        events::sme_default_recorded(&env, &admin, &sme, profile.defaults);
        Self::append_audit_entry(&env, &admin, AdminActionType::RecordDefault);
        Ok(())
    }

    /// Store a debtor risk score keyed by debtor hash. Verifier only.
    ///
    /// Enforces a per-(verifier, debtor_hash) cooldown of MIN_SCORE_UPDATE_INTERVAL seconds
    /// between consecutive updates so that rapid score changes immediately before a
    /// funding or default decision cannot be used to manipulate outcomes.
    pub fn set_debtor_score(
        env: Env,
        verifier: Address,
        debtor_hash: Bytes,
        score: u32,
    ) -> Result<(), KoraError> {
        verifier.require_auth();
        Self::require_verifier(&env, &verifier)?;
        // Validate exact 32-byte SHA-256 length before score
        require_exact_length(&debtor_hash, 32)?;
        require_valid_risk_score(score)?;

        // Enforce cooldown: same verifier cannot update the same debtor_hash within
        // MIN_SCORE_UPDATE_INTERVAL seconds of the previous update.
        let cooldown_key = DataKey::DebtorScoreLastUpdate(verifier.clone(), debtor_hash.clone());
        if let Some(last_update) = env.storage().persistent().get::<_, u64>(&cooldown_key) {
            let next_allowed = last_update
                .checked_add(MIN_SCORE_UPDATE_INTERVAL)
                .ok_or(KoraError::ArithmeticOverflow)?;
            if env.ledger().timestamp() < next_allowed {
                return Err(KoraError::ScoreUpdateCooldownNotElapsed);
            }
        }

        env.storage()
            .persistent()
            .set(&DataKey::DebtorScore(debtor_hash.clone()), &score);
        Self::bump_persistent(&env, &DataKey::DebtorScore(debtor_hash.clone()));

        // Record the update timestamp so the next call can check the cooldown.
        let now = env.ledger().timestamp();
        env.storage().persistent().set(&cooldown_key, &now);
        Self::bump_persistent(&env, &cooldown_key);

        events::debtor_score_set(&env, &verifier, &debtor_hash, score);
        Ok(())
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    pub fn get_sme_profile(env: Env, sme: Address) -> Result<SmeProfile, KoraError> {
        let key = DataKey::SmeProfile(sme);
        let profile: SmeProfile = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(KoraError::SMENotRegistered)?;
        Self::bump_persistent(&env, &key);
        Ok(profile)
    }

    pub fn is_verified_sme(env: Env, sme: Address) -> bool {
        env.storage()
            .persistent()
            .get::<DataKey, SmeProfile>(&DataKey::SmeProfile(sme))
            .map(|p| p.verified)
            .unwrap_or(false)
    }

    pub fn is_compliance_attested(env: Env, sme: Address) -> bool {
        env.storage()
            .persistent()
            .get::<DataKey, SmeProfile>(&DataKey::SmeProfile(sme))
            .map(|p| p.compliance_attested)
            .unwrap_or(false)
    }

    pub fn get_verifier_stake(env: Env, verifier: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::VerifierStake(verifier))
            .unwrap_or(0)
    }

    pub fn get_verifier_reputation(env: Env, verifier: Address) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::VerifierReputation(verifier))
            .unwrap_or(0)
    }

    pub fn is_verifier(env: Env, verifier: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Verifier(verifier))
            .unwrap_or(false)
    }

    /// Returns the debtor score or `KoraError::DebtorNotRegistered` if not found.
    pub fn get_debtor_score(env: Env, debtor_hash: Bytes) -> Result<u32, KoraError> {
        let key = DataKey::DebtorScore(debtor_hash);
        let score: u32 = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(KoraError::DebtorNotRegistered)?;
        Self::bump_persistent(&env, &key);
        Ok(score)
    }

    pub fn get_admin(env: Env) -> Result<Address, KoraError> {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(KoraError::NotInitialized)
    }

    // ── Upgrade ────────────────────────────────────────────────────────────────

    pub fn propose_upgrade(
        env: Env,
        admin: Address,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&DataKey::UpgradeProposal, &(new_wasm_hash.clone(), env.ledger().timestamp()));
        events::upgrade_proposed(&env, &admin, &new_wasm_hash);
        Self::append_audit_entry(&env, &admin, AdminActionType::RegistryProposeUpgrade);
        Ok(())
    }

    pub fn execute_upgrade(env: Env, admin: Address) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        let (wasm_hash, proposed_at): (BytesN<32>, u64) = env
            .storage()
            .instance()
            .get(&DataKey::UpgradeProposal)
            .ok_or(KoraError::NoUpgradeProposed)?;
        if env.ledger().timestamp() < proposed_at + UPGRADE_TIMELOCK_DELAY {
            return Err(KoraError::UpgradeTimelockNotElapsed);
        }
        env.storage().instance().remove(&DataKey::UpgradeProposal);
        events::upgrade_executed(&env, &admin, &wasm_hash);
        Self::append_audit_entry(&env, &admin, AdminActionType::RegistryExecuteUpgrade);
        env.deployer().update_current_contract_wasm(wasm_hash);
        Ok(())
    }

    // ── Audit Log ─────────────────────────────────────────────────────────────

    /// Return a page of audit log entries, newest first.
    /// `page` is 0-indexed; `page_size` is clamped to 1–50.
    pub fn get_audit_log(env: Env, page: u32, page_size: u32) -> Vec<AdminAuditEntry> {
        let page_size = (page_size.max(1).min(50)) as u64;
        let total: u64 = env
            .storage()
            .instance()
            .get(&DataKey::AuditLogTotal)
            .unwrap_or(0);
        let head: u64 = env
            .storage()
            .instance()
            .get(&DataKey::AuditLogHead)
            .unwrap_or(0);
        let stored = total.min(MAX_AUDIT_LOG_SIZE);

        let skip = (page as u64).saturating_mul(page_size);
        let mut results = Vec::new(&env);

        let mut i: u64 = 0;
        while i < page_size {
            let offset = skip + i;
            if offset >= stored {
                break;
            }
            let pos = (head + MAX_AUDIT_LOG_SIZE - 1 - offset) % MAX_AUDIT_LOG_SIZE;
            if let Some(entry) = env
                .storage()
                .persistent()
                .get::<DataKey, AdminAuditEntry>(&DataKey::AuditEntry(pos))
            {
                results.push_back(entry);
            }
            i += 1;
        }

        results
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn require_admin(env: &Env, caller: &Address) -> Result<(), KoraError> {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(KoraError::NotInitialized)?;
        if &admin != caller {
            return Err(KoraError::NotAdmin);
        }
        Ok(())
    }

    fn require_verifier(env: &Env, caller: &Address) -> Result<(), KoraError> {
        let ok: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Verifier(caller.clone()))
            .unwrap_or(false);
        if !ok {
            return Err(KoraError::NotVerifier);
        }
        Ok(())
    }

    fn require_invoice_nft(env: &Env, caller: &Address) -> Result<(), KoraError> {
        let invoice_nft: Address = env
            .storage()
            .persistent()
            .get(&DataKey::InvoiceNft)
            .ok_or(KoraError::NotInitialized)?;
        if &invoice_nft != caller {
            return Err(KoraError::Unauthorized);
        }
        Ok(())
    }

    /// Extend TTL on a persistent entry if it's below the threshold.
    fn bump_persistent(env: &Env, key: &DataKey) {
        env.storage()
            .persistent()
            .extend_ttl(key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_BUMP);
    }

    fn append_audit_entry(env: &Env, actor: &Address, action: AdminActionType) {
        let total: u64 = env
            .storage()
            .instance()
            .get(&DataKey::AuditLogTotal)
            .unwrap_or(0);
        let head: u64 = env
            .storage()
            .instance()
            .get(&DataKey::AuditLogHead)
            .unwrap_or(0);

        let entry = AdminAuditEntry {
            sequence: total,
            timestamp: env.ledger().timestamp(),
            actor: actor.clone(),
            action,
            source: AuditSource::RiskRegistry,
        };

        env.storage()
            .persistent()
            .set(&DataKey::AuditEntry(head), &entry);
        Self::bump_persistent(env, &DataKey::AuditEntry(head));

        events::admin_action_audited(env, &entry);

        let next_head = (head + 1) % MAX_AUDIT_LOG_SIZE;
        env.storage()
            .instance()
            .set(&DataKey::AuditLogHead, &next_head);
        env.storage()
            .instance()
            .set(&DataKey::AuditLogTotal, &(total + 1));
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        Bytes, Env,
    };

    /// Returns (env, admin, invoice_nft, staking_token, client)
    fn setup() -> (Env, Address, Address, Address, RiskRegistryContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, RiskRegistryContract);
        let client = RiskRegistryContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let invoice_nft = Address::generate(&env);
        let staking_token = Address::generate(&env);
        client.initialize(&admin, &invoice_nft, &staking_token, &1_000_000i128, &5_000u32).unwrap();
        (env, admin, invoice_nft, staking_token, client)
    }

    // ── initialize ────────────────────────────────────────────────────────────

    #[test]
    fn test_initialize_success() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, RiskRegistryContract);
        let client = RiskRegistryContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let invoice_nft = Address::generate(&env);
        let staking_token = Address::generate(&env);
        assert!(client.try_initialize(&admin, &invoice_nft, &staking_token, &1_000_000i128, &5_000u32).is_ok());
    }

    #[test]
    fn test_initialize_already_initialized() {
        let (env, admin, invoice_nft, staking_token, client) = setup();
        assert!(client.try_initialize(&admin, &invoice_nft, &staking_token, &1_000_000i128, &5_000u32).is_err());
    }

    // ── transfer_admin ────────────────────────────────────────────────────────

    #[test]
    fn test_transfer_admin_success() {
        let (env, admin, _, staking_token, client) = setup();
        let new_admin = Address::generate(&env);
        client.transfer_admin(&admin, &new_admin).unwrap();
        assert_eq!(client.get_admin().unwrap(), new_admin);
    }

    #[test]
    fn test_transfer_admin_requires_admin() {
        let (env, _, _, client) = setup();
        let stranger = Address::generate(&env);
        let new_admin = Address::generate(&env);
        assert!(client.try_transfer_admin(&stranger, &new_admin).is_err());
    }

    // ── add_verifier / remove_verifier ────────────────────────────────────────

    #[test]
    fn test_add_verifier_success() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        assert!(client.try_add_verifier(&admin, &verifier).is_ok());
        assert!(client.is_verifier(&verifier));
    }

    #[test]
    fn test_add_verifier_not_admin() {
        let (env, _, _, client) = setup();
        let stranger = Address::generate(&env);
        let verifier = Address::generate(&env);
        assert!(client.try_add_verifier(&stranger, &verifier).is_err());
    }

    #[test]
    fn test_remove_verifier_success() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        assert!(client.is_verifier(&verifier));
        assert!(client.try_remove_verifier(&admin, &verifier).is_ok());
        assert!(!client.is_verifier(&verifier));
    }

    #[test]
    fn test_remove_verifier_not_admin() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let stranger = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        assert!(client.try_remove_verifier(&stranger, &verifier).is_err());
    }

    #[test]
    fn test_remove_verifier_not_registered() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        assert!(client.try_remove_verifier(&admin, &verifier).is_err());
    }

    #[test]
    fn test_multiple_verifiers() {
        let (env, admin, _, staking_token, client) = setup();
        let v1 = Address::generate(&env);
        let v2 = Address::generate(&env);
        let sme1 = Address::generate(&env);
        let sme2 = Address::generate(&env);
        client.add_verifier(&admin, &v1, &1_000_000i128).unwrap();
        client.add_verifier(&admin, &v2, &1_000_000i128).unwrap();
        client.register_sme(&v1, &sme1, &30u32, &true).unwrap();
        client.register_sme(&v2, &sme2, &60u32, &true).unwrap();
        assert_eq!(client.get_sme_profile(&sme1).unwrap().risk_score, 30);
        assert_eq!(client.get_sme_profile(&sme2).unwrap().risk_score, 60);
        assert_eq!(client.get_sme_profile(&sme1).unwrap().verifier, v1);
        assert_eq!(client.get_sme_profile(&sme2).unwrap().verifier, v2);
    }

    // ── register_sme ──────────────────────────────────────────────────────────

    #[test]
    fn test_register_sme_flow() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.register_sme(&verifier, &sme, &35u32, &true).unwrap();
        assert!(client.is_verified_sme(&sme));
        let profile = client.get_sme_profile(&sme).unwrap();
        assert_eq!(profile.risk_score, 35);
        assert_eq!(profile.defaults, 0);
        assert_eq!(profile.total_invoices, 0);
        assert!(profile.verified);
        assert_eq!(profile.verifier, verifier);
        assert!(profile.compliance_attested);
    }

    #[test]
    fn test_register_sme_duplicate_rejected() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.register_sme(&verifier, &sme, &35u32, &true).unwrap();
        assert!(client.try_register_sme(&verifier, &sme, &50u32).is_err());
    }

    #[test]
    fn test_register_sme_unverified_verifier() {
        let (env, _, _, client) = setup();
        let stranger = Address::generate(&env);
        let sme = Address::generate(&env);
        assert!(client.try_register_sme(&stranger, &sme, &10u32).is_err());
    }

    #[test]
    fn test_register_sme_invalid_risk_score() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        assert!(client.try_register_sme(&verifier, &sme, &101u32).is_err());
    }

    #[test]
    fn test_register_sme_preserves_history_on_re_registration_attempt() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.register_sme(&verifier, &sme, &35u32, &true).unwrap();
        let _ = client.try_register_sme(&verifier, &sme, &99u32, &true);
        let profile = client.get_sme_profile(&sme).unwrap();
        assert_eq!(profile.risk_score, 35); // unchanged
    }

    #[test]
    fn test_register_sme_compliance_attested_true() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.register_sme(&verifier, &sme, &50u32, &true).unwrap();
        let profile = client.get_sme_profile(&sme).unwrap();
        assert!(profile.compliance_attested);
        assert!(client.is_compliance_attested(&sme));
    }

    #[test]
    fn test_register_sme_compliance_attested_false() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.register_sme(&verifier, &sme, &50u32, &false).unwrap();
        let profile = client.get_sme_profile(&sme).unwrap();
        assert!(!profile.compliance_attested);
        assert!(!client.is_compliance_attested(&sme));
    }

    // ── update_sme_score ──────────────────────────────────────────────────────

    #[test]
    fn test_update_sme_score_success() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.register_sme(&verifier, &sme, &35u32, &true).unwrap();
        client.update_sme_score(&verifier, &sme, &50u32).unwrap();
        assert_eq!(client.get_sme_profile(&sme).unwrap().risk_score, 50);
    }

    #[test]
    fn test_update_sme_score_not_registered() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        assert!(client
            .try_update_sme_score(&verifier, &sme, &50u32)
            .is_err());
    }

    #[test]
    fn test_update_sme_score_invalid() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.register_sme(&verifier, &sme, &35u32, &true).unwrap();
        assert!(client
            .try_update_sme_score(&verifier, &sme, &101u32)
            .is_err());
    }

    #[test]
    fn test_update_sme_score_boundary_values() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.register_sme(&verifier, &sme, &50u32, &true).unwrap();
        client.update_sme_score(&verifier, &sme, &0u32).unwrap();
        assert_eq!(client.get_sme_profile(&sme).unwrap().risk_score, 0);
        client.update_sme_score(&verifier, &sme, &100u32).unwrap();
        assert_eq!(client.get_sme_profile(&sme).unwrap().risk_score, 100);
    }

    // ── increment_invoice_count ───────────────────────────────────────────────

    #[test]
    fn test_increment_invoice_count() {
        let (env, admin, invoice_nft, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.register_sme(&verifier, &sme, &35u32, &true).unwrap();
        assert_eq!(client.get_sme_profile(&sme).unwrap().total_invoices, 0);
        client.increment_invoice_count(&invoice_nft, &sme).unwrap();
        assert_eq!(client.get_sme_profile(&sme).unwrap().total_invoices, 1);
    }

    #[test]
    fn test_increment_invoice_count_multiple() {
        let (env, admin, invoice_nft, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.register_sme(&verifier, &sme, &35u32, &true).unwrap();
        for i in 1u32..=5 {
            client.increment_invoice_count(&invoice_nft, &sme).unwrap();
            assert_eq!(client.get_sme_profile(&sme).unwrap().total_invoices, i);
        }
    }

    #[test]
    fn test_increment_invoice_count_unauthorized_caller() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        let stranger = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.register_sme(&verifier, &sme, &35u32, &true).unwrap();
        assert!(client.try_increment_invoice_count(&stranger, &sme).is_err());
    }

    #[test]
    fn test_increment_invoice_count_sme_not_registered() {
        let (env, _, invoice_nft, client) = setup();
        let sme = Address::generate(&env);
        assert!(client
            .try_increment_invoice_count(&invoice_nft, &sme)
            .is_err());
    }

    // ── record_default ────────────────────────────────────────────────────────

    #[test]
    fn test_record_default() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.register_sme(&verifier, &sme, &35u32, &true).unwrap();
        assert_eq!(client.get_sme_profile(&sme).unwrap().defaults, 0);
        client.record_default(&admin, &sme).unwrap();
        assert_eq!(client.get_sme_profile(&sme).unwrap().defaults, 1);
    }

    #[test]
    fn test_record_default_not_admin() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        let stranger = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.register_sme(&verifier, &sme, &35u32, &true).unwrap();
        assert!(client.try_record_default(&stranger, &sme).is_err());
    }

    #[test]
    fn test_record_default_sme_not_registered() {
        let (env, admin, _, staking_token, client) = setup();
        let sme = Address::generate(&env);
        assert!(client.try_record_default(&admin, &sme).is_err());
    }

    #[test]
    fn test_record_multiple_defaults() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.register_sme(&verifier, &sme, &35u32, &true).unwrap();
        client.record_default(&admin, &sme).unwrap();
        client.record_default(&admin, &sme).unwrap();
        client.record_default(&admin, &sme).unwrap();
        assert_eq!(client.get_sme_profile(&sme).unwrap().defaults, 3);
    }

    // ── set_debtor_score / get_debtor_score ───────────────────────────────────

    #[test]
    fn test_set_debtor_score() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let debtor_hash = Bytes::from_slice(&env, &[0xABu8; 32]);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client
            .set_debtor_score(&verifier, &debtor_hash, &45u32)
            .unwrap();
        assert_eq!(client.get_debtor_score(&debtor_hash).unwrap(), 45u32);
    }

    #[test]
    fn test_set_debtor_score_invalid_score() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let debtor_hash = Bytes::from_slice(&env, &[0xABu8; 32]);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        assert!(client
            .try_set_debtor_score(&verifier, &debtor_hash, &101u32)
            .is_err());
    }

    #[test]
    fn test_set_debtor_score_empty_hash() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let empty_hash = Bytes::from_slice(&env, &[]);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        assert!(client
            .try_set_debtor_score(&verifier, &empty_hash, &50u32)
            .is_err());
    }

    #[test]
    fn test_set_debtor_score_exact_32_bytes_accepted() {
        let (env, admin, _, client) = setup();
        let verifier = Address::generate(&env);
        let hash = Bytes::from_slice(&env, &[0xABu8; 32]);
        client.add_verifier(&admin, &verifier).unwrap();
        assert!(client.try_set_debtor_score(&verifier, &hash, &50u32).is_ok());
    }

    #[test]
    fn test_set_debtor_score_31_bytes_rejected() {
        let (env, admin, _, client) = setup();
        let verifier = Address::generate(&env);
        let hash = Bytes::from_slice(&env, &[0xABu8; 31]);
        client.add_verifier(&admin, &verifier).unwrap();
        let result = client.try_set_debtor_score(&verifier, &hash, &50u32);
        assert_eq!(result.unwrap_err().unwrap(), KoraError::InvalidLength);
    }

    #[test]
    fn test_set_debtor_score_33_bytes_rejected() {
        let (env, admin, _, client) = setup();
        let verifier = Address::generate(&env);
        let hash = Bytes::from_slice(&env, &[0xABu8; 33]);
        client.add_verifier(&admin, &verifier).unwrap();
        let result = client.try_set_debtor_score(&verifier, &hash, &50u32);
        assert_eq!(result.unwrap_err().unwrap(), KoraError::InvalidLength);
    }

    #[test]
    fn test_set_debtor_score_not_verifier() {
        let (env, _, _, client) = setup();
        let stranger = Address::generate(&env);
        let debtor_hash = Bytes::from_slice(&env, &[0xABu8; 32]);
        assert!(client
            .try_set_debtor_score(&stranger, &debtor_hash, &50u32)
            .is_err());
    }

    #[test]
    fn test_get_debtor_score_not_found() {
        let (env, _, _, client) = setup();
        let debtor_hash = Bytes::from_slice(&env, &[0xCDu8; 32]);
        assert!(client.try_get_debtor_score(&debtor_hash).is_err());
    }

    #[test]
    fn test_debtor_score_boundary_values() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        let hash0 = Bytes::from_slice(&env, &[0x01u8; 32]);
        client.set_debtor_score(&verifier, &hash0, &0u32).unwrap();
        assert_eq!(client.get_debtor_score(&hash0).unwrap(), 0u32);
        let hash100 = Bytes::from_slice(&env, &[0x02u8; 32]);
        client
            .set_debtor_score(&verifier, &hash100, &100u32)
            .unwrap();
        assert_eq!(client.get_debtor_score(&hash100).unwrap(), 100u32);
        let hash_invalid = Bytes::from_slice(&env, &[0x03u8; 32]);
        assert!(client
            .try_set_debtor_score(&verifier, &hash_invalid, &101u32)
            .is_err());
    }

    // ── views ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_sme_profile_not_found() {
        let (env, _, _, client) = setup();
        let sme = Address::generate(&env);
        assert!(client.try_get_sme_profile(&sme).is_err());
    }

    #[test]
    fn test_is_verified_sme_false_for_unregistered() {
        let (env, _, _, client) = setup();
        let sme = Address::generate(&env);
        assert!(!client.is_verified_sme(&sme));
    }

    // ── risk score boundary ───────────────────────────────────────────────────

    #[test]
    fn test_risk_score_boundary_values() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        let sme0 = Address::generate(&env);
        client.register_sme(&verifier, &sme0, &0u32, &true).unwrap();
        assert_eq!(client.get_sme_profile(&sme0).unwrap().risk_score, 0);
        let sme100 = Address::generate(&env);
        client.register_sme(&verifier, &sme100, &100u32, &true).unwrap();
        assert_eq!(client.get_sme_profile(&sme100).unwrap().risk_score, 100);
        let sme_invalid = Address::generate(&env);
        assert!(client
            .try_register_sme(&verifier, &sme_invalid, &101u32)
            .is_err());
    }

    // ── event emission ────────────────────────────────────────────────────────

    #[test]
    fn test_add_verifier_emits_event() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        assert!(!env.events().all().is_empty());
    }

    #[test]
    fn test_remove_verifier_emits_event() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        let events_before = env.events().all().len();
        client.remove_verifier(&admin, &verifier).unwrap();
        assert!(env.events().all().len() > events_before);
    }

    #[test]
    fn test_register_sme_emits_event() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        let events_before = env.events().all().len();
        client.register_sme(&verifier, &sme, &42u32, &true).unwrap();
        assert!(env.events().all().len() > events_before);
    }

    #[test]
    fn test_increment_invoice_count_emits_event() {
        let (env, admin, invoice_nft, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.register_sme(&verifier, &sme, &35u32, &true).unwrap();
        let events_before = env.events().all().len();
        client.increment_invoice_count(&invoice_nft, &sme).unwrap();
        assert!(env.events().all().len() > events_before);
        assert_eq!(client.get_sme_profile(&sme).unwrap().total_invoices, 1);
    }

    #[test]
    fn test_failed_operations_do_not_emit_events() {
        let (env, _, _, client) = setup();
        let stranger = Address::generate(&env);
        let verifier = Address::generate(&env);
        let events_before = env.events().all().len();
        let _ = client.try_add_verifier(&stranger, &verifier);
        let _ = client.try_register_sme(&stranger, &verifier, &50u32);
        let _ = client.try_record_default(&stranger, &verifier);
        assert_eq!(env.events().all().len(), events_before);
    }

    #[test]
    fn test_sme_default_event_carries_cumulative_count() {
        let (env, admin, _, staking_token, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.register_sme(&verifier, &sme, &80u32, &true).unwrap();
        client.record_default(&admin, &sme).unwrap();
        assert_eq!(client.get_sme_profile(&sme).unwrap().defaults, 1);
        client.record_default(&admin, &sme).unwrap();
        assert_eq!(client.get_sme_profile(&sme).unwrap().defaults, 2);
        client.record_default(&admin, &sme).unwrap();
        assert_eq!(client.get_sme_profile(&sme).unwrap().defaults, 3);
    }

    #[test]
    fn test_initialize_self_as_admin_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, RiskRegistryContract);
        let client = RiskRegistryContractClient::new(&env, &contract_id);
        let invoice_nft = Address::generate(&env);
        let result = client.try_initialize(&contract_id, &invoice_nft);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_verifier_self_as_verifier_rejected() {
        let (env, admin, _, client) = setup();
        let contract_id = client.address.clone();
        let result = client.try_add_verifier(&admin, &contract_id, &1_000_000i128);
        assert!(result.is_err());
    }

    // ── transfer_admin edge cases ─────────────────────────────────────────────

    #[test]
    fn test_transfer_admin_to_same_address_allowed() {
        // The contract imposes no uniqueness constraint on the new admin —
        // idempotent re-assignment should succeed (it's a no-op in effect).
        let (env, admin, _, client) = setup();
        assert!(client.try_transfer_admin(&admin, &admin).is_ok());
        assert_eq!(client.get_admin().unwrap(), admin);
    }

    // ── update_sme_score with score = 0 ──────────────────────────────────────

    #[test]
    fn test_update_sme_score_to_zero() {
        let (env, admin, _, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier).unwrap();
        client.register_sme(&verifier, &sme, &50u32).unwrap();
        // Score 0 is valid (lowest risk tier boundary).
        client.update_sme_score(&verifier, &sme, &0u32).unwrap();
        assert_eq!(client.get_sme_profile(&sme).unwrap().risk_score, 0);
    }

    // ── set_debtor_score update (overwrite after cooldown) ───────────────────

    #[test]
    fn test_set_debtor_score_update_existing() {
        // set_debtor_score overwrites the score — calling it a second time after the
        // cooldown elapses must persist the latest value.
        let (env, admin, _, _, client) = setup();
        let verifier = Address::generate(&env);
        let debtor_hash = Bytes::from_slice(&env, &[0xAAu8; 32]);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.set_debtor_score(&verifier, &debtor_hash, &30u32).unwrap();
        assert_eq!(client.get_debtor_score(&debtor_hash).unwrap(), 30);
        // Advance past the cooldown before the second update.
        env.ledger().set(LedgerInfo {
            timestamp: MIN_SCORE_UPDATE_INTERVAL,
            ..env.ledger().get()
        });
        client.set_debtor_score(&verifier, &debtor_hash, &75u32).unwrap();
        assert_eq!(client.get_debtor_score(&debtor_hash).unwrap(), 75);
    }

    // ── verifier cannot register itself as an SME ─────────────────────────────

    #[test]
    fn test_verifier_cannot_register_itself_as_sme() {
        // A verifier registering itself as an SME would create a conflict of
        // interest. The require_not_self guard on add_verifier prevents a
        // contract from being added as verifier, but a human verifier address
        // could still call register_sme on itself — which is allowed by the
        // current design. This test documents the current behaviour.
        let (env, admin, _, client) = setup();
        let verifier = Address::generate(&env);
        client.add_verifier(&admin, &verifier).unwrap();
        // A verifier registering themselves as an SME is permitted (no rule
        // prevents it). The test ensures it doesn't panic / silently fail.
        assert!(client.try_register_sme(&verifier, &verifier, &40u32).is_ok());
        assert_eq!(client.get_sme_profile(&verifier).unwrap().verifier, verifier);
    }

    // ── remove verifier while still registered as SME ─────────────────────────

    #[test]
    fn test_remove_verifier_does_not_affect_sme_profile() {
        // Removing a verifier's authorization must not delete SME profiles they
        // previously created — those profiles belong to the SMEs, not the verifier.
        let (env, admin, _, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier).unwrap();
        client.register_sme(&verifier, &sme, &40u32).unwrap();
        client.remove_verifier(&admin, &verifier).unwrap();
        // SME profile still accessible.
        assert_eq!(client.get_sme_profile(&sme).unwrap().risk_score, 40);
        // But the removed verifier can no longer update scores.
        assert!(client.try_update_sme_score(&verifier, &sme, &60u32).is_err());
    }

    // ── register_sme with score = 0 ───────────────────────────────────────────

    #[test]
    fn test_register_sme_score_zero() {
        let (env, admin, _, client) = setup();
        let verifier = Address::generate(&env);
        let sme = Address::generate(&env);
        client.add_verifier(&admin, &verifier).unwrap();
        // Score 0 is valid: AAA tier.
        assert!(client.try_register_sme(&verifier, &sme, &0u32).is_ok());
        assert_eq!(client.get_sme_profile(&sme).unwrap().risk_score, 0);
    }

    // ── get_admin before initialization ───────────────────────────────────────

    #[test]
    fn test_get_admin_before_initialization_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, RiskRegistryContract);
        let client = RiskRegistryContractClient::new(&env, &contract_id);
        assert!(client.try_get_admin().is_err());
    }

    // ── set_debtor_score cooldown ─────────────────────────────────────────────

    #[test]
    fn test_set_debtor_score_first_call_always_succeeds() {
        // There is no prior timestamp, so the first update is always allowed.
        let (env, admin, _, _, client) = setup();
        let verifier = Address::generate(&env);
        let debtor_hash = Bytes::from_slice(&env, &[0xBBu8; 32]);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        assert!(client
            .try_set_debtor_score(&verifier, &debtor_hash, &40u32)
            .is_ok());
    }

    #[test]
    fn test_set_debtor_score_cooldown_blocks_immediate_second_update() {
        // A second update before MIN_SCORE_UPDATE_INTERVAL seconds have passed
        // must be rejected with ScoreUpdateCooldownNotElapsed.
        let (env, admin, _, _, client) = setup();
        let verifier = Address::generate(&env);
        let debtor_hash = Bytes::from_slice(&env, &[0xCCu8; 32]);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        client.set_debtor_score(&verifier, &debtor_hash, &40u32).unwrap();
        // Advance time by one second less than the cooldown — still blocked.
        env.ledger().set(LedgerInfo {
            timestamp: MIN_SCORE_UPDATE_INTERVAL - 1,
            ..env.ledger().get()
        });
        let err = client
            .try_set_debtor_score(&verifier, &debtor_hash, &60u32)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, KoraError::ScoreUpdateCooldownNotElapsed);
    }

    #[test]
    fn test_set_debtor_score_cooldown_allows_update_at_exact_boundary() {
        // At exactly timestamp == last_update + MIN_SCORE_UPDATE_INTERVAL the
        // condition `current < next_allowed` is false, so the call must succeed.
        let (env, admin, _, _, client) = setup();
        let verifier = Address::generate(&env);
        let debtor_hash = Bytes::from_slice(&env, &[0xDDu8; 32]);
        client.add_verifier(&admin, &verifier, &1_000_000i128).unwrap();
        // First update at t=0.
        client.set_debtor_score(&verifier, &debtor_hash, &40u32).unwrap();
        // Advance to exactly the boundary.
        env.ledger().set(LedgerInfo {
            timestamp: MIN_SCORE_UPDATE_INTERVAL,
            ..env.ledger().get()
        });
        assert!(client
            .try_set_debtor_score(&verifier, &debtor_hash, &55u32)
            .is_ok());
        assert_eq!(client.get_debtor_score(&debtor_hash).unwrap(), 55);
    }

    #[test]
    fn test_set_debtor_score_cooldown_is_per_verifier() {
        // Different verifiers operate independent cooldowns for the same debtor_hash.
        let (env, admin, _, _, client) = setup();
        let verifier_a = Address::generate(&env);
        let verifier_b = Address::generate(&env);
        let debtor_hash = Bytes::from_slice(&env, &[0xEEu8; 32]);
        client.add_verifier(&admin, &verifier_a, &1_000_000i128).unwrap();
        client.add_verifier(&admin, &verifier_b, &1_000_000i128).unwrap();
        // verifier_a sets the score; its cooldown now ticks.
        client.set_debtor_score(&verifier_a, &debtor_hash, &40u32).unwrap();
        // verifier_b has never updated this debtor → no cooldown → must succeed.
        assert!(client
            .try_set_debtor_score(&verifier_b, &debtor_hash, &55u32)
            .is_ok());
    }
}
