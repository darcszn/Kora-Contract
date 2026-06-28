#![no_std]

//! # Kora Shared Library
//!
//! Shared types, errors, events, validation helpers, and reentrancy guards
//! used across all Kora Protocol contracts.
//!
//! ## Modules
//!
//! - [`errors`] — `KoraError` enum used across all contracts
//! - [`events`] — Protocol event emission functions (single source of truth)
//! - [`reentrancy`] — RAII reentrancy guard and low-level lock helpers
//! - [`types`] — Shared data structures (`Invoice`, `Listing`, `Pool`, etc.)
//! - [`validation`] — Reusable input validation guards and safe arithmetic
//!
//! ## Design Principles
//!
//! - All financial calculations use checked arithmetic (`checked_*` methods)
//! - No silent overflows — errors are returned as `KoraError::ArithmeticOverflow`
//! - Input validation is centralized and consistent across all contracts
//! - Storage keys use `#[contracttype]` enums for type safety

pub mod audit;
pub mod errors;
pub mod events;
pub mod reentrancy;
pub mod types;
pub mod validation;
