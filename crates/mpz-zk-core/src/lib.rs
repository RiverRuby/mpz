//! Low-level crate containing core functionalities for zero-knowledge protocols.
//!
//! This crate is not intended to be used directly. Instead, use the higher-level APIs provided by
//! the `mpz-zk` crate.
//!
//! # ⚠️ Warning ⚠️
//!
//! Some implementations make assumptions about invariants which may not be checked if using these
//! low-level APIs naively. Failing to uphold these invariants may result in security vulnerabilities.
//!
//! USE AT YOUR OWN RISK.

#![deny(
    unsafe_code,
    missing_docs,
    unused_imports,
    unused_must_use,
    unreachable_pub,
    clippy::all
)]

use mpz_ot_core::TransferId;

pub mod ideal;
pub mod quicksilver;
pub mod test;
pub mod vope;

/// The output the receiver receives from the VOPE functionality.
#[derive(Debug)]
pub struct VOPEReceiverOutput<T> {
    /// The transfer id.
    pub id: TransferId,
    /// The coefficients.
    pub coeff: Vec<T>,
}

/// The output the sender receives from the VOPE functinality.
#[derive(Debug)]
pub struct VOPESenderOutput<T> {
    /// The transfer id.
    pub id: TransferId,
    /// The evaluation value.
    pub eval: T,
}
