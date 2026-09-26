//! Consolidated integration-test binary for the native vector suites.
//!
//! These suites use `NativeSealEngine`; the featureless API tests live in
//! the library. Do not compile native-only integration modules in base mode.
//! `tests/oracle.rs` stays a standalone target: it is gated on the
//! `seal-oracle` feature at the Cargo target level. `support` stays at
//! `tests/support/mod.rs` because both this binary and `oracle` include it.

#![cfg(feature = "native")]

#[path = "../support/mod.rs"]
mod support;

mod fetch_policy;
mod seal_vectors;
mod verify_vectors;
