//! Moved from `crates/oneiron/src/gate/dispatch_compliance/observations.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// One ACTIVE `comm.jurisdiction` observation as the gate ranks it: when it
/// was observed, its normalized token, and its confidence in thousandths.
pub type JurisdictionObservation = (u64, String, Option<u16>);
