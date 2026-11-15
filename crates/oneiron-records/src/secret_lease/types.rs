//! Moved from `crates/oneiron/src/secret_lease/types.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_contracts::secret_lease::SecretLeaseStatus;
pub use oneiron_store::secret_lease::types::*;
use serde::Deserialize;
use serde::Serialize;

/// The T0 door-injection receipt — the ONLY thing the workspace receives
/// from [`Vault::inject_secret_at_door`]. Carries no value bytes by
/// construction; `Debug` and serde are safe (grep-guard tested).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoorInjectionReceipt {
    /// The secret name injected.
    pub secret_ref: String,
    /// The effector the binding was resolved for.
    pub effector: String,
    /// Unix seconds at injection (stamped at materialization, S3 —
    /// environment reads are not interceptable).
    pub injected_at: u64,
    /// The record's rotation generation the value was read at.
    pub value_generation: u32,
    /// SECRET-04 attaches exhaust taint from this token.
    pub taint_token: Vec<SecretTaintRef>,
}
