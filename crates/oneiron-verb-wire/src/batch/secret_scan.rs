//! Moved from `crates/oneiron/src/batch/secret_scan.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::batch::secret_scan::lift_history::LiftCause;
pub use crate::batch::secret_scan::lift_history::LiftCauseCount;
pub use crate::batch::secret_scan::lift_history::LiftCloseReason;
pub use crate::batch::secret_scan::lift_history::LiftTrigger;
pub use crate::batch::secret_scan::lift_history::SecretLiftClose;
pub use crate::batch::secret_scan::lift_history::SecretLiftRequest;

/// The vault's `secrets` setting: whether the write door scans what a host
/// writes into this vault for credential shapes. On by default; only the
/// vault owner switches it, and every switch writes a receipt
/// (`Vault::set_secret_scan_mode`).
/// Serve and export redact credentials in both modes.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SecretScanMode {
    /// The write door scans. A secret it can place in text or a field goes
    /// to custody and leaves its handle there; any other hit refuses the
    /// whole write.
    #[default]
    On,
    /// The write door does not scan; serve and export still redact.
    Off,
}
pub mod lift_history;
