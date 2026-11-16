//! Moved from `crates/oneiron/src/batch/secret_scan.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::batch::secret_scan::lift_history::LiftCause;
pub use crate::batch::secret_scan::lift_history::LiftCauseCount;
pub use crate::batch::secret_scan::lift_history::LiftCloseReason;
pub use crate::batch::secret_scan::lift_history::LiftTrigger;
pub use crate::batch::secret_scan::lift_history::SecretLiftClose;
pub use crate::batch::secret_scan::lift_history::SecretLiftRequest;

/// The vault's `secrets` setting: whether the write door scans what a host
/// writes into this vault for credential shapes. On by default; the vault
/// owner switches it (the engine's catalogue key `secret_scan.mode`), and
/// every switch is a setting change row.
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

/// The engine's catalogue key `secret_scan.mode` holds the switch.
impl oneiron_setting_contract::SettingValue for SecretScanMode {}
pub mod lift_history;
