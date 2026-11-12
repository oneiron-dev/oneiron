//! Moved from `crates/oneiron/src/batch/secret_scan.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::batch::secret_scan::lift_history::LiftCause;
pub use crate::batch::secret_scan::lift_history::LiftCauseCount;
pub use crate::batch::secret_scan::lift_history::LiftCloseReason;
pub use crate::batch::secret_scan::lift_history::LiftCounts;
pub use crate::batch::secret_scan::lift_history::LiftFamily;
pub use crate::batch::secret_scan::lift_history::LiftTrigger;
pub use crate::batch::secret_scan::lift_history::SecretLiftClose;
pub use crate::batch::secret_scan::lift_history::SecretLiftHistoryProposal;
pub use crate::batch::secret_scan::lift_history::SecretLiftProgress;
pub use crate::batch::secret_scan::lift_history::SecretLiftReceipt;
pub use crate::batch::secret_scan::lift_history::SecretLiftRequest;
pub use crate::batch::secret_scan::lift_history::SecretLiftStatus;
use heed::RoTxn;
use heed::RwTxn;
use oneiron_base::error::Error;
use oneiron_base::error::GateError;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_ASSET;
use oneiron_base::registry::ENTITY_TYPE_SECRET_CUSTODY;
use oneiron_store::batch::builder::ops::BatchOp;
use oneiron_store::batch::export::archive_types::ExportSecretsNulledManifest;
pub(crate) use oneiron_store::batch::secret_scan::container::is_container;
pub(crate) use oneiron_store::batch::secret_scan::container::projection_edit::RetainedProjectionEdit;
pub(crate) use oneiron_store::batch::secret_scan::whole_read::Encoding;
use oneiron_store::batch::secret_scan::whole_read::JoinedText;
pub(crate) use oneiron_store::batch::secret_scan::whole_read::encode_as_stored;
use oneiron_store::batch::secret_scan::wordlist;

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
