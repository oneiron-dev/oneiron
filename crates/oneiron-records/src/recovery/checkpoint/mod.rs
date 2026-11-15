//! Moved from `crates/oneiron/src/recovery/checkpoint/mod.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::recovery::checkpoint::admission::facts::AnchorDisposition;
pub use crate::recovery::checkpoint::admission::facts::CustodyRouteFact;
pub use crate::recovery::checkpoint::admission::facts::RetiredBy;
pub use crate::recovery::checkpoint::admission::facts::SignerTrust;
pub use crate::recovery::checkpoint::custody_head::*;
pub use crate::recovery::checkpoint::epochs::RestorePadState;
pub use crate::recovery::checkpoint::pad_custody::PadRestoreNote;
pub use crate::recovery::checkpoint::pad_reopen::PadReopenFault;
pub use crate::recovery::checkpoint::pad_reopen::PadReopenReport;
pub use crate::recovery::checkpoint::pad_reopen::PadReopenStage;
pub use crate::recovery::checkpoint::watermark::BackupSelection;
pub use crate::store::key_custody::protocol as custody_protocol;
pub use oneiron_crypto::backup::ArtifactKind;
pub use oneiron_crypto::backup::CheckpointSigner;
pub use oneiron_crypto::backup::HostHoldsAvailability;
pub use oneiron_crypto::backup::HostHoldsUnavailable;
pub use oneiron_crypto::backup::inspect_backup;
pub use oneiron_crypto::backup::verify_with_pins;
pub use oneiron_store::checkpoint_host_recipient::HostHoldsRecipient;
pub use oneiron_store::checkpoint_host_recipient::HostHoldsSealing;
pub use oneiron_store::recovery_write_budget::AtWriteFloor;
pub use oneiron_store::recovery_write_budget::RecoveryWriteBudget;
pub use oneiron_store::restore_admission::RestoreAdmissionError;
pub use oneiron_store::restore_admission::RestoreAdmissionReason;
pub use oneiron_store::restore_admission::RestoreDestinationState;
pub use oneiron_store::restore_admission::RestorePhase;
pub use oneiron_vault_contract::restore::EscrowRole;
pub use oneiron_vault_contract::restore::FreshRecipient;
pub use oneiron_vault_contract::restore::ReleasedRecipient;
pub use oneiron_vault_contract::restore::RestorePlan;
use serde::Deserialize;
use serde::Serialize;

pub type CanonicalRows = Vec<(Vec<u8>, Vec<u8>)>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestoreReason {
    Restore,
    Wake,
    Migrate,
    /// An owner's activation of an archived vault as a side vault
    /// ([`Vault::activate_archived`]): it lands no checkpoint, so its epoch
    /// names none.
    Activate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreEpoch {
    pub checkpoint_id: String,
    pub restored_at: u64,
    pub reason: RestoreReason,
    /// What it still owes of the world key pads its image names (PAD-2):
    /// absent from a row that owes and says nothing.
    #[serde(default, skip_serializing_if = "RestorePadState::is_empty")]
    pub pad_recovery: RestorePadState,
}
pub mod admission;
pub mod custody_head;
pub mod epochs;
pub mod pad_custody;
pub mod pad_reopen;
pub mod payload;
pub mod tiers;
pub mod watermark;
