//! ARCH-0038 deletion/redaction contract types.

mod delete;
mod erase;
mod gate;
mod publish;
mod receipt;
mod rendezvous;
mod sweep_queue;
mod timeline;
mod tombstone;

#[cfg(test)]
mod tests;

pub use delete::DeleteEntityOutcome;
pub use timeline::{
    HydratedShortIdDeletion, HydratedShortIdDeletionReason, HydratedShortIdDeletionSource,
    MemoryOperationKind, MemoryTimeline, MemoryTimelineRecord, MemoryTimelineRecordState,
    NamedMemoryVerb,
};
pub use tombstone::{
    DecodedTombstoneValue, DeleteReason, TOMBSTONE_VALUE_LEGACY_LEN, TOMBSTONE_VALUE_V2_LEN,
    TombstoneReason, TombstoneValueV2, decode_tombstone_value,
};

pub(crate) use gate::{DeletionGateContext, GatedDeletion};
pub(crate) use receipt::{
    decode_redaction_audit_receipt, receipt_envelope_header, validate_redaction_receipt_body,
};
pub(crate) use sweep_queue::{
    HARD_ERASE_SWEEP_PREFIX, HardEraseSweepJob, decode_hard_erase_sweep_job,
    decode_hard_erase_sweep_seq, encode_hard_erase_sweep_job_value,
};
pub(crate) use tombstone::{LOCAL_HARD_DELETE_PREFIX, local_hard_delete_key};
// The `pt:` window vocabulary and the replay outcome are read by sync
// production (`sync::window`, `sync::quarantine`, `sync::types`) and by the
// white-box test modules that pin the base replay law; a plain no-feature
// library reaches none of them.
#[cfg(any(feature = "sync", test))]
pub(crate) use tombstone::{
    PENDING_TOMBSTONE_PREFIX, ReplayedTombstoneOutcome, window_label_from_timestamp,
};

#[cfg(feature = "sync")]
pub(crate) use receipt::{
    ATT_EMPTY_MAP_BYTE, RECEIPT_ATT_DOMAIN, receipt_attestation_parts,
    redaction_receipt_is_stale_finalization_echo,
};

// Crate-facing paths whose consumers are all `#[cfg(test)]`; the re-export
// carries the same gate so a non-test build re-exports nothing it never uses.
#[cfg(test)]
pub(crate) use receipt::{
    RedactionReceiptInput, RedactionScope, encode_redaction_audit_receipt, hex_lower,
};
#[cfg(test)]
pub(crate) use rendezvous::DeleteRendezvous;
#[cfg(all(test, not(feature = "sync")))]
pub(crate) use rendezvous::arm_fail_first_txn_pending_tombstone;
#[cfg(all(test, feature = "sync"))]
pub(crate) use rendezvous::{
    arm_fail_after_tombstone_before_purge, arm_fail_live_tombstone_persist,
};
#[cfg(test)]
pub(crate) use rendezvous::{install_after_header_read_signal, install_delete_rendezvous};
#[cfg(test)]
pub(crate) use sweep_queue::{
    HARD_ERASE_SWEEP_SLA_SECS, HardEraseSweepExtras, LAST_HARD_ERASE_SWEEP_SEQ_KEY,
    encode_hard_erase_sweep_job, encode_hard_erase_sweep_key,
};
#[cfg(test)]
pub(crate) use tombstone::{is_leap_year, pending_tombstone_key};

// The flat deletion.rs module used to provide this name to the test module
// through `use super::*`; after the directory split the seam re-imports it so
// the sibling `tests.rs` resolves exactly as it did inline.
#[cfg(test)]
use crate::entity_id::EntityId;
