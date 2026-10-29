//! ARCH-0038 deletion/redaction contract types.

mod actor_fields;
mod checkpoint_payload;
mod coop_delivery;
mod coop_reply;
mod coop_request;
mod coop_succession;
mod delete;
mod derived_rows;
mod erase;
mod gate;
mod identity_event_stamps;
mod legal_hold;
mod publish;
mod receipt;
mod receipt_completion;
mod receipt_final;
mod receipt_grammar;
mod receipt_origin;
mod rendezvous;
mod sweep_queue;
mod timeline;
mod tombstone;
pub(crate) mod tombstone_scope;
pub(crate) mod topology_delete_intent;

#[cfg(test)]
mod tests;

pub use coop_delivery::{
    COOP_DELETION_DELIVERY_ATTEMPT_KIND, COOP_DELETION_GIVE_UP_SECS, COOP_DELETION_PEER_PATH,
    COOP_DELETION_REPLY_PEER_PATH, CooperativeDeleteOperation, CooperativeDeleteRecord,
    CooperativeDeleteRecordState, CooperativeDeletionAnswer, CooperativeDeletionDelivery,
    CooperativeDeletionDeliveryStatus, CooperativeDeletionDisposition,
    CooperativeDeletionDispositionKind, CooperativeDeletionIngress, CooperativeDeletionNotice,
    CooperativeDeletionTry, IncomingCooperativeDeletion, cooperative_deletion_recipient_id,
    parse_hex,
};
pub(crate) use coop_delivery::{MAX_REASON_CODE_LEN, courtesy_retained_pacts_in};
pub use coop_reply::{
    COOP_DELETION_REPLY_BODY_KEYS, COOP_DELETION_REPLY_DOMAIN, COOP_DELETION_REPLY_SCHEMA_VERSION,
    CooperativeDeletionReply, CooperativeDeletionReplyOutcome, SignedCooperativeDeletionReply,
    decode_and_verify_cooperative_deletion_reply, encode_cooperative_deletion_reply_body,
    encode_signed_cooperative_deletion_reply,
};
pub use coop_request::{
    COOP_DELETION_REQUEST_BODY_KEYS, COOP_DELETION_REQUEST_DOMAIN,
    COOP_DELETION_REQUEST_SCHEMA_VERSION, CooperativeDeletionRequest, MAX_COOP_DELETION_WORLDS,
    SignedCooperativeDeletionRequest, decode_and_verify_cooperative_deletion_request,
    decode_self_signed_cooperative_deletion_request, encode_cooperative_deletion_request_body,
    encode_signed_cooperative_deletion_request, peek_cooperative_deletion_pact,
};
// Courtesy across a former peer's host re-root (FIX 3014).
pub use coop_succession::{
    COOP_DELETION_SUCCESSION_PEER_PATH, COOP_DELETION_SUCCESSION_SCHEMA_VERSION,
    CooperativeDeletionSuccession,
};
pub use delete::{
    DeleteEntityOptions, DeleteEntityOutcome, DeleteEntityPreview, HeldBytes, LfsChunkImpact,
};
// A maintenance pass's audited corrupt-CLAIM classification (FIX 7800).
pub use erase::CorruptClaimRepair;
pub use legal_hold::{
    ERASE_COMPLETION_PENDING, ErasePendingReason, HostOrderHold, LEGAL_HOLD_DEFERRAL,
    LEGAL_HOLD_LOG_RETENTION_MONTHS, LEGAL_HOLD_REFUSAL, LEGAL_HOLD_SELF_HOSTED_NOTE,
    LIFT_AND_ERASE_PROMPT, LIFT_AND_ERASE_TITLE, LegalHold, LegalHoldActorKind, LegalHoldEvent,
    LegalHoldEventKind, LegalHoldKind, LegalHoldMaintenance, LegalHoldReason, LegalHoldTarget,
    LegalHoldUseLimit, LiftAndEraseOutcome, LiftAndEraseShownState, LiftAndEraseStatus,
    ShownCustomerHold,
};
// A source's dependents go in bounded batches (`Vault::finish_dependent_walks`).
pub use crate::ports::{
    DEFAULT_DEPENDENT_WALK_BATCH, DEFAULT_DEPENDENT_WALK_CHECK_THRESHOLD, DependentWalkCheck,
    DependentWalkPolicy, DependentWalkProgress,
};
pub use sweep_queue::arch0038_carrier_classes;
pub use timeline::{
    HydratedShortIdDeletion, HydratedShortIdDeletionReason, HydratedShortIdDeletionSource,
    MemoryOperationKind, MemoryTimeline, MemoryTimelineRecord, MemoryTimelineRecordState,
    NamedMemoryVerb, NamedMemoryVerbRefusal,
};
pub use tombstone::{
    DecodedTombstoneValue, DeleteReason, TOMBSTONE_VALUE_LEGACY_LEN, TOMBSTONE_VALUE_V2_LEN,
    TombstoneReason, TombstoneValueV2, decode_tombstone_value,
};

// A carrier copy of an erased actor's row settles by one rule (FIX 3878).
pub(crate) use actor_fields::carrier_actor_merged;
pub use actor_fields::{
    ACTOR_ERASE_CARRIER_MERGE, ACTOR_ERASE_CARRIER_SOURCE, CarrierActorMerge, CarrierEraseSource,
};

// Whether an id is no actor: the one header check every lane's actor scrub
// asks (FIX 8908).
pub(crate) use actor_fields::names_no_actor;

// A checkpoint restore reruns the erase's actor sweep (FIX 3655).
pub(crate) use actor_fields::{hard_erased_ids_in, rerun_actor_scrubs_in_txn};
// A due owner-confirmed erase rechecks its pending row (FIX 6337).
pub(crate) use delete::{ConfirmedEraseOutcome, due_erase_requester_in_txn};
pub(crate) use derived_rows::tear_derived_rows_in_txn;
pub(crate) use erase::TombstoneScopeProbes;
pub(crate) use gate::{DeletionClaim, DeletionGateContext, GatedDeletion, GuestRevokeAuthority};
pub(crate) use receipt::decode_redaction_audit_receipt;
// A corrupt CLAIM's repair event is no erase receipt (FIX 7800).
pub(crate) use receipt::is_corrupt_claim_repair_event;
pub(crate) use receipt_completion::{
    append_redaction_sweep_completion_in_txn, redaction_sweep_completion_id,
    redaction_sweep_completion_in_txn,
};
// An erase's overall final row (FIX 5844).
pub(crate) use receipt_final::{
    finish_redaction_erase_in_txn, redaction_erase_final_id, redaction_erase_final_in_txn,
};
pub(crate) use receipt_grammar::validate_redaction_receipt_body;
// This device attests only the erase receipts it made (FIX 2596).
pub(crate) use receipt_origin::receipt_attested_by_this_device_in_txn;
#[cfg(feature = "sync")]
pub(crate) use sweep_queue::withdrawn_generation_cutoff_in_txn;
pub(crate) use sweep_queue::{
    HARD_ERASE_SWEEP_PREFIX, HardEraseSweepJob, WithdrawnReplacement, decode_hard_erase_sweep_job,
    decode_hard_erase_sweep_seq, encode_hard_erase_sweep_job_value,
    enqueue_withdrawn_generation_in_txn,
};
pub(crate) use sweep_queue::{
    HardEraseRetryState, WITHDRAWN_GENERATION_SWEEP_PREFIX, WithdrawnGenerationSweepJob,
    decode_withdrawn_generation_row, encode_withdrawn_generation_job_value,
    raise_withdrawn_generation_fence_in_txn, withdrawn_generation_cutoffs_in_txn,
};
pub(crate) use timeline::{deletion_window_for_row, row_deletion_marked};
#[cfg(all(test, feature = "sync"))]
pub(crate) use tombstone::ROW_DELETION_FENCE_BACKFILLED;
#[cfg(test)]
pub(crate) use tombstone::local_hard_delete_key;
pub(crate) use tombstone::{
    ARCHIVE_TOMBSTONE_PREFIX, LOCAL_HARD_DELETE_PREFIX, PENDING_TOMBSTONE, PendingTombstoneKey,
    ROW_DELETION_FENCE, archive_tombstone_key, stage_engine_row_hard_erasure_at_in_txn,
    stage_engine_row_hard_erasure_in_txn,
};
pub(crate) use topology_delete_intent::topology_delete_reservation_in_txn;
// The replay outcome is read by sync production (`sync::quarantine`) and by
// the white-box test modules that pin the base replay law; a plain
// no-feature library reaches neither.
#[cfg(any(feature = "sync", test))]
pub(crate) use tombstone::ReplayedTombstoneOutcome;
// The `pt:` prefix constant's one remaining crate-external reader is a
// no-feature-only regression fixture (`memory::tests::support`); production
// sync code reaches the pending-tombstone rows through its own typed table.
#[cfg(all(test, not(feature = "sync")))]
pub(crate) use tombstone::PENDING_TOMBSTONE_PREFIX;

#[cfg(feature = "sync")]
pub(crate) use receipt::{ATT_EMPTY_MAP_BYTE, RECEIPT_ATT_DOMAIN, receipt_attestation_parts};

// Crate-facing paths whose consumers are all `#[cfg(test)]`; the re-export
// carries the same gate so a non-test build re-exports nothing it never uses.
#[cfg(test)]
pub(crate) use receipt::{
    RedactionReceiptInput, RedactionScope, encode_redaction_audit_receipt, hex_lower,
};
#[cfg(all(test, not(feature = "sync")))]
pub(crate) use rendezvous::arm_fail_first_txn_pending_tombstone;
#[cfg(test)]
pub(crate) use rendezvous::{DeleteRendezvous, DeleteRendezvousChannels};
#[cfg(all(test, feature = "sync"))]
pub(crate) use rendezvous::{
    arm_fail_after_tombstone_before_purge, arm_fail_live_tombstone_persist,
};
#[cfg(test)]
pub(crate) use sweep_queue::{
    HardEraseSweepExtras, LAST_HARD_ERASE_SWEEP_SEQ_KEY, encode_hard_erase_sweep_job,
    encode_hard_erase_sweep_key,
};
#[cfg(test)]
pub(crate) use tombstone::pending_tombstone_key;
pub(crate) use tombstone::{parse_window_label, window_label_from_timestamp};

// The flat deletion.rs module used to provide this name to the test module
// through `use super::*`; after the directory split the seam re-imports it so
// the sibling `tests.rs` resolves exactly as it did inline.
#[cfg(test)]
use crate::entity_id::EntityId;

#[cfg(test)]
pub(crate) use receipt::receipt_envelope_header;
