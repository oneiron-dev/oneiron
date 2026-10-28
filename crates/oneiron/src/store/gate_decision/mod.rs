//! The append-only gate-decision ledger: decision rows, claim/grant-ref
//! indexes, the pending-deletion sidecar, and the attempt-run index used by
//! the claim-index backfill.

use super::*;

mod actor_erase;
mod checkpoint_custody;
mod claim_refs;
mod context;
mod keys;
mod ledger;
mod lookup;
mod orcb;
mod read_items;
mod retention;
mod retention_scope;
#[cfg(test)]
pub(crate) use super::key_custody::arm_before_retire_lock;
mod sidecar;
mod types;
mod vet;

pub(crate) use self::actor_erase::erase_gate_decision_actor_in_txn;
pub use self::actor_erase::{ACTOR_ERASE_GATE_ATTRIBUTION, GateAttributionErase};
pub(in crate::store) use self::checkpoint_custody::archived_by;
#[cfg(feature = "sync")]
pub(crate) use self::checkpoint_custody::put_back_pad_objects_in_txn;
pub(crate) use self::checkpoint_custody::{
    ExpectedPadObjects, LiveCustody, MadeDestination, PAD_SOURCE_IDENTITY, PadObjectsCapture,
    PadObjectsLanding, PadSourceIdentity, UncapturedPadObjects, admit_existing_vault_root,
    host_hold_rows_in_txn, install_source_pad_objects_in_txn, preflight_absent_custody_rows,
    preflight_checkpoint_rows_rejected, read_live_custody, refuse_custody_beside,
    replace_host_holds_in_txn,
};
#[cfg(test)]
pub(crate) use self::checkpoint_custody::{
    arm_after_restore_destination_made, arm_before_activation_fork, arm_before_live_custody_read,
};
pub use self::context::{
    GateAnalysisCoverage, GateClaimReadSelectors, GateDecisionAnalysis, GateDecisionContext,
    GateDecisionReadContext, GateLoopFamily, GateLoopLink, GateLoopOrigin, GateLoopSource,
    GateReadPosition, GateRiskAxis, GateRiskState,
};
pub(in crate::store) use self::keys::{
    GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY,
    GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE, GATE_DECISION_KEY_PREFIX,
    gate_decision_upper_bound,
};

pub(in crate::store) use self::types::GATE_DIFF_HANDLE_MAX_LEN;
pub(crate) use self::types::{
    GATE_DECISION_LEDGER_VERSION, GATE_SYSTEM_NOTICE_ACTION_LABEL_MAX_LEN,
    GATE_SYSTEM_NOTICE_ACTION_TARGET_MAX_LEN, GATE_SYSTEM_NOTICE_BODY_MAX_LEN,
    GATE_SYSTEM_NOTICE_DOCS_URL_MAX_LEN, GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN,
    GATE_SYSTEM_NOTICE_VERSION_MAX_LEN,
};
pub use self::types::{
    GateDecisionId, GateDecisionRecord, GateSystemNoticeAction, GateSystemNoticeRecord,
};
pub(crate) use self::vet::checker_hold_receipt_reason;

// Test-only seam (open_gates/mod.rs precedent): the store test suite names
// these bare through `use super::*`, but no non-test code reaches them
// through the seam.
#[cfg(test)]
pub(in crate::store) use self::keys::{
    ATTEMPT_RUN_INDEX_PREFIX, GATE_DECISION_CLAIM_INDEX_PREFIX,
    GATE_DECISION_GRANT_REF_INDEX_PREFIX, gate_decision_claim_index_key,
    gate_decision_claim_index_prefix, gate_decision_grant_ref_index_key, gate_decision_key,
};
#[cfg(test)]
pub(in crate::store) use self::ledger::{
    arm_before_gate_grant_decode, arm_before_gate_page_decode, decode_gate_decision,
    encode_gate_decision,
};
#[cfg(test)]
pub(in crate::store) use self::lookup::arm_before_gate_claim_reread;
#[cfg(test)]
pub(in crate::store) use self::types::GATE_DECISION_LEDGER_VERSION_REDACTED;
#[cfg(test)]
pub(in crate::store) use self::vet::valid_gate_receipt_reason;
#[cfg(test)]
pub(in crate::store) use super::key_custody::arm_after_key_marker_check;
