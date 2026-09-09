//! The append-only gate-decision ledger: decision rows, claim/grant-ref
//! indexes, the pending-deletion sidecar, and the attempt-run index used by
//! the claim-index backfill.

use super::*;

mod keys;
mod ledger;
mod lookup;
mod sidecar;
mod types;
mod vet;

// Private seam import, not a re-export: `lookup` names this helper bare
// through `super::`, and it was private to this module before the split.
use self::keys::gate_decision_id_from_key;

pub(in crate::store) use self::keys::{
    GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY,
    GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE, GATE_DECISION_KEY_PREFIX, gate_decision_key,
    gate_decision_upper_bound,
};
pub(in crate::store) use self::ledger::decode_gate_decision;
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
    gate_decision_claim_index_prefix, gate_decision_grant_ref_index_key,
};
#[cfg(test)]
pub(in crate::store) use self::ledger::encode_gate_decision;
#[cfg(test)]
pub(in crate::store) use self::types::GATE_DECISION_LEDGER_VERSION_REDACTED;
#[cfg(test)]
pub(in crate::store) use self::vet::GATE_SYSTEM_NOTICE_PLANE_TOKENS;
#[cfg(test)]
pub(in crate::store) use self::vet::{valid_gate_receipt_reason, valid_gate_system_notice_record};
