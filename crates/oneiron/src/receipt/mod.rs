//! Unified receipt-family query surface over existing receipt emitters.
//!
//! RS1 is intentionally a projection over existing event substrates. This
//! module does not mint a new receipt store and does not change emitter schema.

mod family;
mod field_set;
mod grant;
mod identity_kind;
mod kernel;
mod ledgers;
mod projection;
mod session;

#[cfg(test)]
mod tests;

pub use self::family::{PendingTrayAsk, PendingTrayQuery};
pub use self::field_set::{
    ContextReceiptFields, append_context_receipt_fields, append_pack_manifest_fields,
    eiri_memory_board_state_ref,
};
pub use self::grant::{
    StandingOutboundGrantLensRow, StandingOutboundGrantRevokeAction, StandingOutboundGrantsLens,
    StandingOutboundGrantsLensQuery,
};
pub use self::identity_kind::{proposal_outcome_amended_body, proposal_outcome_delta};
pub use self::kernel::{
    FIELD_MANIFEST_ACTOR_CLAIMS, FIELD_MANIFEST_SKILLS, FIELD_TASK_REF, FIELD_TRANSPORT_DISPATCHED,
    ReceiptKind, ReceiptQuery, ReceiptRecord, ReceiptView,
};
pub use self::ledgers::{attempt_pack_receipt, attempt_pack_receipt_id, outbound_intent_receipt};
pub use self::projection::{
    BriefReceiptProjection, CounterpartyReceiptProjection, GrantReceiptProjection,
    ReceiptProjectionIntent, ReceiptProjectionRun, project_receipts_by_brief,
    project_receipts_by_counterparty, project_receipts_by_grant,
};
pub use self::session::{SessionLocalReceiptLog, SessionReceiptClose};

pub(crate) use self::family::gate_decision_receipt;
pub(crate) use self::kernel::{
    FIELD_AMENDMENT_DELTA, FIELD_AMENDMENT_DELTA_UNCAPTURED, FIELD_DEMOTION_REASON,
    FIELD_ESCALATION_BAND_CEILING, FIELD_ESCALATION_BUDGET_BAND, FIELD_ESCALATION_CITED_RECEIPTS,
    FIELD_ESCALATION_QUESTION, FIELD_ESCALATION_RATIONALE, FIELD_ESCALATION_RULING,
    FIELD_ESCALATION_SCOPE, FIELD_ESCALATION_TRIGGER, FIELD_GRANT_REF, FIELD_OP_KIND,
    FIELD_SCOPE_ACTOR, FIELD_TARGET_CLASS, MAX_RECEIPT_QUERY_SCAN, hex_lower,
    retain_newest_receipt,
};
#[cfg(test)]
pub(crate) use self::ledgers::overwrite_attempt_pack_receipt_for_test;
pub(crate) use self::ledgers::{
    SendReceiptOutcome, delivered_send_receipt_for_task, persist_send_receipt,
    stamp_attempt_pack_receipt_in_txn,
};
pub(crate) use self::projection::{COMMITMENT_TRIGGER_PREFIX, commitment_trigger_ref};

// The flat receipt.rs module used to provide these names to the test module
// through `use super::*`; after the directory split the seam re-imports them so
// the extracted sibling `tests.rs` resolves exactly as it did inline.
#[cfg(test)]
use self::family::{
    SYSTEM_NOTICE_AUDIENCE_ALL, SYSTEM_NOTICE_AUDIENCE_THIRD_PARTY,
    select_gate_system_notice_for_receipt,
};
#[cfg(test)]
use self::kernel::{
    DEFAULT_RECEIPT_QUERY_LIMIT, FIELD_ACTIVATED_MEMORY_IDS, FIELD_BOARD_STATE_REF,
    FIELD_DISCLOSURE_STAMP, FIELD_MODEL, FIELD_PERSONA_COMPILE_STAMP, FIELD_PROMPT_INPUT_REF,
    FIELD_REASONING_EFFORT, FIELD_SUBSTRATE_REF, RECEIPT_VIEW_COMPONENT, attempt_pack_scan_capped,
    gate_receipt_max_buffered, gate_receipt_pages_scanned, reset_attempt_pack_scan_capped,
    reset_gate_receipt_pages_scanned,
};
#[cfg(test)]
use self::ledgers::{
    attempt_pack_receipts, decode_durable_send_receipt, put_attempt_pack_receipt_for_test,
};
#[cfg(test)]
use self::projection::{
    counterparty_contact_records_for_receipts, finalize_receipt_query_records,
    project_receipts_by_counterparty_with_contacts, project_receipts_by_grant_limited,
};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::attempt_queue::{AttemptId, ManifestEntry, ManifestKind};
#[cfg(test)]
use crate::eiri::EiriMemoryBoard;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::outbound::OutboundIntent;
#[cfg(test)]
use crate::prompt::PromptRecompileStamp;
#[cfg(test)]
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
#[cfg(test)]
use crate::store::{GateDecisionRecord, GateSystemNoticeRecord, SEND_RECEIPT_RECORD_VERSION};
#[cfg(test)]
use serde::Serialize;
#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};
