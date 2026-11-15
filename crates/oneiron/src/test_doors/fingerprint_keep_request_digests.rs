//! Door for `tests/fingerprint_keep_request_digests.rs` (PLAN-UC-04 4.1): the request
//! digests a replay or a retention compares with a stored value (a task post, a report,
//! an eval measurement and its re-measure, a campaign request, the Linear mirror's event
//! keys and edit request, a phone line arrival and a queued note request), which the
//! engine computes in private code.

use crate::entity_id::EntityId;
use crate::feedback::ReportRequest;
use crate::gate::CampaignLegFacts;
use crate::memory::campaign_records::program_definition::{
    CampaignProgramOutbound, CampaignProgramStep,
};
use crate::note::{NoteOperation, PendingNoteRequest};
use crate::phone_line::PhoneLineArrival;
use crate::skill_optimize::{EvalMeasurement, EvalMeasurementRequest};
use crate::task_verb::TaskPost;

/// The digest one `tasks.post` request binds, or `None` when the post does not encode.
#[must_use]
pub fn post_request_digest(
    actor: EntityId,
    key: &str,
    post: &TaskPost,
    parent_ref: Option<EntityId>,
) -> Option<[u8; 32]> {
    crate::task_verb::post_request_digest_for_test(actor, key, post, parent_ref).ok()
}

/// The digest of a report's exact request, or `None` when it does not encode.
#[must_use]
pub fn report_request_digest(request: &ReportRequest) -> Option<[u8; 32]> {
    crate::feedback::report_request_digest_for_test(request).ok()
}

/// The digest that keys an eval measurement request's row, or `None` when it does not
/// encode.
#[must_use]
pub fn eval_measurement_request_digest(request: &EvalMeasurementRequest) -> Option<[u8; 32]> {
    crate::skill_optimize::eval_measurement_request_digest_for_test(request).ok()
}

/// Where the request `digest` keys is measured again while its Partial `row` stands.
#[must_use]
pub fn eval_measurement_remeasure_digest(digest: &[u8; 32], row: &EvalMeasurement) -> [u8; 32] {
    crate::skill_optimize::eval_measurement_remeasure_digest_for_test(digest, row)
}

/// A campaign leg's facts, by `CampaignLegFacts`' fields.
#[derive(Clone, Debug)]
pub struct CampaignLeg {
    pub query_ref: EntityId,
    pub campaign_ref: EntityId,
    pub entity_ref: EntityId,
    pub epoch: u64,
    pub program_ref: EntityId,
    pub step_ref: EntityId,
    pub consequence_id: [u8; 16],
    pub call_seq: u64,
    pub payload_digest: [u8; 32],
}

/// One prepared campaign request's identity, the third part of its retained key.
#[must_use]
pub fn campaign_retained_request_digest(
    leg: &CampaignLeg,
    step: &CampaignProgramStep,
    outbound: &CampaignProgramOutbound,
) -> [u8; 32] {
    let facts = CampaignLegFacts {
        query_ref: leg.query_ref,
        campaign_ref: leg.campaign_ref,
        entity_ref: leg.entity_ref,
        epoch: leg.epoch,
        program_ref: leg.program_ref,
        step_ref: leg.step_ref,
        consequence_id: leg.consequence_id,
        call_seq: leg.call_seq,
        payload_digest: leg.payload_digest,
    };
    crate::campaign::enrollment::retained_request_digest_for_test(&facts, step, outbound)
}

/// The mirror event key of one Linear webhook delivery.
#[must_use]
pub fn linear_delivery_key(delivery_id: &str) -> [u8; 33] {
    crate::linear_sync::delivery_key(delivery_id)
}

/// The mirror event key of one Linear mapping edit.
#[must_use]
pub fn linear_mapping_key(task: EntityId, intent_key: &str) -> [u8; 33] {
    crate::linear_sync::mapping_key(task, intent_key)
}

/// The mirror event key of one public title edit.
#[must_use]
pub fn linear_task_edit_key(task: EntityId, actor: EntityId, report_key: &str) -> [u8; 33] {
    crate::linear_sync::task_edit_key(task, actor, report_key)
}

/// The hex digest a Linear edit's request is compared by on a replay.
#[must_use]
pub fn linear_edit_request_digest(parts: &[&[u8]]) -> String {
    crate::linear_sync::request_digest(parts)
}

/// The digest a replay of a phone line arrival is compared by, or `None` when it does
/// not encode.
#[must_use]
pub fn phone_line_input_digest(arrival: &PhoneLineArrival) -> Option<[u8; 32]> {
    crate::phone_line::input_digest(arrival).ok()
}

/// The digest a retry of a note request, as its caller gives it, matches, or `None`
/// when it does not encode.
#[must_use]
pub fn note_request_input_digest(operation: &NoteOperation) -> Option<[u8; 32]> {
    PendingNoteRequest::input_digest(operation).ok()
}
