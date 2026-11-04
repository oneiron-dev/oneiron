//! Deterministic receipt projection of a stored gate decision.

use std::collections::BTreeMap;
use crate::store::{GateDecisionRecord, GateSystemNoticeRecord};
use crate::store::receipt_row::{
    FIELD_BUNDLE_REF, FIELD_GRANT_REF, ReceiptKind, ReceiptRecord, hex_lower,
};

pub(crate) const SYSTEM_NOTICE_AUDIENCE_THIRD_PARTY: &str = "third_party";
pub(crate) const SYSTEM_NOTICE_AUDIENCE_ALL: &str = "all";

pub(crate) fn gate_decision_receipt(record: &GateDecisionRecord) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert("actor_class".to_owned(), record.actor_class.clone());
    fields.insert("content_kind".to_owned(), record.content_kind.clone());
    fields.insert(
        "policy_manifest_version".to_owned(),
        record.policy_manifest_version.clone(),
    );
    fields.insert("diff_handle".to_owned(), hex_lower(&record.diff_handle));
    fields.insert(
        "read_frontier_hash".to_owned(),
        hex_lower(&record.read_frontier_hash),
    );
    if let Some(receipt_reason) = record.receipt_reasons.first() {
        fields.insert("receipt_reason".to_owned(), receipt_reason.clone());
    }
    if record.receipt_reasons.len() > 1 {
        fields.insert(
            "receipt_reasons".to_owned(),
            record.receipt_reasons.join(","),
        );
    }
    if let Some(grant_ref) = record.grant_ref.as_ref() {
        fields.insert(FIELD_GRANT_REF.to_owned(), grant_ref.clone());
        // OF-234 bundle-consent rows reference their bundle through the grant
        // ref; surfacing it as `bundle_ref` joins them into the RS4 bundle lane.
        if grant_ref.starts_with("bundle:") {
            fields.insert(FIELD_BUNDLE_REF.to_owned(), grant_ref.clone());
        }
    }
    if let Some(notice) = select_gate_system_notice_for_receipt(&record.system_notices) {
        fields.insert("system_notice_type".to_owned(), notice.notice_type.clone());
        fields.insert("system_notice_channel".to_owned(), notice.channel.clone());
        fields.insert("system_notice_voice".to_owned(), notice.voice.clone());
        fields.insert("system_notice_audience".to_owned(), notice.audience.clone());
        fields.insert("system_notice".to_owned(), notice.body.clone());
        if let Some(plane) = notice.policy_plane.as_ref() {
            fields.insert("system_notice_policy_plane".to_owned(), plane.clone());
        }
        if let Some(version) = notice.policy_version.as_ref() {
            fields.insert("system_notice_policy_version".to_owned(), version.clone());
        }
        if let Some(docs_url) = notice.docs_url.as_ref() {
            fields.insert("system_notice_docs_url".to_owned(), docs_url.clone());
        }
    }

    let mut policy_trace = record.reason_codes.clone();
    policy_trace.extend(record.receipt_reasons.clone());
    policy_trace.extend(
        record
            .system_notices
            .iter()
            .map(|notice| format!("gate.system_notice.{}", notice.notice_type)),
    );

    ReceiptRecord {
        receipt_id: format!("gate:{}", record.decision_id.to_hex()),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: record.created_at,
        actor: record
            .actor_ref
            .clone()
            .or_else(|| Some(record.actor_class.clone())),
        on_behalf_of: None,
        outcome: record.outcome.clone(),
        job_ref: None,
        trigger_ref: record
            .claim_id
            .map(|id| format!("claim:{}", hex_lower(&id)))
            .or_else(|| {
                // A bundle-level row (no claim id) opens its dreamer run: the
                // RS3 door on the bundle receipt reopens the inbox group.
                record
                    .grant_ref
                    .as_deref()
                    .and_then(|grant_ref| grant_ref.strip_prefix("bundle:"))
                    .map(str::to_owned)
            }),
        policy_trace,
        fields,
    }
}

pub(crate) fn select_gate_system_notice_for_receipt(
    notices: &[GateSystemNoticeRecord],
) -> Option<&GateSystemNoticeRecord> {
    notices
        .iter()
        .find(|notice| notice.audience == SYSTEM_NOTICE_AUDIENCE_THIRD_PARTY)
        .or_else(|| {
            notices
                .iter()
                .find(|notice| notice.audience == SYSTEM_NOTICE_AUDIENCE_ALL)
        })
        .or_else(|| notices.first())
}
