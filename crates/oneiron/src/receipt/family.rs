use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::grant::{
    StandingOutboundGrantsLens, StandingOutboundGrantsLensQuery, access_grant_receipts,
    federation_share_receipts, outbound_grant_receipts, persona_snapshot_export_receipts,
    scan_entities_by_type, standing_outbound_grants_lens,
};
use super::identity_kind::{
    channel_identity_lifecycle_receipts, companion_lifecycle_receipts, identity_topology_receipts,
};
use super::kernel::{
    FIELD_BUNDLE_REF, FIELD_GRANT_REF, MAX_RECEIPT_QUERY_SCAN, ReceiptKind, ReceiptQuery,
    ReceiptRecord, ReceiptView, hex_lower, lineage_scan_query, projection_scan_query,
    retain_newest_receipt,
};
#[cfg(test)]
use super::kernel::{GATE_RECEIPT_MAX_BUFFERED, GATE_RECEIPT_PAGES_SCANNED};
use super::ledgers::{attempt_pack_receipts, durable_send_receipts};
use super::projection::{
    BriefReceiptProjection, CounterpartyReceiptProjection, GrantReceiptProjection,
    counterparty_contact_records_for_receipts, finalize_receipt_query_records,
    project_receipts_by_brief, project_receipts_by_counterparty_with_contacts,
    project_receipts_by_grant_limited,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::{GateDecisionRecord, GateSystemNoticeRecord, PendingGateConsentRecord};

pub(super) const SYSTEM_NOTICE_AUDIENCE_THIRD_PARTY: &str = "third_party";
pub(super) const SYSTEM_NOTICE_AUDIENCE_ALL: &str = "all";

/// Query for the EF-055 pending tray lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTrayQuery {
    pub now: u64,
    pub limit: usize,
}

impl PendingTrayQuery {
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            now: crate::unix_seconds_now(),
            limit,
        }
    }

    #[must_use]
    pub const fn at(now: u64, limit: usize) -> Self {
        Self { now, limit }
    }
}

/// One current pending ask for the logbook tray lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTrayAsk {
    pub claim_id: String,
    pub created_at: u64,
    pub age_secs: u64,
    pub hold_reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hold_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dreamer_run_id: Option<String>,
    pub receipt_view: ReceiptView,
}

impl Vault {
    /// Queries the unified receipt family across existing receipt emitters.
    pub fn receipts(&self, query: ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
        receipt_family_query(self, &query)
    }

    /// Alias for callers that prefer verb-first query naming.
    pub fn query_receipts(&self, query: ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
        self.receipts(query)
    }

    /// Returns the current pending tray lane rows backed by Pending-state Gate receipts.
    pub fn pending_tray(&self, query: PendingTrayQuery) -> Result<Vec<PendingTrayAsk>> {
        pending_tray_query(self, query)
    }

    /// Resolves a stale pending ask by emitting a `let_go` receipt and removing it from the tray.
    pub fn let_go_pending_ask(&self, claim_id: &EntityId) -> Result<Option<ReceiptRecord>> {
        self.let_go_pending_ask_at(claim_id, crate::unix_seconds_now())
    }

    /// Testable variant of [`Vault::let_go_pending_ask`] with an explicit event time.
    pub fn let_go_pending_ask_at(
        &self,
        claim_id: &EntityId,
        now: u64,
    ) -> Result<Option<ReceiptRecord>> {
        let emitted = self.with_write_txn(|wtxn| {
            self.store
                .let_go_pending_gate_consent_in_txn(wtxn, claim_id, now)
        })?;
        Ok(emitted.as_ref().map(gate_decision_receipt))
    }

    /// Computes the brief-rooted receipt projection from the unified family.
    pub fn receipt_projection_by_brief(
        &self,
        brief_ref: impl Into<String>,
        query: ReceiptQuery,
    ) -> Result<BriefReceiptProjection> {
        Ok(project_receipts_by_brief(brief_ref, self.receipts(query)?))
    }

    /// Computes per-counterparty receipt projections from the unified family.
    pub fn receipt_projections_by_counterparty(
        &self,
        query: ReceiptQuery,
    ) -> Result<Vec<CounterpartyReceiptProjection>> {
        if query.limit == 0 {
            return Ok(Vec::new());
        }
        let receipts = self.receipts(projection_scan_query(query))?;
        let contact_records = counterparty_contact_records_for_receipts(self, &receipts)?;
        Ok(project_receipts_by_counterparty_with_contacts(
            receipts,
            &contact_records,
        ))
    }

    /// Computes the per-grant receipt projection from the unified family.
    pub fn receipt_projection_by_grant(
        &self,
        grant_ref: impl Into<String>,
        query: ReceiptQuery,
    ) -> Result<GrantReceiptProjection> {
        let limit = query.limit;
        if limit == 0 {
            return Ok(project_receipts_by_grant_limited(
                grant_ref,
                Vec::new(),
                limit,
            ));
        }
        Ok(project_receipts_by_grant_limited(
            grant_ref,
            self.receipts(projection_scan_query(query))?,
            limit,
        ))
    }

    /// Computes the standing outbound-grants lens behind the logbook.
    pub fn standing_outbound_grants_lens(
        &self,
        query: StandingOutboundGrantsLensQuery,
    ) -> Result<StandingOutboundGrantsLens> {
        standing_outbound_grants_lens(self, query)
    }

    /// DEC-0006 surface (b): the unified consent registry, projected here so
    /// review and one-tap revoke reach it through the receipt family like
    /// every other lens.
    ///
    /// This is a re-export of [`Vault::consent_registry`], not a second
    /// registry — invariant 9 allows exactly two human surfaces, so a lens
    /// that recomputed its own view would BE the forbidden third one.
    /// [`Vault::standing_outbound_grants_lens`] above is likewise a
    /// COMPATIBILITY projection over the outbound grant family, kept for its
    /// existing callers rather than promoted to a separate consent surface.
    pub fn consent_registry_lens(
        &self,
        query: crate::consent::ConsentRegistryQuery,
    ) -> Result<crate::consent::ConsentRegistry> {
        self.consent_registry(query)
    }
}

fn receipt_family_query(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    if query.limit == 0 {
        return Ok(Vec::new());
    }

    let records = collect_receipt_records(vault, query)?;
    let lineage_records = if query.job_ref.is_some() {
        Some(collect_receipt_records(vault, &lineage_scan_query())?)
    } else {
        None
    };
    Ok(finalize_receipt_query_records(
        records,
        query,
        lineage_records.as_deref(),
    ))
}

fn collect_receipt_records(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    let mut records = Vec::new();
    if query.includes_kind(ReceiptKind::Outbound) {
        records.extend(
            durable_send_receipts(vault)?
                .into_iter()
                .filter(|receipt| query.matches(receipt)),
        );
        records.extend(
            attempt_pack_receipts(vault)?
                .into_iter()
                .filter(|receipt| query.matches(receipt)),
        );
    }
    if query.includes_kind(ReceiptKind::Gate) {
        records.extend(gate_receipts(vault, query)?);
        // The SECOND Gate projector (ONE-1748): consent-graduation
        // self-demotions and door-recorded ramp outcomes. They share the kind
        // but not the store — a ramp bookkeeping row has no business in the
        // gate-decision ledger, which ONE-1637 made the erasure chain's H0
        // index. Both projectors open their own read txn, so they run before
        // the shared `rtxn` below.
        records.extend(crate::consent_graduation::ramp_receipts(vault, query)?);
        // The THIRD Gate projector (ONE-1762): escalation rulings and the
        // standing policies they earn. Same kind, own store, own field class —
        // an escalation is a gate decision a human made, so it mints no kind of
        // its own. Opens its own read txn, as the ramp projector does.
        records.extend(crate::edit_distance::escalation::escalation_receipts(
            vault, query,
        )?);
        // The FOURTH Gate projector (ONE-1449): held-out score-gate verdicts on
        // automated skill edits. Same kind, own store, own field class — a gate
        // verdict the engine ruled is still a gate decision, so it mints no kind
        // of its own. Opens its own read txn, as the two above do.
        records.extend(crate::skill_optimize::skill_edit_verdict_receipts(
            vault, query,
        )?);
    }

    if query.includes_kind(ReceiptKind::IdentityLifecycle) {
        records.extend(channel_identity_lifecycle_receipts(vault, query)?);
    }

    // The settle projection opens its own read txn, so it runs before the shared
    // `rtxn` below to avoid a nested read transaction on this thread. It applies
    // the query filter itself (the settlement key is not time-ordered).
    if query.includes_kind(ReceiptKind::ArtifactSettle) {
        records.extend(crate::edit_settle::settle_receipts(vault, query)?);
    }

    let rtxn = vault.store.env.read_txn()?;
    if query.includes_kind(ReceiptKind::IdentityLifecycle) {
        records.extend(companion_lifecycle_receipts(vault, &rtxn, query)?);
    }
    // ONE type-76 scan serves both kinds it projects; the projector-level
    // kind gate keeps a single-kind query from returning the other's rows.
    if query.includes_kind(ReceiptKind::IdentityLifecycle)
        || query.includes_kind(ReceiptKind::ProposalOutcome)
    {
        records.extend(identity_topology_receipts(vault, &rtxn, query)?);
    }
    if query.includes_kind(ReceiptKind::ScopedRead) {
        records.extend(access_grant_receipts(vault, &rtxn, query)?);
        records.extend(outbound_grant_receipts(vault, &rtxn, query)?);
        // ED-09 (ONE-1765): the reservoir export. Same kind, own store, own
        // field class — an export IS a scoped read that left the vault, so it
        // mints no kind of its own, exactly as ONE-1762's escalations project
        // into `Gate`.
        records.extend(crate::edit_distance::reservoir::reservoir_export_receipts(
            vault, &rtxn, query,
        )?);
    }
    if query.includes_kind(ReceiptKind::Share) {
        records.extend(federation_share_receipts(vault, &rtxn, query)?);
        records.extend(persona_snapshot_export_receipts(vault, &rtxn, query)?);
    }
    // CMT-4 (ONE-1541): terminal `commitment.record` rows ARE the lifecycle
    // ledger. Shares the same read txn and the same MAX_RECEIPT_QUERY_SCAN
    // bound as every other projector here.
    if query.includes_kind(ReceiptKind::CommitmentLifecycle) {
        records.extend(commitment_lifecycle_receipts(vault, &rtxn, query)?);
    }

    // ED-01 (ONE-1757): the reserved Δ slot is filled from its own side-ledger
    // once, HERE, rather than by every projector that can emit an amended
    // outcome. Receipts are projections, so a Δ has nowhere else to be
    // stamped; one pass over the collected records keeps the family
    // projectors ignorant of edit distance.
    crate::edit_distance::delta::attach_amendment_deltas(vault, &rtxn, &mut records)?;

    Ok(records)
}

/// Projects one deterministic lifecycle receipt from every TERMINAL
/// `commitment.record` CLAIM in scan range (CMT-4, ONE-1541).
///
/// Projection-first: there is no lifecycle store, so the terminal claim row is
/// both the state and the receipt. The scan is bounded by
/// [`MAX_RECEIPT_QUERY_SCAN`], and the invariant is bounded with it — within
/// that many scanned CLAIM rows, a fulfilled/released/lapsed commitment cannot
/// exist without its receipt. Vaults beyond the bound need the follow-up
/// commitment-status receipt index; this projector does not imply whole-vault
/// coverage.
///
/// `actor` is deliberately `None`. The status writer is not the moral author of
/// a lapse (nothing happened — that IS the lapse), and the same-transaction
/// Gate decision is already the audit record naming who wrote.
///
/// Every scanned body decodes with reserved predicates ALLOWED and is then
/// exact-matched against `commitment.record` before the commitment codec runs,
/// so an unrelated reserved row such as `edge.provenance` sitting beside a
/// terminal commitment coexists instead of poisoning the query.
fn commitment_lifecycle_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    scan_entities_by_type(
        vault,
        txn,
        crate::registry::ENTITY_TYPE_CLAIM,
        "commitment lifecycle claim type index",
        |id, header, body| {
            let Ok(body) = crate::claim::decode_claim_body(body, true) else {
                // A CLAIM row this projector cannot decode is not a commitment
                // it can vouch for; the owning family's query surfaces it.
                return Ok(());
            };
            if body.predicate != crate::commitment::PREDICATE_COMMITMENT_RECORD {
                return Ok(());
            }
            // Past the exact predicate match the codec is authoritative, so a
            // malformed commitment body is corruption rather than a row to skip.
            let record = crate::commitment::decode_commitment_claim(&body)?.ok_or(
                Error::InvalidClaimBody("commitment record value failed validation"),
            )?;
            let (outcome, trace) = match record.status {
                crate::commitment::CommitmentStatus::Fulfilled => {
                    ("fulfilled", "commitment.lifecycle.fulfilled")
                }
                crate::commitment::CommitmentStatus::Released => {
                    ("released", "commitment.lifecycle.waived")
                }
                crate::commitment::CommitmentStatus::Lapsed => {
                    ("let_go", "commitment.instance.gap_decayed")
                }
                // Open is not terminal, and a supersession is a replacement
                // rather than an outcome of the promise.
                crate::commitment::CommitmentStatus::Open
                | crate::commitment::CommitmentStatus::Superseded => return Ok(()),
            };
            let mut fields = BTreeMap::new();
            fields.insert(
                "commitment_status".to_owned(),
                record.status.as_str().to_owned(),
            );
            fields.insert("obligor_ref".to_owned(), record.obligor.entity_ref.to_hex());
            fields.insert("beneficiary_ref".to_owned(), record.beneficiary.to_hex());
            fields.insert("strength".to_owned(), record.strength.as_str().to_owned());
            let receipt = ReceiptRecord {
                receipt_id: format!("commitment:{}:{}", id.to_hex(), record.status.as_str()),
                receipt_kind: ReceiptKind::CommitmentLifecycle,
                occurred_at: header.learned_at,
                actor: None,
                on_behalf_of: None,
                outcome: outcome.to_owned(),
                job_ref: None,
                trigger_ref: Some(format!("commitment:{}", id.to_hex())),
                policy_trace: vec![trace.to_owned()],
                fields,
            };
            if query.matches(&receipt) {
                retain_newest_receipt(&mut receipts, receipt, query.limit);
            }
            Ok(())
        },
    )?;
    Ok(receipts)
}

fn gate_receipts(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    let mut before = None;
    loop {
        #[cfg(test)]
        GATE_RECEIPT_PAGES_SCANNED.with(|count| count.set(count.get() + 1));
        let decisions = vault
            .store
            .gate_decisions_page(before, MAX_RECEIPT_QUERY_SCAN)?;
        let page_len = decisions.len();
        before = decisions.last().map(|decision| decision.decision_id);
        for decision in decisions {
            let receipt = gate_decision_receipt(&decision);
            if query.matches(&receipt) {
                if query.job_ref.is_none() {
                    // Decision ids define ledger traversal, but connector-key
                    // rows may carry caller-supplied, non-monotonic event
                    // times. Scan every page while retaining only the exact
                    // public newest-first top-N. `job_ref` stays exhaustive
                    // because its lineage join runs after collection.
                    retain_newest_receipt(&mut receipts, receipt, query.limit);
                } else {
                    receipts.push(receipt);
                }
                #[cfg(test)]
                GATE_RECEIPT_MAX_BUFFERED.with(|max| max.set(max.get().max(receipts.len())));
            }
        }
        if page_len < MAX_RECEIPT_QUERY_SCAN {
            break;
        }
    }
    Ok(receipts)
}

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

pub(super) fn select_gate_system_notice_for_receipt(
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

fn pending_tray_query(vault: &Vault, query: PendingTrayQuery) -> Result<Vec<PendingTrayAsk>> {
    if query.limit == 0 {
        return Ok(Vec::new());
    }

    let rtxn = vault.store.env.read_txn()?;
    let mut asks = Vec::new();
    for pending in vault
        .store
        .pending_gate_consents_in_txn(&rtxn, query.limit)?
    {
        let Some(decision) = vault
            .store
            .gate_decision_in_txn(&rtxn, pending.decision_id)?
        else {
            return Err(Error::CorruptedIndex("pending gate consent"));
        };
        if decision.outcome != "pending" {
            return Err(Error::CorruptedIndex("pending gate consent"));
        }
        asks.push(pending_tray_ask(&pending, &decision, query.now));
    }
    Ok(asks)
}

fn pending_tray_ask(
    pending: &PendingGateConsentRecord,
    decision: &GateDecisionRecord,
    now: u64,
) -> PendingTrayAsk {
    let receipt = gate_decision_receipt(decision);
    let hold_reasons = pending.reason_codes.clone();
    let hold_reason = hold_reasons
        .first()
        .cloned()
        .unwrap_or_else(|| "gate.pending".to_owned());
    PendingTrayAsk {
        claim_id: hex_lower(&pending.claim_id),
        created_at: pending.created_at,
        age_secs: now.saturating_sub(pending.created_at),
        hold_reason,
        hold_reasons,
        dreamer_run_id: pending.dreamer_run_id.clone(),
        receipt_view: ReceiptView::new(receipt),
    }
}
