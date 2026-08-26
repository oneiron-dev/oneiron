use std::collections::BTreeMap;

use super::grant::scan_entities_by_type;
use super::kernel::{
    FIELD_AMENDED_BODY, FIELD_AMENDMENT_DELTA, FIELD_CLAIM_SOURCE, FIELD_OP_KIND,
    FIELD_PROPOSAL_REF, FIELD_SCOPE_ACTOR, FIELD_TARGET_CLASS, MAX_RECEIPT_QUERY_SCAN, ReceiptKind,
    ReceiptQuery, ReceiptRecord, hex_lower,
};
use crate::Vault;
use crate::companion::{
    ENTITY_TYPE_COMPANION_REGISTER,
    {
        CompanionLifecycleEvent, CompanionRecord, CompanionScope, CompanionSubject,
        decode_companion_record_body,
    },
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::ChannelIdentityLifecycleReceiptRecord;

pub(super) fn companion_lifecycle_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    scan_entities_by_type(
        vault,
        txn,
        ENTITY_TYPE_COMPANION_REGISTER,
        "companion register type index",
        |id, header, body| {
            let record = decode_companion_record_body(body)?;
            for (index, event) in record.lifecycle_events.iter().enumerate() {
                let receipt =
                    companion_lifecycle_receipt(id, &record, *event, index, header.learned_at);
                if query.matches(&receipt) {
                    receipts.push(receipt);
                }
            }
            Ok(())
        },
    )?;
    Ok(receipts)
}

fn companion_lifecycle_receipt(
    id: EntityId,
    record: &CompanionRecord,
    event: CompanionLifecycleEvent,
    event_index: usize,
    learned_at: u64,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert(
        "actor_class".to_owned(),
        record.provenance.actor_class.gate_actor_class().to_owned(),
    );
    fields.insert(
        "source".to_owned(),
        record.provenance.source.as_str().to_owned(),
    );
    fields.insert(
        "approval".to_owned(),
        record.provenance.approval.as_str().to_owned(),
    );
    fields.insert("record_kind".to_owned(), record.kind().as_str().to_owned());
    fields.insert(
        "record_lifecycle".to_owned(),
        record.lifecycle.as_str().to_owned(),
    );
    fields.insert("learned_at".to_owned(), learned_at.to_string());
    append_companion_scope_fields(&mut fields, &record.scope);
    append_companion_subject_fields(&mut fields, &record.subject);

    ReceiptRecord {
        receipt_id: format!(
            "identity_lifecycle:{}:{}:{}",
            id.to_hex(),
            event.kind.as_str(),
            event_index
        ),
        receipt_kind: ReceiptKind::IdentityLifecycle,
        occurred_at: event.at,
        actor: Some(record.provenance.actor_ref.to_hex()),
        on_behalf_of: None,
        outcome: event.kind.as_str().to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("entity:{}", id.to_hex())),
        policy_trace: Vec::new(),
        fields,
    }
}

/// Projects ARCH-0055 identity-topology ledger events (merge / split / undo
/// counter-events, effective AND parked) into `IdentityLifecycle` receipts.
///
/// Scans the type-76 record family NEWEST-FIRST (reverse type-index walk;
/// UUIDv7 ids order by mint time) and caps EVERY visited row, including rows
/// outside the query's `[start_at, end_at]` window. This is a bound on query
/// work, not merely on returned candidates: an attacker-controlled backlog
/// cannot force an unbounded ledger walk. Because mint order is not `at`
/// order, this bounded scan can starve an older-minted in-window receipt;
/// avoiding that requires an `at`-ordered index or cursor pagination. The
/// family is engine-authored and door-validated: an undecodable row is
/// corruption, never skipped.
pub(super) fn identity_topology_receipts(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let start = [crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT];
    let end = [crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT + 1];
    let bounds = (
        std::ops::Bound::Included(&start[..]),
        std::ops::Bound::Excluded(&end[..]),
    );
    let mut receipts = Vec::new();
    for entry in vault
        .store
        .type_index
        .rev_range(rtxn, &bounds)?
        .take(MAX_RECEIPT_QUERY_SCAN)
    {
        let (key, _) = entry?;
        let event_id = crate::vault::entity_id_from_type_index_key(&key)?;
        let record = vault
            .identity_topology_event_in_txn(rtxn, &event_id)?
            .ok_or(Error::CorruptedIndex("identity topology event index"))?;
        if query.end_at.is_some_and(|end_at| record.at > end_at)
            || query.start_at.is_some_and(|start_at| record.at < start_at)
        {
            continue;
        }
        // Per-kind dispatch: a resolution row NAMED by the fold as a
        // duplicate (the proposal already retired by an EARLIER ruling)
        // projects nothing — an outcome receipt for it would read as a
        // second, contradictory decision about one review. Rejection sets
        // arrive from the fold the log itself maintains, so a replay that
        // double-rules converges to the same single receipt everywhere.
        let action_is_resolution = matches!(
            record.action,
            crate::identity_topology::StoredIdentityOpAction::ProposalResolution { .. }
        );
        if action_is_resolution {
            let fold = crate::identity_topology::fold_identity_topology_log(
                &vault.fold_effective_identity_topology_events_in_txn(rtxn)?,
            );
            if fold
                .rejections
                .iter()
                .any(|(rejected, reason)| {
                    *rejected == event_id
                        && matches!(
                            reason,
                            crate::identity_topology::IdentityTopologyRejection::ProposalAlreadyResolved { .. }
                        )
                })
            {
                continue;
            }
        }
        let receipt = if action_is_resolution {
            proposal_outcome_receipt(&event_id, &record)
        } else {
            identity_topology_receipt(&event_id, &record)
        };
        if query.includes_kind(receipt.receipt_kind) && query.matches(&receipt) {
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}

/// Projects the ARCH-0055 r7 proposal-outcome receipt from a resolution
/// ledger event (ONE-1747).
///
/// The three ramp-scope fields (`op_kind`, `target_class`, `actor`) are
/// stamped on ALL THREE outcomes so MS-06 (ONE-1748) can rebuild per-scope
/// ramp statistics from receipts alone, with no ledger dereference.
///
/// `amended_body` carries the amended op bytes as lower hex, present ONLY on
/// `approved_amended` — the producer artifact ED-01 (ONE-1757) diffs
/// against the proposal, never overwritten. It is DISTINCT from
/// [`FIELD_AMENDMENT_DELTA`], the reserved slot ED-01 fills with the encoded
/// Δ schema: two fields, two meanings. This ticket never writes the latter.
fn proposal_outcome_receipt(
    event_id: &EntityId,
    record: &crate::identity_topology::StoredIdentityOpEvent,
) -> ReceiptRecord {
    use crate::identity_topology::StoredIdentityOpAction;

    let StoredIdentityOpAction::ProposalResolution {
        proposal,
        outcome,
        scope,
        amended_body,
    } = &record.action
    else {
        unreachable!("proposal outcome receipt projects only resolution events")
    };

    let mut fields = BTreeMap::new();
    fields.insert(FIELD_PROPOSAL_REF.to_owned(), proposal.to_hex());
    fields.insert(FIELD_OP_KIND.to_owned(), scope.op_kind.to_owned());
    fields.insert(FIELD_TARGET_CLASS.to_owned(), scope.target_class.clone());
    fields.insert(FIELD_SCOPE_ACTOR.to_owned(), scope.actor.clone());
    // NOT `source`: that key is one of the six ARCH-0056 Δ field names this
    // receipt must not project until ED-01 (ONE-1757) builds the Δ schema.
    // The claim-source axis is real and unrelated, so it keeps its own
    // unambiguous key rather than squatting on the reserved one.
    fields.insert(
        FIELD_CLAIM_SOURCE.to_owned(),
        record.source.as_str().to_owned(),
    );
    fields.insert("seq".to_owned(), record.seq.to_string());
    if let Some(amended_body) = amended_body {
        fields.insert(FIELD_AMENDED_BODY.to_owned(), hex_lower(amended_body));
    }

    ReceiptRecord {
        receipt_id: format!("proposal_outcome:{}", event_id.to_hex()),
        receipt_kind: ReceiptKind::ProposalOutcome,
        occurred_at: record.at,
        actor: record.actor.map(|actor| actor.entity_ref().to_hex()),
        on_behalf_of: None,
        outcome: outcome.as_str().to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("event:{}", proposal.to_hex())),
        policy_trace: Vec::new(),
        fields,
    }
}

/// The amended op body a proposal-outcome receipt carries — the raw bytes
/// the decider approved, byte-identical to what was applied. `None` on
/// `approved_untouched` / `rejected` (nothing was amended) and on any other
/// receipt kind.
#[must_use]
pub fn proposal_outcome_amended_body(record: &ReceiptRecord) -> Option<Vec<u8>> {
    receipt_hex_field(record, FIELD_AMENDED_BODY)
}

/// The reserved ARCH-0056 amendment-delta slot (ONE-1747 mints it EMPTY;
/// ED-01 / ONE-1757 fills it with the encoded Δ schema).
///
/// Always `None` today — deliberately, not incidentally: the Δ schema is the
/// ED epic's surface, and building it here would over-build it. Distinct
/// from [`proposal_outcome_amended_body`], which is the producer artifact
/// the Δ is computed FROM.
#[must_use]
pub fn proposal_outcome_delta(record: &ReceiptRecord) -> Option<Vec<u8>> {
    receipt_hex_field(record, FIELD_AMENDMENT_DELTA)
}

/// Decodes an opaque payload field carried as lower hex. A malformed value
/// reads as absent: the field is engine-written through
/// [`hex_lower`], so unparseable content is not a payload the caller can
/// meaningfully act on.
fn receipt_hex_field(record: &ReceiptRecord, field: &str) -> Option<Vec<u8>> {
    let hex = record.fields.get(field)?;
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(hex.get(index..index + 2)?, 16).ok())
        .collect()
}

fn identity_topology_receipt(
    event_id: &EntityId,
    record: &crate::identity_topology::StoredIdentityOpEvent,
) -> ReceiptRecord {
    use crate::identity_topology::StoredIdentityOpAction;

    let mut fields = BTreeMap::new();
    fields.insert("approval".to_owned(), record.approval.as_str().to_owned());
    fields.insert("source".to_owned(), record.source.as_str().to_owned());
    fields.insert("seq".to_owned(), record.seq.to_string());
    if let Some(actor) = record.actor {
        fields.insert(
            "actor_class".to_owned(),
            actor.actor_class().gate_actor_class().to_owned(),
        );
    }
    // DECLARED vs APPLIED (ONE-1745), for every action that carries a
    // reassignment map. The gap is the point: it means the decision named
    // items this vault holds no claim for. Both halves read the STORED
    // record alone, so the projector stays pure — no vault, no txn.
    if let Some(map) = record.action.reassignment_map() {
        let (assigned, residue) = map.assigned_and_residue_counts();
        fields.insert("assigned".to_owned(), assigned.to_string());
        fields.insert("residue".to_owned(), residue.to_string());
    }
    if let Some(applied) = record.action.applied_reassignment_stats() {
        fields.insert("applied_assigned".to_owned(), applied.assigned.to_string());
        fields.insert("applied_residue".to_owned(), applied.residue.to_string());
    }
    let trigger_ref = match &record.action {
        StoredIdentityOpAction::Merge { sources, survivor } => {
            fields.insert("survivor".to_owned(), survivor.to_hex());
            fields.insert("source_count".to_owned(), sources.len().to_string());
            Some(format!("entity:{}", survivor.to_hex()))
        }
        StoredIdentityOpAction::Split { entity, heads, .. } => {
            fields.insert("entity".to_owned(), entity.to_hex());
            fields.insert("head_count".to_owned(), heads.len().to_string());
            Some(format!("entity:{}", entity.to_hex()))
        }
        StoredIdentityOpAction::Facet { entity, facets, .. } => {
            fields.insert("entity".to_owned(), entity.to_hex());
            fields.insert("facet_count".to_owned(), facets.len().to_string());
            Some(format!("entity:{}", entity.to_hex()))
        }
        // ONE-1746: the pair is the decision, and the claim is where it
        // lives — both projected so a reader can audit the assertion without
        // dereferencing the ledger event.
        StoredIdentityOpAction::AssertDistinct { a, b, claim } => {
            fields.insert("pair_a".to_owned(), a.to_hex());
            fields.insert("pair_b".to_owned(), b.to_hex());
            fields.insert("claim".to_owned(), claim.to_hex());
            Some(format!("claim:{}", claim.to_hex()))
        }
        StoredIdentityOpAction::Undo { target } => {
            fields.insert("undo_of".to_owned(), target.to_hex());
            Some(format!("event:{}", target.to_hex()))
        }
        // Resolution rows project the ProposalOutcome receipt instead; the
        // caller dispatches on the action before reaching this projector.
        StoredIdentityOpAction::ProposalResolution { proposal, .. } => {
            Some(format!("event:{}", proposal.to_hex()))
        }
    };

    ReceiptRecord {
        receipt_id: format!("identity_topology:{}", event_id.to_hex()),
        receipt_kind: ReceiptKind::IdentityLifecycle,
        occurred_at: record.at,
        actor: record.actor.map(|actor| actor.entity_ref().to_hex()),
        on_behalf_of: None,
        outcome: record.action.kind_str().to_owned(),
        job_ref: None,
        trigger_ref,
        policy_trace: Vec::new(),
        fields,
    }
}

pub(super) fn channel_identity_lifecycle_receipts(
    vault: &Vault,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    for record in vault
        .store
        .channel_identity_lifecycle_receipts(MAX_RECEIPT_QUERY_SCAN)?
    {
        let receipt = channel_identity_lifecycle_receipt(&record);
        if query.matches(&receipt) {
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}

fn channel_identity_lifecycle_receipt(
    record: &ChannelIdentityLifecycleReceiptRecord,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert("actor_class".to_owned(), record.actor_class.clone());
    fields.insert("verb".to_owned(), record.verb.clone());
    fields.insert("intent_kind".to_owned(), record.intent_kind.clone());
    fields.insert("channel".to_owned(), record.channel.clone());
    fields.insert(
        "address_or_handle".to_owned(),
        record.address_or_handle.clone(),
    );
    fields.insert("state".to_owned(), record.state.clone());
    fields.insert(
        "owner_visible_state".to_owned(),
        record.owner_visible_state.clone(),
    );
    fields.insert(
        "outbound_closed".to_owned(),
        record.outbound_closed.to_string(),
    );
    fields.insert(
        "identity_retiring".to_owned(),
        record.identity_retiring.to_string(),
    );
    if let Some(mode) = record.fulfillment_mode.as_ref() {
        fields.insert("fulfillment_mode".to_owned(), mode.clone());
    }
    if let Some(until) = record.quarantine_until {
        fields.insert("quarantine_until".to_owned(), until.to_string());
    }
    if let Some(decision_id) = record.gate_decision_id {
        fields.insert(
            "gate_decision_ref".to_owned(),
            format!("gate:{}", decision_id.to_hex()),
        );
    }

    ReceiptRecord {
        receipt_id: crate::channel_identity_lifecycle::lifecycle_receipt_ref(record.receipt_id),
        receipt_kind: ReceiptKind::IdentityLifecycle,
        occurred_at: record.created_at,
        actor: record
            .actor_ref
            .clone()
            .or_else(|| Some(record.actor_class.clone())),
        on_behalf_of: None,
        outcome: record.outcome.clone(),
        job_ref: None,
        trigger_ref: Some(format!("entity:{}", hex_lower(&record.identity_id))),
        policy_trace: Vec::new(),
        fields,
    }
}

fn append_companion_scope_fields(fields: &mut BTreeMap<String, String>, scope: &CompanionScope) {
    match scope {
        CompanionScope::Neutral => {
            fields.insert("scope".to_owned(), "neutral".to_owned());
        }
        CompanionScope::Personal { person_ref } => {
            fields.insert("scope".to_owned(), "personal".to_owned());
            fields.insert("person_ref".to_owned(), person_ref.to_hex());
        }
        CompanionScope::SharedVault { vault_id } => {
            fields.insert("scope".to_owned(), "shared_vault".to_owned());
            fields.insert("vault_id".to_owned(), vault_id.to_string());
        }
    }
}

fn append_companion_subject_fields(
    fields: &mut BTreeMap<String, String>,
    subject: &CompanionSubject,
) {
    match subject {
        CompanionSubject::Persona { persona_ref } => {
            fields.insert("subject".to_owned(), "persona".to_owned());
            fields.insert("persona_ref".to_owned(), persona_ref.to_hex());
        }
        CompanionSubject::Relationship {
            source_ref,
            target_ref,
        } => {
            fields.insert("subject".to_owned(), "relationship".to_owned());
            fields.insert("source_ref".to_owned(), source_ref.to_hex());
            fields.insert("target_ref".to_owned(), target_ref.to_hex());
        }
    }
}
