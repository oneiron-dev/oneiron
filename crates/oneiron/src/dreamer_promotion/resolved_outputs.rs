//! A conflict a retried try answered closes the open marker its first try
//! left (FIX 7325, Engine 10-21). A failed conflict step leaves a Proposed
//! marker; once a later try of the same attempt resolves that conflict and
//! every output answering it stands, the marker closes through the existing
//! close door under the handoff's fence, as a granted correction's markers
//! do. A replay that meets only some of those outputs again closes it too
//! (FIX 7380): one stood in its write, none was held, pended or rejected
//! there, and every one still stands. A refused or unstanding close leaves
//! it open, and the outputs stand either way. A created output keeps its
//! binding in its provenance, so a replay that meets the output again still
//! closes the marker.
use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::claim::{ClaimLifecycleStatus, PREDICATE_CONFLICT_OPEN, PREDICATE_CONFLICT_RESOLVED};
use crate::dreamer_consolidation::evidence::ResolvedConflictOutput;
use crate::dreamer_consolidation::resources::{ConsolidationFence, RowRevision};
use crate::dreamer_consolidation::{conflict_close_candidate, marker_ids};

/// Envelope-provenance key binding a created output to the open markers it
/// answers.
const ANSWERS_KEY: &str = "answers_open_conflict";

/// `provenance` with `answers` beside it; unchanged when there are none.
pub(super) fn with_answers(provenance: Value, answers: &[&ResolvedConflictOutput]) -> Value {
    if answers.is_empty() {
        return provenance;
    }
    match provenance {
        Value::Map(mut entries) => {
            entries.push((
                Value::from(ANSWERS_KEY),
                Value::Array(answers.iter().copied().map(answer_value).collect()),
            ));
            Value::Map(entries)
        }
        other => other,
    }
}

fn answer_value(answer: &ResolvedConflictOutput) -> Value {
    Value::Map(vec![
        (
            Value::from("marker"),
            Value::Binary(answer.marker.as_bytes().to_vec()),
        ),
        (Value::from("outputs"), ids_value(&answer.outputs)),
        (
            Value::from("resolution"),
            Value::from(answer.resolution.as_str()),
        ),
    ])
}

fn ids_value(ids: &[EntityId]) -> Value {
    Value::Array(
        ids.iter()
            .map(|id| Value::Binary(id.as_bytes().to_vec()))
            .collect(),
    )
}

/// The bindings `head`'s provenance keeps, for a replay that meets this
/// attempt's own output again. One that does not read or decode binds
/// nothing.
pub(super) fn stored_answers(vault: &Vault, head: EntityId) -> Vec<ResolvedConflictOutput> {
    let body = match vault.get_claim(&head) {
        Ok(Some(body)) => body,
        Ok(None) => return Vec::new(),
        Err(error) => {
            tracing::warn!(
                error_kind = ?error.kind(),
                head = %head.to_hex(),
                "an output's conflict answers did not read"
            );
            return Vec::new();
        }
    };
    let stored = body
        .evidence
        .as_ref()
        .and_then(|evidence| {
            field(
                evidence,
                crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY,
            )
        })
        .and_then(|provenance| field(provenance, ANSWERS_KEY));
    let Some(Value::Array(stored)) = stored else {
        return Vec::new();
    };
    stored.iter().filter_map(decode_answer).collect()
}

fn decode_answer(value: &Value) -> Option<ResolvedConflictOutput> {
    let marker = marker_ids(value, "marker").next()?;
    let outputs: Vec<EntityId> = marker_ids(value, "outputs").collect();
    let resolution = field(value, "resolution")?.as_str()?.to_owned();
    (!outputs.is_empty()).then_some(ResolvedConflictOutput {
        marker,
        outputs,
        resolution,
    })
}

fn field<'v>(value: &'v Value, key: &str) -> Option<&'v Value> {
    match value {
        Value::Map(rows) => rows
            .iter()
            .find(|(name, _)| name.as_str() == Some(key))
            .map(|(_, value)| value),
        _ => None,
    }
}

/// Closes the open marker each of `answers` names once its outputs stand
/// (FIX 7380): at least one stood in this write, none of the others is in
/// `unmet` (met by this write but held, pended or rejected there), and
/// every one stands at the close's read. `stood` maps each head the write
/// landed or met to the evidence its candidate cited; an output this write
/// did not meet cites the turn evidence its stored claim cites. A marker a
/// standing answer already names, and a gone, closed or refused one, close
/// nothing. Best effort: a close that fails is logged by a closed code and
/// its kind, and leaves the marker open.
pub(super) fn close_resolved_outputs(
    vault: &Vault,
    run: &DreamerRunContext,
    fence: &ConsolidationFence,
    answers: &[ResolvedConflictOutput],
    stood: &BTreeMap<EntityId, Vec<EntityId>>,
    unmet: &BTreeSet<EntityId>,
) {
    for answer in answers {
        let met = answer
            .outputs
            .iter()
            .any(|output| stood.contains_key(output));
        let blocked = answer
            .outputs
            .iter()
            .any(|output| !stood.contains_key(output) && unmet.contains(output));
        if !met || blocked {
            continue;
        }
        let (reason, kind) = match close_answer(vault, run, fence, answer, stood) {
            Ok(None) => continue,
            Ok(Some(refused)) => refused,
            Err(error) => ("close_read_failed", Some(error.kind())),
        };
        tracing::warn!(
            reason,
            error_kind = ?kind,
            marker = %answer.marker.to_hex(),
            "an open conflict a retried try answered stayed open"
        );
    }
}

/// Why a close left its marker open: a closed code and the kind of the
/// engine error behind it, when one refused it.
type CloseRefusal = (&'static str, Option<crate::error::ErrorKind>);

/// One answer's close. `Ok(None)`: it closed, or had nothing to close. It
/// cites what each output's candidate cited in this write (`stood`), and
/// for an output this write did not meet, the turn evidence its stored
/// claim cites.
fn close_answer(
    vault: &Vault,
    run: &DreamerRunContext,
    fence: &ConsolidationFence,
    answer: &ResolvedConflictOutput,
    stood: &BTreeMap<EntityId, Vec<EntityId>>,
) -> Result<Option<CloseRefusal>> {
    // The marker, every output and its evidence from one read; each output's
    // revision holds the close's fence to the output as it stood.
    let (marker, outputs, mut evidence) = {
        let txn = vault.store.env.read_txn()?;
        let marker = vault.get_claim_in_txn(&txn, &answer.marker)?;
        let mut outputs = Vec::new();
        let mut evidence: Vec<EntityId> = Vec::new();
        for output in &answer.outputs {
            let body = vault
                .get_claim_in_txn(&txn, output)?
                .filter(crate::claim::claim_surfaceable);
            match (body, RowRevision::read_in(vault, &txn, output)?) {
                (Some(body), Some(revision)) => {
                    outputs.push((*output, revision));
                    match stood.get(output) {
                        Some(cited) => evidence.extend_from_slice(cited),
                        None => evidence.extend(stored_turn_refs(output, &body)),
                    }
                }
                _ => return Ok(Some(("output_not_standing", None))),
            }
        }
        (marker, outputs, evidence)
    };
    evidence.sort_unstable();
    evidence.dedup();
    let Some(marker) = marker else {
        return Ok(None);
    };
    if marker.predicate != PREDICATE_CONFLICT_OPEN
        || marker.lifecycle != ClaimLifecycleStatus::Active
        || marker.approval == ClaimApprovalStatus::Rejected
    {
        return Ok(None);
    }
    let crate::claim::ClaimSubject::Entity(subject) = marker.subject else {
        return Ok(None);
    };
    // A standing answer already names it: a replay closes nothing twice.
    for id in vault.claims_for_subject(&subject)? {
        let Some(claim) = vault.get_claim(&id)? else {
            continue;
        };
        if claim.predicate == PREDICATE_CONFLICT_RESOLVED
            && crate::claim::claim_surfaceable(&claim)
            && marker_ids(&claim.value, "open_marker").any(|named| named == answer.marker)
        {
            return Ok(None);
        }
    }
    let resolution = Value::Map(vec![
        (Value::from("superseded_by"), ids_value(&answer.outputs)),
        (
            Value::from("retried"),
            Value::from(answer.resolution.as_str()),
        ),
    ]);
    let close = match conflict_close_candidate(vault, run, answer.marker, resolution, evidence) {
        Ok(close) => close,
        Err(error) => return Ok(Some(("no_close_candidate", Some(error.kind())))),
    };
    for (output, revision) in outputs {
        fence.relies_on(output, revision);
    }
    let refused = match promote_one(vault, run, close, None, Some(fence), None) {
        Ok(ClaimApprovalStatus::Auto | ClaimApprovalStatus::Proposed) => None,
        Ok(other) => Some((other.as_str(), None)),
        Err(rejection) => Some(("promotion_refused", rejection.kind)),
    };
    for output in &answer.outputs {
        fence.released(*output);
    }
    Ok(refused)
}

/// The turn evidence output `output`'s body `body` cited in its own write:
/// the refs of the consolidation envelope it keeps as its candidate
/// evidence. None for a body without one, or one that does not decode; the
/// latter is logged by its error kind and the holder output's id (the
/// envelope has no id of its own), and the close goes on citing the rest
/// (FIX 7421).
fn stored_turn_refs(output: &EntityId, body: &crate::ClaimBody) -> Vec<EntityId> {
    let Some(stored) = body.evidence.as_ref().and_then(|evidence| {
        field(
            evidence,
            crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
        )
    }) else {
        return Vec::new();
    };
    match crate::dreamer_consolidation::decode_consolidation_evidence(stored) {
        Ok(envelope) => envelope.map(|envelope| envelope.refs).unwrap_or_default(),
        Err(error) => {
            tracing::warn!(
                error_kind = ?error.kind(),
                output = %output.to_hex(),
                "an output's stored candidate evidence did not decode; the close cites the rest"
            );
            Vec::new()
        }
    }
}
