use rmpv::Value;

use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, DreamerIsolationClass};
use crate::compaction::turn_session_membership_in_txn;
use crate::dreamer_consolidation::decode_consolidation_evidence;
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::gate::constants::{
    DREAMER_PROVENANCE_RUN_ID_KEY, DREAMER_PROVENANCE_RUN_KEY, DREAMER_PROVENANCE_RUNNER_KEY,
    DREAMER_PROVENANCE_SURFACE_KEY,
};
use crate::gate::decision::{GateDecision, GateReasonCode};
use crate::gate::dreamer_precommit::{DreamerPrecommitInput, validate_dreamer_precommit};
use crate::registry::{ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::store::Store;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::write_envelope::{WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY, WriteEnvelope};

pub(super) fn pending_consent_dreamer_run_id(
    envelope: Option<&WriteEnvelope>,
    body: &ClaimBody,
) -> Option<String> {
    if body.approval != ClaimApprovalStatus::Proposed || body.source != Some(ClaimSource::Generated)
    {
        return None;
    }

    let envelope = envelope?;
    dreamer_run_id_from_write_envelope(envelope)
}

/// The Dreamer run this write is authored by, if any.
///
/// Authorship is a property of the WRITE, read off provenance and
/// SOURCE-AGNOSTIC: `Agent` actor class, the Dreamer run surface/runner
/// marker, and a non-empty run id. `envelope.source()` is the computed
/// evidence meet — epistemic taint derived FROM the candidate's evidence —
/// so a truthful `ToolOutput` or `Observed` meet says how well the claim is
/// known, never who wrote it, and must not disable the deny-first GATE-12
/// floor. Source narrowing answers the other question, owner-review
/// grouping, and lives solely in `pending_consent_dreamer_run_id`.
pub(in crate::gate) fn dreamer_run_id_from_write_envelope(
    envelope: &WriteEnvelope,
) -> Option<String> {
    if envelope.actor().actor_class() != EdgeActorClass::Agent {
        return None;
    }
    dreamer_run_id_from_provenance(envelope.provenance().value())
}

fn dreamer_run_id_from_provenance(value: &Value) -> Option<String> {
    let Value::Map(entries) = value else {
        return None;
    };
    if !entries.iter().any(|(key, value)| {
        key.as_str().is_some_and(|key| {
            key == DREAMER_PROVENANCE_RUNNER_KEY || key == DREAMER_PROVENANCE_SURFACE_KEY
        }) && value.as_str() == Some(DREAMER_RUNNER_ATTEMPT_KIND)
    }) {
        return None;
    }

    [DREAMER_PROVENANCE_RUN_ID_KEY, DREAMER_PROVENANCE_RUN_KEY]
        .into_iter()
        .find_map(|run_key| {
            entries.iter().find_map(|(key, value)| {
                if key.as_str() != Some(run_key) {
                    return None;
                }
                let run_id = value.as_str()?.trim();
                (!run_id.is_empty()).then(|| run_id.to_owned())
            })
        })
}

/// Runs the GATE-12 pre-commit checks for one Dreamer-authored candidate,
/// returning the pinned denial reason when a check refuses it.
///
/// The existence resolver answers "does this ref resolve to a LIVE entity",
/// through the PASSED transaction and nothing else. An absent key, an
/// unparseable header, a read or deletion-metadata error, and an ARCH-0038
/// soft-delete shell (a header-only row whose tombstone is pending or
/// published) are all "does not resolve" rather than an abort — the floor is
/// looking for one ref that DOES resolve, and every unreadable or erased
/// state is fail-closed non-evidence. Reading through the caller's
/// transaction is what keeps a ref written earlier in the SAME write
/// transaction resolvable, so the miner's write-then-gate order still holds;
/// a live zero-byte payload, which carries no deletion metadata, also still
/// resolves. Liveness is the whole question here: the floor stays
/// type-agnostic.
pub(super) fn dreamer_precommit_denial(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
) -> Option<GateReasonCode> {
    let resolves =
        |id: &EntityId| -> Result<bool> { Ok(live_entity_row_in_txn(store, txn, id)?.is_live()) };

    validate_dreamer_precommit(
        &DreamerPrecommitInput {
            predicate: &body.predicate,
            value: &body.value,
            confidence: body.confidence,
            // `ClaimBody::subject` is a total `ClaimSubject`, so a body that
            // reaches this door always carries one; the validator keeps the
            // axis explicit for the shape contract it pins.
            subject_present: true,
            evidence: body.evidence.as_ref(),
        },
        &resolves,
    )
    .err()
}

/// How many distinct SESSION entities a persona-core Dreamer write must cite
/// before it may be parked for owner review (GATE-13).
///
/// Two is the smallest number that cannot be one conversation. A persona head
/// moves on DELIBERATE transformation — something the owner returned to across
/// sittings — so a single cycle, however emphatic inside itself, is refused
/// rather than queued.
const PERSONA_CORE_MIN_DISTINCT_SESSIONS: usize = 2;

/// The isolation verdict for one Dreamer-authored candidate whose predicate
/// carries an isolation class.
///
/// Both classes force the ceiling to Proposed and both carry the EXISTING
/// criticality marker beside their own code, so the inbox projection keeps
/// classifying them `ManifestCritical` through the equality it already has —
/// no new inbox variant, and no dial that can waive the row.
pub(super) fn dreamer_isolation_decision(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
    isolation_class: DreamerIsolationClass,
) -> GateDecision {
    match isolation_class {
        DreamerIsolationClass::PersonaCore => {
            let sessions = distinct_evidence_session_count(store, txn, body);
            if sessions < PERSONA_CORE_MIN_DISTINCT_SESSIONS {
                GateDecision::deny(GateReasonCode::DenyPersonaSingleCycle)
            } else {
                GateDecision::pending(vec![
                    GateReasonCode::PendingPersonaIsolation,
                    GateReasonCode::PendingCriticalityFloor,
                ])
            }
        }
        DreamerIsolationClass::MirroringProne => GateDecision::pending(vec![
            GateReasonCode::PendingMirroringIsolation,
            GateReasonCode::PendingCriticalityFloor,
        ]),
    }
}

/// Counts the DISTINCT sittings the candidate's own evidence reaches.
///
/// Read from the candidate's `candidate_evidence` payload through the same
/// codec the GATE-12 floor uses, and resolved through the CALLER's
/// transaction so a turn written earlier in this write transaction still
/// answers. Every unreadable state is non-evidence rather than an abort: a
/// legacy payload shape, a structurally broken envelope, a ref that does not
/// resolve, a ref that resolves to something other than a TURN, a turn with
/// no recorded sitting, and a recorded sitting that does not resolve to a
/// live SESSION all fail closed and simply do not count.
fn distinct_evidence_session_count(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
) -> usize {
    let Some(Value::Map(entries)) = body.evidence.as_ref() else {
        return 0;
    };
    let Some(candidate_evidence) = entries.iter().find_map(|(key, value)| {
        (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY)).then_some(value)
    }) else {
        return 0;
    };
    let Ok(Some(evidence)) = decode_consolidation_evidence(candidate_evidence) else {
        return 0;
    };

    let mut sessions: Vec<EntityId> = Vec::new();
    for entity_ref in &evidence.refs {
        let Some(session) = evidence_ref_session(store, txn, entity_ref) else {
            continue;
        };
        if !sessions.contains(&session) {
            sessions.push(session);
        }
    }
    sessions.len()
}

/// The sitting one evidence ref speaks from: the ref must resolve to a live
/// TURN, that turn must carry a RECORDED session membership, and the
/// membership must itself resolve to a live SESSION.
///
/// Membership is the engine-written fact recorded beside the turn at witness
/// time, never a caller-authored field on the turn body — a body a writer
/// controls could otherwise name any sitting it liked and manufacture the
/// second cycle this floor exists to require.
fn evidence_ref_session(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entity_ref: &EntityId,
) -> Option<EntityId> {
    if !live_entity_row_has_type(store, txn, entity_ref, ENTITY_TYPE_TURN) {
        return None;
    }
    let session = turn_session_membership_in_txn(store, txn, entity_ref)
        .ok()
        .flatten()?;
    live_entity_row_has_type(store, txn, &session, ENTITY_TYPE_SESSION).then_some(session)
}

/// Whether `id` reads back as a LIVE row of exactly `entity_type`. A read
/// error, an absent row and an erased shell are all `false`.
fn live_entity_row_has_type(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
) -> bool {
    matches!(
        live_entity_row_in_txn(store, txn, id),
        Ok(LiveEntityRow::Live { entity_type: found, .. }) if found == entity_type
    )
}
