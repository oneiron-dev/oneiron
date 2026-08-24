//! Dormant subsystem — zero production callers as of 2026-08-19. Owner
//! ruling: keep dormant; needs design work before wiring.
//!
//! Contents: the Dreamer magistrate decision/apply/enqueue/overturn chain,
//! the A2A consult-task projection, and the authorship-derivation half of the
//! claim-attribution readers (the live half stays in
//! `entity_delta_facade.rs`). This file's own tests in `tests.rs` are its
//! only exercise path.

use rmpv::Value;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::consult_ladder::{
    A2aTaskProjection, ConsultLadderState, DREAMER_MAGISTRATE_ATTEMPT_TYPE, HumanVerdict,
    LadderTerminalState, LadderTransitionError, MagistrateCase, MagistrateOverturnRecord,
    MagistrateReceipt, MagistrateVerdict, StateAuthorship,
    decide_magistrate_from_derived_authorship, magistrate_decision_layer, project_to_a2a,
};
use crate::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerRunnerStore, EnqueueDreamerAttempt,
    EnqueueDreamerAttemptOutcome,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::validate_actor_class;
use crate::registry::ENTITY_TYPE_TURN;
use crate::temporal::TimeRange;
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};

use super::consult_ladder_facade::ladder_disposition_for_task;
use super::entity_delta_facade::{DREAMER_PROVENANCE_SURFACE_KEYS, claim_envelope_actor};
use super::presence_scan::attempt_hex;
use super::terminal_state::{TaskExecutionState, TaskTerminalRecord};
use super::wire_decode::{
    decode_entity_ref, decode_task_assignee, task_body_field, task_body_optional, task_verb_body,
};
use super::wire_encode::{canonical_bytes, entity_ref_value, task_assignee_value};

/// Lifts one persisted terminal register back into the pure ladder terminal.
///
/// A ONE-1699 row that carries no `result_ref` cannot become a ladder terminal
/// at all — the ladder's `result_ref` is not optional — so it fails closed.
///
/// # Errors
///
/// [`LadderTransitionError::MissingResultRef`] when the persisted record has
/// no durable result.
pub fn ladder_terminal_from_task_terminal(
    record: &TaskTerminalRecord,
) -> std::result::Result<LadderTerminalState, LadderTransitionError> {
    let result_ref = record
        .result_ref
        .ok_or(LadderTransitionError::MissingResultRef)?;
    Ok(LadderTerminalState {
        disposition: record
            .ladder
            .unwrap_or_else(|| ladder_disposition_for_task(record.disposition)),
        result_ref,
        counter_task_ref: record.counter_task_ref,
        finished_at: record.finished_at,
    })
}

/// Projects one consult TASK onto A2A task vocabulary. Projection only — this
/// is neither an A2A server nor a conformance claim.
pub fn project_consult_task_to_a2a(
    vault: &Vault,
    task_ref: EntityId,
) -> Result<Option<A2aTaskProjection>> {
    let Some(body) = task_verb_body(vault, task_ref)? else {
        return Ok(None);
    };
    let Some(state) = &body.state else {
        return Ok(None);
    };
    let ladder = match state {
        // A2A has no `queued`: a task that exists and has not been paused is
        // progressing, which is exactly what `working` says.
        TaskExecutionState::Queued => {
            ConsultLadderState::Working(crate::consult_ladder::WorkingState {
                started_at: body.created_at,
                decision_round: 0,
            })
        }
        TaskExecutionState::Working { started_at } => {
            ConsultLadderState::Working(crate::consult_ladder::WorkingState {
                started_at: *started_at,
                decision_round: 0,
            })
        }
        // ONE-1699's body keeps interruption DETAIL in the referenced case, so
        // the kind is unknown here. `consent_required` is the fail-closed
        // reading — durably paused progress is not progress — and the invented
        // kind is stripped from the projection below rather than guessed at.
        TaskExecutionState::Interrupted => {
            ConsultLadderState::Interrupted(crate::consult_ladder::InterruptedState {
                kind: crate::consult_ladder::InterruptionKind::Contested,
                consent_required: true,
                case_ref: task_ref,
                interrupted_at: body.created_at,
            })
        }
        TaskExecutionState::Terminal(record) => match ladder_terminal_from_task_terminal(record) {
            Ok(terminal) => ConsultLadderState::Terminal(terminal),
            Err(_) => return Ok(None),
        },
    };
    let mut projection = project_to_a2a(
        task_ref,
        &ladder,
        body.consult.as_ref().and_then(|consult| consult.lineage),
    );
    projection.extensions.interruption_kind = None;
    // An UNSTAMPED ONE-1699 terminal has no ladder outcome to project, so its
    // own disposition rides through verbatim: `expired` stays expired rather
    // than being rounded to the nearest ladder word.
    if let TaskExecutionState::Terminal(record) = state
        && record.ladder.is_none()
    {
        projection.extensions.terminal_disposition = Some(record.disposition.as_str().to_owned());
    }
    Ok(Some(projection))
}

// ── Dreamer magistrate bridge (ONE-1888) ────────────────────────────────

/// Whether one write-envelope provenance map names the Dreamer runner surface.
fn provenance_is_dreamer(provenance: &Value) -> bool {
    let Value::Map(entries) = provenance else {
        return false;
    };
    entries.iter().any(|(key, value)| {
        key.as_str()
            .is_some_and(|key| DREAMER_PROVENANCE_SURFACE_KEYS.contains(&key))
            && value.as_str() == Some(DREAMER_RUNNER_ATTEMPT_KIND)
    })
}

/// Derives WHO authored the contested state, from the vault alone.
///
/// The traversal is deliberately unforgeable: it loads the contested state and
/// delta claims, reads their write-envelope attribution, VALIDATES the
/// recorded actor class against the actor entity's own kind, and only then
/// classifies. No caller field participates, because `MagistrateCase` carries
/// none — a summary a caller can write is a summary a caller can forge.
///
/// `ClaimSource::Generated` alone is NOT the test: dispatched agents generate
/// state too. The discriminator is the Dreamer RUN surface on the envelope
/// provenance, and Dreamer authorship of EITHER the contested state or the
/// contested delta recuses — recusal is the conservative direction.
///
/// # Errors
///
/// Fails closed when the contested state carries no recoverable attribution:
/// an unattributable state is not one the writer may rule on.
pub(crate) fn derive_state_authorship(
    vault: &Vault,
    case: &MagistrateCase,
) -> Result<StateAuthorship> {
    let state = resolve_authorship(vault, case.contested_state_ref)?
        .ok_or(Error::InvalidClaimBody("magistrate.state_authorship"))?;
    if state == StateAuthorship::Dreamer {
        return Ok(state);
    }
    match resolve_authorship(vault, case.contested_delta_ref)? {
        Some(StateAuthorship::Dreamer) => Ok(StateAuthorship::Dreamer),
        _ => Ok(state),
    }
}

fn resolve_authorship(vault: &Vault, claim_ref: EntityId) -> Result<Option<StateAuthorship>> {
    let Some(attribution) = claim_envelope_actor(vault, claim_ref)? else {
        return Ok(None);
    };
    let Some(actor_entity_type) = vault.get_entity_type(&attribution.actor)? else {
        return Ok(None);
    };
    // D13: the recorded class must be one the actor entity's kind admits. A
    // row claiming `human` over a MACHINE actor is rejected, not defaulted.
    validate_actor_class(actor_entity_type, attribution.actor_class)?;
    if provenance_is_dreamer(&attribution.provenance) {
        return Ok(Some(StateAuthorship::Dreamer));
    }
    Ok(Some(match attribution.actor_class {
        EdgeActorClass::Human => StateAuthorship::Human,
        EdgeActorClass::Agent => StateAuthorship::OtherAgent,
        EdgeActorClass::System => StateAuthorship::System,
    }))
}

/// Rules on one contested case.
///
/// Authorship is re-derived from the vault BEFORE any evidence is weighed, so
/// a forged "other agent" summary cannot buy a Dreamer-authored case a ruling.
///
/// # Errors
///
/// Propagates the authorship derivation's fail-closed errors.
pub fn decide_magistrate(vault: &Vault, case: &MagistrateCase) -> Result<MagistrateVerdict> {
    let authorship = derive_state_authorship(vault, case)?;
    Ok(decide_magistrate_from_derived_authorship(case, authorship))
}

/// Applies one magistrate verdict and writes its durable receipt.
///
/// The effector floor is STRUCTURAL, not a checklist: the whole write set is
/// (a) the receipt artifact, (b) an existing `Vault::supersede_claim` call
/// when a claim is replaced, and (c) an existing `core.conflict.open` claim
/// when competing live claims remain. No connector, no outbound intent, no
/// destructive delete, no grant widening, no authority edit — none of those
/// APIs is reachable from here.
///
/// Advice, recusal, and pathology write the receipt and NOTHING else: a
/// critical case cannot be terminalized by the Dreamer at all.
///
/// # Errors
///
/// Propagates claim/write failures; nothing partial is committed.
pub fn apply_magistrate_verdict(
    vault: &Vault,
    magistrate_actor: WriteActor,
    case: &MagistrateCase,
    verdict: &MagistrateVerdict,
) -> Result<MagistrateReceipt> {
    let receipt = MagistrateReceipt {
        receipt_ref: EntityId::now(),
        task_ref: case.task_ref,
        verdict: *verdict,
        decisive_layer: magistrate_decision_layer(case, *verdict),
        considered_policy_refs: case.policy.iter().map(|entry| entry.policy_ref).collect(),
        considered_authority_refs: case
            .authority
            .iter()
            .map(|entry| entry.authoritative_actor_ref)
            .collect(),
        considered_temporal_refs: case
            .temporal
            .iter()
            .filter_map(|entry| entry.selected_delta_ref)
            .collect(),
        dreamer_attempt_ref: case.dreamer_attempt_ref,
        // Appeals are filed against the TASK the ruling settled.
        appeal_handle: case.task_ref,
        reversible: true,
        occurred_at: case.now,
    };
    let selected = match verdict {
        MagistrateVerdict::Rule {
            selected_delta_ref, ..
        } => Some(*selected_delta_ref),
        _ => None,
    };
    let envelope = magistrate_envelope(magistrate_actor)?;
    let occurred = TimeRange {
        start: case.now,
        end: case.now,
    };
    let body = canonical_bytes(&magistrate_receipt_value(&receipt));
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .put(
                &receipt.receipt_ref,
                ENTITY_TYPE_TURN,
                occurred,
                case.now,
                &body,
            )
            .apply(wtxn)?;
        let Some(selected) = selected else {
            return Ok(());
        };
        apply_magistrate_selection_in_txn(vault, wtxn, case, selected, &envelope)
    })?;
    Ok(receipt)
}

/// The reversible half of a ruling: supersede the replaced head, and open a
/// conflict claim when other live candidates survive the choice.
fn apply_magistrate_selection_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    case: &MagistrateCase,
    selected: EntityId,
    envelope: &WriteEnvelope,
) -> Result<()> {
    if selected != case.contested_state_ref
        && claim_is_active(vault, selected)?
        && claim_is_active(vault, case.contested_state_ref)?
    {
        vault.supersede_claim_in_txn(wtxn, &selected, &case.contested_state_ref, case.now)?;
    }
    let mut competing: Vec<EntityId> = Vec::new();
    for candidate in &case.candidate_delta_refs {
        if *candidate != selected
            && *candidate != case.contested_state_ref
            && claim_is_active(vault, *candidate)?
        {
            competing.push(*candidate);
        }
    }
    if competing.is_empty() {
        return Ok(());
    }
    vault
        .batch_in()
        .conflict_open_claim(
            &EntityId::now(),
            case.contested_state_ref,
            magistrate_conflict_value(case, selected, &competing),
            1.0,
            envelope,
            TimeRange {
                start: case.now,
                end: case.now,
            },
            case.now,
        )
        .apply(wtxn)?;
    Ok(())
}

fn claim_is_active(vault: &Vault, claim_ref: EntityId) -> Result<bool> {
    Ok(vault
        .get_claim(&claim_ref)?
        .is_some_and(|body| body.lifecycle == ClaimLifecycleStatus::Active))
}

/// The conflict value. Deliberately avoids the `kind`/`schema_version` keys —
/// `claim.rs` reads those as the repo-mutation conflict schema.
fn magistrate_conflict_value(
    case: &MagistrateCase,
    selected: EntityId,
    competing: &[EntityId],
) -> Value {
    Value::Map(vec![
        (
            Value::from("conflict_kind"),
            Value::from("consult_ladder.magistrate"),
        ),
        (Value::from("task_ref"), entity_ref_value(case.task_ref)),
        (
            Value::from("contested_state_ref"),
            entity_ref_value(case.contested_state_ref),
        ),
        (
            Value::from("selected_delta_ref"),
            entity_ref_value(selected),
        ),
        (
            Value::from("competing_delta_refs"),
            Value::Array(competing.iter().copied().map(entity_ref_value).collect()),
        ),
    ])
}

fn magistrate_envelope(magistrate_actor: WriteActor) -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        magistrate_actor,
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (
                Value::from("surface"),
                Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
            ),
            (
                Value::from("attempt_type"),
                Value::from(DREAMER_MAGISTRATE_ATTEMPT_TYPE),
            ),
        ]))?,
        ClaimApprovalStatus::Proposed,
    ))
}

/// Enqueues one magistrate attempt onto the EXISTING Dreamer runner queue as a
/// payload-level attempt type — the `AGENT_DISPATCH_ATTEMPT_TYPE` pattern. No
/// new queue kind, admission rule, lease, or budget.
///
/// # Errors
///
/// Propagates the runner's enqueue failures.
pub fn enqueue_magistrate(
    store: &DreamerRunnerStore<'_>,
    case: &MagistrateCase,
    parent_attempt: Option<AttemptId>,
    run_id: Option<String>,
) -> Result<EnqueueDreamerAttemptOutcome> {
    store.enqueue(EnqueueDreamerAttempt {
        attempt_type: DREAMER_MAGISTRATE_ATTEMPT_TYPE.to_owned(),
        input: magistrate_case_value(case),
        parent_attempt,
        dedupe_key: Some(format!(
            "{DREAMER_MAGISTRATE_ATTEMPT_TYPE}:{}",
            case.task_ref.to_hex()
        )),
        run_id,
        now: case.now,
    })
}

/// Persists one overturn record — the COMPLETE ED training-signal handoff.
/// The ED lane may consume it later; this ticket calls no ED code, enqueues no
/// ED job, and adds no ED dependency.
///
/// # Errors
///
/// Propagates the entity write failure.
pub fn record_magistrate_overturn(
    vault: &Vault,
    record: &MagistrateOverturnRecord,
) -> Result<EntityId> {
    let overturn_ref = EntityId::now();
    let body = canonical_bytes(&magistrate_overturn_value(record));
    let occurred = TimeRange {
        start: record.occurred_at,
        end: record.occurred_at,
    };
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .put(
                &overturn_ref,
                ENTITY_TYPE_TURN,
                occurred,
                record.occurred_at,
                &body,
            )
            .apply(wtxn)
    })?;
    Ok(overturn_ref)
}

fn magistrate_verdict_value(verdict: MagistrateVerdict) -> Value {
    let mut entries = vec![(Value::from("verdict"), Value::from(verdict.as_str()))];
    match verdict {
        MagistrateVerdict::Rule {
            selected_delta_ref,
            rationale_ref,
        } => {
            entries.push((
                Value::from("selected_delta_ref"),
                entity_ref_value(selected_delta_ref),
            ));
            entries.push((
                Value::from("rationale_ref"),
                entity_ref_value(rationale_ref),
            ));
        }
        MagistrateVerdict::Reject { rationale_ref }
        | MagistrateVerdict::EscalatePathology { rationale_ref } => {
            entries.push((
                Value::from("rationale_ref"),
                entity_ref_value(rationale_ref),
            ));
        }
        MagistrateVerdict::AdviceOnly {
            recommended_delta_ref,
            rationale_ref,
        } => {
            entries.push((
                Value::from("recommended_delta_ref"),
                recommended_delta_ref.map_or(Value::Nil, entity_ref_value),
            ));
            entries.push((
                Value::from("rationale_ref"),
                entity_ref_value(rationale_ref),
            ));
        }
        MagistrateVerdict::Recused { reason } => {
            entries.push((Value::from("reason"), Value::from(reason.as_str())));
        }
    }
    Value::Map(entries)
}

fn magistrate_receipt_value(receipt: &MagistrateReceipt) -> Value {
    let refs = |entries: &[EntityId]| {
        Value::Array(entries.iter().copied().map(entity_ref_value).collect())
    };
    Value::Map(vec![
        (
            Value::from("kind"),
            Value::from("consult.magistrate_receipt"),
        ),
        (
            Value::from("receipt_ref"),
            entity_ref_value(receipt.receipt_ref),
        ),
        (Value::from("task_ref"), entity_ref_value(receipt.task_ref)),
        (
            Value::from("verdict"),
            magistrate_verdict_value(receipt.verdict),
        ),
        (
            Value::from("decisive_layer"),
            Value::from(receipt.decisive_layer.as_str()),
        ),
        (
            Value::from("considered_policy_refs"),
            refs(&receipt.considered_policy_refs),
        ),
        (
            Value::from("considered_authority_refs"),
            refs(&receipt.considered_authority_refs),
        ),
        (
            Value::from("considered_temporal_refs"),
            refs(&receipt.considered_temporal_refs),
        ),
        (
            Value::from("dreamer_attempt_ref"),
            receipt
                .dreamer_attempt_ref
                .map_or(Value::Nil, |attempt| Value::from(attempt_hex(attempt))),
        ),
        (
            Value::from("appeal_handle"),
            entity_ref_value(receipt.appeal_handle),
        ),
        (Value::from("reversible"), Value::from(receipt.reversible)),
        (Value::from("occurred_at"), Value::from(receipt.occurred_at)),
    ])
}

fn magistrate_overturn_value(record: &MagistrateOverturnRecord) -> Value {
    Value::Map(vec![
        (
            Value::from("kind"),
            Value::from("consult.magistrate_overturn"),
        ),
        (
            Value::from("original_receipt_ref"),
            entity_ref_value(record.original_receipt_ref),
        ),
        (
            Value::from("overturning_verdict_ref"),
            entity_ref_value(record.overturning_verdict_ref),
        ),
        (
            Value::from("corrected_delta_ref"),
            record
                .corrected_delta_ref
                .map_or(Value::Nil, entity_ref_value),
        ),
        (
            Value::from("rationale_ref"),
            entity_ref_value(record.rationale_ref),
        ),
        (Value::from("occurred_at"), Value::from(record.occurred_at)),
    ])
}

fn magistrate_case_value(case: &MagistrateCase) -> Value {
    Value::Map(vec![
        (Value::from("task_ref"), entity_ref_value(case.task_ref)),
        (
            Value::from("contested_state_ref"),
            entity_ref_value(case.contested_state_ref),
        ),
        (
            Value::from("contested_delta_ref"),
            entity_ref_value(case.contested_delta_ref),
        ),
        (
            Value::from("criticality"),
            Value::from(match case.criticality {
                crate::consult_ladder::CaseCriticality::Normal => "normal",
                crate::consult_ladder::CaseCriticality::Critical => "critical",
            }),
        ),
        (
            Value::from("candidate_delta_refs"),
            Value::Array(
                case.candidate_delta_refs
                    .iter()
                    .copied()
                    .map(entity_ref_value)
                    .collect(),
            ),
        ),
        (Value::from("now"), Value::from(case.now)),
    ])
}

/// Canonical codec for one typed human verdict.
///
/// Override is unrepresentable without BOTH a durable delta and a durable
/// rationale — the enum says so, and the decoder refuses a map that omits
/// either rather than defaulting one.
#[must_use]
pub fn human_verdict_value(verdict: HumanVerdict) -> Value {
    let mut entries = vec![(Value::from("verdict"), Value::from(verdict.as_str()))];
    match verdict {
        HumanVerdict::Approve { rationale_ref } | HumanVerdict::Reject { rationale_ref } => {
            entries.push((
                Value::from("rationale_ref"),
                rationale_ref.map_or(Value::Nil, entity_ref_value),
            ));
        }
        HumanVerdict::OverrideWithDiff {
            delta_ref,
            rationale_ref,
        } => {
            entries.push((Value::from("delta_ref"), entity_ref_value(delta_ref)));
            entries.push((
                Value::from("rationale_ref"),
                entity_ref_value(rationale_ref),
            ));
        }
        HumanVerdict::Escalate {
            assignee,
            rationale_ref,
        } => {
            entries.push((Value::from("assignee"), task_assignee_value(assignee)));
            entries.push((
                Value::from("rationale_ref"),
                entity_ref_value(rationale_ref),
            ));
        }
    }
    Value::Map(entries)
}

/// Decodes one typed human verdict.
///
/// # Errors
///
/// [`Error::InvalidTaskBody`] for an unknown token, a missing required ref, or
/// an assignee that is not exactly ONE-1699's `TaskAssignee`.
pub fn decode_human_verdict(value: &Value) -> Result<HumanVerdict> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.verdict"))?;
    let required = |name| -> Result<EntityId> {
        decode_entity_ref(task_body_field(entries, name)?, "tasks.verdict")
    };
    let optional_rationale = || -> Result<Option<EntityId>> {
        task_body_optional(entries, "rationale_ref")?
            .map(|value| decode_entity_ref(value, "tasks.verdict"))
            .transpose()
    };
    match task_body_field(entries, "verdict")?.as_str() {
        Some("approve") => Ok(HumanVerdict::Approve {
            rationale_ref: optional_rationale()?,
        }),
        Some("reject") => Ok(HumanVerdict::Reject {
            rationale_ref: optional_rationale()?,
        }),
        Some("override_with_diff") => Ok(HumanVerdict::OverrideWithDiff {
            delta_ref: required("delta_ref")?,
            rationale_ref: required("rationale_ref")?,
        }),
        Some("escalate") => Ok(HumanVerdict::Escalate {
            assignee: decode_task_assignee(task_body_field(entries, "assignee")?)?,
            rationale_ref: required("rationale_ref")?,
        }),
        _ => Err(Error::InvalidTaskBody("tasks.verdict")),
    }
}
