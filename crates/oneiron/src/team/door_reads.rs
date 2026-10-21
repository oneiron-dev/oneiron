//! The joins behind the owner's spawn observation (DOOR-111, S6): what the
//! stores hold for one spawned agent, read by its attempt. Nothing here
//! places, plans, seats or restamps; a stamp that disagrees is reported
//! beside the one it disagrees with.
//!
//! Every row the read joins reads in one snapshot: the queue, team start,
//! team receipt, kept type tree, learning rows, seat receipts, critique
//! artifacts and the stored reviews declared for a run.

use std::collections::{BTreeMap, BTreeSet};

use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchInput, AgentDispatchTarget, SpawnPlanReceipt,
    decode_agent_dispatch_input, load_team_type_tree_in_txn, team_pattern,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ManifestKind};
use crate::critic::review::{
    DeclaredCritique, critique_review_refs_in_txn, declared_critiques_in_txn,
};
use crate::critic::{CritiqueArtifact, CritiqueArtifactStore, CritiqueVerdict};
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::error::{Error, Result};
use crate::learning::evidence::evidence_in_txn;
use crate::learning::read::read_learning_in_txn;
use crate::learning::{Anchor, LearningCell};
use crate::memory::{MemoryError, MemoryResult};
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::task_type::TypeTree;
use crate::{EntityId, Vault};

use super::doors::{
    BorrowedCellView, CriticAssociation, CriticObservation, LaunchedMember, LearningCellView,
    LearningEvidenceView, LearningObservation, ObservationIssue, PlanObservation,
    PlannedSpawnObservation, ProviderPinView, ResolvedTeam, RouteObservation, SkillRevisionView,
    TeamBindingView, TeamReceiptView, TypeStamp,
};
use super::pattern::{PAYOFF_AXIS, pattern_cell};
use super::receipt::{PatternSkillRef, TeamReceipt, placed_ancestry_in_txn, team_receipt_in_txn};
use super::run_binding::{TeamRunBinding, team_starts_in_txn};
use super::spawn_intent::{SpawnErasure, SpawnPhase};

/// One team start as read: what [`resolve_team`] holds against the plan.
struct TeamRead<'a> {
    spawn_ref: EntityId,
    record: &'a AttemptRecord,
    input: &'a AgentDispatchInput,
    stamp: &'a TypeStamp,
    binding: &'a TeamRunBinding,
    receipt: Option<&'a TeamReceipt>,
    launched: &'a [LaunchedMember],
    /// Every member the start bound launched under the team's stamp.
    whole: bool,
}

/// What the stores hold for the agent `spawn_ref` runs. The caller proved
/// the owner.
pub(super) fn observe_spawn(
    vault: &Vault,
    spawn_ref: EntityId,
) -> MemoryResult<PlannedSpawnObservation> {
    let spawn = AttemptId::from_bytes(spawn_ref.as_bytes())?;
    let hex = spawn_ref.to_hex();
    let queue = AttemptQueue::new(vault);
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let Some(record) = queue.get_in_txn(&txn, spawn)? else {
        return Err(MemoryError::not_found(format!(
            "no attempt {hex} is queued"
        )));
    };
    let Some(input) = agent_dispatch(&record)? else {
        return Err(MemoryError::bad_request_with(
            format!("attempt {hex} is not a spawned agent's"),
            &[
                "Name the root or leader attempt a spawn answered; a saved workflow's run reads through vault.workflows.status.",
            ],
        ));
    };
    // An erase of the AGENT_DEF it runs as took its text (Engine 10-22): its
    // permanent hard-delete marker, read in this snapshot.
    let target = input.target.agent_definition_ref()?;
    let erased = vault
        .store
        .port_deletion_marked(&txn, DeletionMarker::HardDelete, &target)?;
    let stamp = TypeStamp::from(&input.type_ref);
    let mut issues = Vec::new();
    let plan = input.plan.as_ref().map(plan_view);
    if let Some(plan) = &plan {
        mismatch(&mut issues, "plan", &hex, &stamp, &plan.type_ref);
    }
    // The one team this attempt started as leader. An inherited stamp is
    // not one, and several are named, never picked between.
    let mut starts = team_starts_in_txn(vault, &txn, spawn)?;
    if starts.len() > 1 {
        issues.push(ObservationIssue::SeveralTeams {
            team_refs: starts.drain(..).map(|run| run.stamp.team_ref).collect(),
        });
    } else if starts.is_empty()
        && input
            .plan
            .as_ref()
            .is_some_and(|plan| plan.plan.shape.width > 1)
    {
        issues.push(ObservationIssue::MissingBinding {
            reference: hex.clone(),
        });
    }
    let binding = starts.pop();
    let mut launched = vec![launched_member(spawn_ref, &record, &input)];
    let mut resolved = None;
    let mut receipt = None;
    if let Some(binding) = &binding {
        let whole = launch_members(&queue, &txn, binding, &stamp, &mut launched, &mut issues)?;
        receipt = team_receipt_in_txn(vault, &txn, &binding.stamp.team_ref)?;
        if let Some(receipt) = &receipt {
            let recorded = TypeStamp::from(&receipt.type_ref);
            mismatch(
                &mut issues,
                "team_receipt",
                &receipt.team_ref,
                &stamp,
                &recorded,
            );
        }
        let team = TeamRead {
            spawn_ref,
            record: &record,
            input: &input,
            stamp: &stamp,
            binding,
            receipt: receipt.as_ref(),
            launched: &launched,
            whole,
        };
        match resolve_team(vault, &txn, &team)? {
            Ok(found) => resolved = Some(found),
            Err(reason) => issues.push(unavailable("resolved", reason)),
        }
    }
    let learning = match &receipt {
        Some(receipt) => learning_reads(vault, &txn, receipt, &mut issues)?,
        None => Vec::new(),
    };
    let routes = seat_routes(vault, &txn, &launched, &mut issues)?;
    let critics = critiques(vault, &txn, &launched, &mut issues)?;
    Ok(PlannedSpawnObservation {
        spawn_ref,
        phase: if erased {
            SpawnPhase::Erased
        } else {
            SpawnPhase::Launched
        },
        erasure: erased.then_some(SpawnErasure::TargetErased),
        type_ref: stamp,
        plan,
        launched,
        resolved,
        binding: binding.as_ref().map(binding_view).transpose()?,
        receipt: receipt.as_ref().map(receipt_view),
        routes,
        critics,
        learning,
        issues,
    })
}

/// The dispatch `record` froze, when it is an agent's: `None` for a row of
/// another kind or attempt type, or a saved workflow's.
fn agent_dispatch(record: &AttemptRecord) -> Result<Option<AgentDispatchInput>> {
    if record.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return Ok(None);
    }
    let payload = decode_dreamer_attempt_payload(&record.payload)?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return Ok(None);
    }
    let input = decode_agent_dispatch_input(&payload.input)?;
    Ok(matches!(input.target, AgentDispatchTarget::Custom(_)).then_some(input))
}

/// An attempt's id as the entity id its run and its wire ref carry.
pub(super) fn entity(attempt: AttemptId) -> Result<EntityId> {
    EntityId::from_bytes(*attempt.as_bytes())
}

fn launched_member(
    attempt_ref: EntityId,
    record: &AttemptRecord,
    input: &AgentDispatchInput,
) -> LaunchedMember {
    LaunchedMember {
        attempt_ref,
        state: record.state.as_str().to_owned(),
        type_ref: TypeStamp::from(&input.type_ref),
        team_ref: input.team.as_ref().map(|team| team.team_ref.clone()),
    }
}

/// Appends each member `binding` bound that the queue holds as an agent's
/// dispatch, and reports the rest: a missing or broken row is an issue,
/// never an invented attempt, and a proposal is never a member. `true` when
/// every bound member launched under the team's stamp.
fn launch_members(
    queue: &AttemptQueue<'_>,
    txn: &heed::RoTxn<'_>,
    binding: &TeamRunBinding,
    stamp: &TypeStamp,
    launched: &mut Vec<LaunchedMember>,
    issues: &mut Vec<ObservationIssue>,
) -> Result<bool> {
    let mut whole = true;
    for member in &binding.members {
        let attempt_ref = entity(*member)?;
        let hex = attempt_ref.to_hex();
        let (row, input) = match member_dispatch(queue, txn, *member, &hex) {
            Ok(found) => found,
            Err(reason) => {
                whole = false;
                issues.push(unavailable("member", reason));
                continue;
            }
        };
        if input.team.as_ref() != Some(&binding.stamp) {
            whole = false;
            issues.push(ObservationIssue::TeamMismatch {
                member_ref: attempt_ref,
                expected: binding.stamp.team_ref.clone(),
                actual: input.team.as_ref().map(|team| team.team_ref.clone()),
            });
        }
        let observed = launched_member(attempt_ref, &row, &input);
        mismatch(issues, "member", &hex, stamp, &observed.type_ref);
        launched.push(observed);
    }
    Ok(whole)
}

/// A bound member's row and dispatch, or why it has none to report.
fn member_dispatch(
    queue: &AttemptQueue<'_>,
    txn: &heed::RoTxn<'_>,
    member: AttemptId,
    hex: &str,
) -> std::result::Result<(AttemptRecord, AgentDispatchInput), String> {
    let row = match queue.get_in_txn(txn, member) {
        Ok(Some(row)) => row,
        Ok(None) => {
            return Err(format!(
                "the team start binds member {hex}, which the queue does not hold"
            ));
        }
        Err(error) => return Err(format!("member {hex} does not read: {error}")),
    };
    match agent_dispatch(&row) {
        Ok(Some(input)) => Ok((row, input)),
        Ok(None) => Err(format!("member {hex} is not an agent's dispatch")),
        Err(error) => Err(format!("member {hex}'s dispatch does not decode: {error}")),
    }
}

/// The team the frozen plan resolved to, when the start launched exactly
/// it: the plan's pattern, its width in distinct launched attempts, every
/// stamp the dispatch's, and the selected pattern revision the one the
/// team's receipt names or, before a receipt, the one its leader loaded.
/// `Err` names what did not hold. Without a frozen plan nothing resolves;
/// the binding and receipt views stand alone.
fn resolve_team(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    team: &TeamRead<'_>,
) -> Result<std::result::Result<ResolvedTeam, String>> {
    let Some(plan) = &team.input.plan else {
        return Ok(Err(
            "the spawn froze no plan to resolve its team against".to_owned()
        ));
    };
    let shape = plan.plan.shape;
    let binding = team.binding;
    if !team.whole {
        return Ok(Err(
            "a member the team start bound is missing, broken or in another team".to_owned(),
        ));
    }
    if team_pattern(shape.pattern) != Some(binding.stamp.pattern) {
        return Ok(Err(format!(
            "the team runs {} where the plan resolved {}",
            binding.stamp.pattern.as_str(),
            shape.pattern.as_str()
        )));
    }
    let distinct: BTreeSet<EntityId> = team
        .launched
        .iter()
        .map(|member| member.attempt_ref)
        .collect();
    if u32::try_from(distinct.len()).ok() != Some(shape.width) {
        return Ok(Err(format!(
            "{} distinct agents launched where the plan resolved width {}",
            distinct.len(),
            shape.width
        )));
    }
    let planned = TypeStamp::from(&plan.asked.type_ref);
    let recorded = team
        .receipt
        .map(|receipt| TypeStamp::from(&receipt.type_ref));
    if planned != *team.stamp
        || recorded.as_ref().is_some_and(|stamp| stamp != team.stamp)
        || team
            .launched
            .iter()
            .any(|member| member.type_ref != *team.stamp)
    {
        return Ok(Err(
            "a planned, launched or recorded type stamp is not the dispatch's".to_owned(),
        ));
    }
    let Some(selected) = &plan.plan.pattern_skill else {
        return Ok(Err("the plan selected no pattern skill revision".to_owned()));
    };
    let ran = match team.receipt {
        Some(receipt) => receipt.pattern_skill.as_ref() == Some(selected),
        None => leader_loaded(vault, txn, team.record, selected)?,
    };
    if !ran {
        return Ok(Err(format!(
            "the team did not run the plan's pattern skill {} at {}",
            selected.skill.to_hex(),
            selected.version
        )));
    }
    Ok(Ok(ResolvedTeam {
        type_ref: team.stamp.clone(),
        pattern: shape.pattern.into(),
        width: shape.width,
        model: plan.plan.model.as_str().to_owned(),
        axis: team.receipt.map(|receipt| receipt.axis),
        project_ref: team.input.project_ref,
        root_attempt_ref: team.spawn_ref,
        member_attempt_refs: binding
            .members
            .iter()
            .copied()
            .map(entity)
            .collect::<Result<_>>()?,
        team_ref: Some(binding.stamp.team_ref.clone()),
    }))
}

/// Whether `leader` loaded `selected`: its pack manifest names that skill
/// at that revision.
fn leader_loaded(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    leader: &AttemptRecord,
    selected: &PatternSkillRef,
) -> Result<bool> {
    let Some(skill) = vault.get_skill_record_in_txn(txn, &selected.skill)? else {
        return Ok(false);
    };
    Ok(leader.manifest().iter().any(|entry| {
        entry.kind == ManifestKind::Skill
            && entry.reference == skill.skill_id
            && entry.version == selected.version
    }))
}

pub(super) fn plan_view(receipt: &SpawnPlanReceipt) -> PlanObservation {
    let plan = &receipt.plan;
    PlanObservation {
        type_ref: TypeStamp::from(&receipt.asked.type_ref),
        model: plan.model.as_str().to_owned(),
        width: plan.shape.width,
        pattern: plan.shape.pattern.into(),
        hard_cap_units: plan.envelope.hard_cap_units,
        expected_spend_units: plan.envelope.expected_spend_units,
        available_units: plan.envelope.available_units,
        over_budget: plan.over_budget,
        fitted_to_budget: plan.fitted_to_budget,
        why: receipt.why.clone(),
        team_shape: receipt.team_shape.as_ref().map(SkillRevisionView::from),
        pattern_skill: plan.pattern_skill.as_ref().map(SkillRevisionView::from),
        rung_skill: receipt.rung_skill.as_ref().map(SkillRevisionView::from),
        rung_providers: receipt
            .rung_providers
            .iter()
            .map(ProviderPinView::from)
            .collect(),
    }
}

fn binding_view(binding: &TeamRunBinding) -> Result<TeamBindingView> {
    Ok(TeamBindingView {
        team_ref: binding.stamp.team_ref.clone(),
        pattern: binding.stamp.pattern.into(),
        leader: entity(binding.leader)?,
        member_attempt_refs: binding
            .members
            .iter()
            .copied()
            .map(entity)
            .collect::<Result<_>>()?,
        proposal_refs: binding.proposals.clone(),
        root_task: binding.root_task.clone(),
        started_at: binding.started_at,
    })
}

fn receipt_view(receipt: &TeamReceipt) -> TeamReceiptView {
    TeamReceiptView {
        team_ref: receipt.team_ref.clone(),
        type_ref: TypeStamp::from(&receipt.type_ref),
        pattern: receipt.pattern.into(),
        pattern_skill: receipt.pattern_skill.as_ref().map(SkillRevisionView::from),
        axis: receipt.axis,
        width: receipt.shape.width,
        models: receipt.models.clone(),
        outcome_receipt: receipt
            .outcome
            .as_ref()
            .map(|outcome| outcome.receipt.clone()),
    }
}

/// The reliability read of `receipt`'s pattern skill cell, the cell its
/// settled outcome feeds; none when the receipt names no pattern skill. The
/// read backs off through the tree the receipt was placed in, the chain
/// settlement takes its parents from; a tree no longer kept, or one that
/// does not read, is an issue, and the read then borrows through the tree
/// in force, as settlement does (FIX 5253).
fn learning_reads(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &TeamReceipt,
    issues: &mut Vec<ObservationIssue>,
) -> Result<Vec<LearningObservation>> {
    let Some(skill) = &receipt.pattern_skill else {
        return Ok(Vec::new());
    };
    let executor = receipt.executor_mix();
    let cell = pattern_cell(skill.skill, &executor, &receipt.type_ref);
    let parents = match placed_ancestry_in_txn(vault, txn, receipt) {
        (parents, None) => parents,
        (_, Some(reason)) => match load_team_type_tree_in_txn(vault, txn, receipt.project) {
            Ok(tree) => {
                issues.push(unavailable(
                    "learning",
                    format!("{reason}: the read borrowed through the task-type tree in force"),
                ));
                TypeTree::from(tree).ancestors(&receipt.type_ref)
            }
            Err(error) => {
                issues.push(unavailable(
                    "learning",
                    format!(
                        "{reason}, and the task-type tree in force does not read: {error}: \
                         the read borrowed from no parent type"
                    ),
                ));
                Vec::new()
            }
        },
    };
    let read = read_learning_in_txn(vault, txn, &cell, &parents)?;
    let estimate = &read.estimate;
    let evidence = evidence_in_txn(vault, txn, &cell.digest())?
        .into_iter()
        .map(|(receipt_ref, row)| LearningEvidenceView {
            receipt_ref,
            at: row.at,
            anchor_kind: anchor_kind(row.anchor).to_owned(),
            weight: row.weight,
        })
        .collect();
    Ok(vec![LearningObservation {
        cell: LearningCellView {
            predicate: cell.predicate.as_str().to_owned(),
            subject: cell.subject,
            executor,
            type_ref: TypeStamp::from(&receipt.type_ref),
            axis: PAYOFF_AXIS.to_owned(),
        },
        mean: estimate.mean(),
        own: read.own,
        own_runs: if read.own { estimate.runs } else { 0.0 },
        prior_origin: estimate.prior.origin.as_str().to_owned(),
        prior_weight_runs: estimate.prior.weight_runs,
        borrowed_from: read.borrowed_from.as_ref().map(borrowed_view),
        untested: estimate.untested(),
        window_half_life_secs: estimate.window.half_life,
        estimator_version: estimate.ver,
        evidence,
    }])
}

fn borrowed_view(cell: &LearningCell) -> BorrowedCellView {
    BorrowedCellView {
        predicate: cell.predicate.as_str().to_owned(),
        subject: cell.subject,
        executor: cell.executor.clone(),
        type_ref: cell.type_ref.as_ref().map(TypeStamp::from),
        axis: cell.axis.clone(),
    }
}

const fn anchor_kind(anchor: Anchor) -> &'static str {
    match anchor {
        Anchor::HeldOut => "held_out",
        Anchor::OwnerVerdict => "owner_verdict",
        Anchor::WorldOutcome => "world_outcome",
        Anchor::Audit { .. } => "audit",
        Anchor::Retest => "retest",
        Anchor::FittingCheck => "fitting_check",
    }
}

/// Each launched run's agent-run seat receipt and the stamp the seat was
/// born under (S5), held against the run's dispatch stamp. A run not seated
/// yet is an issue, never a template's model.
fn seat_routes(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    launched: &[LaunchedMember],
    issues: &mut Vec<ObservationIssue>,
) -> Result<Vec<RouteObservation>> {
    let mut routes = Vec::new();
    for member in launched {
        let hex = member.attempt_ref.to_hex();
        let Some(seat) = vault.task_model_seat_receipt_in_txn(txn, member.attempt_ref)? else {
            let reason = format!("run {hex} is not seated: not started, or no model manifest");
            issues.push(unavailable("route", reason));
            continue;
        };
        let type_ref = TypeStamp::from(&seat.type_ref);
        mismatch(issues, "route", &hex, &member.type_ref, &type_ref);
        let receipt = seat.receipt;
        routes.push(RouteObservation {
            run_ref: member.attempt_ref,
            type_ref,
            model: receipt.model.as_str().to_owned(),
            effort: receipt.effort,
            why: receipt.why,
            reused: receipt.reused,
        });
    }
    Ok(routes)
}

/// The critiques found for each launched run: those keyed under its own
/// attempt, those of a review whose run reference is the run's canonical id
/// (`vault.critic.review` keys a review's branch by its run reference's
/// hash), and those of a review its caller declared for the run (FIX 5252).
/// Each is listed once, beside the verdict claim of the review that holds
/// it however it was found: the declared review's, else the stored review's
/// (FIX 6380). A review under a run reference the caller chose, declared for
/// no run, is not found from an attempt, so the list is not exhaustive. A
/// critique or stored review that does not read is an issue on the read, and
/// every other one is still listed (FIX 4468, 4470).
fn critiques(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    launched: &[LaunchedMember],
    issues: &mut Vec<ObservationIssue>,
) -> Result<Vec<CriticObservation>> {
    let store = CritiqueArtifactStore::new(vault);
    let mut declared = declared_critiques(vault, txn, launched, issues);
    let reviewed = critique_reviews(vault, txn, issues);
    // Each critique's listed index, `None` once it was passed over.
    let mut seen: BTreeMap<([u8; 16], String), Option<usize>> = BTreeMap::new();
    let mut critics: Vec<CriticObservation> = Vec::new();
    for member in launched {
        let run = member.attempt_ref.to_hex();
        let named_branch = blake3::hash(run.as_bytes());
        let (direct, direct_unread) = store
            .observe_branch_in_txn(txn, AttemptId::from_bytes(member.attempt_ref.as_bytes())?)?;
        let (named, named_unread) = store
            .observe_branch_in_txn(txn, AttemptId::from_bytes(&named_branch.as_bytes()[..16])?)?;
        for reason in direct_unread.into_iter().chain(named_unread) {
            issues.push(unavailable("critic", format!("run {run}: {reason}")));
        }
        let found = direct
            .into_iter()
            .map(|artifact| (CriticAssociation::BranchAttempt, None, artifact))
            .chain(
                named
                    .into_iter()
                    .filter(|artifact| artifact.run_id == run)
                    .map(|artifact| (CriticAssociation::CanonicalRunRef, None, artifact)),
            )
            .chain(
                declared
                    .remove(&member.attempt_ref)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|critique| {
                        (
                            CriticAssociation::DeclaredSpawnAttempt,
                            critique.verdict_ref,
                            critique.artifact,
                        )
                    }),
            );
        for (association, declared_ref, artifact) in found {
            let key = (
                *artifact.branch_attempt.as_bytes(),
                artifact.artifact_id.clone(),
            );
            let verdict_ref = declared_ref.or_else(|| reviewed.get(&key).copied());
            if let Some(listed) = seen.get(&key) {
                // Listed under its first association; a later declared one
                // still names the review the caller declared for the run.
                if let Some(critic) = listed.and_then(|at| critics.get_mut(at))
                    && (declared_ref.is_some() || critic.review_verdict_ref.is_none())
                {
                    critic.review_verdict_ref = verdict_ref;
                }
                continue;
            }
            let critic = critic_view(&artifact, association, verdict_ref, member, issues)?;
            seen.insert(key, critic.as_ref().map(|_| critics.len()));
            critics.extend(critic);
        }
    }
    Ok(critics)
}

/// The verdict claim of the stored review holding each critique (FIX 6380),
/// from one pass over the stored reviews. A verdict ref that does not read
/// is an issue, and so is a pass that fails: the critiques are listed
/// still, naming no review.
fn critique_reviews(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    issues: &mut Vec<ObservationIssue>,
) -> BTreeMap<([u8; 16], String), EntityId> {
    match critique_review_refs_in_txn(vault, txn) {
        Ok((refs, unread)) => {
            for reason in unread {
                issues.push(unavailable("critic", reason));
            }
            refs
        }
        Err(error) => {
            let reason = format!("the reviews holding a critique did not read: {error}");
            issues.push(unavailable("critic", reason));
            BTreeMap::new()
        }
    }
}

/// The critiques of every stored review declared for a launched run, by run,
/// from one pass over the stored reviews. A review or critique that does not
/// read is an issue, and so is a pass that fails: a declared association
/// never fails the read.
fn declared_critiques(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    launched: &[LaunchedMember],
    issues: &mut Vec<ObservationIssue>,
) -> BTreeMap<EntityId, Vec<DeclaredCritique>> {
    let runs: BTreeSet<EntityId> = launched.iter().map(|member| member.attempt_ref).collect();
    match declared_critiques_in_txn(vault, txn, &runs) {
        Ok((declared, unread)) => {
            for reason in unread {
                issues.push(unavailable("critic", reason));
            }
            declared
        }
        Err(error) => {
            let reason = format!("the reviews declared for a launched run did not read: {error}");
            issues.push(unavailable("critic", reason));
            BTreeMap::new()
        }
    }
}

/// One critique as stored, its calibration stamp held against the dispatch
/// stamp of `member`, the run it was found for, beside the verdict claim of
/// the review that holds it, if one reads. The artifact store refuses a
/// calibration missing its executor, stamp or axis, so one missing them is an
/// issue, not a default.
fn critic_view(
    artifact: &CritiqueArtifact,
    association: CriticAssociation,
    verdict_ref: Option<EntityId>,
    member: &LaunchedMember,
    issues: &mut Vec<ObservationIssue>,
) -> Result<Option<CriticObservation>> {
    let calibration = &artifact.calibration;
    let (Some(type_ref), Some(executor), Some(axis)) = (
        &calibration.type_ref,
        &calibration.executor,
        &calibration.axis,
    ) else {
        let id = &artifact.artifact_id;
        issues.push(unavailable(
            "critic",
            format!("critique {id} keeps no whole calibration stamp"),
        ));
        return Ok(None);
    };
    let type_ref = TypeStamp::from(type_ref);
    let expected = &member.type_ref;
    mismatch(issues, "critic", &artifact.artifact_id, expected, &type_ref);
    Ok(Some(CriticObservation {
        run_ref: artifact.run_id.clone(),
        branch_attempt_ref: entity(artifact.branch_attempt)?,
        association,
        declared_attempt_ref: (association == CriticAssociation::DeclaredSpawnAttempt)
            .then_some(member.attempt_ref),
        review_verdict_ref: verdict_ref,
        artifact_id: artifact.artifact_id.clone(),
        target_ref: artifact.candidate_ref.clone(),
        type_ref,
        lens_ref: calibration.subject,
        lens_id: artifact.lens_id.clone(),
        executor: executor.clone(),
        axis: axis.clone(),
        verdict: verdict_word(artifact.verdict).to_owned(),
    }))
}

const fn verdict_word(verdict: CritiqueVerdict) -> &'static str {
    match verdict {
        CritiqueVerdict::Accept => "accept",
        CritiqueVerdict::Revise => "revise",
        CritiqueVerdict::Discard => "discard",
    }
}

/// Reports `consumer`'s stamp when it is not the dispatch's, both as stored.
fn mismatch(
    issues: &mut Vec<ObservationIssue>,
    consumer: &str,
    reference: &str,
    expected: &TypeStamp,
    actual: &TypeStamp,
) {
    if actual != expected {
        issues.push(ObservationIssue::StampMismatch {
            consumer: consumer.to_owned(),
            reference: reference.to_owned(),
            expected: expected.clone(),
            actual: actual.clone(),
        });
    }
}

fn unavailable(consumer: &str, reason: String) -> ObservationIssue {
    ObservationIssue::Unavailable {
        consumer: consumer.to_owned(),
        reason,
    }
}
