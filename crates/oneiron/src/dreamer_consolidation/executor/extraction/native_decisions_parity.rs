//! Runs the native decision oracle for the extraction decision parity test: one reply's corrections, assembly and conflict packs through native code.
//!
//! The adapter opens the fixture attempt's native branch resources, builds one parsed candidate per operand as the reply parser builds it, decides corrections through the real pack, builds and assembles through the real assembly, then decides each conflict in assembled order through the real skip checks and the real conflict pack. It never reads bound JSON results, the checked rebuild or the crate, and it stops before any write, merge, lander or Conflict marker.

use super::super::super::assembly::assemble_extracted;
use super::super::super::branch::BranchAxes;
use super::super::super::evidence::{EvidenceLocator, VerifiedCandidate};
use super::super::super::extraction_pack::parse_reference;
use super::super::super::judge_context::{bound_correction, fast_path};
use super::super::super::provenance::{KeptDecision, PromotionCandidate};
use super::super::super::resources::{BranchResources, ExtractionSlice};
use super::super::super::support::invalid_consolidation;
use super::super::super::wake_plan::{AttemptPreparation, PreparedWake};
use super::super::super::{ConflictSet, PriorHead};
use super::super::ConsolidationExecutor;
use super::ParsedCandidate;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::DreamerConsolidationScope;
use crate::dreamer_wake::WakePassDeadline;
use crate::entity_id::EntityId;
use crate::model_step_context::DurableStepContext;
use crate::model_step_error::DurableStepResult;
use crate::verbs::CandidateOperand;
use crate::write_envelope::WriteActor;
use crate::{Result, Vault};

/// Carries the native decision oracle inputs for one reply: the fixture attempt with its executor and clock, and the complete operand array without corrections.
pub(crate) struct NativeDecisionsFixture<'a> {
    /// Holds the vault the fixture attempt was admitted in.
    pub(crate) vault: &'a Vault,
    /// Holds the native executor deciding the packs, with the scripted reasoner routed.
    pub(crate) executor: &'a ConsolidationExecutor<'a>,
    /// Holds the admitted fixture attempt.
    pub(crate) attempt: AttemptId,
    /// Holds the fixture attempt's recorded run.
    pub(crate) run: Option<String>,
    /// Holds the fixture attempt's Dreamer actor.
    pub(crate) actor: WriteActor,
    /// Holds the consolidation lane the fixture attempt was admitted in.
    pub(crate) scope: DreamerConsolidationScope,
    /// Holds the fixture pass clock bounding the reads.
    pub(crate) pass: &'a WakePassDeadline,
    /// Holds the fixture Unix time in milliseconds for building and assembly.
    pub(crate) now_ms: u64,
    /// Holds the complete operand array in operand order, without corrections.
    pub(crate) operands: Vec<CandidateOperand>,
}

/// Carries one operand's native correction: its position with the listed head it corrects and its pack decisions.
pub(crate) struct NativeOperandCorrection {
    /// Holds the operand position in the complete array.
    pub(crate) position: usize,
    /// Holds the listed head it corrects, when it corrects one.
    pub(crate) corrects: Option<EntityId>,
    /// Holds its correction pack decisions in pack order.
    pub(crate) decisions: Vec<KeptDecision>,
}

/// Carries one assembled candidate: its assembled position with its native claim.
pub(crate) struct NativeAssembledCandidate {
    /// Holds the assembled position in ready order.
    pub(crate) position: usize,
    /// Holds the native claim.
    pub(crate) claim: EntityId,
}

/// Carries one conflict's native outcome: skipped by a no-model rule or decided by its pack.
pub(crate) enum NativeSetOutcome {
    /// Records a no-model skip with which rules hold.
    Skipped {
        /// Tells whether the single-valued fast path holds.
        fast_path: bool,
        /// Tells whether the bound correction holds.
        bound_correction: bool,
    },
    /// Records a decided pack with its resolution, kept identity and decisions.
    Decided {
        /// Holds the resolution the pack read, when it read one.
        resolution: Option<String>,
        /// Holds the identity a merge or supersede keeps, when one was asked.
        identity: Option<EntityId>,
        /// Holds every kept decision in pack order.
        decisions: Vec<KeptDecision>,
    },
}

/// Carries one conflict in assembled order with its members, heads and outcome.
pub(crate) struct NativeConflictOutcome {
    /// Holds the member claims in conflict order.
    pub(crate) members: Vec<EntityId>,
    /// Holds the prior heads in native order.
    pub(crate) prior_heads: Vec<EntityId>,
    /// Holds the single prior head, when exactly one exists.
    pub(crate) prior_head: Option<EntityId>,
    /// Holds the skipped or decided outcome.
    pub(crate) outcome: NativeSetOutcome,
}

/// Carries what the native oracle decided for one reply: every correction, assembled candidate and conflict in order.
pub(crate) struct NativeDecisionsOutcome {
    /// Holds one correction per operand in operand order.
    pub(crate) corrections: Vec<NativeOperandCorrection>,
    /// Holds the assembled candidates in ready order.
    pub(crate) assembled: Vec<NativeAssembledCandidate>,
    /// Holds every conflict in assembled order.
    pub(crate) conflicts: Vec<NativeConflictOutcome>,
}

/// Decides one reply through the native oracle onto the shared tally: correction pack, build, assembly and one pack per conflict. Returns none when a step trapped.
pub(crate) async fn native_extraction_decisions_for_test(
    fixture: NativeDecisionsFixture<'_>,
    charges: &mut crate::dreamer_consolidation::step_charge::StepChargeTally,
) -> DurableStepResult<Option<NativeDecisionsOutcome>> {
    if fixture.operands.is_empty() {
        return Err(invalid_consolidation("the parity fixture names no operands").into());
    }
    let vault = fixture.vault;
    let wake = PreparedWake::prepare_one(vault, fixture.scope, None, fixture.attempt)?;
    let plan = match wake.preparation(fixture.attempt) {
        Some(AttemptPreparation::Ready(plan)) => plan,
        Some(AttemptPreparation::Refused { reason, .. }) => {
            return Err(invalid_consolidation(reason).into());
        }
        Some(AttemptPreparation::ResidencyDeferred) | None => {
            return Err(
                invalid_consolidation("the parity fixture attempt was not prepared").into(),
            );
        }
    };
    let resources = BranchResources::open_prepared(vault, fixture.actor, plan, &wake)?;
    let axes: BranchAxes = plan.branch().axes();
    let turn_ids = plan.branch().turn_ids();
    let config = vault.consolidation_selection()?;
    let (slices, _) = resources.extraction_slices(&turn_ids, config.extraction_turns_per_child)?;
    let parsed = parse_operands(&fixture.operands, &slices, &resources)?;
    let subject = match plan.branch().subject() {
        Some(subject) => subject,
        None => {
            crate::EntityId::from_bytes(*fixture.attempt.as_bytes()).map_err(crate::Error::from)?
        }
    };
    let step_ctx = DurableStepContext {
        vault,
        attempt_id: fixture.attempt,
        run_id: fixture.run.clone(),
        envelope_actor: fixture.actor,
        subject,
        deadline: Some(fixture.pass),
        now_ms: fixture.now_ms,
        spend_scope: None,
        wake_pass_bound: true,
    };
    let Some(corrections) = fixture
        .executor
        .decide_corrections(&step_ctx, fixture.pass, &parsed, &resources, charges)
        .await?
    else {
        return Ok(None);
    };
    let (candidates, waiting) = ConsolidationExecutor::build_candidates(
        parsed,
        &corrections,
        0,
        &axes,
        &resources,
        fixture.attempt,
        fixture.now_ms,
    );
    if waiting {
        return Err(invalid_consolidation("the parity fixture correction waits on an ask").into());
    }
    let assembled = assemble_extracted(vault, &resources, candidates, fixture.now_ms)?;
    let policy = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        crate::gate::resolve_policy_manifest(&vault.store, &txn)?
    };
    let ready = assembled
        .candidates
        .iter()
        .enumerate()
        .map(|(position, candidate)| NativeAssembledCandidate {
            position,
            claim: candidate.claim_id,
        })
        .collect();
    let mut conflicts = Vec::with_capacity(assembled.conflicts.len());
    for conflict in &assembled.conflicts {
        // A trapped conflict parks without an answer; the caller fails honestly.
        let Some(outcome) =
            decide_one_conflict(&fixture, &resources, &policy, &assembled, conflict, charges)
                .await?
        else {
            return Ok(None);
        };
        conflicts.push(outcome);
    }
    let kept = corrections
        .into_iter()
        .enumerate()
        .map(|(position, correction)| NativeOperandCorrection {
            position,
            corrects: correction.corrects,
            decisions: correction.decisions,
        })
        .collect();
    Ok(Some(NativeDecisionsOutcome {
        corrections: kept,
        assembled: ready,
        conflicts,
    }))
}

/// Builds one parsed candidate per operand as the reply parser builds it for a reply naming the same candidate.
///
/// Each operand cites turns of exactly one native slice; that slice's scope and sources become the candidate's. Confidence and prospective queries ride no decision, so they stay at their neutral values. An operand that proposes a relationship is refused: no parity case carries one, and the oracle maps none.
fn parse_operands<'s>(
    operands: &[CandidateOperand],
    slices: &'s [ExtractionSlice],
    resources: &BranchResources<'_>,
) -> Result<Vec<ParsedCandidate<'s>>> {
    let mut parsed = Vec::with_capacity(operands.len());
    for operand in operands {
        if operand.value.is_null() {
            return Err(invalid_consolidation("extracted candidate names no value"));
        }
        if operand.rel.is_some() {
            return Err(invalid_consolidation(
                "the parity oracle takes no proposed relationship",
            ));
        }
        let locators = operand_locators(operand, resources)?;
        let mut evidence_turn_refs: Vec<EntityId> =
            locators.iter().map(|entry| entry.source_id()).collect();
        evidence_turn_refs.sort_unstable();
        evidence_turn_refs.dedup();
        let slice = slices
            .iter()
            .find(|slice| {
                evidence_turn_refs
                    .iter()
                    .all(|turn| slice.turns.contains(turn))
            })
            .ok_or_else(|| invalid_consolidation("extracted evidence crossed its child slice"))?;
        for id in &evidence_turn_refs {
            if !slice
                .scope
                .allows_read(&resources.pins().source_version(id)?)
            {
                return Err(invalid_consolidation(
                    "extracted evidence crossed its child slice",
                ));
            }
        }
        let project = resources
            .pins()
            .evidence_project(&evidence_turn_refs)?
            .ok_or_else(|| {
                invalid_consolidation("extracted candidate's sources share no one branch project")
            })?;
        parsed.push(ParsedCandidate {
            scope: &slice.scope,
            subject: parse_reference(&operand.subject)?,
            predicate: crate::claim::validate_predicate(&operand.predicate, false)
                .is_ok()
                .then(|| operand.predicate.clone()),
            value: operand.value.clone(),
            confidence: 0.0,
            rel: None,
            topic: operand.topic.clone(),
            locators,
            evidence_turn_refs,
            project,
            prospective_queries: Vec::new(),
            sources: slice.sources.clone(),
        });
    }
    Ok(parsed)
}

/// Builds one operand's TURN locators: the span it quotes, or the whole cited text when it quotes none.
fn operand_locators(
    operand: &CandidateOperand,
    resources: &BranchResources<'_>,
) -> Result<Vec<EvidenceLocator>> {
    if operand.evidence.is_empty() {
        return Err(invalid_consolidation(
            "extracted candidate needs TURN evidence",
        ));
    }
    let mut locators = Vec::with_capacity(operand.evidence.len());
    for cited in &operand.evidence {
        let turn = parse_reference(&cited.turn)?;
        let (start, end) = match cited.span.as_ref() {
            Some(span) => (span_offset(span.start)?, span_offset(span.end)?),
            None => {
                let len = resources
                    .pins()
                    .cited_text(&turn)
                    .map(str::len)
                    .ok_or_else(|| {
                        invalid_consolidation("the parity fixture turn has no cited text")
                    })?;
                (0, len)
            }
        };
        locators.push(EvidenceLocator::turn_range(turn, start, end)?);
    }
    Ok(locators)
}

/// Reads one span bound as a byte offset into the cited text.
fn span_offset(bound: u64) -> Result<usize> {
    usize::try_from(bound)
        .map_err(|_| invalid_consolidation("extracted evidence span is not usable"))
}

/// Decides one conflict in assembled order through the real skip checks and the real conflict pack.
///
/// This mirrors the loop head of `resolve_sets` (`executor/conflicts.rs:57-154`): members, prior, fast path, bound correction, prior heads, step context and `decide_conflict`. It stops before waiting, merged values, markers and gaps, so it changes no stored claim. Returns none when the pack trapped.
async fn decide_one_conflict(
    fixture: &NativeDecisionsFixture<'_>,
    resources: &BranchResources<'_>,
    policy: &crate::gate::PolicyManifestResolution,
    assembled: &super::super::super::assembly::AssembledCandidates,
    conflict: &ConflictSet,
    charges: &mut crate::dreamer_consolidation::step_charge::StepChargeTally,
) -> DurableStepResult<Option<NativeConflictOutcome>> {
    let members: Vec<&VerifiedCandidate> = conflict
        .candidate_indexes
        .iter()
        .map(|index| &assembled.candidates[*index])
        .collect();
    let prior: Option<&PriorHead> = conflict
        .prior_head
        .map(|id| resources.prior(id))
        .transpose()?;
    let member_data: Vec<&PromotionCandidate> =
        members.iter().map(|member| &member.proposal).collect();
    let fast = fast_path(policy, conflict, &member_data, prior);
    let bound = bound_correction(&assembled.corrections, conflict, &member_data, prior);
    let members_ids: Vec<EntityId> = members.iter().map(|member| member.claim_id).collect();
    if fast || bound {
        return Ok(Some(NativeConflictOutcome {
            members: members_ids,
            prior_heads: conflict.prior_heads.clone(),
            prior_head: conflict.prior_head,
            outcome: NativeSetOutcome::Skipped {
                fast_path: fast,
                bound_correction: bound,
            },
        }));
    }
    let prior_heads = conflict
        .prior_heads
        .iter()
        .map(|id| resources.prior(*id).cloned())
        .collect::<Result<Vec<_>>>()?;
    let step_ctx = DurableStepContext {
        vault: fixture.vault,
        attempt_id: fixture.attempt,
        run_id: fixture.run.clone(),
        envelope_actor: fixture.actor,
        subject: conflict.identity.subject,
        deadline: Some(fixture.pass),
        now_ms: fixture.now_ms,
        spend_scope: None,
        wake_pass_bound: true,
    };
    let Some(answers) = fixture
        .executor
        .decide_conflict(
            &step_ctx,
            fixture.pass,
            conflict,
            &members,
            &prior_heads,
            resources,
            charges,
        )
        .await?
    else {
        return Ok(None);
    };
    if answers.waiting() {
        return Err(invalid_consolidation("the parity fixture conflict waits on an ask").into());
    }
    Ok(Some(NativeConflictOutcome {
        members: members_ids,
        prior_heads: conflict.prior_heads.clone(),
        prior_head: conflict.prior_head,
        outcome: NativeSetOutcome::Decided {
            resolution: answers.resolution,
            identity: answers.identity,
            decisions: answers.decisions,
        },
    }))
}
