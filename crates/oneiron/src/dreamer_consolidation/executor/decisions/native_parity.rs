//! Runs the native pack oracle for the extraction parity test: one whole resolution
//! read over fixture operands through the real native stack.
//!
//! The adapter prepares the fixture attempt's wake, opens its native branch resources,
//! assembles each operand with the shared native candidate assembly and id law, verifies
//! it against the branch, and runs the pack through the native conflict wrapper and the
//! native decide. It never reads bound JSON, the checked rebuild or the bound execution:
//! the parity test compares this oracle against the bound leg built from the same vault
//! rows. It covers a single whole page only, as the fixture pins.

use super::super::super::conflict::{ConflictIdentity, ConflictSet, candidate_facts};
use super::super::super::evidence::{EvidenceLocator, ExtractedCandidate, VerifiedCandidate};
use super::super::super::provenance::PromotionCandidate;
use super::super::super::resources::BranchResources;
use super::super::super::support::invalid_consolidation;
use super::super::super::wake_plan::{AttemptPreparation, PreparedWake};
use super::super::ConsolidationExecutor;
use super::super::extraction::{
    CandidateAssemblyInput, PackRelationship, assemble_identity_candidate, claim_id_for_identity,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::claim::{ClaimSource, RelationshipScope, validate_predicate};
use crate::dreamer_consolidation::KeptDecision;
use crate::dreamer_consolidation::step_charge::StepChargeTally;
use crate::dreamer_runner::DreamerConsolidationScope;
use crate::dreamer_wake::WakePassDeadline;
use crate::entity_id::EntityId;
use crate::model_step_context::DurableStepContext;
use crate::model_step_error::DurableStepResult;
use crate::write_envelope::WriteActor;

/// Carries one fixture member as pack operands: its subject, predicate and proposed
/// value with the TURNs it cites. The adapter assembles each operand natively;
/// members spanning more than one conflict refuse, as the bound rebuild refuses them.
#[derive(Debug, Clone)]
pub(crate) struct NativeFixtureMember {
    /// Holds the candidate subject.
    pub(crate) subject: EntityId,
    /// Holds the candidate predicate in claim grammar.
    pub(crate) predicate: String,
    /// Holds the proposed value as JSON, shown to the model and never trusted.
    pub(crate) value: serde_json::Value,
    /// Holds the source TURNs the member cites.
    pub(crate) turns: Vec<EntityId>,
}

/// Carries the native oracle inputs for one whole resolution read: the fixture attempt
/// with its executor and clock, and the member operands with prior heads. Everything
/// else the read needs derives natively inside.
pub(crate) struct NativeResolutionFixture<'a> {
    /// Holds the vault the fixture attempt was admitted in.
    pub(crate) vault: &'a Vault,
    /// Holds the native executor deciding the pack, with the scripted reasoner routed.
    pub(crate) executor: &'a ConsolidationExecutor<'a>,
    /// Holds the admitted fixture attempt.
    pub(crate) attempt: AttemptId,
    /// Holds the fixture attempt's recorded run.
    pub(crate) run: Option<String>,
    /// Holds the fixture attempt's Dreamer actor.
    pub(crate) actor: WriteActor,
    /// Holds the consolidation lane the fixture attempt was admitted in.
    pub(crate) scope: DreamerConsolidationScope,
    /// Holds the fixture pass clock bounding the read.
    pub(crate) pass: &'a WakePassDeadline,
    /// Holds the fixture frozen Unix time in milliseconds.
    pub(crate) now_ms: u64,
    /// Holds the member operands in pack order.
    pub(crate) members: Vec<NativeFixtureMember>,
    /// Holds the prior heads in scope, in native id order.
    pub(crate) prior_ids: Vec<EntityId>,
}

/// Reports what the native oracle read decided: the resolution, the kept identity when
/// a merge or supersede named one, and every kept decision in pack order.
pub(crate) struct NativePackOutcome {
    /// Holds the resolution the pack read, when it read one.
    pub(crate) resolution: Option<String>,
    /// Holds the identity a merge or supersede keeps, when one was asked.
    pub(crate) identity: Option<EntityId>,
    /// Holds every kept decision in pack order.
    pub(crate) decisions: Vec<KeptDecision>,
}

/// Decides the fixture pack through the native oracle with an owned tally for the base
/// red leg. It prepares, opens, assembles, verifies and decides natively, returning the
/// outcome only. It returns none when the step trapped.
pub(crate) async fn native_resolution_snapshot_for_test(
    fixture: NativeResolutionFixture<'_>,
) -> DurableStepResult<Option<NativePackOutcome>> {
    let mut charges = StepChargeTally::default();
    native_resolution_pack_inner(fixture, &mut charges).await
}

/// Prepares the fixture wake, opens its native branch, assembles and verifies each
/// operand with the shared native assembly and id law, and decides the one conflict
/// through the native wrapper. Every input derives natively; no bound value enters.
async fn native_resolution_pack_inner(
    fixture: NativeResolutionFixture<'_>,
    charges: &mut StepChargeTally,
) -> DurableStepResult<Option<NativePackOutcome>> {
    for member in &fixture.members {
        validate_predicate(&member.predicate, false).map_err(|_| {
            invalid_consolidation("the parity fixture predicate breaks the claim grammar")
        })?;
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
    let native_scope = resources.scope();
    let mut members = Vec::with_capacity(fixture.members.len());
    let mut shared_axes: Option<(
        EntityId,
        String,
        Option<EntityId>,
        Option<EntityId>,
        RelationshipScope,
        EntityId,
        Option<Vec<u8>>,
    )> = None;
    for member in &fixture.members {
        let mut turns = member.turns.clone();
        turns.sort_unstable();
        turns.dedup();
        let project = resources.evidence_project(&turns)?.ok_or_else(|| {
            invalid_consolidation("the parity fixture turns share no one branch project")
        })?;
        let candidate = assemble_identity_candidate(&CandidateAssemblyInput {
            subject: member.subject,
            predicate: Some(member.predicate.as_str()),
            value: &member.value,
            rel: PackRelationship::Inherit,
            topic: None,
            corrects: None,
            confidence: 0.0,
            lexical_hints: Vec::new(),
            project,
            world: native_scope.world,
            facet: native_scope.facet,
            scope_relationship: native_scope.relationship.as_ref(),
        })?;
        let claim_id = claim_id_for_identity(fixture.attempt, &candidate)?;
        let facts = candidate_facts(&candidate)?;
        let axes = (
            facts.subject,
            facts.predicate,
            facts.world,
            facts.facet,
            facts.rel,
            facts.project,
            facts.topic,
        );
        match &shared_axes {
            None => shared_axes = Some(axes),
            Some(first) if first == &axes => {}
            Some(_) => {
                return Err(invalid_consolidation(
                    "the parity fixture members span more than one conflict",
                )
                .into());
            }
        }
        let at = fixture.now_ms / 1_000;
        let proposal = PromotionCandidate {
            claim_id,
            candidate,
            evidence_turn_refs: turns.clone(),
            provenance_chain: Vec::new(),
            supersedes: None,
            evidence_meet: ClaimSource::Generated,
            occurred: crate::TimeRange { start: at, end: at },
            learned_at: at,
            decisions: Vec::new(),
        };
        let mut refs = Vec::with_capacity(turns.len());
        for turn in &turns {
            let len = resources
                .pins()
                .cited_text(turn)
                .map(str::len)
                .ok_or_else(|| {
                    invalid_consolidation("the parity fixture turn has no cited text")
                })?;
            refs.push(EvidenceLocator::turn_range(*turn, 0, len)?);
        }
        let extracted = ExtractedCandidate::new(proposal, refs)?;
        members.push(VerifiedCandidate::from_extracted(&resources, extracted)?);
    }
    let Some((subject, predicate, world, facet, rel, project, topic)) = shared_axes else {
        return Err(invalid_consolidation("the parity fixture names no members").into());
    };
    let mut prior_ids = fixture.prior_ids.clone();
    prior_ids.sort_unstable();
    prior_ids.dedup();
    let mut priors = Vec::with_capacity(prior_ids.len());
    for id in &prior_ids {
        priors.push(resources.prior(*id)?.clone());
    }
    let conflict = ConflictSet {
        identity: ConflictIdentity {
            subject,
            predicate,
            world,
            facet,
            rel,
            project,
            topic,
        },
        candidate_indexes: (0..members.len()).collect(),
        prior_head: None,
        prior_heads: prior_ids,
    };
    let member_refs: Vec<&VerifiedCandidate> = members.iter().collect();
    let step_ctx = DurableStepContext {
        vault,
        attempt_id: fixture.attempt,
        run_id: fixture.run.clone(),
        envelope_actor: fixture.actor,
        subject: conflict.identity.subject,
        deadline: Some(fixture.pass),
        now_ms: fixture.now_ms,
        spend_scope: None,
        wake_pass_bound: true,
    };
    let answers = fixture
        .executor
        .decide_conflict(
            &step_ctx,
            fixture.pass,
            &conflict,
            &member_refs,
            &priors,
            &resources,
            charges,
        )
        .await?;
    Ok(answers.map(|answers| NativePackOutcome {
        resolution: answers.resolution,
        identity: answers.identity,
        decisions: answers.decisions,
    }))
}
