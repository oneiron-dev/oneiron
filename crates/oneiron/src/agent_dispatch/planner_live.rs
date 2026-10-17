//! The live spawn planner (ARCH-0079 #planner, OF-541): the one vault-backed
//! service a spawn door and the CEO's top-shapes advice share.
//!
//! For a leased parent attempt it loads the team-shape skill through the
//! ordinary lease-fenced pack door (so its revision lands on the manifest),
//! reads the task-type tree in force and the spawn type's ancestry, states
//! the launch the way dispatch will (cap, what is available, each seat
//! AGENT_DEF's calibrated spend), reads the vault's model descriptions,
//! solo's rate (the seat AGENT_DEF's own reliability on the type) and the
//! planner card's read of every admitted bound pattern skill with its payoff
//! rows' anchored outcomes per width, then runs the planner ladder. The
//! rung that answers runs its configured workflow skill, loaded through the
//! same door, and its executors ride the receipt. Planning never dispatches,
//! never mints a TASK, and confers no authority.

use std::collections::BTreeMap;

use crate::attempt_queue::{AttemptQueue, AttemptRecord, AttemptState};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::{LearningCell, LearningPredicate, LearningRead, TypeRef, read_learning};
use crate::llm::ModelId;
use crate::llm::seat::DescriptionSource;
use crate::skill::{LoadedSkillPack, skill_loadable};
use crate::task_type::{PlacementDecisions, TaskTypeRef, TypeTree};
use crate::team::{PAYOFF_AXIS, PatternSkill, PatternSkillRef, pattern_skills, planner_card};

use super::planner::{
    AvailableModel, MeasuredRate, PatternCandidate, PlanBudget, PlannerDecisions, PlannerEvidence,
    PlannerQuestionContext, PlannerRung, PlannerThresholds, ShapeQuote, SkillRevisionRef,
    SpawnPlanReceipt, plan_ranked, planned_rung, ranked_quotes,
};
use super::task_type_tree::{load_team_type_tree, place_in_tree};
use super::team_shape::{CoordinationPattern, team_shape_skill};
use super::types::{AgentDispatchTarget, SpawnNeed};
use super::widen_record::invalid;
use super::{AgentDispatcher, decode_agent_dispatch_input};

/// Host configuration: the skills the planner reads and runs. The
/// team-shape skill's content and tree are the planner's lessons and type
/// tree; each rung past the floor may run its own workflow skill, and an
/// unset rung asks the bare typed question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannerSkills {
    pub team_shape: EntityId,
    pub cheap_classifier: Option<EntityId>,
    pub small_thinking: Option<EntityId>,
    pub strong: Option<EntityId>,
}

impl PlannerSkills {
    /// The installed team-shape skill and no rung skills.
    ///
    /// # Errors
    ///
    /// Only an id derivation failure.
    pub fn seeded() -> Result<Self> {
        Ok(Self {
            team_shape: team_shape_skill()?,
            cheap_classifier: None,
            small_thinking: None,
            strong: None,
        })
    }

    /// The workflow skill one rung runs.
    #[must_use]
    pub const fn rung(&self, rung: PlannerRung) -> Option<EntityId> {
        match rung {
            PlannerRung::CheapClassifier => self.cheap_classifier,
            PlannerRung::SmallThinking => self.small_thinking,
            PlannerRung::Strong => self.strong,
        }
    }
}

/// One seat a spawn may run on: a model and the AGENT_DEF that runs on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannerSeat {
    pub model: ModelId,
    pub agent_def: EntityId,
}

/// One live planning request: the parent's spawn need (its type already
/// placed once), the seats the host serves, the planner's skills, the
/// executor the parent runs on (`model@revision`, stamped on its pack loads)
/// and the host's ladder, when it installed one.
pub struct LivePlanRequest<'a> {
    pub need: SpawnNeed,
    pub seats: &'a [PlannerSeat],
    pub skills: &'a PlannerSkills,
    pub executor: &'a str,
    pub decisions: Option<&'a PlannerDecisions<'a>>,
}

impl AgentDispatcher<'_> {
    /// Places a spawn's type once, against the tree in force for the leased
    /// parent's project: a requested stamp that tree accepts is kept,
    /// anything else is placed through the placement skill's ladder (the
    /// host's `decisions` route it past the rule rung), and unsure is the
    /// root. The planner and the dispatch then read this stamp; neither
    /// places again.
    ///
    /// # Errors
    ///
    /// A parent that is not its current lease; storage errors.
    pub fn place_spawn_type(
        &self,
        leased: &AttemptRecord,
        need: &str,
        requested: Option<&TaskTypeRef>,
        decisions: Option<&PlacementDecisions<'_>>,
    ) -> Result<TaskTypeRef> {
        let live = self.live_planner_lease(leased)?;
        let project = attempt_project(&live);
        let tree = load_team_type_tree(self.vault, project)?;
        Ok(place_in_tree(
            &tree,
            requested,
            None,
            Some(need.to_owned()),
            project,
            decisions,
        ))
    }

    /// Plans one spawn of the leased parent on the live planner: the
    /// team-shape skill loads through the lease-fenced pack door, the
    /// evidence is the vault's, and the receipt names the skill revisions
    /// and executors it read. Nothing launches.
    ///
    /// # Errors
    ///
    /// A parent that is not its current lease, an invalid need, a seat that
    /// is not dispatchable, a type the tree in force does not hold, or any
    /// planner refusal of invalid input; storage errors.
    pub fn plan_spawn_for_attempt(
        &self,
        leased: &AttemptRecord,
        request: &LivePlanRequest<'_>,
        at: u64,
    ) -> Result<SpawnPlanReceipt> {
        let live = self.live_planner_lease(leased)?;
        let team_shape = self.vault.load_leased_callable_skill_pack(
            &live,
            &request.skills.team_shape,
            request.executor,
            at,
        )?;
        Ok(self
            .plan_with_team_shape(leased, request, &team_shape, at)?
            .0)
    }

    /// The CEO's top shapes for one spawn of the leased parent: the best `n`
    /// candidates with expected payoff and cost, before anything commits.
    ///
    /// # Errors
    ///
    /// As [`Self::plan_spawn_for_attempt`].
    pub fn top_shapes_for_attempt(
        &self,
        leased: &AttemptRecord,
        request: &LivePlanRequest<'_>,
        n: usize,
        at: u64,
    ) -> Result<Vec<ShapeQuote>> {
        request.need.validate()?;
        let live = self.live_planner_lease(leased)?;
        let evidence = self.planner_evidence(&live, &request.need, request.seats, at)?;
        let mut quotes = ranked_quotes(&request.need, &evidence)?;
        quotes.truncate(n.max(1));
        Ok(quotes)
    }

    /// The live plan over an already loaded team-shape pack: the receipt,
    /// and every ranked candidate best first.
    pub(super) fn plan_with_team_shape(
        &self,
        leased: &AttemptRecord,
        request: &LivePlanRequest<'_>,
        team_shape: &LoadedSkillPack,
        at: u64,
    ) -> Result<(SpawnPlanReceipt, Vec<ShapeQuote>)> {
        request.need.validate()?;
        let live = self.live_planner_lease(leased)?;
        let evidence = self.planner_evidence(&live, &request.need, request.seats, at)?;
        let thresholds = PlannerThresholds::from_vault(self.vault)?;
        let quotes = ranked_quotes(&request.need, &evidence)?;
        let rung = planned_rung(&request.need, &quotes, thresholds);
        // The answering rung's workflow skill loads through the same door,
        // so its revision is on the manifest and its executors on the receipt.
        let rung_pack = match (request.decisions, request.skills.rung(rung)) {
            (Some(_), Some(skill)) if rung != PlannerRung::CheapClassifier => {
                let live = self.live_planner_lease(leased)?;
                Some((
                    skill,
                    self.vault.load_leased_callable_skill_pack(
                        &live,
                        &skill,
                        request.executor,
                        at,
                    )?,
                ))
            }
            _ => None,
        };
        let team_text = pack_text(team_shape);
        let rung_text = rung_pack.as_ref().map(|(_, pack)| pack_text(pack));
        let mut receipt = plan_ranked(
            &request.need,
            quotes.clone(),
            &evidence,
            thresholds,
            request.decisions,
            PlannerQuestionContext {
                team_shape: Some(team_text.as_str()),
                rung_skill: rung_text.as_deref(),
            },
        )?;
        receipt.team_shape = Some(SkillRevisionRef {
            skill: request.skills.team_shape,
            version: team_shape.record.version.clone(),
        });
        receipt.rung_skill = rung_pack.map(|(skill, pack)| SkillRevisionRef {
            skill,
            version: pack.record.version,
        });
        Ok((receipt, quotes))
    }

    /// The live row of a parent that still holds the lease it names.
    fn live_planner_lease(&self, leased: &AttemptRecord) -> Result<AttemptRecord> {
        let live = AttemptQueue::new(self.vault)
            .get(leased.id)?
            .ok_or_else(|| invalid("planner parent attempt is missing"))?;
        if live.state != AttemptState::Leased
            || live.lease_owner.is_none()
            || live.lease_owner != leased.lease_owner
            || live.attempt_count != leased.attempt_count
        {
            return Err(invalid("the planner requires the parent's current lease"));
        }
        Ok(live)
    }

    /// Everything one plan reads, from the vault.
    fn planner_evidence(
        &self,
        live: &AttemptRecord,
        need: &SpawnNeed,
        seats: &[PlannerSeat],
        at: u64,
    ) -> Result<PlannerEvidence> {
        if seats.is_empty() {
            return Err(invalid("planner has no seats"));
        }
        let project = attempt_project(live);
        let tree = load_team_type_tree(self.vault, project)?;
        tree.validate_current_ref(&need.type_ref)
            .map_err(|_| invalid("spawn type stamp is not in the tree in force"))?;
        let type_ref = TypeRef::from(&need.type_ref);
        let parents = TypeTree::from(tree).ancestors(&type_ref);

        // Cost: the launch statement dispatch freezes, per seat AGENT_DEF,
        // under the parent's scope and the spawn's budget ask.
        let budget_ask = need.budget_cap_units.as_ref().map(|over| *over.value());
        let mut models: Vec<AvailableModel> = Vec::with_capacity(seats.len());
        let mut budget = PlanBudget::UNMETERED;
        {
            let txn = self.vault.store.env.read_txn()?;
            for seat in seats {
                if models.iter().any(|model| model.model == seat.model) {
                    return Err(invalid("a planner names one seat per model"));
                }
                let launch = self.admit_launch_in_txn(
                    &txn,
                    Some(live.id),
                    None,
                    budget_ask,
                    &AgentDispatchTarget::Custom(seat.agent_def),
                    at,
                )?;
                budget = PlanBudget::from_launch(&launch.plan);
                let expected = launch
                    .plan
                    .nodes
                    .first()
                    .map(|node| node.expected)
                    .ok_or_else(|| invalid("a seat launch states no agent"))?;
                models.push(AvailableModel {
                    model: seat.model.clone(),
                    description: Vec::new(),
                    agent_def: seat.agent_def,
                    expected,
                });
            }
        }
        let order = self.vault.seat_policy()?.evidence_order;
        for model in &mut models {
            model.description = self
                .vault
                .model_description(&model.model)?
                .map(|description| {
                    description
                        .lines(&order)
                        .into_iter()
                        .map(|line| format!("{}: {}", source_token(line.source), line.text))
                        .collect()
                })
                .unwrap_or_default();
        }

        // Solo is a shape: its rate is the seat AGENT_DEF's own reliability
        // on this type, read with the ordinary backoff.
        let mut solo = BTreeMap::new();
        for model in &models {
            let cell = LearningCell::new(LearningPredicate::Reliability, model.agent_def)
                .executor(model.model.as_str())
                .type_ref(type_ref.clone())
                .axis(PAYOFF_AXIS);
            solo.insert(
                model.model.clone(),
                measured(&read_learning(self.vault, &cell, &parents)?),
            );
        }

        // Teams: every admitted bound pattern skill, read off the planner card.
        let mut patterns: Vec<PatternCandidate> = Vec::new();
        for binding in pattern_skills(self.vault)? {
            if let Some(candidate) = self.pattern_candidate(&binding)? {
                patterns.push(candidate);
            }
        }
        let skills: Vec<EntityId> = patterns
            .iter()
            .map(|candidate| candidate.skill.skill)
            .collect();
        if !skills.is_empty() {
            for model in &models {
                let card = planner_card(
                    self.vault,
                    &type_ref,
                    &parents,
                    &[model.model.as_str().to_owned()],
                    &skills,
                )?;
                for entry in &card.patterns {
                    if let Some(candidate) = patterns
                        .iter_mut()
                        .find(|candidate| candidate.skill.skill == entry.skill)
                    {
                        candidate
                            .rates
                            .insert(model.model.clone(), measured(&entry.read));
                    }
                }
                for row in &card.rows {
                    let (Some(skill), Some(width)) = (row.pattern_skill, row_width(&row.shape))
                    else {
                        continue;
                    };
                    if row.models != card.executor_mix {
                        continue;
                    }
                    if let Some(candidate) = patterns
                        .iter_mut()
                        .find(|candidate| candidate.skill.skill == skill)
                    {
                        let cell = candidate
                            .widths
                            .entry(width)
                            .or_default()
                            .entry(model.model.clone())
                            .or_insert((0, 0));
                        cell.0 = cell.0.saturating_add(row.wins);
                        cell.1 = cell.1.saturating_add(row.losses);
                    }
                }
            }
        }
        Ok(PlannerEvidence {
            models,
            solo,
            patterns,
            budget,
        })
    }

    /// A bound pattern skill the planner may run: admitted, at its revision.
    fn pattern_candidate(&self, binding: &PatternSkill) -> Result<Option<PatternCandidate>> {
        let Some(record) = self.vault.get_skill_record(&binding.skill)? else {
            return Ok(None);
        };
        if !skill_loadable(&record) {
            return Ok(None);
        }
        Ok(Some(PatternCandidate {
            skill: PatternSkillRef {
                skill: binding.skill,
                version: record.version,
            },
            pattern: CoordinationPattern::from_team(binding.pattern),
            works_well_for: binding.works_well_for.clone(),
            rates: BTreeMap::new(),
            widths: BTreeMap::new(),
        }))
    }
}

/// The project a dispatched attempt works in; `None` reads the vault tree.
fn attempt_project(live: &AttemptRecord) -> Option<EntityId> {
    let payload = crate::dreamer_runner::decode_dreamer_attempt_payload(&live.payload).ok()?;
    if payload.attempt_type != super::AGENT_DISPATCH_ATTEMPT_TYPE {
        return None;
    }
    decode_agent_dispatch_input(&payload.input)
        .ok()
        .and_then(|input| input.project_ref)
}

/// A learning read as the planner weighs it.
fn measured(read: &LearningRead) -> MeasuredRate {
    MeasuredRate {
        mean: read.estimate.mean(),
        own_runs: if read.own { read.estimate.runs } else { 0.0 },
        weight_runs: read.estimate.runs + read.estimate.prior.weight_runs,
    }
}

/// The width a payoff row's shape signature (`width|roles`) names.
fn row_width(signature: &str) -> Option<u32> {
    signature.split('|').next()?.parse().ok()
}

/// The pack's instructions as loaded: its SKILL.md, else the record's text.
fn pack_text(pack: &LoadedSkillPack) -> String {
    pack.source_files
        .as_ref()
        .and_then(|files| files.iter().find(|file| file.path == "SKILL.md"))
        .map_or_else(
            || pack.record.desc.clone(),
            |file| String::from_utf8_lossy(&file.content).into_owned(),
        )
}

const fn source_token(source: DescriptionSource) -> &'static str {
    match source {
        DescriptionSource::Owner => "owner",
        DescriptionSource::Measured => "measured",
        DescriptionSource::Benchmarks => "benchmarks",
        DescriptionSource::Vendor => "vendor",
    }
}
