//! The skill a project conversation's run loads before it starts (OF-501,
//! ARCH-0067). Two runs come out of a project conversation: the house mind
//! drafting a card on a source the project question answered yes on, and a
//! minted project's leader running the goal-intake interview in its new home
//! room. Each names its job in its briefing, by reference. A briefing is a
//! lookup hint, never authority: the stored verdict or card decides, and the
//! run's own lease loads the host's configured skill, so its manifest names
//! the revision that actually loaded. Nothing here writes a prompt.
use serde::Deserialize;

use super::widen_record::invalid;
use super::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchInput, AgentDispatcher, decode_agent_dispatch_input,
    dispatch_origin_conversation,
};
use crate::attempt_queue::{AttemptQueue, AttemptRecord, AttemptState};
use crate::dreamer_runner::{DreamerAttemptPayload, decode_dreamer_attempt_payload};
use crate::skill::LoadedSkillPack;
use crate::workspace_roster::{ProjectCardState, ProjectDetectionAnswer, ProjectDetectionSource};
use crate::{EntityId, Error, Result};

/// The shipped goal-intake skill, by name; the interview's finalize door
/// requires a loaded skill of this name on the attempt's manifest.
const GOAL_INTAKE_SKILL: &str = "goal-intake";

/// Skill references are host configuration. The goal-intake interview runs
/// the installed goal-intake skill. No drafting skill ships, so a host
/// without one configured refuses a drafting run rather than run it unskilled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectConversationSkills {
    /// The skill that teaches the house mind to draft a project card.
    pub draft: Option<EntityId>,
    /// The goal-intake skill the minted project's leader interviews with.
    pub goal_intake: EntityId,
}

impl ProjectConversationSkills {
    /// The installed goal-intake skill shipped with the bootstrap set, and
    /// the host's drafting skill, if it has one.
    pub fn seeded(draft: Option<EntityId>) -> Result<Self> {
        Ok(Self {
            draft,
            goal_intake: EntityId::derive(
                crate::entity_id::derived_domains::BOOTSTRAP_SKILL,
                &[GOAL_INTAKE_SKILL.as_bytes()],
            )?,
        })
    }
}

/// A project conversation run's briefing, as its dispatcher wrote it.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProjectRunBriefing {
    ProjectProposal(DraftBriefing),
    GoalIntake(IntakeBriefing),
}

/// The drafting run's references (`dispatch_drafter`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftBriefing {
    conversation: String,
    turn: String,
    source_message: String,
    thread: Option<String>,
    principal: String,
}

/// The goal-intake run's references (`dispatch_goal_intake`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntakeBriefing {
    skill: String,
    project: String,
    home_room: String,
    card: String,
}

/// The leased run, read live.
struct LiveRun {
    attempt: AttemptRecord,
    payload: DreamerAttemptPayload,
    input: AgentDispatchInput,
}

impl AgentDispatcher<'_> {
    /// Loads the skill a project conversation's leased run works with, once,
    /// before its first turn: the drafting skill for the house mind's card
    /// draft, the goal-intake skill for the minted project's interview. The
    /// run must still hold `leased`'s lease and match the stored verdict or
    /// card its briefing names; a stale interview (the project's leader
    /// changed since its card) is refused, not loaded for the old leader.
    /// `executor` is the run's resolved `model@revision`. `None` when the run
    /// is no project conversation run.
    ///
    /// # Errors
    ///
    /// A foreign or malformed project briefing, a record it names that is
    /// missing, a skill the host has not configured or that has no SKILL.md,
    /// and the load door's own lease and admission refusals.
    pub fn prepare_project_conversation_run(
        &self,
        leased: &AttemptRecord,
        skills: &ProjectConversationSkills,
        executor: &str,
        at: u64,
    ) -> Result<Option<LoadedSkillPack>> {
        let run = self.live_project_run(leased)?;
        let briefing = self.resolve_attempt_context(run.attempt.id)?.briefing;
        let Some(briefing) = briefing.as_deref().and_then(project_briefing).transpose()? else {
            return Ok(None);
        };
        let skill = match briefing {
            ProjectRunBriefing::ProjectProposal(brief) => {
                self.check_drafting_run(&run, &brief)?;
                skills.draft.ok_or_else(|| {
                    Error::InvalidConfig("project-proposal drafting skill is not configured".into())
                })?
            }
            ProjectRunBriefing::GoalIntake(brief) => {
                self.check_goal_intake_run(&run, &brief)?;
                let record = self
                    .vault
                    .get_skill_record(&skills.goal_intake)?
                    .ok_or_else(|| {
                        Error::InvalidConfig("the configured goal-intake skill is missing".into())
                    })?;
                if record.skill_id != GOAL_INTAKE_SKILL {
                    return Err(Error::InvalidConfig(
                        "the configured goal-intake skill is another skill".into(),
                    ));
                }
                skills.goal_intake
            }
        };
        let loaded = self.vault.load_attempt_skill_pack(
            run.attempt.id,
            &skill,
            run.attempt
                .lease_owner
                .as_deref()
                .ok_or_else(|| invalid("project run has no lease"))?,
            run.attempt.attempt_count,
            executor,
            at,
        )?;
        let body = loaded
            .source_files
            .iter()
            .flatten()
            .find(|file| file.path == "SKILL.md")
            .and_then(|file| std::str::from_utf8(&file.content).ok())
            .is_some_and(|text| !text.trim().is_empty());
        if !body {
            return Err(Error::InvalidConfig(format!(
                "project run skill {} has no SKILL.md body",
                loaded.record.skill_id
            )));
        }
        Ok(Some(loaded))
    }

    /// The run as the queue holds it now, still under `leased`'s lease.
    fn live_project_run(&self, leased: &AttemptRecord) -> Result<LiveRun> {
        let txn = self.vault.store.env.read_txn()?;
        let attempt = AttemptQueue::new(self.vault)
            .get_in_txn(&txn, leased.id)?
            .ok_or(Error::EntityNotFound)?;
        if attempt.state != AttemptState::Leased
            || attempt.lease_owner.is_none()
            || attempt.lease_owner != leased.lease_owner
            || attempt.attempt_count != leased.attempt_count
        {
            return Err(invalid("project run requires its current acquired lease"));
        }
        let payload = decode_dreamer_attempt_payload(&attempt.payload)?;
        if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
            return Err(invalid("project run is not an agent dispatch"));
        }
        let input = decode_agent_dispatch_input(&payload.input)?;
        Ok(LiveRun {
            attempt,
            payload,
            input,
        })
    }

    /// The house mind drafts on the source its stored yes names, and may
    /// still read it.
    fn check_drafting_run(&self, run: &LiveRun, brief: &DraftBriefing) -> Result<()> {
        let message = canonical(&brief.source_message)?;
        let verdict = {
            let txn = self.vault.store.env.read_txn()?;
            self.vault
                .project_detection_verdict_in_txn(&txn, message)?
                .ok_or(Error::EntityNotFound)?
        };
        let drafter = run.input.target.agent_definition_ref()?;
        if verdict.answer != ProjectDetectionAnswer::Yes || verdict.house != Some(drafter) {
            return Err(invalid("this run was not dispatched to draft this card"));
        }
        let source: ProjectDetectionSource = verdict.source;
        let thread = brief.thread.as_deref().map(canonical).transpose()?;
        if source.message != message
            || source.conversation != canonical(&brief.conversation)?
            || source.turn != canonical(&brief.turn)?
            || source.author != canonical(&brief.principal)?
            || source.thread != thread
        {
            return Err(invalid("drafting brief differs from its stored source"));
        }
        let run_id = format!("project-proposal:{}", source.conversation.to_hex());
        if run.payload.parent_attempt.is_some()
            || run.attempt.run_id.as_deref() != Some(run_id.as_str())
            || dispatch_origin_conversation(&run.payload) != Some(source.conversation)
        {
            return Err(invalid("drafting run has foreign lineage"));
        }
        if self.source_text(drafter, &source)?.is_none() {
            return Err(invalid(
                "the drafting source is gone or withheld from the drafter",
            ));
        }
        Ok(())
    }

    /// The interview runs on the project the stored card minted, in its home
    /// room, on its current leader, which is still the card's.
    fn check_goal_intake_run(&self, run: &LiveRun, brief: &IntakeBriefing) -> Result<()> {
        if brief.skill != GOAL_INTAKE_SKILL {
            return Err(invalid("goal-intake brief names another skill"));
        }
        let project = canonical(&brief.project)?;
        let home_room = canonical(&brief.home_room)?;
        let run_id = format!("project:{}", project.to_hex());
        if run.input.project_ref != Some(project)
            || run.payload.parent_attempt.is_some()
            || run.attempt.run_id.as_deref() != Some(run_id.as_str())
            || dispatch_origin_conversation(&run.payload) != Some(home_room)
        {
            return Err(invalid("goal-intake run has foreign lineage"));
        }
        let txn = self.vault.store.env.read_txn()?;
        let card = self
            .vault
            .project_card_record_in_txn(&txn, &brief.card)?
            .ok_or(Error::EntityNotFound)?;
        if card.state != (ProjectCardState::Minted { project }) {
            return Err(invalid("goal-intake card did not mint this project"));
        }
        let (record, effective) = self
            .vault
            .effective_project_in_txn(&txn, project)?
            .ok_or(Error::EntityNotFound)?;
        if record.home_room != home_room.to_hex() {
            return Err(invalid("goal-intake brief names another home room"));
        }
        let leader = EntityId::from_hex(&effective.leader)?;
        if canonical(&card.card.leader_agent_def_ref)? != leader {
            return Err(invalid(
                "the project's leader changed since its card; its owner redispatches the interview",
            ));
        }
        let definition = self.dispatchable_definition_in_txn(&txn, &run.input.target)?;
        if run.input.target.agent_definition_ref()? != leader
            && definition.forked_from != Some(leader)
        {
            return Err(invalid(
                "goal-intake run does not execute the project's current leader",
            ));
        }
        Ok(())
    }
}

/// The project job a briefing names: `None` for any other briefing, an
/// error for a project briefing that is malformed or names both jobs.
fn project_briefing(text: &str) -> Option<Result<ProjectRunBriefing>> {
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(text) else {
        return None;
    };
    match (
        map.contains_key("project_proposal"),
        map.contains_key("goal_intake"),
    ) {
        (false, false) => None,
        (true, true) => Some(Err(invalid(
            "project run briefing names both drafting and goal intake",
        ))),
        _ => Some(
            serde_json::from_value(serde_json::Value::Object(map))
                .map_err(|_| invalid("project run briefing is malformed")),
        ),
    }
}

/// A briefing's hex reference, in its one canonical spelling.
fn canonical(reference: &str) -> Result<EntityId> {
    let id = EntityId::from_hex(reference)
        .map_err(|_| invalid("project run briefing names a malformed reference"))?;
    if id.to_hex() != reference {
        return Err(invalid(
            "project run briefing names a non-canonical reference",
        ));
    }
    Ok(id)
}
