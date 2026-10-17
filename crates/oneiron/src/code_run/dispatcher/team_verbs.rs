//! `self.team.start` and `self.team.record` (OF-540): a pattern-skill run's
//! own team, bound to the running agent attempt. The team rules are
//! [`crate::team::run`]'s; this binds them to the run. Members spawn as the
//! run's children through the one code-mode spawn door, each with the team's
//! stamp, so a replayed start finds the same children.

use super::HostSelfDispatcher;
use crate::agent_dispatch::{AgentDispatchTarget, AgentSpawnContext};
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::{
    SelfAgentSpawnCall, SelfAgentSpawnResult, SelfDispatchOutcome, SelfEffect, SelfFailedResult,
};
use crate::context_projection::ContextSpec;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::team::run::{member_spawn_key, record_led_team, start_stamp};
use crate::team::{SelfTeamCall, TeamMemberAnswer, TeamRecordInput, TeamRunAnswer, TeamStartInput};

type Answered = std::result::Result<TeamRunAnswer, &'static str>;

impl HostSelfDispatcher<'_> {
    pub(super) fn dispatch_team(&self, call: SelfTeamCall) -> Result<SelfDispatchOutcome> {
        let answered = match call {
            SelfTeamCall::Start(input) => self.team_start(input)?,
            SelfTeamCall::Record(input) => self.team_record(&input)?,
        };
        Ok(match answered {
            Ok(answer) => SelfDispatchOutcome::Team(answer),
            Err(code) => SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: SelfEffect::Team,
                error: code.to_owned(),
            }),
        })
    }

    fn team_start(&self, input: TeamStartInput) -> Result<Answered> {
        let Some(leader) = self.agent_parent else {
            return Ok(Err("team_unbound"));
        };
        let stamp = match start_stamp(leader, &input) {
            Ok(stamp) => stamp,
            Err(code) => return Ok(Err(code)),
        };
        let mut members = Vec::with_capacity(input.members.len());
        for member in &input.members {
            let Ok(agent) = crate::EntityId::from_hex(&member.agent) else {
                return Ok(Err("team_start_invalid_agent"));
            };
            let mut context = AgentSpawnContext::default().with_team(stamp.clone());
            if let Some(briefing) = &member.briefing {
                context = context
                    .with_context_spec(ContextSpec::default().with_briefing(briefing.clone()));
            }
            let spawned = self.dispatch_agents_spawn(SelfAgentSpawnCall {
                target: AgentDispatchTarget::Custom(agent),
                context,
                intent_key: member_spawn_key(&input, member),
            })?;
            let (attempt_ref, proposal_ref) = match spawned {
                SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::Queued { attempt_ref }) => {
                    (Some(bytes_to_hex_lower(attempt_ref.as_bytes())), None)
                }
                SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::ProposedWiden {
                    proposal_ref,
                }) => (None, Some(proposal_ref)),
                _ => return Ok(Err("team_start_spawn_refused")),
            };
            members.push(TeamMemberAnswer {
                agent: agent.to_hex(),
                attempt_ref,
                proposal_ref,
            });
        }
        Ok(Ok(TeamRunAnswer::Started {
            team_ref: stamp.team_ref,
            pattern: stamp.pattern,
            members,
        }))
    }

    fn team_record(&self, input: &TeamRecordInput) -> Result<Answered> {
        let Some(leader) = self.agent_parent else {
            return Ok(Err("team_unbound"));
        };
        // A team's receipt is a durable record: an off-record run keeps none.
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Ok(Err("team_off_record"));
        };
        record_led_team(vault, leader, input, crate::unix_seconds_now())
    }
}
