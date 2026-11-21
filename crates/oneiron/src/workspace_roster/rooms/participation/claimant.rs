//! Who claims a room turn, and on what (OF-529).
//! Fact and admitted-result types stay in `participation`.

use super::*;

/// Who claims a room turn, and on what (OF-529).
pub(in crate::workspace_roster::rooms) struct Claimant {
    room: EntityId,
    actor: EntityId,
    branch: Option<EntityId>,
    /// `None` for a person, who claims from its seat or its own Ready join.
    agent: Option<AgentStanding>,
}

impl Claimant {
    /// A person claims from its seat, or on its own live Ready join for the
    /// turn's thread or the room (OF-417). An agent claims on a Ready receipt
    /// for the turn's thread or the room, or the seat its project gives it;
    /// it never takes a seat to claim.
    pub(in crate::workspace_roster::rooms) fn admit_in_txn(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        turn: &RoomTurn,
        actor: EntityId,
    ) -> Result<Self> {
        let branch = turn_root_in_txn(vault, txn, turn)?;
        // A private thread's turn is claimed from its audience alone (FIX
        // 2951), whatever seat or receipt the claimant holds.
        require_thread_audience_in(vault, txn, room, branch, actor)?;
        let now = vault.store.clock.now_recorded_at();
        let agent = match participant_in_txn(vault, txn, actor, now)? {
            Some(JoinSubject::Agent(agent)) => Some(
                agent_standing_in_txn(vault, txn, room, branch, agent, None)?
                    .ok_or_else(invalid)?,
            ),
            subject => {
                if !person_stands_in_txn(vault, txn, room, branch, actor, subject)? {
                    require_member(vault, txn, room, actor)?;
                }
                None
            }
        };
        Ok(Self {
            room,
            actor,
            branch,
            agent,
        })
    }

    /// Claiming a turn is speaking: see [`admit_speech_in`].
    pub(in crate::workspace_roster::rooms) fn admit_speech_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<()> {
        admit_speech_in(vault, txn, self.room, self.actor, self.agent.as_ref())
    }

    /// Whether the claimant takes part as an agent, which claims only a
    /// turn it is named on or whose thread task it holds.
    pub(in crate::workspace_roster::rooms) const fn is_agent(&self) -> bool {
        self.agent.is_some()
    }

    /// The open TASK of the claimed turn's thread this agent holds now: the
    /// task's stored assignee, re-read at every claim, so a reassigned or
    /// terminal task authorizes nothing new. No signed room rule allows an
    /// owner fallback, so the assignee alone holds it. A person holds none.
    pub(in crate::workspace_roster::rooms) fn held_task_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        turn: &RoomTurn,
    ) -> Result<Option<EntityId>> {
        if self.agent.is_none() {
            return Ok(None);
        }
        held_thread_task_in_txn(vault, txn, turn, self.actor)
    }

    /// Records the agent's participation once its claim passes: named on the
    /// turn, and holding the thread's task. A person's claim records nothing.
    pub(in crate::workspace_roster::rooms) fn record_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        turn: EntityId,
        named: bool,
        task: Option<EntityId>,
    ) -> Result<()> {
        let Some(standing) = &self.agent else {
            return Ok(());
        };
        let subject = JoinSubject::Agent(self.actor);
        let at = vault.store.clock.now_recorded_at();
        let causes = named
            .then_some(JoinCause::Addressed { turn })
            .into_iter()
            .chain(task.map(|task| JoinCause::Task { task }));
        for cause in causes {
            record_participation_in_txn(
                vault,
                txn,
                self.room,
                self.branch,
                &subject,
                &cause,
                standing.receipt(),
                at,
            )?;
        }
        Ok(())
    }
}
