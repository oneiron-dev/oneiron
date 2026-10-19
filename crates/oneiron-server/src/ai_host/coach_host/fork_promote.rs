//! The host side of the project tree fork (ARCH-0079 #task-type, OF-420):
//! the engine forks a project's team-shape skill in closed form when the
//! project's own receipts read a clear winner the vault tree does not; the
//! host lends the replay judge that scores the fork against the head on the
//! project's held-out runs. The engine puts a winning fork in force.
//!
//! A leaf a project's fork learned that holds up on runs elsewhere is offered
//! to the vault tree through the shared-skill merge. The host lends the agent
//! the Coach asks "useful upstream?" for, its useful-upstream ladder on a
//! fresh clock for each question, and the same judge for the merge's replay.
use std::time::{Duration, Instant};

use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::dreamer_runner::maintenance::fork_promote::UpstreamSeat;
use oneiron::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill_hub::{SharedSkillMergeDisposition, UsefulUpstreamDecisions};
use oneiron::skill_optimize::HeldOutReplayNotes;
use oneiron::{EntityId, Vault};

use crate::decision_host::DecisionHost;
use crate::server::SyncServer;

/// The clock one useful-upstream question runs on.
const USEFUL_UPSTREAM_BUDGET: Duration = Duration::from_secs(30);

/// One `coach.fork_promote` job.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    // No judge: no fork can be scored and no leaf replayed, so the pass forks
    // and promotes nothing.
    let judge = crate::replay_judge::registered().map(|judge| judge as &dyn HeldOutReplayNotes);
    let host = server.decision_host();
    let resident = coach_resident(vault).unwrap_or_else(|error| {
        tracing::debug!(kind = ?error.kind(), "no agent to ask useful upstream for");
        None
    });
    // With no System One seat and no house read, the question cannot be
    // asked here, so no leaf is offered.
    let seat = resident
        .filter(|_| {
            host.useful_upstream(&RetrievalDeadline::after(USEFUL_UPSTREAM_BUDGET))
                .is_ok()
        })
        .map(|resident| HostSeat { host, resident });
    let report = vault.run_coach_fork_promote(
        admitted,
        judge,
        seat.as_ref().map(|seat| seat as &dyn UpstreamSeat),
        now,
    )?;
    tracing::debug!(?report, "the Coach's project tree fork and promote pass");
    Ok(())
}

/// The agent the Coach asks "useful upstream?" for: the leader of the vault's
/// root project, whose tree a promoted leaf joins. `None` when that leader is
/// not an agent definition.
fn coach_resident(vault: &Vault) -> oneiron::Result<Option<EntityId>> {
    let Some(root) = vault.project(vault.root_project()?)? else {
        return Ok(None);
    };
    let Ok(leader) = EntityId::from_hex(&root.leader) else {
        return Ok(None);
    };
    Ok((vault.get_entity_type(&leader)? == Some(ENTITY_TYPE_AGENT_DEF)).then_some(leader))
}

/// The host's seat for the Coach's useful-upstream questions.
struct HostSeat<'a> {
    host: &'a DecisionHost,
    resident: EntityId,
}

impl UpstreamSeat for HostSeat<'_> {
    fn resident(&self) -> EntityId {
        self.resident
    }

    fn ask(
        &self,
        merge: &dyn Fn(
            &UsefulUpstreamDecisions<'_>,
        ) -> oneiron::Result<SharedSkillMergeDisposition>,
    ) -> oneiron::Result<SharedSkillMergeDisposition> {
        let deadline = RetrievalDeadline::hard(Instant::now(), USEFUL_UPSTREAM_BUDGET);
        merge(&self.host.useful_upstream(&deadline)?)
    }
}
