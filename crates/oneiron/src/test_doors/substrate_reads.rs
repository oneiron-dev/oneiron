//! A Steward grant narrowed to one project, for the integration test of the
//! substrate reads behind a grant (untangle 6.6c; review of #6996), and the
//! rows a narrowed reader reads by the project an attempt ran in (UNBUILT-08
//! PR B): agent runs dispatched into child projects, and agent health
//! findings landed on their cards.

use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent,
};
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;
use crate::workspace_roster::ProjectRecord;

/// Stands a Steward grant on the vault's root for `holder` with `verbs`,
/// its audience narrowed to the one project `project`, as a holder override
/// row leaves a member's grant.
///
/// # Errors
///
/// The vault's.
pub fn stand_project_steward_grant(
    vault: &Vault,
    holder: EntityId,
    verbs: &[&str],
    project: EntityId,
) -> Result<EntityId> {
    vault.stand_project_steward_grant_for_test(holder, verbs, project)
}

/// Dispatches the vault's seeded default agent once at the root project,
/// then, under that root run, once into each of `count` new child projects
/// of the root. Each dispatch records the project it runs in. Returns the
/// root run's attempt, and each child project with its run's attempt.
///
/// # Errors
///
/// The vault's.
pub fn dispatch_into_child_projects(
    vault: &Vault,
    count: usize,
) -> Result<(AttemptId, Vec<(EntityId, AttemptId)>)> {
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.ok_or(Error::EntityNotFound)?.leader)?;
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or(Error::EntityNotFound)?;
    let dispatcher = AgentDispatcher::new(vault);
    let dispatch = |parent_attempt: Option<AttemptId>, spawn: AgentSpawnContext, now: u64| {
        let outcome = dispatcher.dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt,
                dedupe_key: None,
                run_id: None,
                now,
            },
            spawn,
        )?;
        match outcome {
            AgentDispatchOutcome::Dispatched(status) => Ok(status.attempt.id),
            _ => Err(Error::InvariantViolation(
                "a dispatch with no dedupe key enqueues a fresh run",
            )),
        }
    };
    let root_attempt = dispatch(None, AgentSpawnContext::default(), 2)?;
    let mut children = Vec::with_capacity(count);
    let mut now = 3;
    for _ in 0..count {
        let project = EntityId::now();
        vault.put_project(
            project,
            &ProjectRecord::new(project, Some(root), root, leader)?,
            1,
        )?;
        let attempt = dispatch(
            Some(root_attempt),
            AgentSpawnContext::default().with_project(project),
            now,
        )?;
        children.push((project, attempt));
        now += 1;
    }
    Ok((root_attempt, children))
}

/// Lands one `loop` finding on `subject`'s taskless agent health card, as a
/// review lands it: its DIAGNOSTIC first, naming `attempt` in its replay
/// coordinate, then the card it merges into. `None` lands a finding that
/// names no attempt, as a call stream that held no single live run.
///
/// # Errors
///
/// The vault's.
pub fn land_agent_health_finding(
    vault: &Vault,
    subject: EntityId,
    attempt: Option<AttemptId>,
    now: u64,
) -> Result<()> {
    vault.land_agent_health_finding_for_test(subject, attempt, now)
}
