//! Doors for `tests/settling_lineage_deleted_try.rs`: a delegation chain the
//! dispatcher spawns, ending in an attenuated fork pinned to the try whose
//! run minted it (FIX 9559), and the archive mark a cleanup run leaves on
//! that try once it completes, so the owner's archive delete door can take
//! it.

use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::error::{Error, Result};
use crate::store::attempt_archive_mark::{CleanupMark, put_in_txn, revision_of};
use crate::vault::Vault;
use crate::{EntityId, TimeRange};

/// The lease owner every try this door leases runs under.
const LEASE_OWNER: &str = "test-door";

/// A delegation chain of three agents: the delegator's run dispatched the
/// spawner, and the spawner's run minted the fork.
#[derive(Debug, Clone, Copy)]
pub struct DelegatedFork {
    /// The agent the spawner's run ran: the dispatcher's own id for it.
    pub spawner: EntityId,
    /// The try that ran the spawner, recording the delegator's try as its
    /// parent: the fork's pinned delegation parent.
    pub spawning_try: AttemptId,
    /// The attenuated fork the spawner's run minted.
    pub fork: EntityId,
}

/// Dispatches and leases `delegator`'s run, dispatches `spawner` from it and
/// leases that run, then dispatches from it a child whose source definition
/// is `Auto`, wider than the chain allows, so the dispatcher mints the
/// attenuated fork and pins it to the spawner's try (FIX 9559). The spawner
/// is dispatched as itself when its ceiling is within the delegator's, and
/// as its own fork otherwise; [`DelegatedFork::spawner`] names the agent the
/// try ran either way.
///
/// # Errors
///
/// The dispatcher's, and a run that is not dispatched or leased, or a child
/// that is not forked.
pub fn spawn_delegated_fork(
    vault: &Vault,
    delegator: EntityId,
    spawner: EntityId,
) -> Result<DelegatedFork> {
    let now = vault.now_recorded_at();
    let delegating_try = dispatch_and_lease(vault, delegator, None, now)?;
    let (spawning_try, spawner) = {
        let attempt = dispatch_and_lease(vault, spawner, Some(delegating_try), now)?;
        let dispatched = AttemptQueue::new(vault)
            .get(attempt)?
            .as_ref()
            .and_then(crate::agent_dispatch::record_dispatch_input)
            .ok_or_else(|| Error::InvalidConfig("the spawner's try does not read".into()))?
            .target
            .agent_definition_ref()?;
        (attempt, dispatched)
    };
    let source = auto_source(vault)?;
    let AgentDispatchOutcome::Dispatched(child) =
        AgentDispatcher::new(vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(source),
            parent_attempt: Some(spawning_try),
            dedupe_key: None,
            run_id: None,
            now,
        })?
    else {
        return Err(Error::InvalidConfig("the child was not dispatched".into()));
    };
    let fork = child.input.target.agent_definition_ref()?;
    if fork == source {
        return Err(Error::InvalidConfig(
            "the child was not forked for attenuation".into(),
        ));
    }
    Ok(DelegatedFork {
        spawner,
        spawning_try,
        fork,
    })
}

/// Completes the leased try `attempt` and marks it archived the way a
/// cleanup run marks a completed try past retention: bound to its row's
/// exact bytes, so the owner's archive delete door
/// (`vault.archive.attempt.delete.preview` / `.confirm`) takes it.
///
/// # Errors
///
/// A try that is not in the queue or not leased by this door, and the
/// vault's.
pub fn complete_and_archive_try(vault: &Vault, attempt: AttemptId) -> Result<()> {
    let queue = AttemptQueue::new(vault);
    let leased = queue
        .get(attempt)?
        .ok_or_else(|| Error::InvalidConfig("the try is not in the queue".into()))?;
    // Completed now or already: either way the try is Completed.
    queue.complete(CompleteAttempt {
        id: attempt,
        lease_owner: LEASE_OWNER.to_owned(),
        attempt_count: leased.attempt_count,
        now: vault.now_recorded_at(),
    })?;
    vault.with_write_txn_grouped(|txn| {
        let raw = vault
            .store
            .attempt_records
            .get(txn, attempt.as_bytes())?
            .ok_or_else(|| Error::InvalidConfig("the completed try is gone".into()))?
            .into_owned();
        put_in_txn(
            &vault.store,
            txn,
            attempt.as_bytes(),
            CleanupMark::Archived {
                revision: revision_of(&raw),
                run: AttemptId::now(),
            },
        )
    })
}

/// Dispatches `target` under `parent_attempt` and leases its run; the run's
/// try.
///
/// # Errors
///
/// The dispatcher's, and a run that is not dispatched or not leased first.
fn dispatch_and_lease(
    vault: &Vault,
    target: EntityId,
    parent_attempt: Option<AttemptId>,
    now: u64,
) -> Result<AttemptId> {
    let AgentDispatchOutcome::Dispatched(run) =
        AgentDispatcher::new(vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(target),
            parent_attempt,
            dedupe_key: None,
            run_id: None,
            now,
        })?
    else {
        return Err(Error::InvalidConfig("the run was not dispatched".into()));
    };
    // Only the run's own kind: the enrolled vault may hold jobs of others.
    let ClaimOutcome::Claimed(leased) = AttemptQueue::new(vault).claim_kind(
        &run.attempt.kind,
        ClaimAttempt {
            lease_owner: LEASE_OWNER.into(),
            now,
        },
    )?
    else {
        return Err(Error::InvalidConfig("the run was not leased".into()));
    };
    if leased.id != run.attempt.id {
        return Err(Error::InvalidConfig(
            "another attempt was leased first".into(),
        ));
    }
    Ok(leased.id)
}

/// A minimal human-authored `Auto` definition: the source a run's child is
/// dispatched from, wider than any `Proposed` chain above it.
fn auto_source(vault: &Vault) -> Result<EntityId> {
    let definition = AgentDefinition::new(
        "deleted try fork source",
        "Settling lineage fixture agent",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Auto,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("dispatch_chain_deleted_try"),
        )]),
        None,
        true,
        None,
    );
    let id = EntityId::now();
    vault.put_agent_definition(&id, &definition, TimeRange { start: 1, end: 1 }, 1)?;
    Ok(id)
}
