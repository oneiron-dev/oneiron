//! The two grant powers (owner ruling SPAWN-KNOB = A, 10 Nov 2026, beside
//! ARCH-0053:20): `spawn` starts a child, `save_agent` authors a definition.
//! Both are ON by default. A parent may switch either off for a child it
//! spawns, only narrowing; only the owner switches one back on above the
//! parent's own.
//!
//! The ruled tests: a child spawned with `spawn` off is refused at
//! `self.spawn` with the standard refusal and a receipt; the owner switching
//! it back on works; a parent cannot switch a power on above its own grant.
//! Beside them: an agent whose `save_agent` is off authors no definition, on
//! the guest's `vault.agents.put` and on the host's direct put.
//!
//! Every call goes through the public leased host dispatcher and the real
//! dispatch, queue and lease rows.

use std::sync::Arc;

use oneiron::agent_def::{
    AgentCeiling, AgentDefinition, AgentDefinitionPutDisposition, AgentPowerTarget, AgentPowers,
    AgentScope, ChildPowerRequest,
};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::code_run::{
    HostSelfDispatcher, SelfAgentSpawnCall, SelfAgentSpawnResult, SelfCall, SelfDispatchOutcome,
    SelfDispatcher, SelfEffect, SelfReaderSpawnCall, parse_agent_put_request,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use rmpv::Value;
use serde_json::json;
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Fixture ids are `[seed; 16]`; every seed here avoids the pinned bytes a
// fresh vault already holds (`0x00 0x11 0x42 0x47 0xA1..=0xA6 0xD7 0xE1
// 0xFF`, the seeded system agents among them).

const NOW: u64 = 1_700_000_000;

const SPAWN_OFF: &str = "gate.deny.agent_power.spawn_off";
const SAVE_AGENT_OFF: &str = "gate.deny.agent_power.save_agent_off";
const ABOVE_PARENT: &str = "gate.deny.agent_power.above_parent";

const SAVE_OFF: AgentPowers = AgentPowers {
    spawn: true,
    save_agent: false,
};
const SPAWN_ONLY_OFF: AgentPowers = AgentPowers {
    spawn: false,
    save_agent: true,
};

fn definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "agent powers fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        // The codec requires a non-empty provenance map.
        Value::Map(vec![(
            Value::from("definedVia"),
            Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

struct Fixture {
    vault: Vault,
    owner: AuthenticatedOwner,
    clock: Arc<ManualClock>,
    agent: EntityId,
    /// A second owner-created agent: the definition every spawn here starts.
    worker: EntityId,
    leased: AttemptRecord,
    // Dropped after the vault.
    _dir: TempDir,
}

/// A default-policy device vault, its embedded owner, two owner-created Base
/// agents at ceiling Proposed, and the first one's root attempt, leased. The
/// owner set no power: both agents hold both.
fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let clock = ManualClock::new(NOW);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;

    let agent = EntityId::from_bytes([0x93; 16])?;
    vault.create_agent_definition_as(
        &owner,
        &agent,
        &definition("fixture.powers"),
        TimeRange {
            start: NOW,
            end: NOW,
        },
        NOW,
    )?;
    let worker = EntityId::from_bytes([0x96; 16])?;
    vault.create_agent_definition_as(
        &owner,
        &worker,
        &definition("fixture.powers.worker"),
        TimeRange {
            start: NOW,
            end: NOW,
        },
        NOW,
    )?;
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(&vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(agent),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: NOW,
        })?
    else {
        panic!("the agent dispatches without running a model")
    };
    clock.set(NOW + 1);
    let leased = claim_next(&vault, NOW + 1)?;
    assert_eq!(leased.id, status.attempt.id);
    clock.set(NOW + 2);
    assert_eq!(
        vault.agent_powers(AgentPowerTarget::Agent(agent))?,
        AgentPowers::ALL,
        "no row reads as both powers on"
    );
    Ok(Fixture {
        vault,
        owner,
        clock,
        agent,
        worker,
        leased,
        _dir: dir,
    })
}

fn claim_next(vault: &Vault, now: u64) -> TestResult<AttemptRecord> {
    let ClaimOutcome::Claimed(leased) = AttemptQueue::new(vault).claim(ClaimAttempt {
        lease_owner: "agent-powers-fixture".to_owned(),
        now,
    })?
    else {
        panic!("an attempt is ready to lease")
    };
    Ok(leased)
}

/// The leased host dispatcher of `leased`, running as `agent`.
fn host<'a>(
    f: &'a Fixture,
    agent: EntityId,
    leased: &AttemptRecord,
) -> oneiron::Result<HostSelfDispatcher<'a>> {
    HostSelfDispatcher::for_leased_agent_attempt(
        &f.vault,
        WriteActor::new(agent, EdgeActorClass::Agent),
        leased,
    )
}

/// `self.agents.spawn` of the worker agent under `key`, asking `powers`.
fn agents_spawn(f: &Fixture, key: &str, powers: Option<ChildPowerRequest>) -> SelfCall {
    SelfCall::AgentsSpawn(Box::new(SelfAgentSpawnCall {
        target: Some(AgentDispatchTarget::Custom(f.worker)),
        context: AgentSpawnContext {
            powers,
            ..AgentSpawnContext::default()
        },
        intent_key: key.to_owned(),
        ask: None,
    }))
}

/// The guest's literal `self.spawn`, as the bridge parses it: no source bound.
fn reader_spawn(key: &str) -> SelfCall {
    SelfCall::ReaderSpawn(Box::new(SelfReaderSpawnCall {
        source: "result-a".to_owned(),
        ask: "What does it say?".to_owned(),
        intent_key: key.to_owned(),
        bound: None,
        powers: None,
    }))
}

fn queued_attempt(outcome: SelfDispatchOutcome) -> AttemptId {
    match outcome {
        SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::Queued { attempt_ref, .. }) => {
            attempt_ref
        }
        other => panic!("expected a queued child, got {other:?}"),
    }
}

fn assert_denied(outcome: &SelfDispatchOutcome, effect: SelfEffect, reason: &str) {
    let SelfDispatchOutcome::Denied(denied) = outcome else {
        panic!("expected the standard Denied for {reason}, got {outcome:?}");
    };
    assert_eq!(denied.effect, effect);
    assert_eq!(denied.outcome, "deny");
    assert_eq!(denied.reason_codes, vec![reason.to_owned()]);
}

/// The vault's Gate receipts: how many, and whether one is the deny of
/// `reason` by `actor`, decided by `target`'s grant.
fn power_receipts(
    f: &Fixture,
    actor: EntityId,
    reason: &str,
    target: AgentPowerTarget,
) -> TestResult<(usize, bool)> {
    let receipts = f.vault.gate_decisions(4096)?;
    let prefix = format!(
        "agent_power:{:02x}",
        match target {
            AgentPowerTarget::Agent(_) => 0,
            AgentPowerTarget::Attempt(_) => 1,
            AgentPowerTarget::ReaderTask(_) => 2,
        }
    );
    let id_hex = match target {
        AgentPowerTarget::Agent(id) | AgentPowerTarget::ReaderTask(id) => id.to_hex(),
        AgentPowerTarget::Attempt(id) => EntityId::from_bytes(*id.as_bytes())?.to_hex(),
    };
    let found = receipts.iter().any(|receipt| {
        receipt.outcome == "deny"
            && receipt.content_kind == "agent_power"
            && receipt.actor_ref.as_deref() == Some(actor.to_hex().as_str())
            && receipt.reason_codes.iter().any(|code| code == reason)
            && receipt.grant_ref.as_deref() == Some(format!("{prefix}{id_hex}").as_str())
    });
    Ok((receipts.len(), found))
}

/// A worker child the fixture's root attempt spawns asking `powers`, then
/// leased.
fn spawned_child(f: &Fixture, key: &str, powers: ChildPowerRequest) -> TestResult<AttemptRecord> {
    let parent = host(f, f.agent, &f.leased)?;
    let child = queued_attempt(parent.dispatch(agents_spawn(f, key, Some(powers)))?);
    f.clock.set(NOW + 3);
    let leased = claim_next(&f.vault, NOW + 3)?;
    assert_eq!(
        leased.id, child,
        "the spawned child is the next attempt to lease"
    );
    f.clock.set(NOW + 4);
    Ok(leased)
}

#[test]
fn a_child_spawned_with_spawn_off_is_refused_at_self_spawn_with_a_receipt() -> TestResult {
    let f = fixture()?;
    let child = spawned_child(
        &f,
        "child-spawn-off",
        ChildPowerRequest {
            spawn: Some(false),
            save_agent: None,
        },
    )?;
    let held = AgentPowerTarget::Attempt(child.id);
    assert_eq!(
        f.vault.agent_powers(held)?,
        SPAWN_ONLY_OFF,
        "the child is born narrowed"
    );
    assert_eq!(
        f.vault.agent_powers(AgentPowerTarget::Agent(f.worker))?,
        AgentPowers::ALL,
        "the parent's narrowing of its child leaves the agent's root grant"
    );

    let child_host = host(&f, f.worker, &child)?;
    let (before, _) = power_receipts(&f, f.worker, SPAWN_OFF, held)?;
    let outcome = child_host.dispatch(reader_spawn("reader-a"))?;
    assert_denied(&outcome, SelfEffect::ReaderSpawn, SPAWN_OFF);
    let (after, found) = power_receipts(&f, f.worker, SPAWN_OFF, held)?;
    assert_eq!(after, before + 1, "the refusal commits one receipt");
    assert!(found, "the receipt names the child's grant and the reason");

    // The other spelling of the same act is refused the same way.
    let outcome = child_host.dispatch(agents_spawn(&f, "grandchild", None))?;
    assert_denied(&outcome, SelfEffect::AgentsSpawn, SPAWN_OFF);
    let (last, _) = power_receipts(&f, f.worker, SPAWN_OFF, held)?;
    assert_eq!(last, after + 1);
    Ok(())
}

#[test]
fn the_owner_switching_spawn_back_on_lets_the_child_spawn() -> TestResult {
    let f = fixture()?;
    let child = spawned_child(
        &f,
        "child-reenabled",
        ChildPowerRequest {
            spawn: Some(false),
            save_agent: None,
        },
    )?;
    let held = AgentPowerTarget::Attempt(child.id);
    let child_host = host(&f, f.worker, &child)?;
    let outcome = child_host.dispatch(agents_spawn(&f, "grandchild-off", None))?;
    assert_denied(&outcome, SelfEffect::AgentsSpawn, SPAWN_OFF);

    // Only the expected grant is replaced.
    let stale = f
        .vault
        .set_agent_powers_as(&f.owner, held, AgentPowers::ALL, AgentPowers::ALL);
    assert!(stale.is_err(), "a stale expected grant changes nothing");
    assert_eq!(
        f.vault
            .set_agent_powers_as(&f.owner, held, SPAWN_ONLY_OFF, AgentPowers::ALL)?,
        AgentPowers::ALL
    );
    assert_eq!(f.vault.agent_powers(held)?, AgentPowers::ALL);

    let grandchild =
        queued_attempt(child_host.dispatch(agents_spawn(&f, "grandchild-on", None))?);
    assert_eq!(
        f.vault
            .agent_powers(AgentPowerTarget::Attempt(grandchild))?,
        AgentPowers::ALL,
        "the grandchild is born with its re-enabled parent's grant"
    );
    Ok(())
}

#[test]
fn a_parent_cannot_switch_a_power_on_above_its_own_grant() -> TestResult {
    let f = fixture()?;
    let root = AgentPowerTarget::Agent(f.agent);
    f.vault
        .set_agent_powers_as(&f.owner, root, AgentPowers::ALL, SAVE_OFF)?;
    let parent = host(&f, f.agent, &f.leased)?;
    let (before, _) = power_receipts(&f, f.agent, ABOVE_PARENT, root)?;

    let outcome = parent.dispatch(agents_spawn(
        &f,
        "child-above",
        Some(ChildPowerRequest {
            spawn: None,
            save_agent: Some(true),
        }),
    ))?;
    assert_denied(&outcome, SelfEffect::AgentsSpawn, ABOVE_PARENT);
    let (after, found) = power_receipts(&f, f.agent, ABOVE_PARENT, root)?;
    assert_eq!(after, before + 1, "the refusal commits one receipt");
    assert!(found, "the receipt names the parent's grant and the reason");
    f.clock.set(NOW + 3);
    assert!(
        !matches!(
            AttemptQueue::new(&f.vault).claim(ClaimAttempt {
                lease_owner: "agent-powers-fixture".to_owned(),
                now: NOW + 3,
            })?,
            ClaimOutcome::Claimed(_)
        ),
        "a refused spawn queues no child"
    );

    // Asking nothing, the child inherits the parent's narrower grant.
    let child = queued_attempt(parent.dispatch(agents_spawn(&f, "child-inherits", None))?);
    assert_eq!(
        f.vault.agent_powers(AgentPowerTarget::Attempt(child))?,
        SAVE_OFF
    );
    Ok(())
}

#[test]
fn an_agent_with_save_agent_off_authors_no_definition() -> TestResult {
    let f = fixture()?;
    let root = AgentPowerTarget::Agent(f.agent);
    f.vault
        .set_agent_powers_as(&f.owner, root, AgentPowers::ALL, SAVE_OFF)?;
    let parent = host(&f, f.agent, &f.leased)?;
    let draft = json!({
        "agentId": "fixture.powers.child",
        "desc": "agent powers draft",
        "version": "1",
        "scope": {"kind": "base"},
        "ceiling": "proposed",
    });

    let guest_id = EntityId::from_bytes([0x94; 16])?;
    let call = parse_agent_put_request(&guest_id.to_hex(), draft.clone(), NOW + 2)?;
    let (before, _) = power_receipts(&f, f.agent, SAVE_AGENT_OFF, root)?;
    let outcome = parent.dispatch(SelfCall::AgentsPut(Box::new(call)))?;
    assert_denied(&outcome, SelfEffect::AgentsPut, SAVE_AGENT_OFF);
    let (after, found) = power_receipts(&f, f.agent, SAVE_AGENT_OFF, root)?;
    assert_eq!(after, before + 1, "the refusal commits one receipt");
    assert!(found);
    assert!(f.vault.get_agent_definition(&guest_id)?.is_none());

    let direct_id = EntityId::from_bytes([0x95; 16])?;
    let call = parse_agent_put_request(&direct_id.to_hex(), draft.clone(), NOW + 2)?;
    let direct =
        parent.put_agent_definition(&call.id, &call.definition, call.occurred, call.learned_at);
    assert!(direct.is_err(), "the host's direct put is refused too");
    assert!(f.vault.get_agent_definition(&direct_id)?.is_none());

    // The owner switches it back on: the same in-slice draft lands Active.
    f.vault
        .set_agent_powers_as(&f.owner, root, SAVE_OFF, AgentPowers::ALL)?;
    let call = parse_agent_put_request(&guest_id.to_hex(), draft, NOW + 2)?;
    match parent.dispatch(SelfCall::AgentsPut(Box::new(call)))? {
        SelfDispatchOutcome::AgentDefinitionPut(result) => {
            assert_eq!(result.disposition, AgentDefinitionPutDisposition::Active);
        }
        other => panic!("expected the put to land, got {other:?}"),
    }
    Ok(())
}
