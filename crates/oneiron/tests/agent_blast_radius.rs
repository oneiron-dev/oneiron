//! Switching an agent off shows its blast radius (owner ruling AUTHOR-OFF =
//! A, 10 Nov 2026, ARCH-0053 #author-off-no-cascade: "The switch-off and
//! narrow flow shows the blast radius: everything the agent made,
//! transitively, with what each is doing now (active runs, schedules and
//! held grants)").
//!
//! The ruled tests: an agent spawns a child and a watcher, and the owner's
//! switch-off lists both; `vault.agents.made_by.get` lists what an agent
//! made, a definition it saved and what that one made included, and leaves
//! out what another agent made.
//!
//! The owner's calls go through the verbs by name on the embedded owner's
//! handle, as the facade does. The agent's spawn and save go through the
//! public leased host dispatcher and the real dispatch, queue and lease rows.
//!
//! A watcher is a watch TASK the agent owns (ARCH-0080 §4). An agent at the
//! default policy parks its own create for the owner, whose approval lands
//! the TASK under the agent (OF-532); the fixture lands that row directly:
//! the owner creates it with the agent as its owner.

use std::sync::Arc;

use oneiron::agent_def::{
    AgentCeiling, AgentDefinition, AgentDefinitionPutDisposition, AgentScope,
};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
};
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::code_run::{
    HostSelfDispatcher, SelfAgentSpawnCall, SelfAgentSpawnResult, SelfCall, SelfDispatchOutcome,
    SelfDispatcher, parse_agent_put_request,
};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::TaskCreateSpec;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Fixture ids are `[seed; 16]`; every seed here avoids the pinned bytes a
// fresh vault already holds (`0x00 0x11 0x42 0x47 0xA1..=0xA6 0xD7 0xE1
// 0xFF`, the seeded system agents among them).

const GET: &str = "vault.agents.get";
const UPDATE: &str = "vault.agents.update";
const MADE_BY: &str = "vault.agents.made_by.get";

/// The lease owner this test claims rows as.
const WORKER: &str = "agent-blast-radius";

/// How far ahead of the fixture's clock each watcher ticks, seconds.
const WATCH_AHEAD: u64 = 3_600;

fn definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "blast radius fixture",
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
        RmpValue::Map(vec![(
            RmpValue::from("definedVia"),
            RmpValue::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

struct Fixture {
    vault: Vault,
    owner: EntityId,
    /// The author: an owner-made Base agent at ceiling Proposed.
    agent: EntityId,
    /// A second owner-made agent: the definition every spawn here starts.
    worker: EntityId,
    /// The author's root attempt, leased.
    leased: AttemptRecord,
    // Dropped after the vault.
    _dir: TempDir,
}

/// A process-owned device vault (the owner verbs answer the embedded owner
/// on the handle that holds the writer lease), its owner, the author and
/// the worker, and the author's root attempt, leased.
fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let now = vault.now_recorded_at();
    let agent = EntityId::from_bytes([0x93; 16])?;
    let worker = EntityId::from_bytes([0x96; 16])?;
    for (id, name) in [
        (agent, "fixture.blast.author"),
        (worker, "fixture.blast.worker"),
    ] {
        vault.create_agent_definition_as(
            &proof,
            &id,
            &definition(name),
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
    }
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(&vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(agent),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now,
        })?
    else {
        panic!("the author dispatches without running a model")
    };
    let leased = claim(&vault, status.attempt.id)?;
    Ok(Fixture {
        vault,
        owner,
        agent,
        worker,
        leased,
        _dir: dir,
    })
}

/// Leases `id` to this test's worker. Rows are claimed oldest first, so a
/// row queued before it is claimed past.
fn claim(vault: &Vault, id: AttemptId) -> TestResult<AttemptRecord> {
    let queue = AttemptQueue::new(vault);
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now: vault.now_recorded_at(),
            },
        )?
        else {
            break;
        };
        if row.id == id {
            return Ok(row);
        }
    }
    Err("the attempt is ready to claim".into())
}

fn hex(id: AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The leased host dispatcher of the author's root attempt.
fn author_host(f: &Fixture) -> oneiron::Result<HostSelfDispatcher<'_>> {
    HostSelfDispatcher::for_leased_agent_attempt(
        &f.vault,
        WriteActor::new(f.agent, EdgeActorClass::Agent),
        &f.leased,
    )
}

/// The author's `self.agents.spawn` of the worker under `key`: the queued
/// child's attempt.
fn spawn_child(f: &Fixture, key: &str) -> TestResult<AttemptId> {
    let call = SelfCall::AgentsSpawn(Box::new(SelfAgentSpawnCall {
        target: Some(AgentDispatchTarget::Custom(f.worker)),
        context: AgentSpawnContext::default(),
        intent_key: key.to_owned(),
        ask: None,
    }));
    match author_host(f)?.dispatch(call)? {
        SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::Queued { attempt_ref, .. }) => {
            Ok(attempt_ref)
        }
        other => Err(format!("expected a queued child, got {other:?}").into()),
    }
}

/// The author's `vault.agents.put` of an in-slice definition at `id`.
fn save_agent(f: &Fixture, id: EntityId, name: &str) -> TestResult {
    let draft = json!({
        "agentId": name,
        "desc": "blast radius saved agent",
        "version": "1",
        "scope": {"kind": "base"},
        "ceiling": "proposed",
    });
    let call = parse_agent_put_request(&id.to_hex(), draft, f.vault.now_recorded_at())?;
    match author_host(f)?.dispatch(SelfCall::AgentsPut(Box::new(call)))? {
        SelfDispatchOutcome::AgentDefinitionPut(result) => {
            assert_eq!(
                result.disposition,
                AgentDefinitionPutDisposition::Active,
                "FIXTURE: an in-slice definition lands Active"
            );
            Ok(())
        }
        other => Err(format!("expected the put to land, got {other:?}").into()),
    }
}

/// A watch TASK `owner_ref` owns, ticking `WATCH_AHEAD` from now; `None` is
/// the vault owner's own.
fn watcher(f: &Fixture, owner_ref: Option<EntityId>, title: &str) -> TestResult<EntityId> {
    let now = f.vault.now_recorded_at();
    let receipt = f
        .vault
        .memory(f.owner, EdgeActorClass::Human)
        .tasks_create(
            &TaskCreateSpec::new(RmpValue::from(title), None, owner_ref, Some(now))
                .with_due_at(now + WATCH_AHEAD)
                .with_watch(true),
        )?;
    receipt
        .task_ref
        .ok_or_else(|| "FIXTURE: the owner's watch TASK is minted".into())
}

fn as_owner(f: &Fixture, verb: &str, input: Value) -> Result<Value, String> {
    oneiron::task_verb::sdk::invoke(&f.vault.memory(f.owner, EdgeActorClass::Human), verb, input)
        .map_err(|error| format!("{error:?}"))
}

/// The owner's `vault.agents.update` of `agent` at `version`, with `edit`
/// applied to the stored definition and the version moved to `next`.
fn owner_update(
    f: &Fixture,
    agent: EntityId,
    version: &str,
    next: &str,
    edit: impl FnOnce(&mut serde_json::Map<String, Value>),
) -> TestResult<Value> {
    let stored = as_owner(f, GET, json!({"agent_def_ref": agent}))?;
    let mut definition = stored
        .get("definition")
        .and_then(Value::as_object)
        .ok_or("the owner reads the definition")?
        .clone();
    edit(&mut definition);
    definition.insert("version".to_owned(), json!(next));
    as_owner(
        f,
        UPDATE,
        json!({
            "agent_def_ref": agent,
            "expected_version": version,
            "definition": definition,
        }),
    )
    .map_err(Into::into)
}

fn id_json(id: EntityId) -> Value {
    json!(id.to_hex())
}

/// The rows of `list` in `made`, by the value each holds at `key`.
fn keys<'a>(made: &'a Value, list: &str, key: &str) -> Vec<&'a Value> {
    made.get(list)
        .and_then(Value::as_array)
        .map(|rows| rows.iter().filter_map(|row| row.get(key)).collect())
        .unwrap_or_default()
}

/// The ruled test: the author spawns a child and owns a watcher; the
/// owner's switch-off answers both, with who made them and what each is
/// doing. An edit that neither switches the author off nor narrows it
/// answers no blast radius.
#[test]
fn switching_an_agent_off_lists_the_child_it_spawned_and_its_watcher() -> TestResult {
    let f = fixture()?;
    let child = spawn_child(&f, "blast-child")?;
    let task = watcher(&f, Some(f.agent), "watch the inbox for the author")?;

    let edited = owner_update(&f, f.agent, "1", "2", |definition| {
        definition.insert("desc".to_owned(), json!("an edit that narrows nothing"));
    })?;
    assert!(
        edited.get("made_by").is_none(),
        "an edit that narrows nothing answers no blast radius: {edited}"
    );

    let switched_off = owner_update(&f, f.agent, "2", "3", |definition| {
        definition.insert("enabled".to_owned(), json!(false));
    })?;
    let made = switched_off
        .get("made_by")
        .ok_or_else(|| format!("the switch-off answers what the author made: {switched_off}"))?;
    assert_eq!(made["agent_def_ref"], id_json(f.agent), "{made}");
    assert_eq!(made["count"], json!(2), "a child and a watcher: {made}");
    assert_eq!(
        keys(made, "branches", "branch"),
        vec![&json!(hex(child))],
        "{made}"
    );
    let branch = &made["branches"][0];
    assert_eq!(branch["made_by"], id_json(f.agent), "{made}");
    assert_eq!(branch["agent_def_ref"], id_json(f.worker), "{made}");
    assert_eq!(branch["state"], json!("Queued"), "{made}");
    assert_eq!(
        keys(made, "watchers", "task_ref"),
        vec![&id_json(task)],
        "{made}"
    );
    assert_eq!(made["watchers"][0]["made_by"], id_json(f.agent), "{made}");
    assert!(made["watchers"][0]["due_at"].as_u64().is_some(), "{made}");
    assert_eq!(made["agents"], json!([]), "{made}");
    assert_eq!(made["hooks"], json!([]), "{made}");

    // The switch-off does not cascade: the child is still queued.
    let still = AttemptQueue::new(&f.vault)
        .get(child)?
        .ok_or("the child's row reads back")?;
    assert_eq!(still.state, AttemptState::Queued);
    Ok(())
}

/// A definition the author saved is listed with what it is doing now, and
/// what that saved agent made is listed under it.
#[test]
fn made_by_get_lists_what_its_saved_agent_made_too() -> TestResult {
    let f = fixture()?;
    let saved = EntityId::from_bytes([0x97; 16])?;
    save_agent(&f, saved, "fixture.blast.saved")?;
    let task = watcher(&f, Some(saved), "watch the calendar for the saved agent")?;

    let made = as_owner(&f, MADE_BY, json!({"agent_def_ref": f.agent}))?;
    assert_eq!(
        made["count"],
        json!(2),
        "a saved agent and its watcher: {made}"
    );
    assert_eq!(
        keys(&made, "agents", "agent_def_ref"),
        vec![&id_json(saved)],
        "{made}"
    );
    let agent = &made["agents"][0];
    assert_eq!(agent["made_by"], id_json(f.agent), "{made}");
    assert_eq!(agent["agent_id"], json!("fixture.blast.saved"), "{made}");
    assert_eq!(agent["stands"], json!(true), "{made}");
    assert_eq!(agent["runs"], json!([]), "{made}");
    assert_eq!(agent["held_grants"], json!(0), "{made}");
    assert_eq!(
        keys(&made, "watchers", "task_ref"),
        vec![&id_json(task)],
        "{made}"
    );
    assert_eq!(made["watchers"][0]["made_by"], id_json(saved), "{made}");
    assert_eq!(made["branches"], json!([]), "{made}");
    Ok(())
}

/// What another agent made, and the owner's own watcher, are not the
/// author's; the other agent's own answer lists its watcher.
#[test]
fn made_by_get_leaves_out_what_another_agent_made() -> TestResult {
    let f = fixture()?;
    let workers = watcher(&f, Some(f.worker), "watch the build for the worker")?;
    watcher(&f, None, "the owner's own reminder")?;

    let author = as_owner(&f, MADE_BY, json!({"agent_def_ref": f.agent}))?;
    assert_eq!(author["count"], json!(0), "{author}");
    for list in ["agents", "branches", "watchers", "hooks"] {
        assert_eq!(author[list], json!([]), "{list}: {author}");
    }

    let worker = as_owner(&f, MADE_BY, json!({"agent_def_ref": f.worker}))?;
    assert_eq!(worker["count"], json!(1), "{worker}");
    assert_eq!(
        keys(&worker, "watchers", "task_ref"),
        vec![&id_json(workers)],
        "{worker}"
    );
    Ok(())
}
