//! Switching an agent off shows its blast radius (owner ruling AUTHOR-OFF =
//! A, 10 Nov 2026, ARCH-0053 #author-off-no-cascade: "The switch-off and
//! narrow flow shows the blast radius: everything the agent made,
//! transitively, with what each is doing now (active runs, schedules and
//! held grants)").
//!
//! The ruled tests: an agent spawns a child and a watcher, and the owner's
//! switch-off lists both; `vault.agents.made_by.get` lists what an agent
//! made, a definition it saved and what that one made included, and leaves
//! out what another agent made; `vault.agents.pause_tree` pauses what waits
//! in one act with one receipt, a running branch listed and not paused, and
//! `vault.agents.resume_tree` restores exactly what it paused; the
//! switch-off answer offers the pause with its count.
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
    AttemptId, AttemptInterventionKind, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt,
    ClaimOutcome, InterveneAttempt,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::code_run::{
    HostSelfDispatcher, SelfAgentSpawnCall, SelfAgentSpawnResult, SelfCall, SelfDispatchOutcome,
    SelfDispatcher, parse_agent_put_request,
};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::housekeeping::HousekeepingBudget;
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
const PAUSE_TREE: &str = "vault.agents.pause_tree";
const RESUME_TREE: &str = "vault.agents.resume_tree";

/// The reason codes of a tree pause's and a resume's gate decisions.
const PAUSE_REASON: &str = "gate.allow.owner_agent_tree_pause";
const RESUME_REASON: &str = "gate.allow.owner_agent_tree_resume";

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
    watcher_due_in(f, owner_ref, title, WATCH_AHEAD)
}

/// [`watcher`], ticking `ahead` seconds from now.
fn watcher_due_in(
    f: &Fixture,
    owner_ref: Option<EntityId>,
    title: &str,
    ahead: u64,
) -> TestResult<EntityId> {
    let now = f.vault.now_recorded_at();
    let receipt = f
        .vault
        .memory(f.owner, EdgeActorClass::Human)
        .tasks_create(
            &TaskCreateSpec::new(RmpValue::from(title), None, owner_ref, Some(now))
                .with_due_at(now + ahead)
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

fn state(f: &Fixture, id: AttemptId) -> TestResult<AttemptState> {
    Ok(AttemptQueue::new(&f.vault)
        .get(id)?
        .ok_or("the branch's row reads back")?
        .state)
}

fn enabled(f: &Fixture, id: EntityId) -> TestResult<bool> {
    Ok(f.vault
        .get_agent_definition(&id)?
        .ok_or("the definition reads back")?
        .enabled)
}

/// The owner's own pause or resume of one branch, as the queue's door takes it.
fn owner_intervene(f: &Fixture, id: AttemptId, kind: AttemptInterventionKind) -> TestResult {
    AttemptQueue::new(&f.vault).intervene(InterveneAttempt {
        id,
        kind,
        actor: f.owner.to_hex(),
        note: None,
        now: f.vault.now_recorded_at(),
    })?;
    Ok(())
}

/// How many tree-pause gate decisions with `reason` the vault holds.
fn tree_receipts(f: &Fixture, reason: &str) -> TestResult<usize> {
    Ok(f.vault
        .gate_decisions(4096)?
        .iter()
        .filter(|receipt| {
            receipt.content_kind == "agent_tree_pause"
                && receipt.reason_codes.iter().any(|code| code == reason)
        })
        .count())
}

fn no_members() -> Value {
    json!({"agents": [], "branches": [], "watchers": [], "hooks": []})
}

/// The ruled test: the author spawns a child that waits and one that runs,
/// owns a watcher and saved an agent. The owner's pause_tree switches the
/// saved agent off, pauses the waiting child and holds the watcher's tick
/// in one act with one receipt; the running child is listed, not paused.
/// resume_tree restores each, and a repeat answers that resume.
#[test]
fn pause_tree_pauses_the_child_and_the_watcher_and_resume_tree_restores_them() -> TestResult {
    let f = fixture()?;
    let running = spawn_child(&f, "blast-running")?;
    claim(&f.vault, running)?;
    let child = spawn_child(&f, "blast-child")?;
    let task = watcher(&f, Some(f.agent), "watch the inbox for the author")?;
    let saved = EntityId::from_bytes([0x97; 16])?;
    save_agent(&f, saved, "fixture.blast.saved")?;

    let before = as_owner(&f, MADE_BY, json!({"agent_def_ref": f.agent}))?;
    assert_eq!(
        before["pause_offer"],
        json!({"verb": PAUSE_TREE, "pausable": 3}),
        "the saved agent, the waiting child and the watcher: {before}"
    );

    let paused = as_owner(&f, PAUSE_TREE, json!({"agent_def_ref": f.agent}))?;
    assert_eq!(paused["agent_def_ref"], id_json(f.agent), "{paused}");
    assert_eq!(paused["count"], json!(3), "{paused}");
    assert_eq!(
        paused["paused"]["agents"],
        json!([saved.to_hex()]),
        "{paused}"
    );
    assert_eq!(
        paused["paused"]["branches"],
        json!([hex(child)]),
        "{paused}"
    );
    assert_eq!(
        paused["paused"]["watchers"],
        json!([task.to_hex()]),
        "{paused}"
    );
    assert_eq!(paused["paused"]["hooks"], json!([]), "{paused}");
    assert_eq!(
        paused["running"],
        json!([hex(running)]),
        "a running branch is listed, not paused: {paused}"
    );
    assert!(paused["running_cancel_door"].as_str().is_some(), "{paused}");
    assert!(
        paused["receipt_ref"]
            .as_str()
            .is_some_and(|receipt| receipt.starts_with("gate:")),
        "{paused}"
    );
    assert_eq!(tree_receipts(&f, PAUSE_REASON)?, 1, "one receipt");
    assert_eq!(state(&f, child)?, AttemptState::Paused);
    assert_eq!(state(&f, running)?, AttemptState::Leased);
    assert!(!enabled(&f, saved)?, "the saved agent is switched off");
    let held = as_owner(&f, MADE_BY, json!({"agent_def_ref": f.agent}))?;
    assert_eq!(held["watchers"][0]["held"], json!(true), "{held}");
    assert!(held["pause_offer"].is_null(), "nothing waits: {held}");

    let pause_ref = paused["pause_ref"].clone();
    let resumed = as_owner(&f, RESUME_TREE, json!({"pause_ref": pause_ref}))?;
    assert_eq!(resumed["already_resumed"], json!(false), "{resumed}");
    assert_eq!(resumed["resumed"], paused["paused"], "{resumed}");
    assert_eq!(resumed["left_as_found"], no_members(), "{resumed}");
    assert_eq!(tree_receipts(&f, RESUME_REASON)?, 1, "one receipt");
    assert_eq!(state(&f, child)?, AttemptState::Queued);
    assert!(enabled(&f, saved)?, "the saved agent is back on");
    let restored = as_owner(&f, MADE_BY, json!({"agent_def_ref": f.agent}))?;
    assert_eq!(restored["watchers"][0]["held"], json!(false), "{restored}");
    assert_eq!(restored["pause_offer"], before["pause_offer"], "{restored}");

    let again = as_owner(&f, RESUME_TREE, json!({"pause_ref": pause_ref}))?;
    assert_eq!(again["already_resumed"], json!(true), "{again}");
    assert_eq!(again["receipt_ref"], resumed["receipt_ref"], "{again}");
    assert_eq!(
        tree_receipts(&f, RESUME_REASON)?,
        1,
        "a repeat writes nothing"
    );
    Ok(())
}

/// What was off or paused before the pause stays as it was after the
/// resume, and a member the owner moved since is left as found.
#[test]
fn resume_tree_leaves_paused_what_was_paused_before() -> TestResult {
    let f = fixture()?;
    let paused_before = spawn_child(&f, "blast-paused-before")?;
    owner_intervene(&f, paused_before, AttemptInterventionKind::Pause)?;
    let child = spawn_child(&f, "blast-child")?;
    let off_before = EntityId::from_bytes([0x98; 16])?;
    save_agent(&f, off_before, "fixture.blast.off")?;
    owner_update(&f, off_before, "1", "2", |definition| {
        definition.insert("enabled".to_owned(), json!(false));
    })?;
    let saved = EntityId::from_bytes([0x97; 16])?;
    save_agent(&f, saved, "fixture.blast.saved")?;

    let paused = as_owner(&f, PAUSE_TREE, json!({"agent_def_ref": f.agent}))?;
    assert_eq!(
        paused["paused"]["branches"],
        json!([hex(child)]),
        "{paused}"
    );
    assert_eq!(
        paused["paused"]["agents"],
        json!([saved.to_hex()]),
        "{paused}"
    );

    // The owner resumes the child by hand before the tree resume.
    owner_intervene(&f, child, AttemptInterventionKind::Resume)?;
    let resumed = as_owner(
        &f,
        RESUME_TREE,
        json!({"pause_ref": paused["pause_ref"].clone()}),
    )?;
    assert_eq!(
        resumed["resumed"]["agents"],
        json!([saved.to_hex()]),
        "{resumed}"
    );
    assert_eq!(resumed["resumed"]["branches"], json!([]), "{resumed}");
    assert_eq!(
        resumed["left_as_found"]["branches"],
        json!([hex(child)]),
        "{resumed}"
    );
    assert_eq!(state(&f, paused_before)?, AttemptState::Paused);
    assert_eq!(state(&f, child)?, AttemptState::Queued);
    assert!(!enabled(&f, off_before)?, "what was off before stays off");
    assert!(enabled(&f, saved)?);
    Ok(())
}

/// The owner's switch-off offers the pause: the verb and how many entries
/// it would pause.
#[test]
fn the_switch_off_answer_offers_pause_tree_with_the_count() -> TestResult {
    let f = fixture()?;
    spawn_child(&f, "blast-child")?;
    watcher(&f, Some(f.agent), "watch the inbox for the author")?;

    let switched_off = owner_update(&f, f.agent, "1", "2", |definition| {
        definition.insert("enabled".to_owned(), json!(false));
    })?;
    assert_eq!(
        switched_off["made_by"]["pause_offer"],
        json!({"verb": PAUSE_TREE, "pausable": 2}),
        "{switched_off}"
    );
    Ok(())
}

/// A held watcher does not tick when its due time passes; after the
/// resume it ticks once, late, and its watch TASK settles.
#[test]
fn a_held_watcher_ticks_only_after_resume_tree() -> TestResult {
    let f = fixture()?;
    let task = watcher_due_in(&f, Some(f.agent), "watch the build in a moment", 2)?;
    let paused = as_owner(&f, PAUSE_TREE, json!({"agent_def_ref": f.agent}))?;
    assert_eq!(
        paused["paused"]["watchers"],
        json!([task.to_hex()]),
        "{paused}"
    );

    std::thread::sleep(std::time::Duration::from_secs(3));
    f.vault.housekeeping(HousekeepingBudget::unbounded())?;
    let held = as_owner(&f, MADE_BY, json!({"agent_def_ref": f.agent}))?;
    assert_eq!(
        keys(&held, "watchers", "task_ref"),
        vec![&id_json(task)],
        "a held tick does not release: {held}"
    );
    assert_eq!(held["watchers"][0]["held"], json!(true), "{held}");

    as_owner(
        &f,
        RESUME_TREE,
        json!({"pause_ref": paused["pause_ref"].clone()}),
    )?;
    f.vault.housekeeping(HousekeepingBudget::unbounded())?;
    let ticked = as_owner(&f, MADE_BY, json!({"agent_def_ref": f.agent}))?;
    assert_eq!(
        ticked["watchers"],
        json!([]),
        "after the resume the tick releases, late, and settles the watch TASK: {ticked}"
    );
    Ok(())
}
