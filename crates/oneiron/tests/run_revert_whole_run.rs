//! ARCH-0040 #revert-run (line 318, REV-2; PLAN L7-32): one action takes
//! back a whole run, its children included. The acceptance test undoes one
//! full run across claims, edges, notes and topology. A root agent run with
//! no `run_id` runs under `agent:<root hex>`; a child it spawns now joins that
//! run (`run_id` = the root's run reference), so the root's undo-all reaches
//! the child's changes too. The root's wait on that child still counts it as
//! its own.
//!
//! The owner's run calls the note and cluster verbs through its host's verb
//! door, which serves each call on the owner's memory bound to the run's own
//! write origin, as a host's door does. The agent runs are the seeded default
//! agent, dispatched as a root with no `run_id`; the root spawns its child
//! through its own `self.agents.spawn`.
//!
//! Red on main: the whole-run test lists only the run's claim and merge (no
//! edge or note writer joins a run's journal there), and the edge and the
//! note stay live after the revert. Red on the base (runchanges-6-edges):
//! the child's claim journals under `agent:<child hex>`, so the root lists
//! nothing and its revert answers not_found. The wait test is a guard: green
//! on main, on the base and on the head.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test run_revert_whole_run`
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use std::sync::Arc;

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    AgentWaitSetResult, DEFAULT_BASE_LOGICAL_ID, DispatchAgent, agent_dispatch_actor,
};
use oneiron::attempt_queue::{ClaimAttempt, ClaimOutcome};
use oneiron::authority::MachineRole;
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, HostSelfDispatcher, RunCall,
    RunSpeechDestination, SelfAgentSpawnCall, SelfAgentSpawnResult, SelfAgentVerbCall, SelfCall,
    SelfDispatchOutcome, SelfDispatcher, SelfEffect, SelfMemoryPutClaimCall, SelfMemoryPutEdgeCall,
    TaskWaitSetCall,
};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::identity_topology::EntityLifecycleState;
use oneiron::memory::HostWriteOrigin;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{AgentVerb, invoke};
use oneiron::test_doors::run_changes::put_claim_asking_auto;
use oneiron::test_support::{
    bind_host_owner, provision_engine_machines, put_policy_manifest_bytes,
};
use oneiron::{
    AttemptId, AttemptQueue, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EdgeKind,
    EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The lease owner this test claims its root agent's row as.
const WORKER: &str = "run-revert-whole-run";

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

const fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn hex(id: AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// An owned vault (its writer lease is what the owner's verb doors ask for,
/// `Memory::embedded_owner`) that carries this install's signing keys and a
/// live machine profile (a topology judgment is sealed by the install), its
/// shipped policy manifest replaced at its own id by one whose defaults let
/// the owner's run and the seeded default agent land their Generated claims,
/// and its embedded owner bound under the host root (the run review doors act
/// only for the root owner). As tests/run_changes_notes.rs and
/// tests/run_changes_topology.rs, plus the default agent's ceiling.
struct Fixture {
    vault: Arc<Vault>,
    owner: EntityId,
    /// The seeded default agent: every agent run of this file runs it.
    agent: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Vault::open_owned(dir.path(), config).map_err(at("open owned"))?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .map_err(at("this install's signing keys"))?;
        let owner = vault
            .ensure_embedded_owner_actor()
            .map_err(at("embedded owner"))?;
        let (agent, _) = vault
            .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)
            .map_err(at("read the default agent"))?
            .ok_or("the default agent is seeded")?;
        let shipped = oneiron_store::policy_record::default_policy_manifest_id()
            .map_err(at("the shipped manifest's id"))?;
        put_policy_manifest_bytes(&vault, shipped, &run_policy(owner, agent)?)
            .map_err(at("install the policy"))?;
        // The host root's genesis and this install's live machine profile,
        // then the owner bound under the root.
        let issuer = provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .map_err(at("this install's machine profile"))?;
        bind_host_owner(&vault, &issuer, owner).map_err(at("owner host binding"))?;
        Ok(Self {
            vault: Arc::new(vault),
            owner,
            agent,
            _dir: dir,
        })
    }

    /// A fresh PERSON, so no change of one test meets another's.
    fn person(&self) -> TestResult<EntityId> {
        let id = EntityId::now();
        self.vault
            .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, b"person")
            .map_err(at("put a PERSON"))?;
        Ok(id)
    }

    /// The owner's NOTE of `markdown`, written outside any run.
    fn note(&self, markdown: &str) -> TestResult<EntityId> {
        self.vault
            .create_note(
                "research",
                markdown,
                WriteActor::new(self.owner, EdgeActorClass::Human),
            )
            .map_err(at("the owner's NOTE"))
    }

    /// `note`'s text now.
    fn text(&self, note: EntityId) -> TestResult<String> {
        Ok(self
            .vault
            .note_program_document(note)
            .map_err(at("read the NOTE"))?
            .ok_or("the NOTE has no document")?
            .text())
    }

    /// The owner's code run under the run reference `run`, its verb calls
    /// served by the host's door.
    fn run(&self, run: &str) -> TestResult<HostSelfDispatcher<'_>> {
        let door = Arc::new(OwnerVerbDoor {
            vault: Arc::clone(&self.vault),
            owner: self.owner,
        });
        Ok(HostSelfDispatcher::new(
            &self.vault,
            WriteActor::new(self.owner, EdgeActorClass::Human),
            run,
        )
        .map_err(at("the run's dispatcher"))?
        .with_agent_verb_door(door))
    }

    /// One claim of `run` about `subject`, at a fresh id: the claim put a
    /// live run asks Auto, so it lands at once.
    fn put(
        run: &HostSelfDispatcher<'_>,
        subject: EntityId,
        value: &str,
        at_time: u64,
    ) -> TestResult<EntityId> {
        let id = EntityId::now();
        put_claim_asking_auto(
            run,
            SelfMemoryPutClaimCall::new(
                id,
                ClaimCandidate::new(
                    "profile.favorite_drink",
                    ClaimSubject::Entity(subject),
                    Value::from(value),
                    0.8,
                ),
                range(at_time),
                at_time + 1,
            ),
        )
        .map_err(at("the run's claim put"))?;
        Ok(id)
    }

    /// The run's call of `verb`, as its guest makes it, and its output.
    fn call(
        run: &HostSelfDispatcher<'_>,
        verb: &str,
        input: serde_json::Value,
    ) -> TestResult<serde_json::Value> {
        match run
            .dispatch(SelfCall::AgentVerb(SelfAgentVerbCall {
                verb: AgentVerb::from_name(verb).ok_or("no such verb")?,
                input,
            }))
            .map_err(at("the run's verb call"))?
        {
            SelfDispatchOutcome::AgentVerb(answer) => Ok(answer.output),
            other => Err(format!("{verb} answered {other:?}").into()),
        }
    }

    /// The owner's own call of `verb`, outside any run.
    fn owner_call(&self, verb: &str, input: serde_json::Value) -> TestResult<serde_json::Value> {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        invoke(&memory, verb, input).map_err(at("the owner's verb call"))
    }

    /// The run's changes as `vault.runs.changes.get` lists them.
    fn changes(&self, run: &str) -> TestResult<Vec<serde_json::Value>> {
        let listed = self.owner_call("vault.runs.changes.get", json!({ "run_id": run }))?;
        Ok(listed["changes"]
            .as_array()
            .ok_or("the list names no changes")?
            .clone())
    }

    /// `vault.revert_run` of the whole run as the vault owner, by verb name,
    /// with no selection.
    fn revert_all(&self, run: &str) -> TestResult<serde_json::Value> {
        self.owner_call("vault.revert_run", json!({ "run_id": run }))
    }

    /// The claim's (approval, lifecycle) as stored.
    fn claim_state(&self, id: EntityId) -> TestResult<(String, String)> {
        let body = self
            .vault
            .get_claim(&id)
            .map_err(at("read a claim"))?
            .ok_or("the claim reads nothing")?;
        Ok((
            body.approval.as_str().to_owned(),
            body.lifecycle.as_str().to_owned(),
        ))
    }

    /// `id`'s lifecycle state on the identity ledger now.
    fn entity_state(&self, id: EntityId) -> TestResult<EntityLifecycleState> {
        self.vault
            .entity_lifecycle_state(&id)
            .map_err(at("read a lifecycle state"))
    }

    /// A root run of the default agent with no `run_id`, one level of
    /// delegation left, leased as its worker leases it: its attempt and the
    /// actor it runs as.
    fn root_agent(&self, now: u64) -> TestResult<(AttemptId, WriteActor)> {
        let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(&self.vault)
            .dispatch_with_context(
                DispatchAgent {
                    target: AgentDispatchTarget::Custom(self.agent),
                    parent_attempt: None,
                    dedupe_key: None,
                    run_id: None,
                    now,
                },
                AgentSpawnContext::default().with_depth_remaining(1),
            )
            .map_err(at("dispatch the root agent"))?
        else {
            return Err("expected one fresh root run".into());
        };
        assert_eq!(status.attempt.run_id, None, "the root names no run");
        self.lease(status.attempt.id)?;
        Ok((status.attempt.id, agent_dispatch_actor(&status.input)?))
    }

    /// Leases `id` to this test's worker. The runner's rows are claimed
    /// oldest first, so rows queued before it are claimed past.
    fn lease(&self, id: AttemptId) -> TestResult {
        let queue = AttemptQueue::new(&self.vault);
        for _ in 0..64 {
            let ClaimOutcome::Claimed(row) = queue
                .claim_kind(
                    DREAMER_RUNNER_ATTEMPT_KIND,
                    ClaimAttempt {
                        lease_owner: WORKER.to_owned(),
                        now: u64::MAX,
                    },
                )
                .map_err(at("lease a row"))?
            else {
                break;
            };
            if row.id == id {
                return Ok(());
            }
        }
        Err("the root is ready to lease".into())
    }

    /// The root's own `self.agents.spawn` of the default agent under `key`:
    /// the child it queued.
    fn spawn(&self, root: AttemptId, actor: WriteActor, key: &str) -> TestResult<AttemptId> {
        let outcome = HostSelfDispatcher::for_agent_attempt(&self.vault, actor, root)
            .map_err(at("the root's dispatcher"))?
            .dispatch(SelfCall::AgentsSpawn(Box::new(SelfAgentSpawnCall {
                target: Some(AgentDispatchTarget::Custom(self.agent)),
                context: AgentSpawnContext::default(),
                intent_key: key.to_owned(),
                ask: None,
            })))
            .map_err(at("the root's spawn"))?;
        match outcome {
            SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::Queued {
                attempt_ref, ..
            }) => Ok(attempt_ref),
            other => Err(format!("expected a queued child, got {other:?}").into()),
        }
    }

    /// The `run_id` `attempt`'s queue row holds.
    fn run_id_of(&self, attempt: AttemptId) -> TestResult<Option<String>> {
        Ok(AttemptQueue::new(&self.vault)
            .get(attempt)
            .map_err(at("read a queue row"))?
            .ok_or("the queue row reads nothing")?
            .run_id)
    }
}

/// The host's verb door for the owner's run: it serves each call through the
/// generated dispatcher on the owner's memory bound to the run's own write
/// origin, as a host's door does (`run_host_door::agent_memory`).
struct OwnerVerbDoor {
    vault: Arc<Vault>,
    owner: EntityId,
}

impl AgentVerbDoor for OwnerVerbDoor {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        _invocation: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        let memory = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_host_origin(origin.clone());
        let output = invoke(&memory, call.verb.as_str(), call.input.clone()).map_err(|error| {
            oneiron::Error::InvalidConfig(format!("{}: {error:?}", call.verb.as_str()))
        })?;
        Ok(Ok(AgentVerbAnswer::new(output, None)))
    }

    fn admit_run_call(
        &self,
        _call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        Ok(None)
    }

    fn admit_run_speech(
        &self,
        _effect: SelfEffect,
        _destination: RunSpeechDestination,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        Ok(None)
    }
}

/// Defaults that land the owner's and the default agent's Generated claims,
/// as the code-run gate pins install them (tests/gate_pins_claim_producers.rs).
fn run_policy(owner: EntityId, agent: EntityId) -> TestResult<Vec<u8>> {
    let axes = || {
        Value::Map(vec![
            (Value::from("criticality"), Value::from("normal")),
            (Value::from("sensitivity"), Value::from("normal")),
        ])
    };
    let ceiling = |class: &str, actor: EntityId| {
        Value::Map(vec![
            (Value::from("actor_class"), Value::from(class)),
            (Value::from("actor_ref"), Value::from(actor.to_hex())),
            (Value::from("ceiling"), Value::from("auto")),
        ])
    };
    let manifest = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(oneiron_store::policy_record::POLICY_SCHEMA_VERSION),
        ),
        (Value::from("pack_id"), Value::from("run-revert-whole-run")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (Value::from("defaults"), axes()),
        (Value::from("rules"), Value::Array(Vec::new())),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![ceiling("human", owner), ceiling("agent", agent)]),
        ),
        (
            Value::from("source_trust"),
            Value::Map(vec![(
                Value::from(ClaimSource::Generated.as_str()),
                Value::Map(vec![
                    (Value::from("max_auto_sensitivity"), Value::from(2_u64)),
                    (Value::from("receipted"), Value::Boolean(true)),
                    (Value::from("warned"), Value::Boolean(true)),
                ]),
            )]),
        ),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest)?;
    Ok(data)
}

/// The outcome's (change, receipt or reason) rows of list `key`, sorted.
fn rows(outcome: &serde_json::Value, key: &str, field: &str) -> TestResult<Vec<(String, String)>> {
    let mut rows = outcome[key]
        .as_array()
        .ok_or_else(|| format!("the outcome names no {key} list: {outcome}"))?
        .iter()
        .map(|row| {
            let change = row["change"].as_str().ok_or("a row names no change")?;
            let value = row[field].as_str().ok_or("a row names no value")?;
            Ok((change.to_owned(), value.to_owned()))
        })
        .collect::<TestResult<Vec<_>>>()?;
    rows.sort();
    Ok(rows)
}

/// The record a listed change of `kind` names under `field`.
fn named(change: &serde_json::Value, kind: &str, field: &str) -> TestResult<String> {
    if change["kind"] != kind {
        return Err(format!("a {kind} change: {change}").into());
    }
    Ok(change[field]
        .as_str()
        .ok_or_else(|| format!("the change names no {field}: {change}"))?
        .to_owned())
}

/// The NOTE's version now, as `vault.notes.read` names it.
fn version(f: &Fixture, note: EntityId) -> TestResult<serde_json::Value> {
    let read = f.owner_call("vault.notes.read", json!({ "note_ref": note.to_hex() }))?;
    Ok(read["value"]["version"].clone())
}

/// The canon's acceptance test (ARCH-0040:318): the owner's run, nobody
/// settled, puts a claim, puts an edge, lands a fork of a NOTE through its
/// own proposal, and merges two PERSONs. The run lists all four changes, in
/// write order. One `vault.revert_run` with no selection takes back all of
/// them, each under its own compensation receipt, and leaves none undone: the
/// claim and the edge's provenance Claim read retracted, the NOTE reads its
/// text from before the run, and the merged PERSON is active again.
#[test]
fn whole_run_revert_takes_back_claims_edges_notes_and_topology() -> TestResult {
    let f = Fixture::open()?;
    let run = f.run("whole-1")?;
    let (subject, owen, yuki) = (f.person()?, f.person()?, f.person()?);
    let (source, survivor) = (f.person()?, f.person()?);
    let note = f.note("The first line.")?;

    let claim = Fixture::put(&run, subject, "sencha", 10)?;
    run.dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
        owen,
        EdgeKind::Mentions,
        yuki,
        0.7,
    )))
    .map_err(at("the run's edge put"))?;
    let edit = json!({
        "kind": "whole_text",
        "text": "The first line. The run's line.",
        "timeout_ms": 5000,
        "base": version(&f, note)?,
    });
    let forked = Fixture::call(
        &run,
        "vault.notes.fork",
        json!({ "note_ref": note.to_hex(), "base": version(&f, note)?, "edit": edit }),
    )?;
    let fork = forked["record"]["fork_ref"]
        .as_str()
        .ok_or("the fork names no ref")?
        .to_owned();
    let opened = Fixture::call(
        &run,
        "vault.notes.proposals.open",
        json!({
            "forks": [{ "note_ref": note.to_hex(), "fork_ref": fork }],
            "explainer": "The run's edit.",
        }),
    )?;
    assert_eq!(
        opened["landed"][0]["fork_ref"], fork,
        "the run's own proposal lands its fork"
    );
    Fixture::call(
        &run,
        "vault.cluster.merge",
        json!({ "merge": {
            "sources": [source.to_hex()],
            "survivor": survivor.to_hex(),
            "evidence": { "refs": [], "rationale": "one person, written twice" },
        } }),
    )?;
    assert_eq!(
        f.claim_state(claim)?,
        ("auto".to_owned(), "active".to_owned()),
        "the run's claim lands at once"
    );
    assert_eq!(f.text(note)?, "The first line. The run's line.");
    assert_eq!(f.entity_state(source)?, EntityLifecycleState::Merged);

    let listed = f.changes("whole-1")?;
    assert_eq!(
        listed.len(),
        4,
        "a claim, an edge, a NOTE, a merge: {listed:?}"
    );
    assert_eq!(named(&listed[0], "claim", "claim_ref")?, claim.to_hex());
    let edge = EntityId::from_hex(&named(&listed[1], "edge", "provenance_ref")?)?;
    assert_eq!(named(&listed[2], "note", "fork_ref")?, fork);
    assert_eq!(named(&listed[2], "note", "note_ref")?, note.to_hex());
    let merge = named(&listed[3], "topology", "event_ref")?;
    assert_eq!(f.claim_state(edge)?.1, "active", "the edge's record stands");

    let outcome = f.revert_all("whole-1")?;
    assert_eq!(outcome["run_id"], "whole-1");
    let undone = rows(&outcome, "compensated", "receipt")?;
    let mut every = vec![claim.to_hex(), edge.to_hex(), fork.clone(), merge];
    every.sort();
    assert_eq!(
        undone
            .iter()
            .map(|(change, _)| change.clone())
            .collect::<Vec<_>>(),
        every,
        "one action takes back all four changes"
    );
    assert!(
        undone
            .iter()
            .all(|(_, receipt)| receipt.starts_with("gate:")),
        "each compensation has its own receipt: {undone:?}"
    );
    assert_eq!(
        rows(&outcome, "not_undone", "reason")?,
        Vec::new(),
        "nothing of the run is left standing"
    );
    assert_eq!(
        f.claim_state(claim)?.1,
        "retracted",
        "the claim is taken back"
    );
    assert_eq!(
        f.claim_state(edge)?.1,
        "retracted",
        "the edge is taken back"
    );
    assert_eq!(
        f.text(note)?,
        "The first line.",
        "the NOTE's revision from before the run is restored"
    );
    assert_eq!(
        f.entity_state(source)?,
        EntityLifecycleState::Active,
        "the merge is undone"
    );
    Ok(())
}

/// A root agent run with no `run_id` runs under `agent:<root hex>`. It
/// spawns a child through its own `self.agents.spawn`, and the child puts a
/// claim that lands at once. The child joins its root's run: its row holds
/// the root's run reference, the root's run lists the child's claim, and the
/// owner's undo-all of the root retracts it.
#[test]
fn a_root_without_a_run_id_takes_back_its_childs_changes() -> TestResult {
    let f = Fixture::open()?;
    let (root, actor) = f.root_agent(10)?;
    let child = f.spawn(root, actor, "child-1")?;
    let root_run = format!("agent:{}", hex(root));
    assert_eq!(
        f.run_id_of(child)?,
        Some(root_run.clone()),
        "the child joins its root's run"
    );
    let child_actor = WriteActor::new(f.agent, EdgeActorClass::Agent);
    let child_run = HostSelfDispatcher::for_agent_attempt(&f.vault, child_actor, child)
        .map_err(at("the child's dispatcher"))?;
    let claim = Fixture::put(&child_run, f.person()?, "matcha", 12)?;
    assert_eq!(
        f.claim_state(claim)?,
        ("auto".to_owned(), "active".to_owned()),
        "the child's claim lands at once"
    );

    assert_eq!(
        f.changes(&root_run)?,
        vec![json!({ "kind": "claim", "claim_ref": claim.to_hex() })],
        "the root's run lists its child's claim"
    );
    let outcome = f.revert_all(&root_run)?;
    assert_eq!(outcome["run_id"], root_run.as_str());
    let undone = rows(&outcome, "compensated", "receipt")?;
    assert_eq!(
        undone
            .iter()
            .map(|(change, _)| change.clone())
            .collect::<Vec<_>>(),
        vec![claim.to_hex()],
        "the root's undo-all takes back its child's claim"
    );
    assert!(undone[0].1.starts_with("gate:"), "{undone:?}");
    assert_eq!(rows(&outcome, "not_undone", "reason")?, Vec::new());
    assert_eq!(f.claim_state(claim)?.1, "retracted");
    Ok(())
}

/// The root of a run with no `run_id` waits on the child it spawned: the
/// wait opens and answers the child as pending, not as another run's
/// attempt (`task_wait_not_own`). A guard of the child's joined run
/// reference: green before the join and after it.
#[test]
fn a_child_of_a_root_without_a_run_id_still_counts_as_its_own_for_a_wait() -> TestResult {
    let f = Fixture::open()?;
    let (root, actor) = f.root_agent(10)?;
    let child = f.spawn(root, actor, "child-1")?;
    let call: TaskWaitSetCall = serde_json::from_value(json!({
        "tasks": [],
        "agents": [hex(child)],
        "n_of": null,
        "step_key": "children",
    }))?;
    let outcome = HostSelfDispatcher::for_agent_attempt(&f.vault, actor, root)
        .map_err(at("the root's dispatcher"))?
        .dispatch(SelfCall::TasksWaitSet(call))
        .map_err(at("the root's wait"))?;
    let SelfDispatchOutcome::AgentVerb(answer) = outcome else {
        return Err(format!("expected the wait's reduction, got {outcome:?}").into());
    };
    let waited: AgentWaitSetResult = serde_json::from_value(answer.output)?;
    assert!(!waited.done, "the child has not ended");
    assert!(waited.settled.is_empty());
    assert_eq!(
        waited.pending,
        vec![hex(child)],
        "the child is the root's own"
    );
    Ok(())
}
