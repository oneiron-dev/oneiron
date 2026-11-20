//! ARCH-0040 #revert-run (REV-2: "undo all N changes, or pick which"),
//! design RUNCHANGES-3 row D (Engine 13 Nov 10:30): a code run's delete of a
//! private thread joins its change journal, as its `vault.delete` does
//! (FIX RUN-JOURNAL-UNCOVERED-WRITERS, part A; UNBUILT3-39).
//! `vault.rooms.thread_delete` runs the room's delete rail, a policy delete
//! of the root that removes the root's own MESSAGEs first; each of those
//! deletes is recorded under the run in the write that commits it. The
//! journal lists them, and `vault.revert_run` of the run nobody settled
//! reports them and undoes none.
//!
//! The run calls `vault.rooms.thread_delete` through its host's verb door,
//! which serves each call on the owner's memory bound to the run's own write
//! origin, as a host's door does. Fixture as tests/run_changes_deletion.rs,
//! plus a project home room led by the owner, a trunk turn of the owner, and
//! a private thread on it whose audience is the owner alone.
//!
//! Red on main (cc184ff09aea): the room's delete rail binds no run, so the
//! run's journal is empty and its revert answers not_found. Green on the
//! head.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test run_changes_thread_delete`
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, HostSelfDispatcher, RunCall,
    RunSpeechDestination, SelfAgentVerbCall, SelfCall, SelfDispatcher, SelfEffect,
};
use oneiron::memory::{HostWriteOrigin, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{AgentVerb, invoke};
use oneiron::test_support::{
    bind_host_owner, provision_engine_machines, put_policy_manifest_bytes,
};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{ClaimSource, EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use rmpv::Value;
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

/// An owned vault (its writer lease is what the owner's verb doors ask for,
/// `Memory::embedded_owner`) that carries this install's signing keys (an
/// erase writes a signed receipt) and a live machine profile, its shipped
/// policy manifest replaced at its own id by one whose defaults let the
/// owner's run write its claims, and its embedded owner bound under the host
/// root (the run review doors act only for the root owner). As
/// tests/run_changes_deletion.rs.
struct Fixture {
    vault: Arc<Vault>,
    owner: EntityId,
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
        let shipped = oneiron_store::policy_record::default_policy_manifest_id()
            .map_err(at("the shipped manifest's id"))?;
        put_policy_manifest_bytes(&vault, shipped, &run_policy(owner)?)
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
            _dir: dir,
        })
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

    /// A project led by the owner, and its home room.
    fn home_room(&self) -> TestResult<EntityId> {
        let root = self.vault.root_project().map_err(at("root project"))?;
        let project = EntityId::now();
        let record = ProjectRecord::new(project, Some(root), root, self.owner)
            .map_err(at("a project record"))?;
        self.vault
            .put_project(project, &record, self.vault.now_recorded_at())
            .map_err(at("the project"))?;
        Ok(EntityId::from_hex(&record.home_room)?)
    }

    /// The owner's witness turn `turn` in `room` with one MESSAGE, outside
    /// any run: a trunk turn, or with `thread_of` the root of a private
    /// thread on that trunk turn whose audience is the owner alone. Returns
    /// the MESSAGE id.
    fn speak(
        &self,
        room: EntityId,
        turn: EntityId,
        thread_of: Option<EntityId>,
    ) -> TestResult<EntityId> {
        let message = EntityId::now();
        let mut metadata = serde_json::Map::new();
        if let Some(anchor) = thread_of {
            metadata.insert("room_thread_of".into(), anchor.to_hex().into());
        }
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .rooms_speak(&WitnessTurn {
                conversation_ref: room.to_hex(),
                turn_ref: Some(turn.to_hex()),
                thread_audience: thread_of.map(|_| BTreeSet::from([self.owner])),
                project: None,
                messages: vec![WitnessMessage {
                    id: Some(message.to_hex()),
                    author: WitnessAuthor::User,
                    message_type: "text".into(),
                    content: "a turn of the room".into(),
                    parts: None,
                    metadata: Some(serde_json::Value::Object(metadata)),
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at: self.vault.now_recorded_at(),
                assertions: Default::default(),
            })
            .map_err(at("the owner speaks"))?;
        Ok(message)
    }

    /// A private thread of the owner alone in a fresh home room: its root
    /// TURN and the root's one MESSAGE.
    fn private_thread(&self) -> TestResult<(EntityId, EntityId)> {
        let room = self.home_room()?;
        let anchor = EntityId::now();
        self.speak(room, anchor, None)?;
        let root = EntityId::now();
        let message = self.speak(room, root, Some(anchor))?;
        Ok((root, message))
    }

    /// The run's call of `verb`, as its guest makes it.
    fn call(
        &self,
        run: &HostSelfDispatcher<'_>,
        verb: &str,
        input: serde_json::Value,
    ) -> TestResult {
        run.dispatch(SelfCall::AgentVerb(SelfAgentVerbCall {
            verb: AgentVerb::from_name(verb).ok_or("no such verb")?,
            input,
        }))
        .map_err(at("the run's verb call"))?;
        Ok(())
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

    /// `vault.revert_run` of the whole run as the vault owner, by verb name.
    fn revert_all(&self, run: &str) -> TestResult<serde_json::Value> {
        self.owner_call("vault.revert_run", json!({ "run_id": run }))
    }
}

/// The host's verb door for the run: it serves each call through the
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

/// Defaults that land the owner's Generated claims, as the code-run gate
/// pins install them (tests/gate_pins_claim_producers.rs).
fn run_policy(actor: EntityId) -> TestResult<Vec<u8>> {
    let axes = || {
        Value::Map(vec![
            (Value::from("criticality"), Value::from("normal")),
            (Value::from("sensitivity"), Value::from("normal")),
        ])
    };
    let manifest = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(oneiron_store::policy_record::POLICY_SCHEMA_VERSION),
        ),
        (
            Value::from("pack_id"),
            Value::from("run-changes-thread-delete"),
        ),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (Value::from("defaults"), axes()),
        (Value::from("rules"), Value::Array(Vec::new())),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_class"), Value::from("human")),
                (Value::from("actor_ref"), Value::from(actor.to_hex())),
                (Value::from("ceiling"), Value::from("auto")),
            ])]),
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

/// The outcome's (change, receipt or reason) rows of list `key`, in order.
fn rows(outcome: &serde_json::Value, key: &str, field: &str) -> TestResult<Vec<(String, String)>> {
    outcome[key]
        .as_array()
        .ok_or("the outcome names no such list")?
        .iter()
        .map(|row| {
            let change = row["change"].as_str().ok_or("a row names no change")?;
            let value = row[field].as_str().ok_or("a row names no value")?;
            Ok((change.to_owned(), value.to_owned()))
        })
        .collect()
}

/// The entity each change of `changes` names, in order, and whether every
/// one is a delete or an erase.
fn deleted_refs(changes: &[serde_json::Value]) -> TestResult<(Vec<String>, bool)> {
    let mut refs = Vec::new();
    let mut deletes = true;
    for change in changes {
        let kind = change["kind"].as_str().ok_or("a change names no kind")?;
        deletes &= matches!(kind, "delete" | "erase");
        let entity = change["entity_ref"]
            .as_str()
            .ok_or("a change names no entity")?;
        refs.push(entity.to_owned());
    }
    Ok((refs, deletes))
}

/// A run deletes a private thread whose root holds one MESSAGE. The run's
/// changes name the MESSAGE's delete and then the root's, and no other
/// change; the owner's own thread delete, outside any run, joins no run.
#[test]
fn a_runs_private_thread_delete_is_in_its_changes() -> TestResult {
    let f = Fixture::open()?;
    let (root, message) = f.private_thread()?;
    let run = f.run("run-thread-delete-list")?;
    f.call(
        &run,
        "vault.rooms.thread_delete",
        json!({ "thread_ref": root.to_hex() }),
    )?;
    assert!(f.vault.is_deleted_shell(&root)?, "the run's delete applied");

    let (refs, deletes) = deleted_refs(&f.changes("run-thread-delete-list")?)?;
    assert_eq!(
        refs,
        vec![message.to_hex(), root.to_hex()],
        "the MESSAGE's delete, then the root's, in write order"
    );
    assert!(deletes, "each change is a delete or an erase");

    let (own_root, _) = f.private_thread()?;
    f.owner_call(
        "vault.rooms.thread_delete",
        json!({ "thread_ref": own_root.to_hex() }),
    )?;
    let (refs, _) = deleted_refs(&f.changes("run:run-thread-delete-list")?)?;
    assert!(
        !refs.contains(&own_root.to_hex()),
        "the owner's delete outside any run joins no run's journal"
    );
    Ok(())
}

/// Undo-all of a run nobody reviewed, whose one act deleted a private
/// thread, takes back none of it: it reports each delete it cannot undo,
/// the root's first (newest first), and compensates nothing. Red on main:
/// the run has no change, so its revert answers not_found.
#[test]
fn revert_all_reports_a_runs_thread_delete_and_undoes_none() -> TestResult {
    let f = Fixture::open()?;
    let (root, message) = f.private_thread()?;
    let run = f.run("run-thread-delete-revert")?;
    f.call(
        &run,
        "vault.rooms.thread_delete",
        json!({ "thread_ref": root.to_hex() }),
    )?;

    let outcome = f.revert_all("run-thread-delete-revert")?;
    assert_eq!(outcome["run_id"], "run-thread-delete-revert");
    assert_eq!(
        rows(&outcome, "compensated", "receipt")?,
        Vec::<(String, String)>::new(),
        "a delete has no live undo"
    );
    let reported = rows(&outcome, "not_undone", "reason")?
        .into_iter()
        .map(|(change, _)| {
            change
                .split_once(':')
                .map(|(_, id)| id.to_owned())
                .ok_or("a change names no entity")
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        reported,
        vec![root.to_hex(), message.to_hex()],
        "the root's delete and the MESSAGE's, newest first"
    );
    Ok(())
}
