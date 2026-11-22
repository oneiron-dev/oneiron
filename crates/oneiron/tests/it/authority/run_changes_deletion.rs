//! ARCH-0040 #revert-run (REV-2), design RUNCHANGES-3 row D (Engine 13 Nov
//! 10:30): a run's deletes join its change journal. A `vault.delete` the run
//! asks is recorded under the run in the write that commits it: a soft
//! delete in its scrub, an erase in its purge beside the `dt:` marker. The
//! journal lists it beside the run's claims, in write order, and
//! `vault.revert_run` of a run nobody settled reports a delete as
//! backup-only and an erase as one-way, as ARCH-0040:314 says; it undoes
//! neither.
//!
//! The run calls `vault.delete` through its host's verb door, which serves
//! each call on the owner's memory bound to the run's own write origin, as a
//! host's door does.
//!
//! A deletion's ref is its kind and the entity it removed (`delete:<id>`,
//! `erase:<id>`), so a run that wrote a claim and then deleted it, or deleted
//! and then erased one entity, lists and reverts each change apart. A
//! headerless delete whose purge removed only index rows joins the journal
//! too.
//!
//! Red on the base (runchanges-3): no delete joins a run's journal, so a run
//! lists only its claims, and the revert of a run that only deleted answers
//! not_found. Red at the first head (16967d75fa7, review round 1 of #7564):
//! a claim and its delete, or a delete and an erase of one entity, list as
//! one change, and a headerless delete that purged only index rows joins no
//! journal. Green on the head.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test run_changes_deletion`
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, HostSelfDispatcher, RunCall,
    RunSpeechDestination, SelfAgentVerbCall, SelfCall, SelfDispatcher, SelfEffect,
    SelfMemoryPutClaimCall,
};
use oneiron::memory::HostWriteOrigin;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{AgentVerb, invoke};
use oneiron::test_support::{
    bind_host_owner, provision_engine_machines, put_policy_manifest_bytes,
};
use oneiron::{
    ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId, SafeDeleteReason,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

const fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// An owned vault (its writer lease is what the owner's verb doors ask for,
/// `Memory::embedded_owner`) that carries this install's signing keys (an
/// erase writes a signed receipt) and a live machine profile, its shipped
/// policy manifest replaced at its own id by one whose defaults let the
/// owner's run write its claims, and its embedded owner bound under the host
/// root (the run review doors act only for the root owner). As
/// tests/run_changes_topology.rs.
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

    /// A fresh PERSON.
    fn person(&self) -> TestResult<EntityId> {
        let id = EntityId::now();
        self.vault
            .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, b"person")
            .map_err(at("put a PERSON"))?;
        Ok(id)
    }

    /// The owner's code run under the run reference `run`, its verb calls
    /// served by the host's door.
    fn run(&self, run: &str) -> TestResult<HostSelfDispatcher<'_>> {
        self.run_through(run, false)
    }

    /// As [`Self::run`], its door serving `vault.delete` by
    /// `Memory::safe_delete` directly.
    fn run_direct(&self, run: &str) -> TestResult<HostSelfDispatcher<'_>> {
        self.run_through(run, true)
    }

    fn run_through(&self, run: &str, direct_delete: bool) -> TestResult<HostSelfDispatcher<'_>> {
        let door = Arc::new(OwnerVerbDoor {
            vault: Arc::clone(&self.vault),
            owner: self.owner,
            direct_delete,
        });
        Ok(HostSelfDispatcher::new(
            &self.vault,
            WriteActor::new(self.owner, EdgeActorClass::Human),
            run,
        )
        .map_err(at("the run's dispatcher"))?
        .with_agent_verb_door(door))
    }

    /// One code-mode `self.memory.put_claim` of the run, at a fresh id.
    fn put(&self, run: &HostSelfDispatcher<'_>, value: &str, at_time: u64) -> TestResult<EntityId> {
        let id = EntityId::now();
        run.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id,
            ClaimCandidate::new(
                "profile.favorite_drink",
                ClaimSubject::Entity(self.person()?),
                Value::from(value),
                0.8,
            ),
            range(at_time),
            at_time + 1,
        )))
        .map_err(at("the run's claim put"))?;
        Ok(id)
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
/// origin, as a host's door does (`run_host_door::agent_memory`). With
/// `direct_delete` it serves `vault.delete` by `Memory::safe_delete` on that
/// memory, as a host door with no verb-table refs check does: the
/// dispatcher's refs check finds no record at an id that holds only index
/// rows.
struct OwnerVerbDoor {
    vault: Arc<Vault>,
    owner: EntityId,
    direct_delete: bool,
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
        if self.direct_delete && call.verb.as_str() == "vault.delete" {
            let entity_ref = call.input["entity_ref"].as_str().unwrap_or_default();
            let reason: SafeDeleteReason = serde_json::from_value(call.input["reason"].clone())
                .map_err(|error| oneiron::Error::InvalidConfig(format!("reason: {error}")))?;
            memory
                .safe_delete(entity_ref, reason)
                .map_err(|error| oneiron::Error::InvalidConfig(format!("delete: {error:?}")))?;
            return Ok(Ok(AgentVerbAnswer::new(serde_json::Value::Null, None)));
        }
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
        (Value::from("pack_id"), Value::from("run-changes-deletion")),
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

/// The run's `vault.delete` of `entity` under `reason`.
fn delete(f: &Fixture, run: &HostSelfDispatcher<'_>, entity: EntityId, reason: &str) -> TestResult {
    f.call(
        run,
        "vault.delete",
        json!({ "entity_ref": entity.to_hex(), "reason": reason }),
    )
}

/// A run writes a claim, deletes one PERSON and erases another through
/// `vault.delete`. Another run deletes a third, and the owner deletes a
/// fourth outside any run. The run lists its claim, its delete and its
/// erase, in write order; the other run lists its own delete only, and the
/// owner's delete joins neither.
#[test]
fn run_changes_list_names_a_runs_delete_and_erase() -> TestResult {
    let f = Fixture::open()?;
    let run = f.run("run-deletion-list")?;
    let other = f.run("run-deletion-other")?;
    let (deleted, erased, theirs, own) = (f.person()?, f.person()?, f.person()?, f.person()?);
    let claim = f.put(&run, "sencha", 10)?;
    delete(&f, &run, deleted, "user_delete")?;
    delete(&f, &run, erased, "user_hard_delete")?;
    delete(&f, &other, theirs, "user_delete")?;
    f.owner_call(
        "vault.delete",
        json!({ "entity_ref": own.to_hex(), "reason": "user_delete" }),
    )?;

    assert_eq!(
        f.changes("run-deletion-list")?,
        vec![
            json!({ "kind": "claim", "claim_ref": claim.to_hex() }),
            json!({ "kind": "delete", "entity_ref": deleted.to_hex() }),
            json!({ "kind": "erase", "entity_ref": erased.to_hex() }),
        ],
        "the claim, the delete and the erase, in write order"
    );
    assert_eq!(
        f.changes("run:run-deletion-other")?,
        vec![json!({ "kind": "delete", "entity_ref": theirs.to_hex() })],
        "the other run's delete only"
    );
    Ok(())
}

/// A run nobody reviewed deletes one PERSON and erases another. Undo-all of
/// the run takes back neither: it reports the delete as backup-only and the
/// erase as one-way, newest first, and compensates nothing. Asked again, it
/// answers the same.
#[test]
fn revert_all_reports_a_runs_delete_backup_only_and_erase_one_way() -> TestResult {
    let f = Fixture::open()?;
    let run = f.run("run-deletion-revert")?;
    let (deleted, erased) = (f.person()?, f.person()?);
    delete(&f, &run, deleted, "user_delete")?;
    delete(&f, &run, erased, "user_hard_delete")?;

    let outcome = f.revert_all("run-deletion-revert")?;
    assert_eq!(outcome["run_id"], "run-deletion-revert");
    assert_eq!(
        rows(&outcome, "compensated", "receipt")?,
        Vec::<(String, String)>::new(),
        "a delete has no live undo"
    );
    let reported = vec![
        (format!("erase:{}", erased.to_hex()), "one_way".to_owned()),
        (
            format!("delete:{}", deleted.to_hex()),
            "backup_only".to_owned(),
        ),
    ];
    assert_eq!(rows(&outcome, "not_undone", "reason")?, reported);

    let again = f.revert_all("run:run-deletion-revert")?;
    assert_eq!(
        rows(&again, "compensated", "receipt")?,
        Vec::<(String, String)>::new()
    );
    assert_eq!(rows(&again, "not_undone", "reason")?, reported);
    Ok(())
}

/// A run writes a claim and then deletes it, and deletes one PERSON and then
/// erases it. The run lists all four changes in write order: the claim and
/// its delete apart, the delete and the erase of the PERSON apart. A review
/// of the PERSON's delete and erase binds both, each under its own ref.
/// Undo-all, newest first, reports the erase one-way, the PERSON's delete
/// one-way (its entity is erased now), the claim's delete backup-only, and
/// the claim dependent: its body is gone, so it has no undo. The run's door
/// serves its deletes by `Memory::safe_delete`, so the erase of the deleted
/// PERSON does not rest on the verb's refs check reading a deleted record.
#[test]
fn a_runs_claim_and_its_delete_list_and_revert_apart() -> TestResult {
    let f = Fixture::open()?;
    let run = f.run_direct("run-deletion-apart")?;
    let person = f.person()?;
    let claim = f.put(&run, "genmaicha", 10)?;
    delete(&f, &run, claim, "user_delete")?;
    delete(&f, &run, person, "user_delete")?;
    delete(&f, &run, person, "user_hard_delete")?;

    assert_eq!(
        f.changes("run-deletion-apart")?,
        vec![
            json!({ "kind": "claim", "claim_ref": claim.to_hex() }),
            json!({ "kind": "delete", "entity_ref": claim.to_hex() }),
            json!({ "kind": "delete", "entity_ref": person.to_hex() }),
            json!({ "kind": "erase", "entity_ref": person.to_hex() }),
        ],
        "each change once, a claim and its delete apart"
    );

    let review = f.owner_call(
        "vault.runs.review",
        json!({
            "run_id": "run-deletion-apart",
            "changes": [
                { "kind": "delete", "entity_ref": person.to_hex() },
                { "kind": "erase", "entity_ref": person.to_hex() },
            ],
        }),
    )?;
    assert_eq!(
        rows(&review, "changes", "verdict")?,
        vec![
            (format!("delete:{}", person.to_hex()), "landed".to_owned()),
            (format!("erase:{}", person.to_hex()), "landed".to_owned()),
        ],
        "a delete and the erase that followed it bind apart"
    );

    let outcome = f.revert_all("run-deletion-apart")?;
    assert_eq!(
        rows(&outcome, "compensated", "receipt")?,
        Vec::<(String, String)>::new(),
        "nothing has a live undo"
    );
    assert_eq!(
        rows(&outcome, "not_undone", "reason")?,
        vec![
            (format!("erase:{}", person.to_hex()), "one_way".to_owned()),
            (format!("delete:{}", person.to_hex()), "one_way".to_owned()),
            (
                format!("delete:{}", claim.to_hex()),
                "backup_only".to_owned()
            ),
            (claim.to_hex(), "dependent".to_owned()),
        ]
    );
    Ok(())
}

/// A run deletes an id that holds only text-index rows and no entity record
/// (`batch().text` with no put; the purge cleans such rows, batch/deindex.rs).
/// The delete takes the headerless leg, whose purge removes those rows, so
/// the run lists the delete and undo-all reports it backup-only. The run's
/// door serves the delete by `Memory::safe_delete`.
#[test]
fn a_runs_delete_of_index_only_rows_joins_its_journal() -> TestResult {
    let f = Fixture::open()?;
    let run = f.run_direct("run-deletion-residue")?;
    let residue = EntityId::now();
    f.vault
        .batch()
        .text(&residue, &[("body", "jasmine")])
        .commit()
        .map_err(at("index text with no record"))?;
    delete(&f, &run, residue, "user_delete")?;

    assert_eq!(
        f.changes("run-deletion-residue")?,
        vec![json!({ "kind": "delete", "entity_ref": residue.to_hex() })],
        "the headerless delete"
    );
    let outcome = f.revert_all("run-deletion-residue")?;
    assert_eq!(
        rows(&outcome, "not_undone", "reason")?,
        vec![(
            format!("delete:{}", residue.to_hex()),
            "backup_only".to_owned()
        )]
    );
    Ok(())
}
