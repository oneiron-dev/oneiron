//! ARCH-0040 #revert-run (REV-2), design RUNCHANGES-3 (Engine 13 Nov 10:30):
//! a run's identity-topology judgments join its change journal. A merge or
//! split the run asks through `vault.cluster.*`, applied or parked as a
//! proposal, is recorded under the run in the event's own write, as is a
//! merge, split or facet item of the run's derivation batch. The journal
//! lists it beside the run's claims, in write order, and `vault.revert_run`
//! of a run nobody settled undoes an applied event through the topology
//! ledger's own undo and reports a proposal still open as never landed.
//!
//! The run calls the cluster verbs through its host's verb door, which serves
//! each call on the owner's memory bound to the run's own write origin, as a
//! host's door does.
//!
//! Red on the base (runchanges-2): no topology event joins a run's journal,
//! so each run lists only its claims. Green on the head.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test run_changes_topology`
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, HostSelfDispatcher, RunCall,
    RunSpeechDestination, SelfAgentVerbCall, SelfCall, SelfDispatcher, SelfEffect,
    SelfMemoryPutClaimCall,
};
use oneiron::identity_topology::{EntityLifecycleState, StoredIdentityOpAction};
use oneiron::memory::HostWriteOrigin;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{AgentVerb, invoke};
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    Derived, Distinct, Merge, commit, define_auto_agent, grant_derive_rows, grant_topology_seal,
};
use oneiron::test_doors::run_changes::journal_changes;
use oneiron::test_support::{
    bind_host_owner, provision_engine_machines, put_policy_manifest_bytes,
};
use oneiron::{
    ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId, TimeRange, Vault,
    VaultConfig, WriteActor,
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
/// `Memory::embedded_owner`) that carries this install's signing keys and a
/// live machine profile (a topology judgment is sealed by the install), its
/// shipped policy manifest replaced at its own id by one whose defaults let
/// the owner's run write its claims, and its embedded owner bound under the
/// host root (the run review doors act only for the root owner). As
/// tests/run_revert_unsettled.rs, plus the install's keys and profile.
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

    /// `id`'s lifecycle state on the ledger now.
    fn state(&self, id: EntityId) -> TestResult<EntityLifecycleState> {
        self.vault
            .entity_lifecycle_state(&id)
            .map_err(at("read a lifecycle state"))
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

/// The merge judgment `sources` are `survivor`, as the cluster verbs take it.
fn merge(source: EntityId, survivor: EntityId) -> serde_json::Value {
    json!({
        "sources": [source.to_hex()],
        "survivor": survivor.to_hex(),
        "evidence": { "refs": [], "rationale": "one person, written twice" },
    })
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
        (Value::from("pack_id"), Value::from("run-changes-topology")),
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

/// The topology event a listed change names.
fn event_of(change: &serde_json::Value) -> TestResult<EntityId> {
    if change["kind"] != "topology" {
        return Err(format!("a topology change: {change}").into());
    }
    let event = change["event_ref"]
        .as_str()
        .ok_or("the change names no event")?;
    Ok(EntityId::from_hex(event)?)
}

/// That `event` is the stored merge of `source` into `survivor`.
fn assert_merge(
    vault: &Vault,
    event: EntityId,
    source: EntityId,
    survivor: EntityId,
) -> TestResult {
    let stored = vault
        .identity_topology_event(&event)
        .map_err(at("read the event"))?
        .ok_or("the event reads nothing")?;
    let StoredIdentityOpAction::Merge {
        sources,
        survivor: merged_into,
    } = stored.action
    else {
        return Err(format!("a merge event: {:?}", stored.action).into());
    };
    assert_eq!((sources, merged_into), (vec![source], survivor));
    Ok(())
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

/// A run writes a claim, merges two PERSONs through `vault.cluster.merge`,
/// then writes another claim. Another run merges two others, and the owner
/// merges a third pair outside any run. The run lists its claim, its merge
/// event and its claim, in write order; the other run lists its own merge
/// only, and the owner's merge joins neither.
#[test]
fn run_changes_list_names_a_runs_identity_merge() -> TestResult {
    let f = Fixture::open()?;
    let run = f.run("run-topology-list")?;
    let other = f.run("run-topology-other")?;
    let (source, survivor) = (f.person()?, f.person()?);
    let first = f.put(&run, "sencha", 10)?;
    f.call(
        &run,
        "vault.cluster.merge",
        json!({ "merge": merge(source, survivor) }),
    )?;
    let second = f.put(&run, "matcha", 12)?;
    let (their_source, their_survivor) = (f.person()?, f.person()?);
    f.call(
        &other,
        "vault.cluster.merge",
        json!({ "merge": merge(their_source, their_survivor) }),
    )?;
    let (own_source, own_survivor) = (f.person()?, f.person()?);
    f.owner_call(
        "vault.cluster.merge",
        json!({ "merge": merge(own_source, own_survivor) }),
    )?;
    for merged in [source, their_source, own_source] {
        assert_eq!(f.state(merged)?, EntityLifecycleState::Merged);
    }

    let listed = f.changes("run-topology-list")?;
    assert_eq!(listed.len(), 3, "two claims and one merge: {listed:?}");
    assert_eq!(
        listed[0],
        json!({ "kind": "claim", "claim_ref": first.to_hex() })
    );
    assert_merge(&f.vault, event_of(&listed[1])?, source, survivor)?;
    assert_eq!(
        listed[2],
        json!({ "kind": "claim", "claim_ref": second.to_hex() })
    );
    let theirs = f.changes("run:run-topology-other")?;
    assert_eq!(theirs.len(), 1, "the other run's merge only: {theirs:?}");
    assert_merge(
        &f.vault,
        event_of(&theirs[0])?,
        their_source,
        their_survivor,
    )?;
    Ok(())
}

/// A run nobody reviewed merges two PERSONs and proposes a merge of two
/// others. Undo-all of the run undoes the applied merge, with its own
/// receipt, and reports the open proposal as never landed. Asked again, it
/// answers with the same receipt and writes nothing new.
#[test]
fn revert_all_undoes_an_unsettled_runs_identity_merge() -> TestResult {
    let f = Fixture::open()?;
    let run = f.run("run-topology-revert")?;
    let (source, survivor) = (f.person()?, f.person()?);
    let (held, held_survivor) = (f.person()?, f.person()?);
    f.call(
        &run,
        "vault.cluster.merge",
        json!({ "merge": merge(source, survivor) }),
    )?;
    let mut proposal = merge(held, held_survivor);
    proposal["kind"] = json!("merge");
    f.call(
        &run,
        "vault.cluster.propose",
        json!({ "operation": proposal }),
    )?;
    let listed = f.changes("run-topology-revert")?;
    assert_eq!(listed.len(), 2, "the merge and the proposal: {listed:?}");
    let (merged, proposed) = (event_of(&listed[0])?, event_of(&listed[1])?);
    assert_merge(&f.vault, merged, source, survivor)?;
    assert_eq!(f.state(source)?, EntityLifecycleState::Merged);
    assert_eq!(
        f.state(held)?,
        EntityLifecycleState::Active,
        "a proposal changes nothing until it is ruled"
    );

    let outcome = f.revert_all("run-topology-revert")?;
    assert_eq!(outcome["run_id"], "run-topology-revert");
    let undone = rows(&outcome, "compensated", "receipt")?;
    assert_eq!(
        undone
            .iter()
            .map(|(change, _)| change.clone())
            .collect::<Vec<_>>(),
        vec![merged.to_hex()],
        "the applied merge only"
    );
    assert!(
        undone[0].1.starts_with("gate:"),
        "the compensation has its own receipt: {undone:?}"
    );
    let never_landed = vec![(proposed.to_hex(), "not_landed".to_owned())];
    assert_eq!(rows(&outcome, "not_undone", "reason")?, never_landed);
    assert_eq!(
        f.state(source)?,
        EntityLifecycleState::Active,
        "the run's merge is undone"
    );
    assert_eq!(f.state(held)?, EntityLifecycleState::Active);

    let again = f.revert_all("run:run-topology-revert")?;
    assert_eq!(
        rows(&again, "compensated", "receipt")?,
        undone,
        "a repeat answers with the kept receipt"
    );
    assert_eq!(rows(&again, "not_undone", "reason")?, never_landed);
    Ok(())
}

/// A run's derivation batch holds a merge proposal and a distinct
/// assertion, each under the agent's own `topology_seal` Grant. The run's
/// journal names the merge proposal's event only: a distinct assertion is no
/// change a run review takes back.
#[test]
fn run_changes_list_names_a_runs_derived_merge_proposal() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_dreamer_vault(dir.path(), "reader").map_err(at("the Dreamer's vault"))?;
    let person = |body: &[u8]| -> TestResult<EntityId> {
        let id = EntityId::now();
        let at_time = vault.now_recorded_at();
        vault
            .put_entity(&id, ENTITY_TYPE_PERSON, range(at_time), at_time, body)
            .map_err(at("put a PERSON"))?;
        Ok(id)
    };
    let (source, survivor) = (person(b"source")?, person(b"survivor")?);
    let (a, b) = (person(b"one")?, person(b"another")?);
    let agent = define_auto_agent(&vault).map_err(at("an agent"))?;
    grant_derive_rows(&vault, &[agent]).map_err(at("the agent's landing and read rows"))?;
    let grant = grant_topology_seal(&vault, agent).map_err(at("the agent's topology grant"))?;
    let committed = commit(
        &vault,
        agent,
        EdgeActorClass::Agent,
        "run-topology-derive",
        &[
            Derived::Merge(Merge {
                local: "merge",
                sources: vec![source],
                survivor,
                grant,
                apply: false,
            }),
            Derived::Distinct(Distinct {
                local: "distinct",
                a,
                b,
                grant,
                apply: false,
            }),
        ],
    )
    .map_err(at("commit"))?;
    let [merged, distinct] = committed.items.as_slice() else {
        return Err(format!("two items: {:?}", committed.items).into());
    };
    assert!(
        merged.landed,
        "the merge proposal lands: {:?}",
        merged.reasons
    );
    assert!(
        distinct.landed,
        "the distinct assertion lands: {:?}",
        distinct.reasons
    );
    let [event] = merged.rows.as_slice() else {
        return Err(format!("one merge event: {:?}", merged.rows).into());
    };
    assert_eq!(
        journal_changes(&vault, "run-topology-derive").map_err(at("the run's journal"))?,
        json!([{ "kind": "topology", "event_ref": event.to_hex() }]),
        "the run's merge proposal, and no distinct assertion"
    );
    Ok(())
}
