//! L8-48 (ARCH-0040 #revert-run, REV-2): the engine lists a run's changes by
//! itself. Each claim a run writes joins that run's change journal in the
//! claim's own write, and `vault.runs.changes.get` reads it back, once each
//! and in write order, as the change set `vault.runs.review` takes. The run
//! is the reference its dispatcher bound, never an actor or a time: another
//! run's writes and the owner's own writes stay out.
//!
//! The run writes through both of its claim doors: `self.memory.put_claim`
//! (the code-mode bridge) and a verb call its host's verb door serves under
//! the run's write origin (`vault.claims.upsert`).
//!
//! Red on main: `vault.runs.changes.get` is not a verb there, so every list
//! is refused. Green on the head.
//!
//! `cargo test --locked -p oneiron --all-features --test run_changes_list`
#![cfg(feature = "test-support")]

use std::sync::Arc;

use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, HostSelfDispatcher, RunCall,
    RunSpeechDestination, SelfAgentVerbCall, SelfCall, SelfDispatcher, SelfEffect,
    SelfMemoryPutClaimCall,
};
use oneiron::memory::{ClaimInput, HostWriteOrigin};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{AgentVerb, invoke};
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
/// `Memory::embedded_owner`), its shipped policy manifest replaced at its own
/// id by one whose defaults let the owner's run land its claims (a manifest
/// at a new id would still meet the shipped pack's fallback), and its
/// embedded owner bound under the host root (the run review doors act only
/// for the root owner).
struct Fixture {
    vault: Arc<Vault>,
    owner: EntityId,
    subject: EntityId,
    facet: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Vault::open_owned(dir.path(), config).map_err(at("open owned"))?;
        let owner = vault
            .ensure_embedded_owner_actor()
            .map_err(at("embedded owner"))?;
        let shipped = oneiron_store::policy_record::default_policy_manifest_id()
            .map_err(at("the shipped manifest's id"))?;
        put_policy_manifest_bytes(&vault, shipped, &run_policy(owner)?)
            .map_err(at("install the policy"))?;
        // The host root's genesis, then the owner bound under it.
        let issuer = provision_engine_machines(&vault);
        bind_host_owner(&vault, &issuer, owner).map_err(at("owner host binding"))?;
        let subject = EntityId::now();
        vault
            .put_entity(&subject, ENTITY_TYPE_PERSON, range(1), 1, b"person")
            .map_err(at("put a PERSON"))?;
        let facet = vault.default_facet().map_err(at("the default facet"))?;
        Ok(Self {
            vault: Arc::new(vault),
            owner,
            subject,
            facet,
            _dir: dir,
        })
    }

    /// The owner's code run under the run reference `run`.
    fn run(&self, run: &str) -> TestResult<HostSelfDispatcher<'_>> {
        HostSelfDispatcher::new(
            &self.vault,
            WriteActor::new(self.owner, EdgeActorClass::Human),
            run,
        )
        .map_err(at("the run's dispatcher"))
    }

    /// One `self.memory.put_claim` of the run, at a fresh id.
    fn put(&self, run: &HostSelfDispatcher<'_>, value: &str, at_time: u64) -> TestResult<EntityId> {
        let id = EntityId::now();
        run.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id,
            ClaimCandidate::new(
                "profile.favorite_drink",
                ClaimSubject::Entity(self.subject),
                Value::from(value),
                0.8,
            ),
            range(at_time),
            at_time + 1,
        )))
        .map_err(at("the run's claim put"))?;
        Ok(id)
    }

    /// `vault.runs.changes.get` as the vault owner, by verb name.
    fn changes(&self, run: &str) -> TestResult<serde_json::Value> {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        invoke(&memory, "vault.runs.changes.get", json!({ "run_id": run }))
            .map_err(at("vault.runs.changes.get"))
    }
}

/// The listed change set: each claim ref, in the list's order.
fn listed_claims(listed: &serde_json::Value) -> TestResult<Vec<String>> {
    listed["changes"]
        .as_array()
        .ok_or("the list names no changes")?
        .iter()
        .map(|change| {
            if change["kind"] != "claim" {
                return Err(format!("a change of another kind: {change}").into());
            }
            change["claim_ref"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("a claim change names no claim_ref: {change}").into())
        })
        .collect()
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
        (Value::from("pack_id"), Value::from("run-changes-list")),
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

/// The host's verb door for the run's `vault.claims.upsert`: it serves the
/// call on the owner's memory bound to the run's own write origin, as a
/// host's door does.
struct ClaimUpsertDoor {
    vault: Arc<Vault>,
    owner: EntityId,
}

impl AgentVerbDoor for ClaimUpsertDoor {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        _invocation: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        if call.verb.as_str() != "vault.claims.upsert" {
            return Ok(Err(AgentVerbRefusal {
                code: "verb_not_bound".to_owned(),
                hook_notice: None,
            }));
        }
        let input: ClaimInput = serde_json::from_value(call.input.clone())
            .map_err(|error| oneiron::Error::InvalidConfig(format!("claim input: {error}")))?;
        let receipt = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_host_origin(origin.clone())
            .claim_upsert(&input)
            .map_err(|error| oneiron::Error::InvalidConfig(format!("claim upsert: {error:?}")))?;
        Ok(Ok(AgentVerbAnswer::new(
            json!({ "claim_short_id": receipt.claim_short_id }),
            None,
        )))
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

/// A run writes 3 claims. Another run writes 1 and the owner writes 1
/// outside any run. The run's list is exactly its 3, in write order, under
/// its job id and under its `run:` handle. The other run lists its own one,
/// and a run that wrote nothing lists none.
#[test]
fn run_changes_list_names_exactly_the_runs_claims() -> TestResult {
    let f = Fixture::open()?;
    let run = f.run("run-changes-a")?;
    let other = f.run("run-changes-b")?;
    let first = f.put(&run, "sencha", 10)?;
    let elsewhere = f.put(&other, "oolong", 11)?;
    let second = f.put(&run, "matcha", 12)?;
    f.vault
        .memory(f.owner, EdgeActorClass::Human)
        .claim_upsert(&ClaimInput {
            id: None,
            predicate: "profile.favorite_drink".to_owned(),
            subject_ref: f.subject.to_hex(),
            value: json!("water"),
            confidence: 1.0,
            confidence_details: None,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: Some(json!({ "facet": f.facet.to_hex() })),
            valid_from: Some(13),
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        })
        .map_err(at("the owner's own claim"))?;
    let third = f.put(&run, "genmaicha", 14)?;

    let ours: Vec<String> = [first, second, third]
        .iter()
        .map(EntityId::to_hex)
        .collect();
    let listed = f.changes("run-changes-a")?;
    assert_eq!(listed["run_id"], "run-changes-a");
    assert_eq!(
        listed_claims(&listed)?,
        ours,
        "exactly the run's claims, in write order"
    );
    assert_eq!(
        listed_claims(&f.changes("run:run-changes-a")?)?,
        ours,
        "the settlement's run: handle names the same run"
    );
    assert_eq!(
        listed_claims(&f.changes("run-changes-b")?)?,
        vec![elsewhere.to_hex()]
    );
    assert_eq!(
        listed_claims(&f.changes("run-changes-none")?)?,
        Vec::<String>::new()
    );
    Ok(())
}

/// A claim the run writes through its host's verb door, under the run's own
/// write origin, joins the run beside its bridge put, in write order.
#[test]
fn run_changes_list_names_a_claim_the_run_wrote_through_a_verb_door() -> TestResult {
    let f = Fixture::open()?;
    let door = Arc::new(ClaimUpsertDoor {
        vault: Arc::clone(&f.vault),
        owner: f.owner,
    });
    let run = f.run("run-changes-door")?.with_agent_verb_door(door);
    let bridged = f.put(&run, "sencha", 10)?;
    let served = EntityId::now();
    run.dispatch(SelfCall::AgentVerb(SelfAgentVerbCall {
        verb: AgentVerb::from_name("vault.claims.upsert").ok_or("no vault.claims.upsert verb")?,
        input: json!({
            "id": served.to_hex(),
            "predicate": "profile.favorite_drink",
            "subject_ref": f.subject.to_hex(),
            "value": "matcha",
            "confidence": 0.8,
            "source": "inferred",
            "scope": { "facet": f.facet.to_hex() },
            "valid_from": 12,
        }),
    }))
    .map_err(at("the run's verb call"))?;
    assert_eq!(
        listed_claims(&f.changes("run-changes-door")?)?,
        vec![bridged.to_hex(), served.to_hex()],
        "the bridge put and the verb door's claim, in write order"
    );
    Ok(())
}
