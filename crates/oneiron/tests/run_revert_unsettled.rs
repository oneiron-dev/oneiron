//! ARCH-0040 #revert-run (REV-2), ruling RUNCHANGES-REVERT-UNSETTLED = A
//! (13 Nov): the owner takes back a run nobody settled. `vault.revert_run`
//! with no settlement takes the run's members from its change journal: each
//! landed claim gets the undo a settle would give it, each compensation is
//! kept on the change's journal row, and a later change resting on one of the
//! run's claims keeps that claim and is reported as dependent.
//!
//! Red on main: `vault.revert_run` reverts only a settled run there, so a run
//! nobody settled answers not_found. Green on the head.
//!
//! `cargo test --locked -p oneiron --all-features --test run_revert_unsettled`
#![cfg(feature = "test-support")]

use oneiron::code_run::{
    HostSelfDispatcher, SelfCall, SelfDispatcher, SelfMemoryPutClaimCall,
    SelfMemorySupersedeClaimCall,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::sdk::invoke;
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

/// A vault with no manifest yet, a manifest whose defaults let the owner's
/// run land its claims, and its embedded owner bound under the host root
/// (the run review doors act only for the root owner). As
/// tests/run_changes_list.rs.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 64 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Vault::open_unseeded_for_test(dir.path(), config).map_err(at("open"))?;
        let owner = vault
            .ensure_embedded_owner_actor()
            .map_err(at("embedded owner"))?;
        put_policy_manifest_bytes(&vault, EntityId::now(), &run_policy(owner)?)
            .map_err(at("install the policy"))?;
        // The host root's genesis, then the owner bound under it.
        let issuer = provision_engine_machines(&vault);
        bind_host_owner(&vault, &issuer, owner).map_err(at("owner host binding"))?;
        Ok(Self {
            vault,
            owner,
            _dir: dir,
        })
    }

    /// A fresh PERSON, so no claim of one subject meets another's.
    fn person(&self) -> TestResult<EntityId> {
        let id = EntityId::now();
        self.vault
            .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, b"person")
            .map_err(at("put a PERSON"))?;
        Ok(id)
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

    /// One `self.memory.put_claim` of the run about `subject`, at a fresh id.
    fn put(
        &self,
        run: &HostSelfDispatcher<'_>,
        subject: EntityId,
        value: &str,
        at_time: u64,
    ) -> TestResult<EntityId> {
        let id = EntityId::now();
        run.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id,
            ClaimCandidate::new(
                "profile.favorite_drink",
                ClaimSubject::Entity(subject),
                Value::from(value),
                0.8,
            ),
            range(at_time),
            at_time + 1,
        )))
        .map_err(at("the run's claim put"))?;
        Ok(id)
    }

    /// `vault.revert_run` of the whole run as the vault owner, by verb name.
    fn revert_all(&self, run: &str) -> TestResult<serde_json::Value> {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        invoke(&memory, "vault.revert_run", json!({ "run_id": run }))
            .map_err(at("vault.revert_run"))
    }

    /// The claim's (approval, lifecycle) as stored.
    fn state(&self, id: EntityId) -> TestResult<(String, String)> {
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
        (Value::from("pack_id"), Value::from("run-revert-unsettled")),
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

/// The outcome's compensated changes, each as (change, receipt), in order.
fn compensated(outcome: &serde_json::Value) -> TestResult<Vec<(String, String)>> {
    outcome["compensated"]
        .as_array()
        .ok_or("the outcome names no compensated list")?
        .iter()
        .map(|row| {
            let change = row["change"].as_str().ok_or("a row names no change")?;
            let receipt = row["receipt"].as_str().ok_or("a row names no receipt")?;
            Ok((change.to_owned(), receipt.to_owned()))
        })
        .collect()
}

/// The outcome's changes not undone, each as (change, reason), in order.
fn not_undone(outcome: &serde_json::Value) -> TestResult<Vec<(String, String)>> {
    outcome["not_undone"]
        .as_array()
        .ok_or("the outcome names no not_undone list")?
        .iter()
        .map(|row| {
            let change = row["change"].as_str().ok_or("a row names no change")?;
            let reason = row["reason"].as_str().ok_or("a row names no reason")?;
            Ok((change.to_owned(), reason.to_owned()))
        })
        .collect()
}

/// A run nobody reviewed writes 3 claims that land at Auto; another run
/// writes 1. Undo-all of the first run retracts its 3, newest first, each
/// with its own receipt, and leaves the other run's claim standing. Asked
/// again, it answers with the same 3 receipts and writes nothing new.
#[test]
fn revert_all_undoes_an_unsettled_runs_changes() -> TestResult {
    let f = Fixture::open()?;
    let run = f.run("run-revert-a")?;
    let other = f.run("run-revert-b")?;
    let mut ours = Vec::new();
    for (value, at_time) in [("sencha", 10), ("matcha", 12), ("genmaicha", 14)] {
        let subject = f.person()?;
        ours.push(f.put(&run, subject, value, at_time)?);
    }
    let theirs = f.put(&other, f.person()?, "oolong", 16)?;
    for id in ours.iter().chain([&theirs]) {
        assert_eq!(
            f.state(*id)?,
            ("auto".to_owned(), "active".to_owned()),
            "each run claim lands at Auto"
        );
    }

    let outcome = f.revert_all("run-revert-a")?;
    assert_eq!(outcome["run_id"], "run-revert-a");
    let undone = compensated(&outcome)?;
    assert_eq!(
        undone
            .iter()
            .map(|(change, _)| change.clone())
            .collect::<Vec<_>>(),
        ours.iter().rev().map(EntityId::to_hex).collect::<Vec<_>>(),
        "every change of the run, newest first"
    );
    assert!(
        undone
            .iter()
            .all(|(_, receipt)| receipt.starts_with("gate:")),
        "each compensation has its own receipt: {undone:?}"
    );
    assert_eq!(not_undone(&outcome)?, Vec::new());
    for id in &ours {
        assert_eq!(
            f.state(*id)?.1,
            "retracted",
            "the run's claim is taken back"
        );
    }
    assert_eq!(f.state(theirs)?.1, "active", "another run's claim stands");

    let again = f.revert_all("run:run-revert-a")?;
    assert_eq!(
        compensated(&again)?,
        undone,
        "a repeat answers with the kept receipts"
    );
    assert_eq!(not_undone(&again)?, Vec::new());
    Ok(())
}

/// A run nobody reviewed writes 2 claims. Another run then supersedes the
/// first with its own claim. Undo-all of the first run takes back the second
/// claim, keeps the first under the later claim that rests on it, and
/// reports it as dependent.
#[test]
fn revert_all_keeps_and_reports_a_later_change_on_a_runs_claim() -> TestResult {
    let f = Fixture::open()?;
    let run = f.run("run-revert-kept")?;
    let later = f.run("run-revert-later")?;
    let subject = f.person()?;
    let first = f.put(&run, subject, "sencha", 10)?;
    let second = f.put(&run, f.person()?, "matcha", 12)?;
    let replacement = f.put(&later, subject, "hojicha", 14)?;
    later
        .dispatch(SelfCall::MemorySupersedeClaim(
            SelfMemorySupersedeClaimCall::new(replacement, first, 20),
        ))
        .map_err(at("the later run's supersede"))?;
    assert_eq!(f.state(first)?.1, "superseded");

    let outcome = f.revert_all("run-revert-kept")?;
    assert_eq!(
        compensated(&outcome)?
            .into_iter()
            .map(|(change, _)| change)
            .collect::<Vec<_>>(),
        vec![second.to_hex()],
        "only the claim nothing rests on is taken back"
    );
    assert_eq!(
        not_undone(&outcome)?,
        vec![(first.to_hex(), "dependent".to_owned())],
        "the claim a later change rests on is kept and reported"
    );
    assert_eq!(f.state(second)?.1, "retracted");
    assert_eq!(
        f.state(first)?.1,
        "superseded",
        "the run's first claim is kept"
    );
    assert_eq!(f.state(replacement)?.1, "active", "the later change stands");
    Ok(())
}
