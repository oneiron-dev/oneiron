//! ARCH-0040 #revert-run (REV-2), ruling RUNCHANGES-EDGE-REF = A (13 Nov): a
//! code run's edge joins its change journal. The run's edge trap writes the
//! edge's `edge.provenance` Claim in the edge's own write, under the run's
//! actor, and journals it as the run's edge change. Undo-all of a run nobody
//! settled takes the edge back through the existing provenance retraction:
//! the Claim is retracted, a semantic edge reads the retracted stamp, and a
//! structural edge keeps its stored value.
//!
//! The run is the owner's code run; its edges go through the code-mode
//! bridge (`self.memory.put_edge`), the one trap every code-run edge takes.
//!
//! Red on the base (runchanges-5): the edge trap writes no provenance Claim,
//! so the run's journal lists no edge. Green on the head.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test run_changes_edges`
#![cfg(feature = "test-support")]

use oneiron::code_run::{HostSelfDispatcher, SelfCall, SelfDispatcher, SelfMemoryPutEdgeCall};
use oneiron::edge::EdgeConfirmationStatus;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_support::{
    bind_host_owner, provision_engine_machines, put_policy_manifest_bytes,
};
use oneiron::{
    ClaimSource, ClaimSubject, EdgeActorClass, EdgeInfo, EdgeKind, EntityId, TimeRange, Vault,
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

/// An owned vault (its writer lease is what the owner's verb doors ask for),
/// its shipped policy manifest replaced at its own id by one whose defaults
/// let the owner's run land its writes, and its embedded owner bound under
/// the host root (the run review doors act only for the root owner). As
/// tests/run_revert_unsettled.rs.
struct Fixture {
    vault: Vault,
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
        Ok(Self {
            vault,
            owner,
            _dir: dir,
        })
    }

    /// A fresh PERSON, so no edge of one test meets another's.
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

    /// One `self.memory.put_edge` of the run.
    fn put_edge(
        run: &HostSelfDispatcher<'_>,
        src: EntityId,
        kind: EdgeKind,
        tgt: EntityId,
    ) -> TestResult {
        run.dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
            src, kind, tgt, 0.7,
        )))
        .map_err(at("the run's edge put"))?;
        Ok(())
    }

    /// One owner verb call by name.
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

    /// The provenance Claim's (subject, approval, lifecycle) as stored.
    fn record(&self, id: EntityId) -> TestResult<(ClaimSubject, String, String)> {
        let body = self
            .vault
            .get_claim(&id)
            .map_err(at("read a provenance claim"))?
            .ok_or("the provenance claim reads nothing")?;
        if body.predicate != "edge.provenance" {
            return Err(format!("an edge.provenance claim, not {}", body.predicate).into());
        }
        Ok((
            body.subject,
            body.approval.as_str().to_owned(),
            body.lifecycle.as_str().to_owned(),
        ))
    }

    /// The stored edge `src -kind-> tgt`.
    fn edge(&self, src: EntityId, kind: EdgeKind, tgt: EntityId) -> TestResult<EdgeInfo> {
        self.vault
            .edges_out(&src)
            .map_err(at("read the edges out"))?
            .into_iter()
            .find(|edge| edge.kind == kind && edge.target == tgt)
            .ok_or_else(|| format!("no {kind:?} edge is stored").into())
    }
}

/// The provenance Claim a listed edge change names.
fn provenance_of(change: &serde_json::Value) -> TestResult<EntityId> {
    if change["kind"] != "edge" {
        return Err(format!("an edge change: {change}").into());
    }
    let id = change["provenance_ref"]
        .as_str()
        .ok_or("the change names no provenance claim")?;
    Ok(EntityId::from_hex(id)?)
}

/// Defaults that land the owner's Generated writes, as the code-run gate
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
        (Value::from("pack_id"), Value::from("run-changes-edges")),
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
fn outcome_rows(
    outcome: &serde_json::Value,
    key: &str,
    value: &str,
) -> TestResult<Vec<(String, String)>> {
    outcome[key]
        .as_array()
        .ok_or_else(|| format!("the outcome names no {key} list"))?
        .iter()
        .map(|row| {
            let change = row["change"].as_str().ok_or("a row names no change")?;
            let field = row[value].as_str().ok_or("a row names no value")?;
            Ok((change.to_owned(), field.to_owned()))
        })
        .collect()
}

/// A run nobody settled puts a semantic `mentions` edge and a structural
/// `refs` edge; another run puts one edge. Each edge lands with its
/// provenance Claim under its run, and the run's journal lists both as edge
/// changes, in write order. Undo-all of the first run retracts both Claims,
/// newest first, each with its own receipt: the `mentions` edge then reads
/// the retracted stamp, and the `refs` edge keeps its stored value. The other
/// run's edge Claim stands, and a repeat answers with the kept receipts.
#[test]
fn revert_all_takes_back_a_code_run_edge() -> TestResult {
    let f = Fixture::open()?;
    let run = f.run("run-edges-revert")?;
    let other = f.run("run-edges-other")?;
    let (owen, yuki, ada) = (f.person()?, f.person()?, f.person()?);
    Fixture::put_edge(&run, owen, EdgeKind::Mentions, yuki)?;
    Fixture::put_edge(&run, owen, EdgeKind::Refs, ada)?;
    Fixture::put_edge(&other, yuki, EdgeKind::Mentions, ada)?;

    let listed = f.changes("run-edges-revert")?;
    assert_eq!(
        listed.len(),
        2,
        "the run's two edges are listed: {listed:?}"
    );
    let mentions = provenance_of(&listed[0])?;
    let refs = provenance_of(&listed[1])?;
    assert_eq!(
        f.record(mentions)?,
        (
            ClaimSubject::Edge {
                source: owen,
                kind: EdgeKind::Mentions,
                target: yuki,
            },
            "auto".to_owned(),
            "active".to_owned()
        ),
        "the mentions edge's provenance Claim stands"
    );
    assert_eq!(
        f.record(refs)?,
        (
            ClaimSubject::Edge {
                source: owen,
                kind: EdgeKind::Refs,
                target: ada,
            },
            "auto".to_owned(),
            "active".to_owned()
        ),
        "the refs edge's provenance Claim stands"
    );
    assert_eq!(
        f.edge(owen, EdgeKind::Mentions, yuki)?.provenance,
        None,
        "the run's edge keeps the value it put"
    );
    let theirs = f.changes("run-edges-other")?;
    assert_eq!(
        theirs.len(),
        1,
        "the other run's edge is its own: {theirs:?}"
    );
    let theirs = provenance_of(&theirs[0])?;

    let outcome = f.revert_all("run-edges-revert")?;
    assert_eq!(outcome["run_id"], "run-edges-revert");
    let undone = outcome_rows(&outcome, "compensated", "receipt")?;
    assert_eq!(
        undone
            .iter()
            .map(|(change, _)| change.clone())
            .collect::<Vec<_>>(),
        vec![refs.to_hex(), mentions.to_hex()],
        "both edges of the run, newest first"
    );
    assert!(
        undone
            .iter()
            .all(|(_, receipt)| receipt.starts_with("gate:")),
        "each compensation has its own receipt: {undone:?}"
    );
    assert_eq!(outcome_rows(&outcome, "not_undone", "reason")?, Vec::new());
    for id in [mentions, refs] {
        assert_eq!(
            f.record(id)?.2,
            "retracted",
            "the run's edge record is taken back"
        );
    }
    let flags = f
        .edge(owen, EdgeKind::Mentions, yuki)?
        .provenance
        .ok_or("the retracted edge carries no stamp")?;
    assert_eq!(flags.confirmation_status, EdgeConfirmationStatus::Retracted);
    assert_eq!(flags.actor_class, EdgeActorClass::Human);
    assert_eq!(
        f.edge(owen, EdgeKind::Refs, ada)?.provenance,
        None,
        "a structural edge keeps its stored value"
    );
    assert_eq!(f.record(theirs)?.2, "active", "another run's edge stands");

    let again = f.revert_all("run:run-edges-revert")?;
    assert_eq!(
        outcome_rows(&again, "compensated", "receipt")?,
        undone,
        "a repeat answers with the kept receipts"
    );
    Ok(())
}
