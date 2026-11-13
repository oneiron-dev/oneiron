//! ARCH-0040 #revert-run (REV-2), design RUNCHANGES-3 row N and ruling
//! RUNCHANGES-NOTE-UNDO = A (Engine 13 Nov 10:30): a run's NOTE forks join
//! its change journal. A fork a run opens (`vault.notes.fork`, or a
//! `vault.notes.edit` that does not land in place) names the run, and is
//! recorded under it in the fork's own write. Whoever lands such a fork, its
//! landing keeps the undo that restores the revision from before it on that
//! run's journal row, in the landing's own write. `vault.revert_run` of a
//! run nobody settled then restores the NOTE, as ARCH-0040:314 says, and
//! reports a fork still pending as not landed.
//!
//! A run review reads a fork decided before it (landed or rejected) by the
//! receipt that decided it; before, it refused the whole review with
//! not_found "no pending NOTE fork has that ref" (note/run_review.rs).
//!
//! The run calls each verb through its host's verb door, which serves each
//! call on the owner's memory bound to the run's own write origin, as a
//! host's door does.
//!
//! Red on the base (runchanges-4-effects): no fork joins a run's journal, so
//! the run lists no change and the revert answers not_found; the review of a
//! decided fork answers not_found. Green on the head.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test run_changes_notes`
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, HostSelfDispatcher, RunCall,
    RunSpeechDestination, SelfAgentVerbCall, SelfCall, SelfDispatchOutcome, SelfDispatcher,
    SelfEffect,
};
use oneiron::memory::HostWriteOrigin;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{AgentVerb, invoke};
use oneiron::test_support::{
    bind_host_owner, provision_engine_machines, put_policy_manifest_bytes,
};
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

    /// The run's call of `verb`, as its guest makes it, and its output.
    fn call(
        &self,
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
        (Value::from("pack_id"), Value::from("run-changes-notes")),
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

/// The NOTE's version now, as `vault.notes.read` names it.
fn version(f: &Fixture, note: EntityId) -> TestResult<serde_json::Value> {
    let read = f.owner_call("vault.notes.read", json!({ "note_ref": note.to_hex() }))?;
    Ok(read["value"]["version"].clone())
}

/// The run's `vault.notes.fork` of `note` at its version now, under `edit`,
/// and the fork's ref.
fn fork(
    f: &Fixture,
    run: &HostSelfDispatcher<'_>,
    note: EntityId,
    edit: serde_json::Value,
) -> TestResult<String> {
    let forked = f.call(
        run,
        "vault.notes.fork",
        json!({ "note_ref": note.to_hex(), "base": version(f, note)?, "edit": edit }),
    )?;
    Ok(forked["record"]["fork_ref"]
        .as_str()
        .ok_or("the fork names no ref")?
        .to_owned())
}

/// A whole-text edit of `note` to `text`, at its version now: a fork of it
/// merges.
fn whole_text(f: &Fixture, note: EntityId, text: &str) -> TestResult<serde_json::Value> {
    Ok(json!({
        "kind": "whole_text",
        "text": text,
        "timeout_ms": 5000,
        "base": version(f, note)?,
    }))
}

/// The run's `vault.notes.proposals.open` of its `fork` of `note`: the
/// proposal it opened, with the forks that landed and those that wait.
fn open_proposal(
    f: &Fixture,
    run: &HostSelfDispatcher<'_>,
    note: EntityId,
    fork: &str,
) -> TestResult<serde_json::Value> {
    f.call(
        run,
        "vault.notes.proposals.open",
        json!({
            "forks": [{ "note_ref": note.to_hex(), "fork_ref": fork }],
            "explainer": "The run's edit.",
        }),
    )
}

/// The journal row of the run's `fork` of `note`.
fn note_change(note: EntityId, fork: &str) -> serde_json::Value {
    json!({ "kind": "note", "note_ref": note.to_hex(), "fork_ref": fork })
}

/// A run nobody reviewed forks one NOTE and lands the fork itself, through
/// its own proposal (the owner's run lands under the owner's grant), and
/// forks a second NOTE with a rewrite it leaves pending. The run lists both
/// forks, in write order. Undo-all of the run restores the first NOTE's
/// text from before the run, under the owner's compensation receipt, and
/// reports the pending fork as not landed; the second NOTE keeps its text.
/// Asked again, it answers the same receipt and writes nothing.
#[test]
fn revert_all_restores_a_note_an_unsettled_run_edited() -> TestResult {
    let f = Fixture::open()?;
    let run = f.run("run-notes-revert")?;
    let (edited, pending) = (f.note("The first line.")?, f.note("The other note.")?);
    let landed = fork(
        &f,
        &run,
        edited,
        whole_text(&f, edited, "The first line. The run's line.")?,
    )?;
    let opened = open_proposal(&f, &run, edited, &landed)?;
    assert_eq!(
        opened["landed"][0]["fork_ref"], landed,
        "the run's own proposal lands its fork"
    );
    assert_eq!(f.text(edited)?, "The first line. The run's line.");
    let rewrite = fork(
        &f,
        &run,
        pending,
        json!({ "kind": "rewrite", "text": "A rewritten note." }),
    )?;

    assert_eq!(
        f.changes("run-notes-revert")?,
        vec![note_change(edited, &landed), note_change(pending, &rewrite)],
        "both forks, in write order"
    );

    let outcome = f.revert_all("run-notes-revert")?;
    let compensated = rows(&outcome, "compensated", "receipt")?;
    assert_eq!(
        compensated
            .iter()
            .map(|(change, _)| change.as_str())
            .collect::<Vec<_>>(),
        vec![landed.as_str()],
        "the landed fork is taken back"
    );
    assert!(compensated[0].1.starts_with("gate:"));
    assert_eq!(
        rows(&outcome, "not_undone", "reason")?,
        vec![(rewrite.clone(), "not_landed".to_owned())]
    );
    assert_eq!(
        f.text(edited)?,
        "The first line.",
        "the revision from before the run is restored"
    );
    assert_eq!(f.text(pending)?, "The other note.");

    let again = f.revert_all("run:run-notes-revert")?;
    assert_eq!(rows(&again, "compensated", "receipt")?, compensated);
    assert_eq!(f.text(edited)?, "The first line.");
    Ok(())
}

/// A run lands a fork of one NOTE through its own proposal, and opens a
/// rewrite of a second NOTE that the owner then rejects. The owner's review
/// of the run, over both forks, reads the first as landed and the second as
/// rejected, where it refused before. The owner settles that review; the
/// landed fork's undo is the one its landing kept on the run's journal, so
/// the revert of the settled run restores the first NOTE.
#[test]
fn run_review_reads_a_decided_note_fork() -> TestResult {
    let f = Fixture::open()?;
    let run = f.run("run-notes-review")?;
    let (merged, rejected) = (f.note("A merged note.")?, f.note("A rejected note.")?);
    let landed = fork(
        &f,
        &run,
        merged,
        whole_text(&f, merged, "A merged note, edited by the run.")?,
    )?;
    open_proposal(&f, &run, merged, &landed)?;
    let rewrite = fork(
        &f,
        &run,
        rejected,
        json!({ "kind": "rewrite", "text": "A rewrite the owner rejects." }),
    )?;
    let proposal = open_proposal(&f, &run, rejected, &rewrite)?;
    assert_eq!(
        proposal["waiting"][0]["record"]["fork_ref"], rewrite,
        "a rewrite waits for a switch"
    );
    f.owner_call(
        "vault.notes.proposals.reject",
        json!({ "proposal_ref": proposal["proposal_ref"] }),
    )?;

    let changes = vec![
        note_change(merged, &landed),
        note_change(rejected, &rewrite),
    ];
    let review = f.owner_call(
        "vault.runs.review",
        json!({ "run_id": "run-notes-review", "changes": changes }),
    )?;
    let verdicts: Vec<(String, String)> = review["changes"]
        .as_array()
        .ok_or("the review names no changes")?
        .iter()
        .map(|row| {
            (
                row["change"].as_str().unwrap_or_default().to_owned(),
                row["verdict"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        verdicts,
        vec![
            (landed.clone(), "landed".to_owned()),
            (rewrite.clone(), "rejected".to_owned()),
        ],
        "each decided fork reads the verdict that decided it"
    );
    assert_eq!(f.changes("run-notes-review")?, changes);

    let settlement = f.owner_call(
        "vault.runs.settle",
        json!({
            "review": { "run_id": "run-notes-review", "changes": changes },
            "review_id": review["review_id"],
            "decision": "approve",
        }),
    )?;
    assert_eq!(settlement["changes"][0]["verdict"], "landed");
    assert_eq!(settlement["changes"][1]["verdict"], "rejected");

    let outcome = f.revert_all("run-notes-review")?;
    assert_eq!(
        rows(&outcome, "compensated", "receipt")?
            .into_iter()
            .map(|(change, _)| change)
            .collect::<Vec<_>>(),
        vec![landed],
        "the settled landing's undo restores its NOTE"
    );
    assert_eq!(
        rows(&outcome, "not_undone", "reason")?,
        vec![(rewrite, "not_landed".to_owned())]
    );
    assert_eq!(f.text(merged)?, "A merged note.");
    assert_eq!(f.text(rejected)?, "A rejected note.");
    Ok(())
}
