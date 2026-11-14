//! ARCH-0040 #revert-run (REV-2), design RUNCHANGES-3 row X (Engine 13 Nov
//! 10:30): a run's external effects join its change journal. Each gate
//! receipt an effect the run asks records is recorded under the run in the
//! receipt's own write: a `connector.outbound.schedule` through the outbound
//! chokepoint's held admission, and a `cancel` of a TASK through its own
//! external-effect gate. The journal lists each receipt beside the run's
//! other changes, in write order, and `vault.revert_run` of a run nobody
//! settled never replays one: it reports an effect that ran as one-way and
//! one the gate held or refused as never landed.
//!
//! The run calls the verbs through its host's verb door, which serves each
//! call on the owner's memory bound to the run's own write origin, as a
//! host's door does.
//!
//! Red on the base (runchanges-4-deletion): no effect receipt joins a run's
//! journal, so the runs list none, and the revert of a run that only asked
//! effects answers not_found. Green on the head.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test run_changes_effects`
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
use oneiron_authority::federation::scope_codec::{effect_preset, encode_scope_value};
use rmpv::Value;
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

/// An owned vault (its writer lease is what the owner's verb doors ask for,
/// `Memory::embedded_owner`) that carries this install's signing keys and a
/// live machine profile, its shipped policy manifest replaced at its own id
/// by one whose defaults let the owner's run write its claims, and its
/// embedded owner bound under the host root (the run review doors act only
/// for the root owner). As tests/run_changes_deletion.rs.
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

    /// The run's call of `verb`, as its guest makes it: the verb's answer.
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
            other => Err(format!("{verb} answered no verb output: {other:?}").into()),
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
/// pins install them (tests/gate_pins_claim_producers.rs), and one scoped
/// grant that lets the owner's TASK cancel run. Without a grant for it the
/// cancel's external-effect gate asks (an irreversible effect, and no
/// authority for the `tasks` channel), under the shipped manifest too: the
/// crate's own cancel tests mint a standing grant for it first.
fn run_policy(actor: EntityId) -> TestResult<Vec<u8>> {
    let axes = || {
        Value::Map(vec![
            (Value::from("criticality"), Value::from("normal")),
            (Value::from("sensitivity"), Value::from("normal")),
        ])
    };
    let cancel_grant = Value::Map(vec![
        (Value::from("actor_class"), Value::from("human")),
        (Value::from("actor_ref"), Value::from(actor.to_hex())),
        (Value::from("effector"), Value::from("external:cancel")),
        (
            Value::from("scope"),
            encode_scope_value(&effect_preset()).map_err(at("the effect scope"))?,
        ),
        (
            Value::from("selectors"),
            Value::Map(vec![(Value::from("channel"), Value::from("tasks"))]),
        ),
    ]);
    let manifest = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(oneiron_store::policy_record::POLICY_SCHEMA_VERSION),
        ),
        (Value::from("pack_id"), Value::from("run-changes-effects")),
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
        (
            Value::from("scoped_grants"),
            Value::Array(vec![cancel_grant]),
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

/// A `connector.outbound.schedule` of one send to `target` on
/// `email_resend`, as a guest asks it. The channel has a `send` verb and no
/// built-in pack names it: a seeded vault refuses a channel a built-in pack
/// names (`email`) until that pack is installed Active and its connection
/// checked (OF-519), which no test can ready (tests/outbound_undo_send.rs).
fn send_to(target: &str) -> serde_json::Value {
    json!({
        "verb": "send",
        "channel": "email_resend",
        "target": target,
        "idempotency_key": format!("run-changes-effects:{target}"),
        "trigger": "agent_immediate",
        "trigger_ref": "run-changes-effects",
    })
}

/// The gate receipt a verb's answer names.
fn receipt_of(answer: &serde_json::Value) -> TestResult<String> {
    Ok(answer["gate_decision_ref"]
        .as_str()
        .ok_or_else(|| format!("the answer names no gate receipt: {answer}"))?
        .to_owned())
}

/// The external-effect receipts the run lists, in order.
fn effects(f: &Fixture, run: &str) -> TestResult<Vec<String>> {
    f.changes(run)?
        .iter()
        .filter(|change| change["kind"] == "external_effect")
        .map(|change| {
            Ok(change["receipt_ref"]
                .as_str()
                .ok_or("an effect names no receipt")?
                .to_owned())
        })
        .collect()
}

/// The owner's own TASK, made outside any run.
fn owner_task(f: &Fixture) -> TestResult<String> {
    let created = f.owner_call(
        "tasks.create",
        json!({ "spec": { "summary": "tidy the week's notes" } }),
    )?;
    Ok(created["task_ref"]
        .as_str()
        .ok_or_else(|| format!("no created task: {created}"))?
        .to_owned())
}

/// What a revert reports for an effect whose gate answered `outcome`: one
/// the gate let run is one-way, any other never landed.
fn reported_for(outcome: &serde_json::Value) -> &'static str {
    match outcome.as_str() {
        Some("allow") => "one_way",
        _ => "not_landed",
    }
}

/// A run schedules a send and cancels the owner's TASK. Another run
/// schedules a send of its own, and the owner schedules one outside any run.
/// The run lists its two effect receipts, in write order; the other run
/// lists its own only, and the owner's joins neither.
#[test]
fn run_changes_list_names_a_runs_scheduled_send_and_cancel() -> TestResult {
    let f = Fixture::open()?;
    let run = f.run("run-effects-list")?;
    let other = f.run("run-effects-other")?;
    let task = owner_task(&f)?;
    let sent = f.call(
        &run,
        "connector.outbound.schedule",
        send_to("owen@example.com"),
    )?;
    let cancelled = f.call(&run, "cancel", json!({ "task_ref": task }))?;
    let theirs = f.call(
        &other,
        "connector.outbound.schedule",
        send_to("yuki@example.com"),
    )?;
    let own = f.owner_call(
        "connector.outbound.schedule",
        send_to("yuki.home@example.com"),
    )?;

    let listed = effects(&f, "run-effects-list")?;
    assert_eq!(
        listed,
        vec![receipt_of(&sent)?, receipt_of(&cancelled)?],
        "the send's receipt, then the cancel's"
    );
    assert_eq!(
        effects(&f, "run:run-effects-other")?,
        vec![receipt_of(&theirs)?],
        "the other run's send only"
    );
    assert!(
        !listed.contains(&receipt_of(&own)?),
        "the owner's own send joins no run"
    );
    Ok(())
}

/// A run nobody reviewed schedules a send and cancels the owner's TASK.
/// Undo-all of the run replays and takes back neither: it reports the
/// cancel, which its gate let run, as one-way, and the send as its gate
/// answered it, one-way if let run and never landed if held. Asked again, it
/// answers the same.
#[test]
fn revert_all_reports_a_runs_effects_without_replaying_them() -> TestResult {
    let f = Fixture::open()?;
    let run = f.run("run-effects-revert")?;
    let task = owner_task(&f)?;
    let sent = f.call(
        &run,
        "connector.outbound.schedule",
        send_to("owen@example.com"),
    )?;
    let cancelled = f.call(&run, "cancel", json!({ "task_ref": task }))?;
    assert_eq!(
        cancelled["approval"], "auto",
        "the owner's run cancels the owner's TASK at once: {cancelled}"
    );
    let (send, cancel) = (receipt_of(&sent)?, receipt_of(&cancelled)?);

    let expected = vec![
        (cancel.clone(), "one_way".to_owned()),
        (send.clone(), reported_for(&sent["gate_outcome"]).to_owned()),
    ];
    for outcome in [
        f.revert_all("run-effects-revert")?,
        f.revert_all("run:run-effects-revert")?,
    ] {
        assert_eq!(outcome["run_id"], "run-effects-revert");
        let compensated = rows(&outcome, "compensated", "receipt")?;
        assert!(
            compensated
                .iter()
                .all(|(change, _)| *change != send && *change != cancel),
            "no effect is taken back: {compensated:?}"
        );
        let reported: Vec<_> = rows(&outcome, "not_undone", "reason")?
            .into_iter()
            .filter(|(change, _)| *change == send || *change == cancel)
            .collect();
        assert_eq!(reported, expected, "newest first");
    }
    Ok(())
}
