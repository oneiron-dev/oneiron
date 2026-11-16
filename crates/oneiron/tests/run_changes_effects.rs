//! ARCH-0040 #revert-run (REV-2), design RUNCHANGES-3 row X (Engine 13 Nov
//! 10:30): a run's external effects join its change journal. Each gate
//! receipt an effect the run asks records is recorded under the run in the
//! receipt's own write, as a `connector.outbound.schedule` through the
//! outbound chokepoint's held admission does. The vault owner's run cancels
//! the owner's own TASK on the owner's proof, with no gate asked
//! (OWNER-SOFT-CANCEL, #8097), so no receipt stands for it: the journal
//! records an `owner_task_cancel` change naming the TASK in the cancel's
//! write (ruling RUNCHANGES-OWNER-CANCEL-IN-RUN = B, 16 Nov). The journal
//! lists each change beside the run's other changes, in write order, and
//! `vault.revert_run` of a run nobody settled never replays one: it reports
//! an effect that ran as one-way and one the gate held or refused as never
//! landed.
//!
//! The run calls the verbs through its host's verb door, which serves each
//! call on the owner's memory bound to the run's own write origin, as a
//! host's door does.
//!
//! Red on main: no effect receipt joins a run's journal, so the runs list
//! none, and the revert of a run that only asked effects answers not_found.
//! Red with the owner's gate-free cancel and no journal for it: the run lists
//! its send only, and the revert reports no cancel. Green on the head.
//!
//! Review round 2 of #8213: a held dispatch send names no held call, so a
//! pass in no run that sends it answers its listed receipt; and a held call
//! the consent sweep minted carries its adopting caller's run. Red on this
//! head without those two fixes: the sent send reads never landed, and the
//! adopted call names no run.
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
use oneiron::test_doors::run_changes::{
    append_binding_decision, append_effect_receipt, journal_run_effect,
    sweep_minted_call_adopted_run,
};
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
/// pins install them (tests/gate_pins_claim_producers.rs). The manifest
/// holds no grant for the `tasks` channel: the owner's run cancels the
/// owner's own TASK on the owner's proof, which asks no gate.
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

/// The effects the run lists, in order: an external effect by its gate
/// receipt, an owner's gate-free TASK cancel by its TASK.
fn effects(f: &Fixture, run: &str) -> TestResult<Vec<(String, String)>> {
    let mut listed = Vec::new();
    for change in f.changes(run)? {
        let (kind, field) = match change["kind"].as_str() {
            Some(kind @ "external_effect") => (kind, "receipt_ref"),
            Some(kind @ "owner_task_cancel") => (kind, "task_ref"),
            _ => continue,
        };
        let named = change[field].as_str().ok_or("an effect names no ref")?;
        listed.push((kind.to_owned(), named.to_owned()));
    }
    Ok(listed)
}

/// The change ref of the owner's TASK cancel the run lists: the id the
/// cancel took for itself, which a revert reports it by.
fn owner_cancel_of(f: &Fixture, run: &str) -> TestResult<String> {
    let changes = f.changes(run)?;
    let cancel = changes
        .iter()
        .find(|change| change["kind"] == "owner_task_cancel")
        .ok_or_else(|| format!("the run lists no owner's TASK cancel: {changes:?}"))?;
    Ok(cancel["cancel_ref"]
        .as_str()
        .ok_or("the cancel names no cancel_ref")?
        .to_owned())
}

/// The owner's run cancels the owner's TASK at once and asks no gate.
fn assert_gate_free(cancelled: &serde_json::Value) {
    assert_eq!(
        cancelled["approval"], "auto",
        "the owner's run cancels the owner's TASK at once: {cancelled}"
    );
    assert!(
        cancelled["gate_decision_ref"].is_null(),
        "the owner's own cancel asks no gate: {cancelled}"
    );
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
/// The run lists its send's receipt, then its gate-free cancel of the TASK,
/// in write order; the other run lists its own send only, and the owner's
/// joins neither.
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
    assert_gate_free(&cancelled);
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
        vec![
            ("external_effect".to_owned(), receipt_of(&sent)?),
            ("owner_task_cancel".to_owned(), task),
        ],
        "the send's receipt, then the cancel of the TASK"
    );
    assert_eq!(
        effects(&f, "run:run-effects-other")?,
        vec![("external_effect".to_owned(), receipt_of(&theirs)?)],
        "the other run's send only"
    );
    let own = receipt_of(&own)?;
    assert!(
        listed.iter().all(|(_, named)| *named != own),
        "the owner's own send joins no run"
    );
    Ok(())
}

/// A run nobody reviewed schedules a send and cancels the owner's TASK.
/// Undo-all of the run replays and takes back neither: it reports the
/// cancel, which ran on the owner's proof, as one-way, and the send as its
/// gate answered it, one-way if let run and never landed if held. Asked
/// again, it answers the same.
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
    assert_gate_free(&cancelled);
    let (send, cancel) = (
        receipt_of(&sent)?,
        owner_cancel_of(&f, "run-effects-revert")?,
    );

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

/// Two held calls of one AlwaysAsk tool that differ only in their arguments
/// share one effect binding, which names no call, so the gate hands the
/// second call the first call's pending receipt
/// (`gate_decision_matches_pending_candidate`). The run lists that receipt
/// for its first call and folds the first call's answer into it; it lists
/// the second call's answer for itself. Each reads its own call's answer:
/// the first call ran, so the revert reports it one-way, though the newest
/// decision on the binding is the second call's refusal, which never
/// landed. An effect whose gate input names no call folds its answer by its
/// binding, as before.
#[test]
fn a_runs_two_held_calls_of_one_binding_list_apart_under_their_own_answers() -> TestResult {
    let f = Fixture::open()?;
    let run = "run-effects-calls";
    let binding = b"one AlwaysAsk tool's effect binding".as_slice();
    let (first, second) = ("a1".repeat(32), "b2".repeat(32));
    let held = append_effect_receipt(&f.vault, "pending", binding)?;
    journal_run_effect(&f.vault, run, &held, Some(first.as_str()))?;
    let ran = append_effect_receipt(&f.vault, "allow", binding)?;
    journal_run_effect(&f.vault, run, &ran, Some(first.as_str()))?;
    journal_run_effect(&f.vault, run, &held, Some(second.as_str()))?;
    let refused = append_effect_receipt(&f.vault, "deny", binding)?;
    journal_run_effect(&f.vault, run, &refused, Some(second.as_str()))?;

    let effect = |receipt: &str| ("external_effect".to_owned(), receipt.to_owned());
    assert_eq!(
        effects(&f, run)?,
        vec![effect(&held), effect(&refused)],
        "the first call's receipt, then the second call's answer"
    );
    let outcome = f.revert_all(run)?;
    assert_eq!(
        rows(&outcome, "not_undone", "reason")?,
        vec![
            (refused, "not_landed".to_owned()),
            (held, "one_way".to_owned()),
        ],
        "newest first, each under its own call's answer"
    );
    assert!(rows(&outcome, "compensated", "receipt")?.is_empty());

    let plain = "run-effects-binding";
    let binding = b"a send's own effect binding".as_slice();
    let sent = append_effect_receipt(&f.vault, "pending", binding)?;
    journal_run_effect(&f.vault, plain, &sent, None)?;
    let answer = append_effect_receipt(&f.vault, "allow", binding)?;
    journal_run_effect(&f.vault, plain, &answer, None)?;
    assert_eq!(
        effects(&f, plain)?,
        vec![effect(&sent)],
        "one effect, its answer folded"
    );
    assert_eq!(
        rows(&f.revert_all(plain)?, "not_undone", "reason")?,
        vec![(sent, "one_way".to_owned())]
    );
    Ok(())
}

/// A run schedules a send its gate holds. A pass no run asks then sends it:
/// the connector-send executor dispatches the due send with no run, and its
/// gate records the answer on the send's own effect binding. The run lists
/// the held receipt once, and reads it by the newest decision on its
/// binding (FIX 11478): the send went out, so the revert reports it one-way.
/// A dispatch send names no held call, so no call's answer, which no
/// run-less pass journals, stands in for it.
#[test]
fn a_runs_held_send_reads_landed_once_a_pass_in_no_run_sends_it() -> TestResult {
    let f = Fixture::open()?;
    let run = f.run("run-effects-sent")?;
    let sent = f.call(
        &run,
        "connector.outbound.schedule",
        send_to("owen.sent@example.com"),
    )?;
    assert_eq!(
        sent["gate_outcome"], "pending",
        "the gate holds the send: {sent}"
    );
    let held = receipt_of(&sent)?;
    let answer = append_binding_decision(&f.vault, &held, "allow")?;

    let listed = effects(&f, "run-effects-sent")?;
    assert_eq!(
        listed,
        vec![("external_effect".to_owned(), held.clone())],
        "the held receipt, once: the executor's pass joins no run"
    );
    assert!(listed.iter().all(|(_, named)| *named != answer));
    let outcome = f.revert_all("run-effects-sent")?;
    let reported: Vec<_> = rows(&outcome, "not_undone", "reason")?
        .into_iter()
        .filter(|(change, _)| *change == held)
        .collect();
    assert_eq!(
        reported,
        vec![(held.clone(), "one_way".to_owned())],
        "the send went out: one-way, not never landed"
    );
    assert!(
        rows(&outcome, "compensated", "receipt")?
            .iter()
            .all(|(change, _)| *change != held),
        "the send is not taken back"
    );
    Ok(())
}

/// The consent sweep mints a held call's row anew when the call's own row
/// was lost: the original pass's run is unknown to it. The same caller's
/// call adopts that row, and with it the run its write binds, so the
/// resume's gate receipts join that run's journal (the drive hands the row's
/// run to the chokepoint). A caller in no run leaves the row in none.
#[test]
fn a_sweep_minted_call_adopted_by_a_runs_caller_carries_that_run() -> TestResult {
    assert_eq!(
        sweep_minted_call_adopted_run(Some("run-effects-adopted")),
        Some("run-effects-adopted".to_owned()),
        "the adopting caller's run"
    );
    assert_eq!(sweep_minted_call_adopted_run(None), None);
    Ok(())
}
