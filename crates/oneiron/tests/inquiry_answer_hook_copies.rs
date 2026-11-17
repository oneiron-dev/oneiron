//! UNBUILT3-27 PR 2 (FIX INQUIRY-TASK-ANSWER-RUN-COPIES; canon
//! federation.md #inquiry-keep; Engine ruling INQUIRE-SHAPE Q6 = A): a
//! member's answer to an inquiry kept `task` is "held with the task and
//! bound to the asking actor", so no verb hook reads the member's words, and
//! neither a hook's run record nor the saved answer of a call a hook's ask
//! paused keeps them. PR 1 (#9225) closed the code run's own records; this
//! file pins the two hook writers left.
//!
//! Every hook here is the owner's, bound by the owner's put of a pack, and
//! its body runs on a recording runtime the test installs: it keeps each
//! input the chain hands it and answers a fixed outcome.
//!
//! - `a_post_hook_reads_and_keeps_no_task_held_statement`: a post hook on
//!   `vault.inquire`. The row boundary's post chain (`row_post`, which every
//!   door that runs a row crosses) hands the hook the answer with its
//!   statements withheld, and the hook's run record keeps that input: a
//!   replay (`Vault::hooks_replay`) hands the body the saved input again,
//!   and it holds no statement. The caller still reads the whole answer.
//!   Red on the base: the hook reads the statement and its record keeps it.
//! - `a_post_hook_reads_a_copy_answer_whole`: an answer kept `copy` lands in
//!   the company vault by canon, so its hook reads the statement. Passes on
//!   the base and with the fix.
//! - `a_drained_ask_saves_no_task_held_statement`: a pre hook asks before a
//!   credential caller's `vault.inquire`; the owner answers proceed; the
//!   drain runs the call again through the host's credential check (the
//!   test's answers as the company host's door does once the member
//!   answered) and saves what it returned for the caller's retry, 7 days.
//!   With no answer held for the task, the retry reads the saved answer: no
//!   statement, `statements_withheld`. Red on the base: the saved answer
//!   holds the statement.
//! - `a_drained_ask_retry_reads_the_statements_its_task_holds`: the same,
//!   with the answer held for the caller's open task, as an answered `task`
//!   send holds it: the retry reads the statement back from the task.
//!   Passes on the base (which saves the whole answer) and with the fix.
//! - `a_drained_ask_retry_keeps_what_a_post_hook_redacted` (review of
//!   #9318): the drain's rerun crosses the post chain, and a post hook that
//!   redacted `statements` there leaves only the mark; the retry keeps the
//!   redaction even while the task holds the answer. Passes on the base and
//!   with the fix; failed at the PR's first head, which restored on the
//!   mark alone.
//! - `a_post_hook_that_redacts_keep_leaves_the_statements_withheld` (blind
//!   review round 1 of #9318): a post hook redacts `keep` from the kept
//!   form. The caller's view keeps both stand-ins and no statement: the
//!   statements go back only into an answer that still says it is kept
//!   `task`. Red on the base (the hook reads the whole answer, so the view
//!   keeps the statement) and at the PR head 0edcc19d95 (it restored on the
//!   stand-ins alone).
//! - `a_drained_ask_saves_no_statement_of_an_answer_with_no_keep`: the same
//!   review. A drained rerun whose answer reaches the save with its `keep`
//!   gone, as a post hook that redacted `keep` left it at 0edcc19d95, is
//!   saved withheld, and the retry restores nothing into it even while the
//!   task holds the answer. Red on the base and at 0edcc19d95 (both saved
//!   the answer whole: only `keep` = `task` was withheld).
//!
//! The doors build only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test inquiry_answer_hook_copies`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use oneiron::consent::AuthenticatedOwner;
use oneiron::inquiry::{InquiryStatement, StatementSource};
use oneiron::runtime_hooks::verb::{
    InvocationId, VerbAskCredentialCheck, VerbAskCredentialRef, VerbAskCredentialSource,
    VerbAskCredentialWitness, VerbAskDoor, VerbAskDrainPermit, VerbAskInstrument, VerbAskResumed,
    VerbAskSavedCall, VerbHookStop,
};
use oneiron::runtime_hooks::{HookBodyRun, HookBodyRuntime, HookRunContext};
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::PackInstallDisposition;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::verb_hook_boundary::{row_post, row_pre};
use oneiron::task_verb::{TaskAskHandle, TaskAskOptionId, TaskAskWord, TaskCreateSpec};
use oneiron::test_doors::inquiry as door;
use oneiron::verbs::VERB_TABLE;
use oneiron::{EdgeActorClass, EntityId, Memory, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

/// The member's word, as the member host answered it. Distinct enough that
/// no other byte of a hook's input holds it by chance.
const MEMBER_WORD: &str = "away Thursday afternoon for the clinic visit, member word 9c41";
/// The answer's `valid_until`: 2100-01-01, past any test clock.
const VALID_UNTIL: u64 = 4_102_444_800;
/// The row every hook here is bound to.
const VERB: &str = "vault.inquire";

/// The pack the owner puts, and its one hook.
const PACK: &str = "example.inquiryhook";
const HOOK: &str = "inquiry-read";
const PACK_MD: &str = "---
name: example.inquiryhook
description: One verb hook on vault.inquire the owner binds.
version: 1.0.0
kind: capability
hooks: [\"inquiry-read\"]
---
A pack whose one verb hook reads each inquiry answer.
";
/// The body the recording runtime stands in for: its bytes bind the hook.
const BODY_JS: &str = "return { kind: \"continue\" };\n";

/// A post hook's outcome that hands the result on unchanged.
const CONTINUE: &str = r#"{"kind":"continue"}"#;
/// A pre hook's outcome that pauses the call on the owner's answer.
const ASK: &str = r#"{"kind":"ask","question":"Send this inquiry?"}"#;
/// A post hook's outcome that redacts the answer's `keep`.
const REDACT_KEEP: &str = r#"{"kind":"redact","paths":["/keep"]}"#;

/// The hook sandbox the test installs: it keeps each input it is handed and
/// answers `outcome`.
struct RecordingRuntime {
    outcome: &'static str,
    inputs: Mutex<Vec<String>>,
}

impl RecordingRuntime {
    fn answering(outcome: &'static str) -> Self {
        Self {
            outcome,
            inputs: Mutex::new(Vec::new()),
        }
    }

    fn inputs(&self) -> Vec<String> {
        self.inputs.lock().expect("the inputs").clone()
    }
}

impl HookBodyRuntime for RecordingRuntime {
    fn run_hook(
        &self,
        _body: &str,
        input_json: &str,
        _context: &mut HookRunContext,
        _read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> oneiron::Result<HookBodyRun> {
        self.inputs
            .lock()
            .expect("the inputs")
            .push(input_json.to_owned());
        Ok(HookBodyRun {
            outcome_json: self.outcome.to_owned(),
            fuel_used: None,
            host_calls: 1,
        })
    }
}

/// The host's credential check, as the company host's: it keeps every
/// credential, and runs a drained call again by answering `reply`, as the
/// host's door answers `vault.inquire` once the member answered.
struct AnsweringCheck {
    reply: Value,
}

impl VerbAskCredentialCheck for AnsweringCheck {
    fn retain_in_txn(
        &self,
        _vault: &Vault,
        _txn: &heed::RoTxn<'_>,
        _reference: &VerbAskCredentialRef,
        _witness: &VerbAskCredentialWitness,
    ) -> bool {
        true
    }

    fn resume(&self, _call: VerbAskSavedCall, _drain: VerbAskDrainPermit) -> VerbAskResumed {
        VerbAskResumed::Ran((Ok(self.reply.clone()), None))
    }
}

/// One test's company vault: its owner, the owner's proof, and the
/// recording runtime its verb hooks run on.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    runtime: Arc<RecordingRuntime>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    /// A device vault with its owner, whose verb hooks answer `outcome`.
    fn new(outcome: &'static str) -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let runtime = Arc::new(RecordingRuntime::answering(outcome));
        vault
            .install_hook_runtime(Arc::clone(&runtime) as Arc<dyn HookBodyRuntime>)
            .expect("the recording runtime runs the verb hooks");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            owner,
            owner_proof,
            runtime,
            _directory: directory,
        }
    }

    /// The owner's put of the pack, its one hook on `vault.inquire` in
    /// `phase` with `outcome`; answers the binding's id.
    fn bind_hook(&self, phase: &str, outcome: &str) -> EntityId {
        let hook_md = format!(
            "---\nname: {HOOK}\nversion: 1.0.0\nverbs: [\"{VERB}\"]\nphase: {phase}\noutcomes: [\"{outcome}\"]\n---\nRead each inquiry answer.\n"
        );
        let files = vec![
            HubFile::new("PACK.md", PACK_MD),
            HubFile::new(format!("hooks/{HOOK}/HOOK.md"), hook_md),
            HubFile::new(format!("hooks/{HOOK}/body.js"), BODY_JS),
        ];
        match self.vault.put_pack(&self.owner_proof, files) {
            Ok(PackInstallDisposition::Installed(receipt)) => assert_eq!(receipt.pack_name, PACK),
            other => panic!("the owner's put installs the pack and binds its hook: {other:?}"),
        }
        let bindings = self.vault.pack_hook_bindings().expect("hook bindings");
        let (id, _) = bindings
            .iter()
            .find(|(_, binding)| binding.pack == PACK && binding.hook == HOOK)
            .expect("the owner's hook is bound");
        *id
    }

    /// The owner's `vault.inquire` through the row boundary, a fresh
    /// invocation: its pre chain, then its post chain over `reply`. Answers
    /// the caller's view.
    fn post_chain(&self, reply: &Value) -> Value {
        let memory = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_invocation(InvocationId::mint());
        let pre = row_pre(&memory, &VERB_TABLE, VERB, inquire_args(EntityId::now()))
            .expect("no pre hook stops the call");
        row_post(&self.vault, pre, reply.clone()).expect("the post hook hands the answer on")
    }

    /// The owner as a credential caller (an attested owner at the facade),
    /// under `invocation`, as the host's door builds the caller's handle, so
    /// a hook's ask saves the call for the drain to run again.
    fn credential_caller(&self, invocation: InvocationId) -> Memory<'_> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .for_credential()
            .with_credential_instrument(VerbAskInstrument {
                source: VerbAskCredentialSource::AttestedOwner { holder: self.owner },
                vault: [0xA5; 32],
                ceiling: [0x5A; 32],
            })
            .with_credential_door(VerbAskDoor::Facade { room: None })
            .with_invocation(invocation)
    }

    /// A credential caller's `vault.inquire` for `task`: the pre hook asks,
    /// the owner answers proceed, the drain runs the call again, and the
    /// caller's retry of the same invocation reads what the drain saved.
    /// Answers that saved answer as the retry reads it.
    fn drained_retry(&self, binding: EntityId, task: EntityId) -> Value {
        let invocation = InvocationId::mint();
        let args = inquire_args(task);
        let paused = row_pre(
            &self.credential_caller(invocation),
            &VERB_TABLE,
            VERB,
            args.clone(),
        )
        .err()
        .expect("the pre hook's ask pauses the call");
        let ask = match paused.hook.as_deref() {
            Some(VerbHookStop::Pending { ask, .. }) => {
                EntityId::from_hex(ask).expect("the ask's id")
            }
            other => panic!("the call waits on the hook's ask: {other:?}"),
        };
        self.answer_proceed(binding, ask);
        self.vault.drain_verb_asks().expect("the drain runs");
        let retried = row_pre(&self.credential_caller(invocation), &VERB_TABLE, VERB, args)
            .err()
            .expect("the retry reads the drained call's outcome");
        match retried.hook.as_deref() {
            Some(VerbHookStop::Completed { result, .. }) => result.clone(),
            other => panic!("the retry reads what the drained call returned: {other:?}"),
        }
    }

    /// The owner answers the hook's ask `ask` proceed. The word's result row
    /// is the hook's binding, the ask's question.
    fn answer_proceed(&self, binding: EntityId, ask: EntityId) {
        let mut word = TaskAskWord::new(binding);
        word.option = Some(TaskAskOptionId::new("proceed").expect("the proceed option"));
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .tasks_answer(&TaskAskHandle { group_ref: ask }, &word)
            .expect("the owner answers proceed");
    }

    /// An open TASK an agent of the company created.
    fn open_task(&self) -> EntityId {
        let agent = EntityId::now();
        self.vault
            .put_entity(
                &agent,
                oneiron::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"an agent of the company",
            )
            .expect("the agent's person");
        self.vault
            .memory(agent, EdgeActorClass::Agent)
            .tasks_create(&TaskCreateSpec::new(
                rmpv::Value::from("plan the clinic visit"),
                None,
                None,
                Some(3_600),
            ))
            .expect("the agent creates its TASK")
            .task_ref
            .expect("the TASK is minted")
    }
}

/// `vault.inquire`'s input: one inquiry for `task`.
fn inquire_args(task: EntityId) -> Value {
    json!({
        "shared_vault_id": 1,
        "member": EntityId::now(),
        "question": "Is the member free on Thursday afternoon?",
        "task": task,
        "purpose": "plan the clinic visit",
        "expires_at": VALID_UNTIL,
    })
}

/// `vault.inquire`'s answer to `inquiry` once the member answered, kept
/// `keep`, as the company host's door answers it.
fn answer(inquiry: EntityId, keep: &str) -> Value {
    json!({
        "inquiry_id": inquiry,
        "outcome": "answered",
        "statements": [{"text": MEMBER_WORD, "source": "member_word"}],
        "valid_until": VALID_UNTIL,
        "keep": keep,
        "receipt_id": "inquiry-receipt-1",
        "held": keep == "task",
    })
}

/// A hook input whose `result` is a task-kept answer's kept form: no
/// statement text anywhere, the empty list and `statements_withheld`.
fn assert_withheld(input_json: &str, what: &str) {
    assert!(
        !input_json.contains(MEMBER_WORD),
        "{what} holds no statement of the member: {input_json}"
    );
    let input: Value = serde_json::from_str(input_json).expect("a hook input is JSON");
    assert_eq!(input["result"]["statements"], json!([]), "{what}: {input}");
    assert_eq!(
        input["result"]["statements_withheld"],
        json!(true),
        "{what}: {input}"
    );
}

#[test]
fn a_post_hook_reads_and_keeps_no_task_held_statement() {
    let fixture = Fixture::new(CONTINUE);
    let binding = fixture.bind_hook("post", "continue");
    let reply = answer(EntityId::now(), "task");

    let view = fixture.post_chain(&reply);
    assert_eq!(view, reply, "the caller reads the whole answer");
    let inputs = fixture.runtime.inputs();
    assert_eq!(inputs.len(), 1, "the post hook ran once");
    assert_withheld(&inputs[0], "the post hook's input");

    // The hook's run record keeps the input it read: a replay hands the body
    // the saved input again.
    let replayed = fixture
        .vault
        .hooks_replay(fixture.runtime.as_ref(), None, binding, None, 8)
        .expect("replay the hook's saved runs");
    assert_eq!(replayed.len(), 1, "the hook's one saved run replays");
    let inputs = fixture.runtime.inputs();
    assert_eq!(
        inputs.len(),
        2,
        "the replay ran the body over the saved run"
    );
    assert_withheld(&inputs[1], "the hook's saved run");
}

#[test]
fn a_post_hook_reads_a_copy_answer_whole() {
    let fixture = Fixture::new(CONTINUE);
    fixture.bind_hook("post", "continue");
    let reply = answer(EntityId::now(), "copy");

    let view = fixture.post_chain(&reply);
    assert_eq!(view, reply, "the caller reads the whole answer");
    let inputs = fixture.runtime.inputs();
    assert_eq!(inputs.len(), 1, "the post hook ran once");
    let input: Value = serde_json::from_str(&inputs[0]).expect("a hook input is JSON");
    assert_eq!(
        input["result"], reply,
        "a copy answer, a company record, reaches its hook whole"
    );
}

#[test]
fn a_drained_ask_saves_no_task_held_statement() {
    let fixture = Fixture::new(ASK);
    let binding = fixture.bind_hook("pre", "ask");
    let inquiry = EntityId::now();
    fixture
        .vault
        .install_verb_ask_credential_check(Arc::new(AnsweringCheck {
            reply: answer(inquiry, "task"),
        }));

    // No answer is held for this task: the retry reads the saved answer as
    // the drain saved it.
    let saved = fixture.drained_retry(binding, EntityId::now());
    assert!(
        !saved.to_string().contains(MEMBER_WORD),
        "the saved answer holds no statement of the member: {saved}"
    );
    assert_eq!(saved["statements"], json!([]), "{saved}");
    assert_eq!(saved["statements_withheld"], json!(true), "{saved}");
    assert_eq!(saved["inquiry_id"], json!(inquiry), "{saved}");
    assert_eq!(saved["outcome"], json!("answered"), "{saved}");
}

#[test]
fn a_drained_ask_retry_reads_the_statements_its_task_holds() {
    let fixture = Fixture::new(ASK);
    let binding = fixture.bind_hook("pre", "ask");
    let inquiry = EntityId::now();
    let task = fixture.open_task();
    let statement = InquiryStatement::new(MEMBER_WORD, StatementSource::MemberWord)
        .expect("the member's statement");
    assert!(
        door::hold_answer(
            &fixture.vault,
            fixture.owner,
            task,
            inquiry,
            &[statement],
            VALID_UNTIL,
        )
        .expect("hold the answer"),
        "the open task holds the answer"
    );
    fixture
        .vault
        .install_verb_ask_credential_check(Arc::new(AnsweringCheck {
            reply: answer(inquiry, "task"),
        }));

    let retried = fixture.drained_retry(binding, task);
    assert_eq!(
        retried,
        answer(inquiry, "task"),
        "the retry reads the member's words from the open task"
    );
}

#[test]
fn a_drained_ask_retry_keeps_what_a_post_hook_redacted() {
    let fixture = Fixture::new(ASK);
    let binding = fixture.bind_hook("pre", "ask");
    let inquiry = EntityId::now();
    let task = fixture.open_task();
    let statement = InquiryStatement::new(MEMBER_WORD, StatementSource::MemberWord)
        .expect("the member's statement");
    assert!(
        door::hold_answer(
            &fixture.vault,
            fixture.owner,
            task,
            inquiry,
            &[statement],
            VALID_UNTIL,
        )
        .expect("hold the answer"),
        "the open task holds the answer"
    );
    // The view a post hook leaves when it redacts `statements` from the kept
    // form at the drain's rerun: the mark, no statements.
    let mut redacted = answer(inquiry, "task");
    let fields = redacted.as_object_mut().expect("an answer object");
    fields.remove("statements");
    fields.insert("statements_withheld".to_owned(), json!(true));
    fixture
        .vault
        .install_verb_ask_credential_check(Arc::new(AnsweringCheck {
            reply: redacted.clone(),
        }));

    let retried = fixture.drained_retry(binding, task);
    assert!(
        !retried.to_string().contains(MEMBER_WORD),
        "the retry reads no statement the hook redacted: {retried}"
    );
    assert_eq!(
        retried, redacted,
        "the retry reads the answer as the hook left it"
    );
}

#[test]
fn a_post_hook_that_redacts_keep_leaves_the_statements_withheld() {
    let fixture = Fixture::new(REDACT_KEEP);
    fixture.bind_hook("post", "redact");
    let reply = answer(EntityId::now(), "task");

    let view = fixture.post_chain(&reply);
    let inputs = fixture.runtime.inputs();
    assert_eq!(inputs.len(), 1, "the post hook ran once");
    assert_withheld(&inputs[0], "the post hook's input");
    assert!(
        !view.to_string().contains(MEMBER_WORD),
        "the caller's view of an answer whose keep a hook redacted holds no statement: {view}"
    );
    assert_eq!(view.get("keep"), None, "the hook redacted keep: {view}");
    assert_eq!(view["statements"], json!([]), "{view}");
    assert_eq!(view["statements_withheld"], json!(true), "{view}");
    assert_eq!(view["inquiry_id"], reply["inquiry_id"], "{view}");
}

#[test]
fn a_drained_ask_saves_no_statement_of_an_answer_with_no_keep() {
    let fixture = Fixture::new(ASK);
    let binding = fixture.bind_hook("pre", "ask");
    let inquiry = EntityId::now();
    let task = fixture.open_task();
    let statement = InquiryStatement::new(MEMBER_WORD, StatementSource::MemberWord)
        .expect("the member's statement");
    assert!(
        door::hold_answer(
            &fixture.vault,
            fixture.owner,
            task,
            inquiry,
            &[statement],
            VALID_UNTIL,
        )
        .expect("hold the answer"),
        "the open task holds the answer"
    );
    // The view a post hook that redacted `keep` left at the drain's rerun on
    // the PR head 0edcc19d95: the statements back, no `keep`.
    let mut unkept = answer(inquiry, "task");
    unkept
        .as_object_mut()
        .expect("an answer object")
        .remove("keep");
    fixture
        .vault
        .install_verb_ask_credential_check(Arc::new(AnsweringCheck {
            reply: unkept.clone(),
        }));

    let retried = fixture.drained_retry(binding, task);
    assert!(
        !retried.to_string().contains(MEMBER_WORD),
        "the saved answer with no keep holds no statement, and the retry restores none: {retried}"
    );
    assert_eq!(retried.get("keep"), None, "{retried}");
    assert_eq!(retried["statements"], json!([]), "{retried}");
    assert_eq!(retried["statements_withheld"], json!(true), "{retried}");
    assert_eq!(retried["inquiry_id"], json!(inquiry), "{retried}");
}
