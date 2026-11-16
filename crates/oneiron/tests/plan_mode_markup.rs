//! Plan mode's markup: the owner marks up a plan-doc with anchored threads.
//!
//! Canon (agent-runtime-v1.md, "Plan mode reuses built review parts"): plan
//! mode reuses "the anchored-comment primitive ... the anchor becomes a
//! document, a frontier and a cursor span, and an anchor that cannot be
//! mapped is marked drifted rather than silently repositioned"; "the anchor
//! triple (artifact_id, version, locator) is storage-agnostic and retargets
//! from a blob version to a NOTE document, a frontier and a cursor span".
//!
//! The owner opens a thread on a line of an agent's plan-doc through the
//! anchored-comment verbs (`vault.artifacts.threads.*`): a text span of the
//! plan's text at its head. Each read follows the span's characters to the
//! head: pinned while they sit where they were, mapped where an edit before
//! them moved them, drifted once they no longer all stand. These tests call
//! the verbs by name, so on a tree where a NOTE takes no thread each fails
//! at run time on the refused anchor.
//!
//! `cargo test --locked -p oneiron --all-features --test plan_mode_markup`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::note::{NoteProgramDocument, NoteProgramEdit};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use serde_json::{Value, json};

const PROPOSE: &str = "vault.plans.propose";
const GET: &str = "vault.plans.get";
const APPROVE: &str = "vault.plans.approve";
const OPEN: &str = "vault.artifacts.threads.open";
const COMMENT: &str = "vault.artifacts.threads.comment";
const READ: &str = "vault.artifacts.threads.read";
const LIST: &str = "vault.artifacts.threads.list";

/// The plan step the owner marks up.
const MARKED_STEP: &str = "Merge the duplicate dawn readings";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    // The owner verbs answer the embedded owner on the handle of the process
    // that holds the vault's writer lease.
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("owned vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let agent = EntityId::now();
    vault
        .put_entity(
            &agent,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )
        .expect("the agent's PERSON");
    Fixture {
        vault,
        owner,
        agent,
        _dir: dir,
    }
}

fn call(
    fixture: &Fixture,
    actor: EntityId,
    class: EdgeActorClass,
    verb: &str,
    input: Value,
) -> Result<Value, String> {
    oneiron::task_verb::sdk::invoke(&fixture.vault.memory(actor, class), verb, input)
        .map_err(|error| format!("{error:?}"))
}

fn as_owner(fixture: &Fixture, verb: &str, input: Value) -> Result<Value, String> {
    call(fixture, fixture.owner, EdgeActorClass::Human, verb, input)
}

fn text<'a>(value: &'a Value, pointer: &str) -> &'a str {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{pointer} is text in {value}"))
}

fn number(value: &Value, pointer: &str) -> u64 {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{pointer} is a number in {value}"))
}

/// The agent proposes a plan; returns the plan-doc's ref.
fn propose(fixture: &Fixture) -> String {
    let plan = json!({
        "title": "Tidy the tide log",
        "steps": ["Read the last week of tide entries", MARKED_STEP],
        "scope_asked": ["notes tagged tide"],
        "budget": 400,
    });
    let proposed = call(
        fixture,
        fixture.agent,
        EdgeActorClass::Agent,
        PROPOSE,
        json!({"plan": plan}),
    )
    .expect("the agent proposes its plan");
    text(&proposed, "/plan_ref").to_owned()
}

/// The owner reads plan-doc `plan_ref`; returns its view.
fn read_plan(fixture: &Fixture, plan_ref: &str) -> Value {
    let read =
        as_owner(fixture, GET, json!({"plan_ref": plan_ref})).expect("the owner reads the plan");
    read.get("value")
        .cloned()
        .filter(|view| !view.is_null())
        .unwrap_or_else(|| panic!("the owner reads the plan-doc: {read}"))
}

/// The Unicode scalar span of `needle` in `haystack`.
fn char_span(haystack: &str, needle: &str) -> (u64, u64) {
    let byte = haystack
        .find(needle)
        .unwrap_or_else(|| panic!("{needle:?} is in {haystack:?}"));
    let start = haystack[..byte].chars().count() as u64;
    (start, start + needle.chars().count() as u64)
}

/// The owner opens a thread on `MARKED_STEP` of plan-doc `plan_ref`.
fn mark_up_step(fixture: &Fixture, plan_ref: &str) -> Result<Value, String> {
    let markdown = text(&read_plan(fixture, plan_ref), "/markdown").to_owned();
    let (start, end) = char_span(&markdown, MARKED_STEP);
    as_owner(
        fixture,
        OPEN,
        json!({
            "artifact_ref": plan_ref,
            "version": 0,
            "locator": {"format": "text", "char_start": start, "char_end": end},
            "text": "Use the harbour gauge's readings for this.",
        }),
    )
}

/// The owner reads thread `thread_ref` on plan-doc `plan_ref`.
fn read_thread(fixture: &Fixture, plan_ref: &str, thread_ref: &str) -> Value {
    let read = as_owner(
        fixture,
        READ,
        json!({"artifact_ref": plan_ref, "thread_ref": thread_ref}),
    )
    .expect("the owner reads the thread");
    assert!(!read.is_null(), "the thread reads back");
    read
}

/// The owner's edit of plan-doc `plan` through the document's anchors.
fn edit(
    fixture: &Fixture,
    plan: EntityId,
    build: impl FnOnce(&NoteProgramDocument) -> NoteProgramEdit,
) {
    let doc = fixture
        .vault
        .note_program_document(plan)
        .expect("read the document")
        .expect("the plan-doc's document");
    fixture
        .vault
        .edit_note(
            plan,
            &build(&doc),
            WriteActor::new(fixture.owner, EdgeActorClass::Human),
        )
        .expect("the owner's edit lands");
}

#[test]
fn the_owner_marks_up_a_plan_line() {
    let fixture = fixture();
    let plan_ref = propose(&fixture);
    let revision = text(&read_plan(&fixture, &plan_ref), "/revision").to_owned();
    as_owner(
        &fixture,
        APPROVE,
        json!({"plan_ref": plan_ref, "expected_revision": revision}),
    )
    .expect("the owner approves");

    let opened = mark_up_step(&fixture, &plan_ref).expect("the owner marks up a plan line");
    assert_eq!(text(&opened, "/resolution"), "pinned", "{opened}");
    assert_eq!(text(&opened, "/origin/quote"), MARKED_STEP, "{opened}");
    assert_eq!(text(&opened, "/anchor/quote"), MARKED_STEP, "{opened}");
    assert_eq!(number(&opened, "/origin/version"), 0, "{opened}");
    assert_eq!(text(&opened, "/origin/locator/format"), "text", "{opened}");
    assert!(
        opened
            .pointer("/origin/body/frontier")
            .is_some_and(Value::is_array),
        "the anchor holds the text frontier it was read at: {opened}"
    );
    assert_eq!(text(&opened, "/state"), "open", "{opened}");
    let thread_ref = text(&opened, "/thread_id").to_owned();

    as_owner(
        &fixture,
        COMMENT,
        json!({
            "artifact_ref": plan_ref,
            "thread_ref": thread_ref,
            "text": "And keep the gauge's own timestamps.",
        }),
    )
    .expect("the owner adds to the thread");
    let thread = read_thread(&fixture, &plan_ref, &thread_ref);
    let comments: Vec<&str> = thread
        .get("comments")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("comments in {thread}"))
        .iter()
        .map(|comment| text(comment, "/text"))
        .collect();
    assert_eq!(
        comments,
        vec![
            "Use the harbour gauge's readings for this.",
            "And keep the gauge's own timestamps.",
        ]
    );
    for comment in thread["comments"].as_array().unwrap() {
        assert_eq!(text(comment, "/author"), fixture.owner.to_hex());
    }
    assert_eq!(text(&thread, "/resolution"), "pinned", "{thread}");

    let listed = as_owner(&fixture, LIST, json!({"artifact_ref": plan_ref}))
        .expect("the owner lists the plan's threads");
    let listed = listed.as_array().expect("a thread list");
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(text(&listed[0], "/thread_id"), thread_ref);

    // Markup is no edit: the plan keeps its text, its revision and the
    // owner's approval.
    let after = read_plan(&fixture, &plan_ref);
    assert_eq!(text(&after, "/revision"), revision, "{after}");
    assert_eq!(text(&after, "/state"), "approved", "{after}");
}

#[test]
fn a_thread_drifts_when_its_line_is_rewritten() {
    let fixture = fixture();
    let plan_ref = propose(&fixture);
    let plan = EntityId::from_hex(&plan_ref).expect("the plan-doc id");
    let opened = mark_up_step(&fixture, &plan_ref).expect("the owner marks up a plan line");
    let thread_ref = text(&opened, "/thread_id").to_owned();
    let start = number(&opened, "/origin/locator/char_start");
    let end = number(&opened, "/origin/locator/char_end");

    // An edit above the line moves it: the thread follows its words.
    let preface = "Draft plan.\n";
    edit(&fixture, plan, |doc| NoteProgramEdit::InsertAfter {
        anchor: doc.anchor(0).expect("the start anchor"),
        text: preface.to_owned(),
    });
    let moved = read_thread(&fixture, &plan_ref, &thread_ref);
    let shift = preface.chars().count() as u64;
    assert_eq!(text(&moved, "/resolution"), "mapped", "{moved}");
    assert_eq!(number(&moved, "/anchor/locator/char_start"), start + shift);
    assert_eq!(number(&moved, "/anchor/locator/char_end"), end + shift);
    assert_eq!(text(&moved, "/anchor/quote"), MARKED_STEP, "{moved}");
    assert_eq!(number(&moved, "/origin/locator/char_start"), start);
    assert_eq!(text(&moved, "/origin/quote"), MARKED_STEP, "{moved}");

    // Rewriting the line takes its words away: the thread is drifted and
    // stays on the line it was opened on, never on the new words.
    let rewrite = "Keep every dawn reading as it is";
    edit(&fixture, plan, |doc| NoteProgramEdit::ReplaceSpan {
        start: doc
            .anchor(usize::try_from(start + shift).unwrap())
            .expect("the line's start"),
        end: doc
            .anchor(usize::try_from(end + shift).unwrap())
            .expect("the line's end"),
        text: rewrite.to_owned(),
    });
    let markdown = text(&read_plan(&fixture, &plan_ref), "/markdown").to_owned();
    assert!(
        markdown.contains(rewrite),
        "the line is rewritten: {markdown}"
    );
    assert!(!markdown.contains(MARKED_STEP), "{markdown}");
    let drifted = read_thread(&fixture, &plan_ref, &thread_ref);
    assert_eq!(text(&drifted, "/resolution"), "drifted", "{drifted}");
    assert_eq!(drifted.get("anchor"), drifted.get("origin"), "{drifted}");
    assert_eq!(text(&drifted, "/anchor/quote"), MARKED_STEP, "{drifted}");
    assert_eq!(number(&drifted, "/anchor/locator/char_start"), start);
}

#[test]
fn a_thread_stays_drifted_when_a_deleted_letter_is_typed_again() {
    let fixture = fixture();
    let plan_ref = propose(&fixture);
    let plan = EntityId::from_hex(&plan_ref).expect("the plan-doc id");
    let opened = mark_up_step(&fixture, &plan_ref).expect("the owner marks up a plan line");
    let thread_ref = text(&opened, "/thread_id").to_owned();
    let start = number(&opened, "/origin/locator/char_start");
    let letter = start
        + MARKED_STEP
            .chars()
            .position(|c| c == 'u')
            .expect("a 'u' inside the line") as u64;
    let replace_letter = |with: &str| {
        edit(&fixture, plan, |doc| NoteProgramEdit::ReplaceSpan {
            start: doc
                .anchor(usize::try_from(letter).unwrap())
                .expect("the letter's start"),
            end: doc
                .anchor(usize::try_from(letter + 1).unwrap())
                .expect("the letter's end"),
            text: with.to_owned(),
        });
    };

    // A letter inside the line is replaced: the quoted characters no longer
    // all stand.
    replace_letter("o");
    let markdown = text(&read_plan(&fixture, &plan_ref), "/markdown").to_owned();
    assert!(
        markdown.contains("Merge the doplicate dawn readings"),
        "the letter is replaced: {markdown}"
    );
    let replaced = read_thread(&fixture, &plan_ref, &thread_ref);
    assert_eq!(text(&replaced, "/resolution"), "drifted", "{replaced}");

    // Typing the same letter back gives the line its old text, but the
    // quoted letter itself stays deleted: the thread stays drifted on the
    // span it was opened on and never reattaches to the new letter.
    replace_letter("u");
    let markdown = text(&read_plan(&fixture, &plan_ref), "/markdown").to_owned();
    assert!(
        markdown.contains(MARKED_STEP),
        "the line has its old text: {markdown}"
    );
    let retyped = read_thread(&fixture, &plan_ref, &thread_ref);
    assert_eq!(text(&retyped, "/resolution"), "drifted", "{retyped}");
    assert_eq!(retyped.get("anchor"), retyped.get("origin"), "{retyped}");
    assert_eq!(text(&retyped, "/anchor/quote"), MARKED_STEP, "{retyped}");
    assert_eq!(number(&retyped, "/anchor/locator/char_start"), start);
}

#[test]
fn a_note_that_is_no_plan_doc_takes_no_thread() {
    let fixture = fixture();
    let note = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .create_note("research", "Dawn readings run high in spring.")
        .expect("the owner's research NOTE");
    let refused = as_owner(
        &fixture,
        OPEN,
        json!({
            "artifact_ref": note.id_hex,
            "version": 0,
            "locator": {"format": "text", "char_start": 0, "char_end": 4},
            "text": "Which gauge?",
        }),
    );
    assert!(
        refused.is_err(),
        "a NOTE that is no plan-doc takes no thread: {refused:?}"
    );
}
