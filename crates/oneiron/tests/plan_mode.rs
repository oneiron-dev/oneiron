//! Plan mode: an agent's plan waits for the owner's verdict on its revision.
//!
//! Canon (agent-runtime-v1.md, "Plan mode reuses built review parts"): plan
//! mode is "propose-only execution (ARCH-0028 authority tier) + a plan-doc
//! `NOTE` (kind `Plugin("plan")`, kin to ARCH-0032's brief — never an OF-368
//! blob) + comment review (GATE-07 bundle) + execute-on-approve through the
//! gate". The census row (UNBUILT Top 15, item 4): "a run started from a plan
//! carries the approved revision's hash, and an edit after approval reopens
//! review".
//!
//! An agent proposes a plan (`vault.plans.propose`): a NOTE `plugin/plan`
//! written from a typed body. The owner reads it (`vault.plans.get`) with its
//! revision, the hash of its text, and answers that revision
//! (`vault.plans.approve`, `vault.plans.reject`). The verdict holds while the
//! text is the revision answered; an edit that lands returns the plan to
//! review. These tests call the verbs by name, so on a tree without them each
//! fails at run time as an unknown verb.
//!
//! `cargo test --locked -p oneiron --all-features --test plan_mode`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::note::{NoteKind, NoteProgramEdit};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use serde_json::{Value, json};

const PROPOSE: &str = "vault.plans.propose";
const GET: &str = "vault.plans.get";
const APPROVE: &str = "vault.plans.approve";
const REJECT: &str = "vault.plans.reject";

/// The gate decision content kind of a verdict on a plan-doc.
const VERDICT_CONTENT_KIND: &str = "plan_doc_verdict";

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

/// The plan the agent proposes.
fn plan() -> Value {
    json!({
        "title": "Tidy the tide log",
        "steps": [
            "Read the last week of tide entries",
            "Merge the duplicate dawn readings",
        ],
        "scope_asked": ["notes tagged tide"],
        "budget": 400,
    })
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

fn as_agent(fixture: &Fixture, verb: &str, input: Value) -> Result<Value, String> {
    call(fixture, fixture.agent, EdgeActorClass::Agent, verb, input)
}

fn text<'a>(value: &'a Value, pointer: &str) -> &'a str {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{pointer} is text in {value}"))
}

/// The agent proposes [`plan`]; returns the plan-doc's view.
fn propose(fixture: &Fixture) -> Value {
    as_agent(fixture, PROPOSE, json!({"plan": plan()})).expect("the agent proposes its plan")
}

/// The owner reads plan-doc `plan_ref`; returns its view.
fn read(fixture: &Fixture, plan_ref: &str) -> Value {
    let read =
        as_owner(fixture, GET, json!({"plan_ref": plan_ref})).expect("the owner reads the plan");
    read.get("value")
        .cloned()
        .filter(|view| !view.is_null())
        .unwrap_or_else(|| panic!("the owner reads the plan-doc: {read}"))
}

fn verdict(fixture: &Fixture, verb: &str, plan_ref: &str, revision: &str) -> Result<Value, String> {
    as_owner(
        fixture,
        verb,
        json!({"plan_ref": plan_ref, "expected_revision": revision}),
    )
}

/// The verdict gate decisions the vault holds.
fn verdict_records(fixture: &Fixture) -> Vec<oneiron::store::GateDecisionRecord> {
    fixture
        .vault
        .gate_decisions(256)
        .expect("read the gate decisions")
        .into_iter()
        .filter(|record| record.content_kind == VERDICT_CONTENT_KIND)
        .collect()
}

/// Holds the gate decision `receipt_ref` names: the owner as actor, `reason`,
/// the NOTE as grant ref and the answered revision as diff handle.
fn assert_verdict_recorded(
    fixture: &Fixture,
    receipt_ref: &str,
    plan_ref: &str,
    revision: &str,
    outcome: &str,
    reason: &str,
) {
    let hex = receipt_ref
        .strip_prefix("gate:")
        .unwrap_or_else(|| panic!("{receipt_ref} names a gate decision"));
    let record = verdict_records(fixture)
        .into_iter()
        .find(|record| record.decision_id.to_hex() == hex)
        .unwrap_or_else(|| panic!("no verdict gate decision {hex}"));
    assert_eq!(record.outcome, outcome);
    assert_eq!(record.reason_codes, vec![reason.to_owned()]);
    assert_eq!(
        record.actor_ref.as_deref(),
        Some(fixture.owner.to_hex().as_str())
    );
    assert_eq!(record.grant_ref, Some(format!("note:{plan_ref}")));
    let handle: String = record
        .diff_handle
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(handle, revision, "the diff handle is the revision answered");
}

#[test]
fn an_agents_plan_waits_in_review() {
    let fixture = fixture();
    let proposed = propose(&fixture);
    assert_eq!(text(&proposed, "/state"), "in_review", "{proposed}");
    assert_eq!(
        proposed.get("body"),
        Some(&plan()),
        "the typed body reads back from the text"
    );
    assert_eq!(text(&proposed, "/proposed_by"), fixture.agent.to_hex());
    assert!(
        proposed.get("verdict").is_some_and(Value::is_null),
        "no verdict yet: {proposed}"
    );
    let revision = text(&proposed, "/revision");
    assert_eq!(revision.len(), 64, "a revision is a 32-byte hash");
    let plan_ref = text(&proposed, "/plan_ref");
    let id = EntityId::from_hex(plan_ref).expect("the plan-doc id");
    let note = fixture
        .vault
        .read_note(&id)
        .expect("read the NOTE")
        .expect("the plan-doc is a NOTE");
    assert_eq!(note.kind, NoteKind::Plugin("plan".to_owned()));
    assert!(
        note.markdown.starts_with("# Tidy the tide log\n"),
        "{}",
        note.markdown
    );
    let owner_view = read(&fixture, plan_ref);
    assert_eq!(text(&owner_view, "/state"), "in_review");
    assert_eq!(text(&owner_view, "/revision"), revision);
    assert!(
        verdict_records(&fixture).is_empty(),
        "no verdict was recorded"
    );
}

#[test]
fn the_owner_approves_the_plan_at_the_revision_read() {
    let fixture = fixture();
    let proposed = propose(&fixture);
    let plan_ref = text(&proposed, "/plan_ref");
    let revision = text(&read(&fixture, plan_ref), "/revision").to_owned();
    let stale = verdict(&fixture, APPROVE, plan_ref, &"0".repeat(64));
    assert!(
        stale.is_err(),
        "an approval of a revision the text is not at is refused: {stale:?}"
    );
    assert!(
        verdict_records(&fixture).is_empty(),
        "the refused approval wrote nothing"
    );
    assert_eq!(text(&read(&fixture, plan_ref), "/state"), "in_review");
    let settled =
        verdict(&fixture, APPROVE, plan_ref, &revision).expect("the owner approves what they read");
    assert_eq!(text(&settled, "/decision"), "approved");
    assert_eq!(text(&settled, "/revision"), revision);
    assert_eq!(text(&settled, "/proposed_by"), fixture.agent.to_hex());
    let receipt = text(&settled, "/receipt_ref");
    assert_verdict_recorded(
        &fixture,
        receipt,
        plan_ref,
        &revision,
        "allow",
        "gate.allow.owner_plan_doc",
    );
    let approved = read(&fixture, plan_ref);
    assert_eq!(text(&approved, "/state"), "approved");
    assert_eq!(text(&approved, "/verdict/decision"), "approved");
    assert_eq!(text(&approved, "/verdict/revision"), revision);
    assert_eq!(text(&approved, "/verdict/receipt_ref"), receipt);
}

#[test]
fn an_edit_after_approval_returns_the_plan_to_review() {
    let fixture = fixture();
    let proposed = propose(&fixture);
    let plan_ref = text(&proposed, "/plan_ref");
    let id = EntityId::from_hex(plan_ref).expect("the plan-doc id");
    let revision = text(&proposed, "/revision").to_owned();
    verdict(&fixture, APPROVE, plan_ref, &revision).expect("the owner approves");
    assert_eq!(text(&read(&fixture, plan_ref), "/state"), "approved");
    let doc = fixture
        .vault
        .note_program_document(id)
        .expect("read the document")
        .expect("the plan-doc's document");
    let edit = NoteProgramEdit::InsertAfter {
        anchor: doc
            .anchor(doc.text().chars().count())
            .expect("the end anchor"),
        text: "\nOne more pass at dusk.\n".to_owned(),
    };
    fixture
        .vault
        .edit_note(
            id,
            &edit,
            WriteActor::new(fixture.owner, EdgeActorClass::Human),
        )
        .expect("the owner's edit lands");
    let edited = read(&fixture, plan_ref);
    assert_eq!(
        text(&edited, "/state"),
        "in_review",
        "an edit after approval reopens review: {edited}"
    );
    assert_ne!(
        text(&edited, "/revision"),
        revision,
        "the edit moved the revision"
    );
    assert_eq!(
        text(&edited, "/verdict/decision"),
        "approved",
        "the last verdict stays on record"
    );
    assert_eq!(text(&edited, "/verdict/revision"), revision);
    assert!(
        edited.get("body").is_some_and(Value::is_null),
        "the edit took the text out of the plan's sections"
    );
    let stale = verdict(&fixture, APPROVE, plan_ref, &revision);
    assert!(
        stale.is_err(),
        "the old revision's approval is refused once the text moved: {stale:?}"
    );
    let current = text(&edited, "/revision").to_owned();
    verdict(&fixture, APPROVE, plan_ref, &current).expect("the owner approves the edited revision");
    assert_eq!(text(&read(&fixture, plan_ref), "/state"), "approved");
}

#[test]
fn the_owner_rejects_the_plan() {
    let fixture = fixture();
    let proposed = propose(&fixture);
    let plan_ref = text(&proposed, "/plan_ref");
    let revision = text(&proposed, "/revision").to_owned();
    let settled =
        verdict(&fixture, REJECT, plan_ref, &revision).expect("the owner rejects what they read");
    assert_eq!(text(&settled, "/decision"), "rejected");
    assert_verdict_recorded(
        &fixture,
        text(&settled, "/receipt_ref"),
        plan_ref,
        &revision,
        "deny",
        "gate.deny.owner_plan_doc",
    );
    let rejected = read(&fixture, plan_ref);
    assert_eq!(text(&rejected, "/state"), "rejected");
    assert_eq!(
        rejected.get("body"),
        Some(&plan()),
        "a rejected plan stays readable"
    );
}

#[test]
fn an_agent_cannot_answer_its_own_plan() {
    let fixture = fixture();
    let proposed = propose(&fixture);
    let plan_ref = text(&proposed, "/plan_ref");
    let revision = text(&proposed, "/revision");
    for verb in [APPROVE, REJECT] {
        let answer = as_agent(
            &fixture,
            verb,
            json!({"plan_ref": plan_ref, "expected_revision": revision}),
        );
        assert!(
            answer.is_err(),
            "{verb} is the owner's, never its proposer's: {answer:?}"
        );
    }
    assert!(
        verdict_records(&fixture).is_empty(),
        "the agent's answers wrote nothing"
    );
    assert_eq!(text(&read(&fixture, plan_ref), "/state"), "in_review");
}
