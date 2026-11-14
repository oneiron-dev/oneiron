//! A task brief composed by a local model from a one-liner plus lens context
//! (census L8-07; canon workbench-engine-asks.md:76: "composed by a local
//! model from a one-liner plus lens context, approved like any proposal").
//!
//! Engine rulings, 14 Nov 09:11: L8-07-DOOR = A. `tasks.create` gains
//! `one_liner` + `lens_refs`; the engine composes the brief and mints the
//! composer stamp itself in the same call; a caller-set stamp is refused.
//! The composer is local only; with no local model bound the create is
//! refused, and nothing falls back to a third party. L8-07-APPROVAL = A: a
//! composed brief always lands as a proposal, whatever the caller's ceiling.
//!
//! The owner's ceiling is Auto, so his written brief mints at once; his
//! composed one parks. The model is a scripted local one the door installs.
//! On a tree without the composer, `tasks.create` refuses the `one_liner`
//! field and takes a stamped brief as written, so every test here fails.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test tasks_compose_brief_from_one_liner`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::claim::ClaimApprovalStatus;
use oneiron::memory::{
    MEMORY_CODE_MODEL_UNAVAILABLE, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};
use oneiron::task_type::TaskTypeTree;
use oneiron::task_verb::TaskCreateReceipt;
use oneiron::test_doors::task_brief_compose::{install_scripted_brief_model, parked_post_brief};
use oneiron::verbs::{TaskCreateRequest, task_create_spec};
use oneiron::{EdgeActorClass, EntityId, ModelLocality, Vault, VaultConfig, WriteActor};
use serde_json::{Value, json};

const ONE_LINER: &str = "Find out why the dawn tide readings run high";
const LENS_TEXT: &str = "Dawn tide readings in the harbour log run 4 cm above the gauge.";
const LOCAL_MODEL: &str = "scripted-local-reasoner";
const OBJECTIVE: &str = "Explain the high dawn tide readings";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    /// A NOTE the owner wrote: the lens context.
    lens: EntityId,
    _dir: tempfile::TempDir,
}

/// A vault with its embedded owner, who wrote one NOTE.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let lens = vault
        .create_note(
            "research",
            LENS_TEXT,
            WriteActor::new(owner, EdgeActorClass::Human),
        )
        .expect("the owner's NOTE");
    Fixture {
        vault,
        owner,
        lens,
        _dir: dir,
    }
}

fn owner(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

/// The id a brief's `type_ref` names the seeded `research` node by.
fn research_node() -> EntityId {
    TaskTypeTree::seeded()
        .node("research")
        .expect("the seeded research node")
        .entity_id()
        .expect("node id")
}

/// The scripted model's draft.
fn draft() -> String {
    json!({
        "objective": OBJECTIVE,
        "need": "The harbour log's dawn readings disagree with the gauge.",
        "type": "research",
        "notes": ["Read the harbour log before the gauge data."],
        "question": "Is the cause of the high dawn readings found?",
        "yes_if_all": ["The cause is named with the log rows that show it."],
        "no_if_any": []
    })
    .to_string()
}

/// `tasks.create` as its verb row runs it: the request through the verb's
/// own mapping, then the create.
fn create(memory: &Memory<'_>, request: Value) -> MemoryResult<TaskCreateReceipt> {
    let input: TaskCreateRequest = serde_json::from_value(request)
        .map_err(|error| MemoryError::bad_request(format!("request: {error}")))?;
    let spec = task_create_spec(memory, input)?;
    memory.tasks_create(&spec)
}

fn one_liner_request(key: &str, lens: &[EntityId]) -> Value {
    json!({
        "spec": null,
        "intent_key": key,
        "one_liner": ONE_LINER,
        "lens_refs": lens.iter().map(EntityId::to_hex).collect::<Vec<_>>(),
    })
}

/// A written brief for the same work, with `composed` when given.
fn written_request(fixture: &Fixture, key: &str, composed: Option<Value>) -> Value {
    let mut brief = json!({
        "schema": 1,
        "type_ref": {"node_id": research_node().to_hex(), "tree_version": 1},
        "objective": OBJECTIVE,
        "intent": {"need": "The dawn readings disagree with the gauge."},
        "success": {
            "question": "Is the cause of the high dawn readings found?",
            "criteria": {"yes_if_all": [{"text": "The cause is named."}]},
        },
        "settled": [],
        "escalation": {
            "to": {"people": [fixture.owner.to_hex()]},
            "triggers": [],
            "default": "hold",
            "reversibility": "reversible_read",
        },
    });
    if let Some(composed) = composed {
        brief["composed"] = composed;
    }
    json!({"spec": null, "intent_key": key, "brief": brief})
}

fn refusal(result: MemoryResult<TaskCreateReceipt>, why: &str) -> MemoryError {
    match result {
        Err(error) => error,
        Ok(receipt) => panic!("{why}: expected a refusal, got {receipt:?}"),
    }
}

#[test]
fn one_liner_create_composes_a_stamped_brief_that_parks() {
    let fixture = fixture();
    let owner = owner(&fixture);
    let written = create(&owner, written_request(&fixture, "dawn-tide/written", None))
        .expect("the owner's written brief lands");
    assert!(
        written.task_ref.is_some() && written.approval == ClaimApprovalStatus::Auto,
        "precondition: the owner's ceiling is Auto, so a written brief mints at once: {written:?}"
    );

    let model = install_scripted_brief_model(
        &fixture.vault,
        LOCAL_MODEL,
        ModelLocality::OnDevice,
        &draft(),
    );
    let composed = match create(
        &owner,
        one_liner_request("dawn-tide/composed", &[fixture.lens]),
    ) {
        Ok(receipt) => receipt,
        Err(error) => panic!("a one-liner create composes its brief: {error:?}"),
    };
    assert_eq!(
        (composed.approval, composed.task_ref),
        (ClaimApprovalStatus::Proposed, None),
        "a composed brief parks as a proposal under an Auto ceiling: {composed:?}"
    );
    let proposal = composed.proposal_ref.expect("the parked proposal");

    let calls = model.calls();
    assert_eq!(calls.len(), 1, "one model call composes the brief");
    assert!(
        calls[0].input.contains(ONE_LINER),
        "the model reads the one-liner"
    );
    assert!(
        calls[0].input.contains(LENS_TEXT),
        "the model reads the lens NOTE's text under the owner's read: {}",
        calls[0].input
    );
    let type_enum = calls[0].schema["properties"]["type"]["enum"]
        .as_array()
        .expect("the reply schema lists the task types");
    assert!(
        type_enum.iter().any(|node| node == "research"),
        "the schema offers the live type nodes: {type_enum:?}"
    );

    let brief = parked_post_brief(&fixture.vault, proposal)
        .expect("read the proposal")
        .expect("the proposal holds the composed brief");
    let brief = serde_json::to_value(&brief).expect("brief json");
    assert_eq!(
        brief["objective"], OBJECTIVE,
        "the model drafts the objective"
    );
    assert_eq!(
        brief["type_ref"]["node_id"],
        research_node().to_hex(),
        "the engine maps the model's type to its node"
    );
    assert_eq!(
        brief["composed"]["seat"], LOCAL_MODEL,
        "the stamp names the model"
    );
    assert_eq!(
        brief["composed"]["lens_refs"],
        json!([fixture.lens.to_hex()]),
        "the stamp names the lens rows"
    );
    assert_eq!(
        brief["escalation"]["reversibility"], "outbound_effect",
        "the engine, not the model, sets reversibility"
    );
    assert_eq!(brief["escalation"]["default"], "hold");
    assert!(
        brief["escalation"]["to"]["people"].is_array(),
        "the engine escalates to the vault's owners: {}",
        brief["escalation"]
    );

    let replay = create(
        &owner,
        one_liner_request("dawn-tide/composed", &[fixture.lens]),
    )
    .expect("the same request replays");
    assert_eq!(
        replay.proposal_ref,
        Some(proposal),
        "a replay answers its proposal"
    );
    assert_eq!(model.calls().len(), 1, "a replay composes nothing");

    let unread = refusal(
        create(
            &owner,
            one_liner_request("dawn-tide/unread", &[EntityId::now()]),
        ),
        "a lens ref the owner does not read",
    );
    assert_eq!(unread.code, MEMORY_CODE_NOT_FOUND, "{unread:?}");
    assert_eq!(
        model.calls().len(),
        1,
        "an unread lens row reaches no model"
    );
}

#[test]
fn caller_set_composer_stamp_is_refused() {
    let fixture = fixture();
    let stamp = json!({
        "seat": "forged-seat",
        "one_liner_digest": "00".repeat(32),
        "lens_refs": [],
        "at": 1,
    });
    let forged = refusal(
        create(
            &owner(&fixture),
            written_request(&fixture, "dawn-tide/forged", Some(stamp)),
        ),
        "a caller-set composer stamp",
    );
    assert!(
        forged.message.contains("composer stamp"),
        "the refusal names the stamp: {forged:?}"
    );
    assert!(
        fixture
            .vault
            .tasks_by_owner(fixture.owner, None, 64)
            .expect("owner tasks")
            .is_empty(),
        "a forged stamp mints nothing"
    );
}

#[test]
fn one_liner_create_without_a_local_model_is_refused() {
    let fixture = fixture();
    let owner = owner(&fixture);
    let unbound = refusal(
        create(
            &owner,
            one_liner_request("dawn-tide/unbound", &[fixture.lens]),
        ),
        "no task-brief model is bound",
    );
    assert_eq!(unbound.code, MEMORY_CODE_MODEL_UNAVAILABLE, "{unbound:?}");
    assert!(
        unbound
            .suggestions
            .iter()
            .any(|line| line.contains("local_reasoner")),
        "the refusal names the binding to add: {unbound:?}"
    );

    let model = install_scripted_brief_model(
        &fixture.vault,
        "hosted-model",
        ModelLocality::ThirdParty,
        &draft(),
    );
    let third_party = refusal(
        create(
            &owner,
            one_liner_request("dawn-tide/third-party", &[fixture.lens]),
        ),
        "a third-party task-brief model",
    );
    assert_eq!(
        third_party.code, MEMORY_CODE_MODEL_UNAVAILABLE,
        "{third_party:?}"
    );
    assert!(
        model.calls().is_empty(),
        "the lens context never reaches a third-party model"
    );
    assert!(
        fixture
            .vault
            .tasks_by_owner(fixture.owner, None, 64)
            .expect("owner tasks")
            .is_empty(),
        "a refused composition mints nothing"
    );
}
