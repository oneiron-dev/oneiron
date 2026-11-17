//! A composed task post keeps its lens rows' worlds (census L8-07; review
//! #7814 P1).
//!
//! The local model reads each lens row a composed brief names, so the
//! brief's words may be that row's. The parked proposal names the lens rows
//! as prompt inputs in its birth, and so does the TASK it settles into, so a
//! device kept from a lens row's world is kept from both, as from a claim a
//! model wrote from recalled rows (`settings::device_only`, FIX 8192). On a
//! tree whose composed proposal is born like any other proposal, it sits in
//! base reality alone, and such a device reads it.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test tasks_composed_post_keeps_lens_worlds`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::federation::record_scope::BirthPosition;
use oneiron::memory::{
    ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest, ClaimSettlementVerdict,
    Memory, MemoryError, MemoryResult,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::TaskCreateReceipt;
use oneiron::test_doors::composed_lens_world::kept_from_world;
use oneiron::test_doors::task_brief_compose::install_scripted_brief_model;
use oneiron::verbs::{TaskCreateRequest, task_create_spec};
use oneiron::{ClaimApprovalStatus, EdgeActorClass, EntityId, ModelLocality, Vault, VaultConfig};
use serde_json::{Value, json};

/// The lens NOTE's words, which the brief may carry.
const LENS_TEXT: &str = "Harbour survey: the dawn gauge sits beside the outfall pipe.";

/// The scripted local model's draft.
fn draft() -> String {
    json!({
        "objective": "Explain the high dawn tide readings",
        "need": "The dawn gauge sits beside the outfall pipe.",
        "type": "research",
        "notes": ["The gauge sits beside the outfall pipe."],
        "question": "Is the cause of the high dawn readings found?",
        "yes_if_all": ["The cause is named with the log rows that show it."],
        "no_if_any": []
    })
    .to_string()
}

/// `tasks.create` as its verb row runs it.
fn create(memory: &Memory<'_>, request: Value) -> MemoryResult<TaskCreateReceipt> {
    let input: TaskCreateRequest = serde_json::from_value(request)
        .map_err(|error| MemoryError::bad_request(format!("request: {error}")))?;
    let spec = task_create_spec(memory, input)?;
    memory.tasks_create(&spec)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

#[test]
fn a_composed_post_and_its_task_keep_the_lens_rows_world() {
    let dir = tempfile::tempdir().expect("tempdir");
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("open vault");
    let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof = vault
        .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let world = vault
        .create_world(&owner_proof, "harbour survey", now_secs())
        .expect("the lens world");
    let lens = vault
        .memory(owner_id, EdgeActorClass::Human)
        .with_birth_position(BirthPosition {
            world: Some(world),
            facet: None,
        })
        .create_note("research", LENS_TEXT)
        .expect("the owner's NOTE in the lens world");
    let lens = EntityId::from_hex(&lens.id_hex).expect("the NOTE's id");
    assert!(
        kept_from_world(&vault, world, lens).expect("judge the NOTE"),
        "precondition: the lens NOTE sits in its world"
    );

    let owner = vault.memory(owner_id, EdgeActorClass::Human);
    install_scripted_brief_model(
        &vault,
        "scripted-local-reasoner",
        ModelLocality::OnDevice,
        &draft(),
    );
    let parked = create(
        &owner,
        json!({
            "spec": null,
            "intent_key": "dawn-tide/lens-world",
            "one_liner": "Find out why the dawn tide readings run high",
            "lens_refs": [lens.to_hex()],
        }),
    )
    .expect("the owner's one-liner create composes its brief");
    assert_eq!(
        (parked.approval, parked.task_ref),
        (ClaimApprovalStatus::Proposed, None),
        "precondition: a composed post parks: {parked:?}"
    );
    let proposal = parked.proposal_ref.expect("the parked proposal");
    assert!(
        kept_from_world(&vault, world, proposal).expect("judge the proposal"),
        "a device kept from the lens world is kept from the composed proposal"
    );

    let review = owner
        .claim_review(&ClaimProposalReviewRequest {
            claim_ref: proposal.to_hex(),
            grant_ref: None,
        })
        .expect("the owner reviews his composed post");
    let settled = owner
        .claim_settle(&ClaimSettleRequest {
            claim_ref: proposal.to_hex(),
            review_id: review.review_id,
            decision: ClaimSettleDecision::Approve,
            grant_ref: None,
        })
        .expect("the owner settles his own composed post");
    assert_eq!(
        settled.verdict,
        ClaimSettlementVerdict::Landed,
        "{settled:?}"
    );
    let tasks = vault
        .tasks_by_owner(owner_id, None, 64)
        .expect("owner tasks");
    assert_eq!(tasks.len(), 1, "the approved post lands its TASK");
    assert!(
        kept_from_world(&vault, world, tasks[0]).expect("judge the TASK"),
        "a device kept from the lens world is kept from the TASK the post settled into"
    );
}
