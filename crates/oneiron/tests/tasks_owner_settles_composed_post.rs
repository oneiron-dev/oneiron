//! The vault owner settles his own composed task post (census L8-07).
//!
//! Engine rulings, 14 Nov: L8-07-APPROVAL = A (09:11) parks every composed
//! post as a proposal, the owner's too, though his ceiling is Auto.
//! L8-07-OWNER-OPENER = A (09:35): a composed post whose opener is the vault
//! owner may be settled by that owner. Its brief is the engine's local-model
//! draft, and he is the person who reads it before it runs. The opener
//! refusal stays for every other opener and every other proposal.
//!
//! The owner composes a post with a scripted local model, reviews the parked
//! proposal through `vault.claims.review` and approves it through
//! `vault.claims.settle`, and the TASK lands. On a tree where an opener never
//! settles his own proposal, the settle is refused as `FORBIDDEN`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test tasks_owner_settles_composed_post`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::memory::{
    ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest, ClaimSettlementVerdict,
    Memory, MemoryError, MemoryResult,
};
use oneiron::task_verb::TaskCreateReceipt;
use oneiron::test_doors::task_brief_compose::install_scripted_brief_model;
use oneiron::verbs::{TaskCreateRequest, task_create_spec};
use oneiron::{ClaimApprovalStatus, EdgeActorClass, ModelLocality, Vault, VaultConfig};
use serde_json::{Value, json};

/// The scripted local model's draft.
fn draft() -> String {
    json!({
        "objective": "Explain the high dawn tide readings",
        "need": "The harbour log's dawn readings disagree with the gauge.",
        "type": "research",
        "notes": [],
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

#[test]
fn the_owner_settles_his_own_composed_post_and_its_task_lands() {
    let dir = tempfile::tempdir().expect("tempdir");
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("open vault");
    let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
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
            "intent_key": "dawn-tide/owner-composed",
            "one_liner": "Find out why the dawn tide readings run high",
        }),
    )
    .expect("the owner's one-liner create composes its brief");
    assert_eq!(
        (parked.approval, parked.task_ref),
        (ClaimApprovalStatus::Proposed, None),
        "precondition: a composed post parks, the owner's too: {parked:?}"
    );
    let proposal = parked.proposal_ref.expect("the parked proposal");
    assert!(
        vault
            .tasks_by_owner(owner_id, None, 64)
            .expect("owner tasks")
            .is_empty(),
        "precondition: no TASK before the settle"
    );

    let review = owner
        .claim_review(&ClaimProposalReviewRequest {
            claim_ref: proposal.to_hex(),
            grant_ref: None,
        })
        .expect("the owner reviews his composed post");
    assert_eq!(
        review.opener_ref,
        Some(owner_id.to_hex()),
        "precondition: the owner opened the proposal"
    );
    let settled = match owner.claim_settle(&ClaimSettleRequest {
        claim_ref: proposal.to_hex(),
        review_id: review.review_id,
        decision: ClaimSettleDecision::Approve,
        grant_ref: None,
    }) {
        Ok(settled) => settled,
        Err(error) => panic!("the owner settles his own composed post: {error:?}"),
    };
    assert_eq!(
        settled.verdict,
        ClaimSettlementVerdict::Landed,
        "{settled:?}"
    );
    assert_eq!(
        vault
            .get_claim(&proposal)
            .expect("read the proposal")
            .expect("the proposal")
            .approval,
        ClaimApprovalStatus::Approved
    );
    assert_eq!(
        vault
            .tasks_by_owner(owner_id, None, 64)
            .expect("owner tasks")
            .len(),
        1,
        "the approved post lands its TASK"
    );
}
