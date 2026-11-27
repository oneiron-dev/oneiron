//! An agent corrects its own claim, the old claim names the correction, and its retract waits.

mod common;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    ClaimCorrectionInput, ClaimFilteredReadRequest, ClaimInput, ClaimProposalReviewRequest,
    ClaimSettleDecision, ClaimSettleRequest, ClaimSettlement, ClaimSettlementVerdict,
    CommitReceipt, MemoryResult, resolve_entity_ref,
};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, EdgeActorClass, EntityId, Vault,
    VaultConfig,
};
use serde_json::json;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent_a: EntityId,
    agent_b: EntityId,
    subject: EntityId,
    facet: EntityId,
    owner_proof: AuthenticatedOwner,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let agent_a = vault
            .ensure_agent_principal("correct-author")
            .expect("agent A");
        let agent_b = vault
            .ensure_agent_principal("correct-bystander")
            .expect("agent B");
        let subject = vault
            .ensure_agent_principal("correct-subject")
            .expect("subject");
        let facet = vault.default_facet().expect("default facet");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        for principal in [agent_a, agent_b] {
            vault
                .grant_foreign_principal(&owner_proof, &principal.to_hex())
                .expect("the owner grants the agent read and propose");
        }
        Self {
            vault,
            owner,
            agent_a,
            agent_b,
            subject,
            facet,
            owner_proof,
            _directory: directory,
        }
    }

    /// Agent A's claim, proposed and then approved by the owner: a live claim A wrote.
    fn live_claim(&self) -> EntityId {
        let input = ClaimInput {
            id: None,
            predicate: "profile.name".to_owned(),
            subject_ref: self.subject.to_hex(),
            value: json!("Yuki"),
            confidence: 1.0,
            confidence_details: None,
            source: "inferred".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: Some(json!({ "facet": self.facet.to_hex() })),
            valid_from: Some(100),
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        };
        let receipt = self
            .vault
            .memory(self.agent_a, EdgeActorClass::Agent)
            .claim_propose(&input)
            .expect("agent proposal");
        assert_eq!(
            receipt.approval, "proposed",
            "a proposal answers proposed before the owner settles it"
        );
        let id = resolve_entity_ref(&self.vault, &receipt.claim_short_id).expect("proposal id");
        let settled = self.settle(id, ClaimSettleDecision::Approve);
        assert_eq!(
            settled.verdict,
            ClaimSettlementVerdict::Landed,
            "the owner's approval lands the proposal"
        );
        let body = self.body(id);
        assert_eq!(
            body.approval,
            ClaimApprovalStatus::Approved,
            "a settled proposal reads approved"
        );
        assert_eq!(
            body.lifecycle,
            ClaimLifecycleStatus::Active,
            "a settled proposal stays active"
        );
        id
    }

    /// A's correction of `corrects` with a new value.
    fn correction(&self, corrects: EntityId, value: &str) -> ClaimCorrectionInput {
        ClaimCorrectionInput {
            corrects: corrects.to_hex(),
            claim: ClaimInput {
                id: None,
                predicate: "profile.name".to_owned(),
                subject_ref: self.subject.to_hex(),
                value: json!(value),
                confidence: 1.0,
                confidence_details: None,
                source: "inferred".to_owned(),
                world_ref: None,
                relationship_ref: None,
                scope: None,
                valid_from: Some(100),
                valid_to: None,
                occurred_at: None,
                learned_at: None,
                salience: None,
            },
        }
    }

    fn correct_as(
        &self,
        actor: EntityId,
        input: &ClaimCorrectionInput,
    ) -> MemoryResult<CommitReceipt> {
        self.vault
            .memory(actor, EdgeActorClass::Agent)
            .claim_correct(input)
    }

    fn read_filtered_as(
        &self,
        actor: EntityId,
        id: EntityId,
    ) -> Option<oneiron::memory::ClaimView> {
        self.vault
            .memory(actor, EdgeActorClass::Agent)
            .claim_read_filtered(&ClaimFilteredReadRequest {
                claim_ref: id.to_hex(),
                filter: None,
                project_refs: Vec::new(),
            })
            .expect("filtered read runs")
            .value
    }

    fn pending_count_as(&self, actor: EntityId) -> usize {
        self.vault
            .memory(actor, EdgeActorClass::Agent)
            .pending_writes(100)
            .expect("pending writes list")
            .len()
    }

    fn review(&self, id: EntityId) -> MemoryResult<String> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .claim_review_as_owner(
                &self.owner_proof,
                &ClaimProposalReviewRequest {
                    claim_ref: id.to_hex(),
                    grant_ref: None,
                },
            )
            .map(|review| review.review_id)
    }

    fn settle(&self, id: EntityId, decision: ClaimSettleDecision) -> ClaimSettlement {
        let review_id = self.review(id).expect("review");
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .claim_settle_as_owner(
                &self.owner_proof,
                &ClaimSettleRequest {
                    claim_ref: id.to_hex(),
                    review_id,
                    decision,
                    grant_ref: None,
                },
            )
            .expect("settle")
    }

    fn body(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("read claim")
            .expect("claim exists")
    }
}

#[test]
fn a_correction_is_held_and_named_on_the_old_claim() {
    let f = Fixture::new();
    let old = f.live_claim();

    let receipt = f
        .correct_as(f.agent_a, &f.correction(old, "Yuki Tanaka"))
        .expect("A corrects its own claim");
    assert_eq!(
        receipt.approval, "proposed",
        "a correction waits for the owner"
    );
    let view = f
        .read_filtered_as(f.agent_a, old)
        .expect("the old claim still reads while its correction waits");
    let pending = view
        .pending_correction
        .clone()
        .expect("the old claim names its pending correction");
    let new_id = resolve_entity_ref(&f.vault, &receipt.claim_short_id).expect("correction id");
    assert_eq!(
        pending.claim_ref,
        new_id.to_hex(),
        "the pending correction names the new claim"
    );
    assert_eq!(
        pending.decision_ref, receipt.receipt_ref,
        "the pending correction names the correction's decision"
    );
    assert!(
        f.read_filtered_as(f.agent_b, old)
            .is_none_or(|view| view.pending_correction.is_none()),
        "another agent's read of the old claim names no pending correction"
    );
    assert!(
        receipt
            .reason_codes
            .iter()
            .any(|code| code == "gate.pending.contradiction_closure"),
        "a correction is held for contradiction closure: {:?}",
        receipt.reason_codes
    );
    assert_eq!(
        f.body(old).lifecycle,
        ClaimLifecycleStatus::Active,
        "the old claim stays live while its correction waits"
    );
}

#[test]
fn an_agents_retract_of_a_corrected_claim_waits() {
    let f = Fixture::new();
    let old = f.live_claim();
    let correction = f
        .correct_as(f.agent_a, &f.correction(old, "Yuki Tanaka"))
        .expect("A corrects its own claim");
    let before = f.pending_count_as(f.agent_a);
    assert_eq!(before, 1, "the correction parks one tray row");

    let receipt = f
        .vault
        .memory(f.agent_a, EdgeActorClass::Agent)
        .claim_retract(&old.to_hex())
        .expect("A retracts its corrected claim");
    assert!(
        receipt.approval == "pending" && receipt.note.is_some(),
        "a retract of a corrected claim waits with its note"
    );
    assert_eq!(
        receipt.receipt_ref, correction.receipt_ref,
        "the waiting retract answers the correction's decision"
    );
    let view = f
        .read_filtered_as(f.agent_a, old)
        .expect("the old claim still reads while its retract waits");
    let short = view
        .short_ref
        .clone()
        .expect("the old claim has a short ref");
    let expected_note = format!(
        "{short} closes when the correction is approved; it stays live if the correction is rejected."
    );
    assert_eq!(
        receipt.note.as_deref(),
        Some(expected_note.as_str()),
        "the waiting retract names the correction's two outcomes"
    );
    assert_eq!(
        f.body(old).lifecycle,
        ClaimLifecycleStatus::Active,
        "a waiting retract closes nothing"
    );
    assert_eq!(
        f.pending_count_as(f.agent_a),
        before,
        "a waiting retract stores no new tray row"
    );
}

#[test]
fn the_owners_approval_closes_the_old_claim() {
    let f = Fixture::new();
    let old = f.live_claim();
    let correction = f
        .correct_as(f.agent_a, &f.correction(old, "Yuki Tanaka"))
        .expect("A corrects its own claim");
    let new_id = resolve_entity_ref(&f.vault, &correction.claim_short_id).expect("correction id");

    let settled = f.settle(new_id, ClaimSettleDecision::Approve);

    assert_eq!(
        settled.verdict,
        ClaimSettlementVerdict::Landed,
        "the owner's approval lands the correction"
    );
    assert_eq!(
        f.body(old).lifecycle,
        ClaimLifecycleStatus::Superseded,
        "the owner's approval closes the old claim"
    );
    let new_body = f.body(new_id);
    assert_eq!(
        new_body.approval,
        ClaimApprovalStatus::Approved,
        "the approved correction reads approved"
    );
    assert_eq!(
        new_body.lifecycle,
        ClaimLifecycleStatus::Active,
        "the approved correction stays active"
    );
    let view = f
        .read_filtered_as(f.agent_a, new_id)
        .expect("the approved correction reads");
    assert!(
        view.held.is_none(),
        "an approved correction carries no held mark"
    );
}

#[test]
fn a_rejected_correction_leaves_the_old_claim_live() {
    let f = Fixture::new();
    let old = f.live_claim();
    let correction = f
        .correct_as(f.agent_a, &f.correction(old, "Yuki Tanaka"))
        .expect("A corrects its own claim");
    let new_id = resolve_entity_ref(&f.vault, &correction.claim_short_id).expect("correction id");

    let settled = f.settle(new_id, ClaimSettleDecision::Reject);

    assert_eq!(
        settled.verdict,
        ClaimSettlementVerdict::Rejected,
        "the owner's rejection declines the correction"
    );
    assert_eq!(
        f.body(old).lifecycle,
        ClaimLifecycleStatus::Active,
        "a rejected correction leaves the old claim live"
    );
    let view = f
        .read_filtered_as(f.agent_a, old)
        .expect("the old claim still reads after its correction is rejected");
    assert!(
        view.pending_correction.is_none(),
        "a rejected correction leaves no pending mark on the old claim"
    );
}

#[test]
fn another_actor_cannot_correct_a_claim_it_did_not_write() {
    let f = Fixture::new();
    let old = f.live_claim();
    let before = f.pending_count_as(f.agent_a);
    assert_eq!(before, 0, "a live claim parks no tray row");

    let refused = f.correct_as(f.agent_b, &f.correction(old, "Yuki Tanaka"));

    assert!(
        refused.is_err(),
        "another actor cannot correct a claim it did not write: {refused:?}"
    );
    let error = refused.expect_err("the correction is refused");
    assert!(
        error.suggestions.iter().any(
            |hint| hint == "you can correct only claims you wrote; propose a new claim instead"
        ),
        "the authorship refusal names the correction rule: {:?}",
        error.suggestions
    );
    assert_eq!(
        f.pending_count_as(f.agent_a),
        before,
        "a refused correction stores nothing"
    );
}

#[test]
fn a_correction_beside_a_different_head_is_refused() {
    let f = Fixture::new();
    let old = f.live_claim();
    let input = ClaimCorrectionInput {
        corrects: old.to_hex(),
        claim: ClaimInput {
            id: None,
            predicate: "profile.name".to_owned(),
            subject_ref: f.agent_b.to_hex(),
            value: json!("Yuki Tanaka"),
            confidence: 1.0,
            confidence_details: None,
            source: "inferred".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: Some(100),
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        },
    };

    let refused = f.correct_as(f.agent_a, &input);

    assert!(
        refused.is_err(),
        "a correction beside a different head is refused: {refused:?}"
    );
    let error = refused.expect_err("the correction is refused");
    let hints = error.suggestions.join(" ");
    assert!(
        hints.contains(&f.subject.to_hex()) && hints.contains(&f.agent_b.to_hex()),
        "the subject refusal names both subjects: {hints:?}"
    );
}

#[test]
fn a_retried_correction_with_a_changed_value_still_closes_the_named_claim() {
    let f = Fixture::new();
    let old = f.live_claim();
    let fixed_id = EntityId::now();
    let mut first = f.correction(old, "Yuki Tanaka");
    first.claim.id = Some(fixed_id.to_hex());
    let first_receipt = f
        .correct_as(f.agent_a, &first)
        .expect("A corrects its own claim under a fixed id");
    assert_eq!(
        resolve_entity_ref(&f.vault, &first_receipt.claim_short_id).expect("first id"),
        fixed_id,
        "the first try keeps the id it asked for"
    );
    let mut retry = f.correction(old, "Yuki Sato");
    retry.claim.id = Some(fixed_id.to_hex());
    let retry_receipt = f
        .correct_as(f.agent_a, &retry)
        .expect("A retries the correction under the same id with a changed value");
    let retry_id = resolve_entity_ref(&f.vault, &retry_receipt.claim_short_id).expect("retry id");
    assert_ne!(
        retry_id, fixed_id,
        "a changed value under a used id lands under a fresh id"
    );

    let settled = f.settle(retry_id, ClaimSettleDecision::Approve);

    assert_eq!(
        settled.verdict,
        ClaimSettlementVerdict::Landed,
        "the owner's approval lands the retried correction"
    );
    assert_eq!(
        f.body(old).lifecycle,
        ClaimLifecycleStatus::Superseded,
        "approving the retried correction closes the claim it names"
    );
    assert_eq!(
        f.body(retry_id).lifecycle,
        ClaimLifecycleStatus::Active,
        "the approved retry stays active"
    );
}

#[test]
fn the_owners_retract_is_unchanged() {
    let f = Fixture::new();
    let old = f.live_claim();
    f.correct_as(f.agent_a, &f.correction(old, "Yuki Tanaka"))
        .expect("A corrects its own claim");

    let receipt = f
        .vault
        .memory(f.owner, EdgeActorClass::Human)
        .claim_retract(&old.to_hex())
        .expect("the owner retracts while a correction waits");

    assert_ne!(
        receipt.approval, "pending",
        "the owner's retract lands instead of waiting"
    );
    assert!(
        receipt.note.is_none(),
        "the owner's retract carries no wait note"
    );
    assert_eq!(
        f.body(old).lifecycle,
        ClaimLifecycleStatus::Retracted,
        "the owner's retract closes the old claim at once"
    );
    assert_eq!(
        f.pending_count_as(f.agent_a),
        1,
        "the parked correction stays parked after the owner's retract"
    );
}
