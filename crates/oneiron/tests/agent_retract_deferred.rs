//! An agent's retract of its own approved claim waits for the holder
//! (e2e MEMORY-01; ARCH-0040 `mcp:5`: "destructive supersede/retract defers
//! closure until approval"). The retract parks for the holder's consent and
//! the claim stands until the holder settles it: an approval retracts it, a
//! decline leaves it as it was. Another agent's retract is still refused,
//! and so is a retract while another action waits on the claim.

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    ClaimSettlement, ClaimSettlementVerdict, CommitReceipt, MemoryResult, resolve_entity_ref,
};
use oneiron::store::GateDecisionId;
use oneiron::write_envelope::claim_body::ClaimDemotionAction;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, EdgeActorClass, EntityId, Vault,
    VaultConfig,
};
use serde_json::json;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    other_agent: EntityId,
    subject: EntityId,
    facet: EntityId,
    owner_proof: AuthenticatedOwner,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        // A host loads this install's signing keys from its keystore after
        // each open.
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let agent = vault
            .ensure_agent_principal("retract-author")
            .expect("agent");
        let other_agent = vault
            .ensure_agent_principal("retract-bystander")
            .expect("other agent");
        let subject = vault
            .ensure_agent_principal("retract-subject")
            .expect("subject");
        let facet = vault.default_facet().expect("default facet");
        // The local host attests its own owner.
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        // Both agents read and propose, as a paired agent session does.
        for principal in [agent, other_agent] {
            vault
                .grant_foreign_principal(&owner_proof, &principal.to_hex())
                .expect("the owner grants the agent read and propose");
        }
        Self {
            vault,
            owner,
            agent,
            other_agent,
            subject,
            facet,
            owner_proof,
            _directory: directory,
        }
    }

    /// The agent's claim, proposed and then approved by the owner: an
    /// approved claim the agent wrote.
    fn approved_agent_claim(&self) -> EntityId {
        self.approved_agent_claim_on("profile.name", "Yuki")
    }

    /// [`Self::approved_agent_claim`] on `predicate`.
    fn approved_agent_claim_on(&self, predicate: &str, value: &str) -> EntityId {
        let input = ClaimInput {
            id: None,
            predicate: predicate.to_owned(),
            subject_ref: self.subject.to_hex(),
            value: json!(value),
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
            .memory(self.agent, EdgeActorClass::Agent)
            .claim_propose(&input)
            .expect("agent proposal");
        assert_eq!(receipt.approval, "proposed");
        let id = resolve_entity_ref(&self.vault, &receipt.claim_short_id).expect("proposal id");
        let settled = self.settle(id, ClaimSettleDecision::Approve);
        assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
        let body = self.body(id);
        assert_eq!(body.approval, ClaimApprovalStatus::Approved);
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
        id
    }

    fn retract_as(&self, actor: EntityId, id: EntityId) -> MemoryResult<CommitReceipt> {
        self.vault
            .memory(actor, EdgeActorClass::Agent)
            .claim_retract(&id.to_hex())
    }

    /// The agent's retract of its own approved claim, which must park.
    fn park(&self, id: EntityId) -> CommitReceipt {
        let receipt = self
            .retract_as(self.agent, id)
            .unwrap_or_else(|error| panic!("the author's retract is refused: {error:?}"));
        assert_eq!(
            receipt.approval, "pending",
            "the retract waits for the holder"
        );
        assert!(
            receipt.receipt_ref.starts_with("gate:"),
            "the receipt names the pending decision: {}",
            receipt.receipt_ref
        );
        receipt
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

    /// The claim still stands as the owner approved it.
    fn assert_standing(&self, id: EntityId, why: &str) {
        let body = self.body(id);
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active, "{why}");
        assert_eq!(body.approval, ClaimApprovalStatus::Approved, "{why}");
        assert_eq!(body.valid_to, None, "{why}");
    }
}

#[test]
fn an_agents_retract_of_its_approved_claim_parks_for_the_holder() {
    let f = Fixture::new();
    let id = f.approved_agent_claim();

    f.park(id);

    f.assert_standing(id, "nothing closes before the holder consents");
    assert!(f.review(id).is_ok(), "the owner reviews the parked retract");
}

#[test]
fn the_holders_approval_retracts_the_parked_claim() {
    let f = Fixture::new();
    let id = f.approved_agent_claim();
    f.park(id);

    let settled = f.settle(id, ClaimSettleDecision::Approve);

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    assert!(settled.revert.is_none(), "a retraction is final");
    let body = f.body(id);
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Retracted);
    assert!(
        body.valid_to.is_some(),
        "the retracted claim's validity ends"
    );
    assert!(f.review(id).is_err(), "nothing is left to settle");
}

#[test]
fn the_holders_decline_leaves_the_claim_standing() {
    let f = Fixture::new();
    let id = f.approved_agent_claim();
    f.park(id);

    let settled = f.settle(id, ClaimSettleDecision::Reject);

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Rejected);
    f.assert_standing(
        id,
        "a declined retract leaves the claim approved, never rejected",
    );
    assert!(f.review(id).is_err(), "the declined retract is gone");
}

#[test]
fn a_repeat_retract_while_parked_retracts_nothing() {
    let f = Fixture::new();
    let id = f.approved_agent_claim();
    let first = f.park(id);

    let again = f.park(id);

    assert_eq!(
        again.receipt_ref, first.receipt_ref,
        "the repeat answers the same pending decision"
    );
    f.assert_standing(id, "the author never redeems its own parked retract");
    assert!(f.review(id).is_ok(), "the retract still waits");
}

#[test]
fn the_owners_own_retract_while_parked_lands() {
    let f = Fixture::new();
    let id = f.approved_agent_claim();
    f.park(id);

    f.vault
        .memory(f.owner, EdgeActorClass::Human)
        .claim_retract(&id.to_hex())
        .expect("the owner retracts the claim");

    assert_eq!(f.body(id).lifecycle, ClaimLifecycleStatus::Retracted);
    assert!(f.review(id).is_err(), "no parked retract is left behind");
}

#[test]
fn another_agents_retract_is_still_refused() {
    let f = Fixture::new();
    let id = f.approved_agent_claim();

    let refused = f.retract_as(f.other_agent, id);

    assert!(
        refused.is_err(),
        "an agent retracts only a claim it wrote: {refused:?}"
    );
    f.assert_standing(id, "a refused retract changes nothing");
    assert!(f.review(id).is_err(), "nothing parks for the holder");
}

/// A retract while the owner's critical confirm of a stale mark waits on
/// the claim is refused: it would close that confirm's tray row as its own
/// consent. The stale mark still waits (review round 1 of #7289).
#[test]
fn a_retract_while_another_action_waits_on_the_claim_is_refused() {
    let f = Fixture::new();
    // A predicate the default manifest declares critical.
    let id = f.approved_agent_claim_on("health.allergy", "peanuts");
    let held = f
        .vault
        .apply_claim_demotion(&id, ClaimDemotionAction::MarkStale, 1_000);
    assert!(
        held.is_err(),
        "a critical stale mark waits for the owner's confirm: {held:?}"
    );
    assert!(matches!(
        f.vault
            .pending_claim_demotion(&id)
            .expect("read the demotion"),
        Some(ClaimDemotionAction::MarkStale)
    ));

    let refused = f.retract_as(f.agent, id);

    assert!(
        refused.is_err(),
        "the retract waits for the parked stale mark: {refused:?}"
    );
    f.assert_standing(id, "a refused retract changes nothing");
    assert!(
        matches!(
            f.vault
                .pending_claim_demotion(&id)
                .expect("read the demotion"),
            Some(ClaimDemotionAction::MarkStale)
        ),
        "the owner's stale-mark confirm still waits"
    );
}
