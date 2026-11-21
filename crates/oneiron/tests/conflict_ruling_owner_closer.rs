//! The root owner's conflict ruling closes the disputed claim as the owner
//! (FIX OWNER-CONFLICT-RULING-CLOSES-WITH-NO-CLOSER). The case: an agent's
//! claim the owner approved, on a predicate a trusted policy then declares
//! critical. The claim's subject proposes a correction and raises a private
//! dispute; the owner rules for the correction
//! (`Memory::rule_claim_conflict`). The ruling writes its own Approved row
//! and supersedes the disputed head, and on a declared critical class each
//! write pends on the declared criticality floor, which no fallback lift
//! clears. The owner's proof, revalidated in the ruling's transaction, is the
//! in-person confirmation that floor asks for, as on the owner's settle
//! (#10161); the reviewer is the close's verified closer. On main the ruling
//! writes its row with no owner proof and closes the head with no closer, so
//! the owner's ruling is refused there.
//!
//! The control rules the same dispute on a predicate no policy declares
//! critical: no floor asks for the owner's proof, so the reviewer as the
//! close's closer is all it needs. On main the close of the agent's head is
//! judged as its author, whose foreign-agent ceiling holds an Approved close
//! pending with no tray row, so the control is expected to fail there too.
//!
//! The vault is rooted under a host (a ruling needs a rooted vault and the
//! owner's active human binding under its root).
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test conflict_ruling_owner_closer`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    ClaimConflictQuestion, ClaimConflictReceipt, ClaimInput, ClaimProposalReviewRequest,
    ClaimSettleDecision, ClaimSettleRequest, ClaimSettlementVerdict, MemoryResult,
    resolve_entity_ref,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::consolidation::declare_predicate_critical;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, EdgeActorClass, EntityId, Vault,
    VaultConfig,
};
use serde_json::json;

const PREDICATE: &str = "profile.name";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    author: EntityId,
    subject: EntityId,
    facet: EntityId,
    owner_proof: AuthenticatedOwner,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

/// A raised dispute: the disputed claim, the correction it proposes, and
/// the packet's id.
struct Dispute {
    disputed: EntityId,
    proposal: EntityId,
    bundle_id: [u8; 32],
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("FIXTURE: vault dir");
        let vault =
            Vault::open(directory.path(), VaultConfig::device()).expect("FIXTURE: open vault");
        // A host loads this install's signing keys from its keystore after
        // each open.
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("FIXTURE: load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("FIXTURE: owner");
        let issuer = HostSlipIssuer::from_secret(b"conflict-ruling-owner-closer")
            .expect("FIXTURE: host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("FIXTURE: the host root binds the owner");
        let author = vault
            .ensure_agent_principal("conflict-ruling-author")
            .expect("FIXTURE: author");
        let subject = vault
            .ensure_agent_principal("conflict-ruling-subject")
            .expect("FIXTURE: subject");
        let facet = vault.default_facet().expect("FIXTURE: default facet");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("FIXTURE: owner proof");
        for agent in [author, subject] {
            vault
                .grant_foreign_principal(&owner_proof, &agent.to_hex())
                .expect("FIXTURE: the owner grants the agent read and propose");
        }
        Self {
            vault,
            owner,
            author,
            subject,
            facet,
            owner_proof,
            _directory: directory,
        }
    }

    fn body(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("read claim")
            .expect("the claim remains stored")
    }

    /// `agent`'s `profile.name` proposal about the subject: its id.
    fn proposes(&self, agent: EntityId, value: &str) -> EntityId {
        let input = ClaimInput {
            id: None,
            predicate: PREDICATE.to_owned(),
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
            .memory(agent, EdgeActorClass::Agent)
            .claim_propose(&input)
            .expect("FIXTURE: the agent's proposal");
        assert_eq!(
            receipt.approval, "proposed",
            "FIXTURE: the agent's claim waits for the owner"
        );
        resolve_entity_ref(&self.vault, &receipt.claim_short_id).expect("FIXTURE: proposal id")
    }

    /// The owner reviews and approves the proposal `id` through the owner's
    /// Memory settle.
    fn owner_approves(&self, id: EntityId) {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        let review = memory
            .claim_review_as_owner(
                &self.owner_proof,
                &ClaimProposalReviewRequest {
                    claim_ref: id.to_hex(),
                    grant_ref: None,
                },
            )
            .expect("FIXTURE: the owner reviews the proposal");
        let settled = memory
            .claim_settle_as_owner(
                &self.owner_proof,
                &ClaimSettleRequest {
                    claim_ref: id.to_hex(),
                    review_id: review.review_id,
                    decision: ClaimSettleDecision::Approve,
                    grant_ref: None,
                },
            )
            .expect("FIXTURE: the owner approves the author's proposal");
        assert_eq!(
            settled.verdict,
            ClaimSettlementVerdict::Landed,
            "FIXTURE: the owner's approval lands"
        );
    }

    /// The author's claim about the subject, which the owner approved;
    /// when `declared_critical`, a trusted policy then declares its
    /// predicate critical. The subject proposes a correction and raises a
    /// private dispute over the claim.
    fn dispute_over_an_approved_claim(&self, declared_critical: bool) -> Dispute {
        let disputed = self.proposes(self.author, "Yuki");
        self.owner_approves(disputed);
        self.assert_standing(disputed, "FIXTURE: the approved claim is active");
        if declared_critical {
            declare_predicate_critical(&self.vault, PREDICATE)
                .expect("FIXTURE: the policy declares the claim's predicate critical");
        }
        let proposal = self.proposes(self.subject, "Yuki Tanaka");
        let bundle = self
            .vault
            .memory(self.subject, EdgeActorClass::Agent)
            .question_claim_conflict(
                ClaimConflictQuestion::ConflictOfInterest,
                &disputed.to_hex(),
                &proposal.to_hex(),
            )
            .expect("FIXTURE: the subject raises its dispute over the claim");
        Dispute {
            disputed,
            proposal,
            bundle_id: bundle.bundle_id,
        }
    }

    /// The owner's ruling on `dispute`, under the owner's proof.
    fn owner_rules(&self, dispute: &Dispute) -> MemoryResult<ClaimConflictReceipt> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .rule_claim_conflict(
                &self.owner_proof,
                dispute.bundle_id,
                self.vault.now_recorded_at(),
            )
    }

    /// The claim `id` still stands as the owner approved it.
    fn assert_standing(&self, id: EntityId, why: &str) {
        let body = self.body(id);
        assert_eq!(
            (body.approval, body.lifecycle),
            (ClaimApprovalStatus::Approved, ClaimLifecycleStatus::Active),
            "{why}"
        );
        assert_eq!(body.valid_to, None, "{why}");
    }

    /// The ruling `receipt` on `dispute` landed whole: the disputed claim is
    /// superseded by the ruling's own Approved row, which holds the
    /// correction, and the consumed proposal is retracted.
    fn assert_ruled(&self, dispute: &Dispute, receipt: &ClaimConflictReceipt) {
        assert_eq!(
            receipt.superseded_claim, dispute.disputed,
            "the ruling names the disputed claim it superseded"
        );
        let closed = self.body(dispute.disputed);
        assert_eq!(
            closed.lifecycle,
            ClaimLifecycleStatus::Superseded,
            "the ruling supersedes the disputed claim"
        );
        assert!(
            closed.valid_to.is_some(),
            "the disputed claim's validity ends"
        );
        self.assert_standing(receipt.ruling_claim, "the ruling's own row stands approved");
        let ruled = self.body(receipt.ruling_claim);
        assert_eq!(
            ruled.predicate, PREDICATE,
            "the ruling's row is about the disputed predicate"
        );
        assert_eq!(
            self.body(dispute.proposal).lifecycle,
            ClaimLifecycleStatus::Retracted,
            "the ruling consumes the proposal"
        );
    }
}

#[test]
fn the_owners_ruling_closes_an_approved_claim_on_a_declared_critical_predicate() {
    let f = Fixture::new();
    let dispute = f.dispute_over_an_approved_claim(true);

    let ruled = f.owner_rules(&dispute);

    let receipt = ruled.unwrap_or_else(|error| {
        panic!(
            "the owner's ruling writes its approved row and closes the approved claim it \
             supersedes, confirmed by the owner's proof: {error:?}"
        )
    });
    f.assert_ruled(&dispute, &receipt);
}

/// Control: the same ruling on a predicate no policy declares critical,
/// where the reviewer as closer is enough and no owner proof is asked.
#[test]
fn the_owners_ruling_closes_an_approved_claim_on_an_ordinary_predicate() {
    let f = Fixture::new();
    let dispute = f.dispute_over_an_approved_claim(false);

    let ruled = f.owner_rules(&dispute);

    let receipt = ruled
        .unwrap_or_else(|error| panic!("the owner's ruling on an ordinary class lands: {error:?}"));
    f.assert_ruled(&dispute, &receipt);
}
