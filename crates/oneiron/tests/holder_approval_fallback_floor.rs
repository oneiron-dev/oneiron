//! A Grant holder's approval lands under the holder's Grant on a predicate no
//! manifest rule names ([HOLDER-APPROVAL-FALLBACK-FLOOR]). ARCH-0003
//! §Criticality: "A schema-valid claim on an unregistered predicate lands
//! under the actor's Grant", and the critical default "does not stop the
//! write". Before this change the gate parked a holder's `vault.claims.settle`
//! approval of such a proposal at `gate.pending.criticality_floor`. A declared
//! critical class (`health.`) still waits for the owner, and a holder whose
//! ceiling stops at proposals is still refused.
//!
//! Run with `cargo test --locked -p oneiron --all-features --test holder_approval_fallback_floor`.

use oneiron::agent_def::AgentCeiling;
use oneiron::authority::HostSlipIssuer;
use oneiron::consent::{AuthenticatedOwner, consent_receipt_grant_ref};
use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    ClaimSettlementReason, ClaimSettlementVerdict, MemoryAuthoringAction, resolve_entity_ref,
};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, EdgeActorClass, EntityId, Vault,
    VaultConfig, WriteActor,
};
use serde_json::json;

/// No rule of the shipped manifest names this predicate: it resolves
/// critical by fallback.
const UNDECLARED_PREDICATE: &str = "loop.alpha";
/// The shipped manifest declares the `health.` class critical.
const DECLARED_CRITICAL_PREDICATE: &str = "health.allergy";
/// The gate's reason for a write parked on the criticality floor.
const CRITICALITY_FLOOR: &str = "gate.pending.criticality_floor";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    holder: EntityId,
    subject: EntityId,
    facet: EntityId,
    owner_proof: AuthenticatedOwner,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    /// A vault rooted under a host (an owner's native Grant needs a rooted
    /// vault), opened with the shipped default manifest; an agent the owner
    /// granted read and propose; and a second agent, the holder, whose
    /// ceiling the owner set to `holder_ceiling`.
    fn new(holder_ceiling: AgentCeiling) -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let issuer = HostSlipIssuer::from_secret(b"holder-approval-fallback-floor")
            .expect("fixture host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("the host root binds the owner");
        let agent = vault
            .ensure_agent_principal("holder-floor-proposer")
            .expect("agent");
        let holder = vault
            .ensure_agent_principal("holder-floor-holder")
            .expect("holder");
        let subject = vault
            .ensure_agent_principal("holder-floor-subject")
            .expect("subject");
        let facet = vault.default_facet().expect("default facet");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        vault
            .grant_foreign_principal(&owner_proof, &agent.to_hex())
            .expect("the owner grants the proposer read and propose");
        vault
            .grant_agent_principal(&owner_proof, &holder.to_hex(), holder_ceiling)
            .expect("the owner grants the holder read and its ceiling");
        Self {
            vault,
            owner,
            agent,
            holder,
            subject,
            facet,
            owner_proof,
            _directory: directory,
        }
    }

    fn input(&self, predicate: &str, value: &str) -> ClaimInput {
        ClaimInput {
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
        }
    }

    /// The agent's proposal, parked for review.
    fn propose(&self, predicate: &str, value: &str) -> EntityId {
        let receipt = self
            .vault
            .memory(self.agent, EdgeActorClass::Agent)
            .claim_propose(&self.input(predicate, value))
            .expect("agent proposal");
        assert_eq!(receipt.approval, "proposed");
        resolve_entity_ref(&self.vault, &receipt.claim_short_id).expect("proposal id")
    }

    /// The owner's native Grant: the holder may review and settle this one
    /// proposal. Returns its 64-hex grant_ref.
    fn grant_review(&self, id: EntityId) -> String {
        let receipt = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .delegate_memory_authoring(
                &self.owner_proof,
                WriteActor::new(self.holder, EdgeActorClass::Agent),
                MemoryAuthoringAction::ReviewClaim,
                id,
            )
            .expect("the owner grants the holder this proposal's review");
        consent_receipt_grant_ref(&receipt).expect("a standing grant names its grant_ref")
    }

    /// The holder's `vault.claims.review` then `vault.claims.settle`
    /// (approve), both under the named Grant.
    fn holder_settles(
        &self,
        id: EntityId,
    ) -> oneiron::memory::MemoryResult<oneiron::memory::ClaimSettlement> {
        let grant_ref = self.grant_review(id);
        let memory = self.vault.memory(self.holder, EdgeActorClass::Agent);
        let review = memory
            .claim_review(&ClaimProposalReviewRequest {
                claim_ref: id.to_hex(),
                grant_ref: Some(grant_ref.clone()),
            })
            .expect("the holder reviews under its Grant");
        assert_eq!(review.opener_ref, Some(self.agent.to_hex()));
        memory.claim_settle(&ClaimSettleRequest {
            claim_ref: id.to_hex(),
            review_id: review.review_id,
            decision: ClaimSettleDecision::Approve,
            grant_ref: Some(grant_ref),
        })
    }

    fn body(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("read claim")
            .expect("claim exists")
    }

    /// The proposal reads back still Proposed and live: nothing landed.
    fn assert_still_proposed(&self, id: EntityId, predicate: &str) {
        let body = self.body(id);
        assert_eq!(body.predicate, predicate);
        assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
    }
}

/// `vault.claims.settle` with a grant_ref: a holder with an Auto ceiling
/// approves an agent's proposal on a predicate no rule names. Before this
/// change the approval answered FORBIDDEN `gate.pending.criticality_floor`.
#[test]
fn holder_settle_lands_an_agent_proposal_on_an_undeclared_predicate() {
    let f = Fixture::new(AgentCeiling::Auto);
    let id = f.propose(UNDECLARED_PREDICATE, "the first loop note");

    let settled = f
        .holder_settles(id)
        .expect("the holder's approval lands under its Grant");

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    assert_eq!(settled.reason, ClaimSettlementReason::HolderApproved);
    let body = f.body(id);
    assert_eq!(body.predicate, UNDECLARED_PREDICATE);
    assert_eq!(body.approval, ClaimApprovalStatus::Approved);
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
}

/// A declared critical class still waits for the owner: the same holder's
/// approval on `health.allergy` pends on the floor, and the proposal stays
/// Proposed.
#[test]
fn holder_settle_on_a_declared_critical_predicate_still_pends() {
    let f = Fixture::new(AgentCeiling::Auto);
    let id = f.propose(DECLARED_CRITICAL_PREDICATE, "peanuts");

    let refused = f
        .holder_settles(id)
        .expect_err("a holder's approval does not land a declared critical class");

    assert_eq!(refused.code, "FORBIDDEN");
    assert!(
        refused.message.contains(CRITICALITY_FLOOR),
        "the declared floor pends: {}",
        refused.message
    );
    f.assert_still_proposed(id, DECLARED_CRITICAL_PREDICATE);
}

/// A holder whose ceiling stops at proposals is refused at the gate on an
/// undeclared predicate too: the lift answers only the floor, never the
/// holder's own ceiling.
#[test]
fn holder_with_a_proposed_ceiling_is_refused_on_an_undeclared_predicate() {
    let f = Fixture::new(AgentCeiling::Proposed);
    let id = f.propose(UNDECLARED_PREDICATE, "the second loop note");

    let refused = f
        .holder_settles(id)
        .expect_err("a Proposed-ceiling holder's approval does not land");

    assert_eq!(refused.code, "FORBIDDEN");
    f.assert_still_proposed(id, UNDECLARED_PREDICATE);
}
