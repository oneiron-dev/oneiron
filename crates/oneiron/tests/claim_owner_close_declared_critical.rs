//! The vault owner's other close doors carry the owner's proof to the Gate
//! (FIX OWNER-CLOSE-DOORS-DECLARED-CRITICAL-APPROVED-CLOSE-PENDS, found
//! fixing review 10099 round 2). The case: an agent's claim the owner
//! approved, on a predicate a trusted policy then declares critical. Its tray
//! row is gone, and the close of an Approved claim on a declared critical
//! class pends on the declared criticality floor, which no fallback lift
//! clears. The owner's proof, revalidated in the close's transaction, is the
//! in-person confirmation that floor asks for, as on the owner's supersede
//! door (#10099): through `Vault::retract_claim_as_owner`, through the
//! owner's `Memory::claim_retract`, and through the owner's settle of a
//! proposal whose approval supersedes the claim. A close with no owner proof
//! stays held.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test claim_owner_close_declared_critical`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    ClaimSettlementVerdict, resolve_entity_ref,
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
    agent: EntityId,
    subject: EntityId,
    facet: EntityId,
    owner_proof: AuthenticatedOwner,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
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
        let agent = vault
            .ensure_agent_principal("critical-close-author")
            .expect("FIXTURE: agent");
        let subject = vault
            .ensure_agent_principal("critical-close-subject")
            .expect("FIXTURE: subject");
        let facet = vault.default_facet().expect("FIXTURE: default facet");
        // The local host attests its own owner.
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("FIXTURE: owner proof");
        // The agent reads and proposes, as a paired agent session does.
        vault
            .grant_foreign_principal(&owner_proof, &agent.to_hex())
            .expect("FIXTURE: the owner grants the agent read and propose");
        Self {
            vault,
            owner,
            agent,
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

    /// The agent's `profile.name` proposal about the subject: its id.
    fn agent_proposal(&self, value: &str) -> EntityId {
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
            .memory(self.agent, EdgeActorClass::Agent)
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
    fn owner_settles(
        &self,
        id: EntityId,
    ) -> oneiron::memory::MemoryResult<oneiron::memory::ClaimSettlement> {
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
        memory.claim_settle_as_owner(
            &self.owner_proof,
            &ClaimSettleRequest {
                claim_ref: id.to_hex(),
                review_id: review.review_id,
                decision: ClaimSettleDecision::Approve,
                grant_ref: None,
            },
        )
    }

    /// The agent's claim, proposed and approved by the owner, after which a
    /// trusted policy declares its predicate critical: an Approved, Active
    /// claim with no tray row, on a declared critical class. Its id.
    fn approved_claim_on_a_declared_critical_predicate(&self) -> EntityId {
        let id = self.agent_proposal("Yuki");
        let settled = self
            .owner_settles(id)
            .expect("FIXTURE: the owner approves the agent's proposal");
        assert_eq!(
            settled.verdict,
            ClaimSettlementVerdict::Landed,
            "FIXTURE: the owner's approval lands"
        );
        let body = self.body(id);
        assert_eq!(
            (body.approval, body.lifecycle),
            (ClaimApprovalStatus::Approved, ClaimLifecycleStatus::Active),
            "FIXTURE: the approved claim is active"
        );
        declare_predicate_critical(&self.vault, PREDICATE)
            .expect("FIXTURE: the policy declares the claim's predicate critical");
        id
    }

    /// The claim `id` was closed as `lifecycle` says.
    fn assert_closed(&self, id: EntityId, lifecycle: ClaimLifecycleStatus, why: &str) {
        let body = self.body(id);
        assert_eq!(body.lifecycle, lifecycle, "{why}");
        assert!(body.valid_to.is_some(), "{why}: its validity ends");
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
}

#[test]
fn the_owners_vault_retract_closes_an_approved_claim_on_a_declared_critical_predicate() {
    let f = Fixture::new();
    let id = f.approved_claim_on_a_declared_critical_predicate();

    let retract = f
        .vault
        .retract_claim_as_owner(&f.owner_proof, &id, f.vault.now_recorded_at());

    assert!(
        retract.is_ok(),
        "the owner's retract through the vault owner door closes the approved claim as the \
         owner's act, confirmed by the owner's proof: {retract:?}"
    );
    f.assert_closed(
        id,
        ClaimLifecycleStatus::Retracted,
        "the owner's vault retract closes the claim",
    );
}

#[test]
fn the_owners_memory_retract_closes_an_approved_claim_on_a_declared_critical_predicate() {
    let f = Fixture::new();
    let id = f.approved_claim_on_a_declared_critical_predicate();

    let retract = f
        .vault
        .memory(f.owner, EdgeActorClass::Human)
        .with_owner_authorship(&f.owner_proof)
        .claim_retract(&id.to_hex());

    assert!(
        retract.is_ok(),
        "the owner's Memory retract closes the approved claim, confirmed by the owner's \
         proof: {retract:?}"
    );
    f.assert_closed(
        id,
        ClaimLifecycleStatus::Retracted,
        "the owner's Memory retract closes the claim",
    );
}

#[test]
fn the_owners_settle_supersedes_an_approved_head_on_a_declared_critical_predicate() {
    let f = Fixture::new();
    let head = f.approved_claim_on_a_declared_critical_predicate();
    let replacement = f.agent_proposal("Yuki Tanaka");

    let settled = f.owner_settles(replacement);

    let settled = settled.unwrap_or_else(|error| {
        panic!(
            "the owner's approval of the replacement closes the approved head it supersedes, \
             confirmed by the owner's proof: {error:?}"
        )
    });
    assert_eq!(
        settled.verdict,
        ClaimSettlementVerdict::Landed,
        "the owner's approval of the replacement lands"
    );
    f.assert_closed(
        head,
        ClaimLifecycleStatus::Superseded,
        "the approval supersedes the approved head",
    );
    let replaced = f.body(replacement);
    assert_eq!(
        (replaced.approval, replaced.lifecycle),
        (ClaimApprovalStatus::Approved, ClaimLifecycleStatus::Active),
        "the replacement stands approved"
    );
}

/// Control: the same close through `Vault::retract_claim`, which names no
/// closer and carries no owner proof, stays held: the owner's proof lifts the
/// declared floor only for the owner's own close.
#[test]
fn a_vault_retract_with_no_owner_proof_stays_held_on_a_declared_critical_predicate() {
    let f = Fixture::new();
    let id = f.approved_claim_on_a_declared_critical_predicate();

    let retract = f.vault.retract_claim(&id, f.vault.now_recorded_at());

    assert!(
        retract.is_err(),
        "a close with no owner proof stays held: {retract:?}"
    );
    f.assert_standing(id, "the held close leaves the approved claim active");
}

/// Control: the owner's Memory surface with no owner proof bound carries
/// none to the Gate, so its close stays held.
#[test]
fn a_memory_retract_with_no_bound_owner_proof_stays_held_on_a_declared_critical_predicate() {
    let f = Fixture::new();
    let id = f.approved_claim_on_a_declared_critical_predicate();

    let retract = f
        .vault
        .memory(f.owner, EdgeActorClass::Human)
        .claim_retract(&id.to_hex());

    assert!(
        retract.is_err(),
        "a Memory close with no bound owner proof stays held: {retract:?}"
    );
    f.assert_standing(id, "the held close leaves the approved claim active");
}
