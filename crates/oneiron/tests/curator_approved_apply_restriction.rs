// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! [RESTRICTION-CURATOR-APPROVED-APPLY-REJUDGE] (Astra census-l2-derive-recheck
//! F1 on #8238, the approved path's remainder): an approved curator finding
//! (`dreamer.curator.proposal`) whose rung did not apply with its approval
//! (FIX 5423's savepoint logs it) is applied by a later write, the consent
//! door's retry or the nightly pass, on the approval's judgment. RULING
//! RESTRICTION-CLOSE-BY-CURATOR-APPROVAL = A (15 Nov 18:33): an approval of a
//! curator finding that retracts a restricting row by no person stays for a
//! person; `vault.claims.settle` asks it, but only in the approval's write.
//!
//! A contact mapping (`counterparty_contact.counterparty`) restricts by its
//! contact's other heads: once the contact opts out, its mapping restricts
//! someone's access while the mapping's own body, the one the finding
//! graded, stays. So a finding approved while the contact stood, whose rung
//! did not apply then, was applied by the nightly pass after the opt-out:
//! the Dreamer retracted a restricting mapping with no person.
//!
//! The red: the pass leaves that mapping active and the finding approved
//! and unapplied. The controls: the pass still retracts the mapping of a
//! contact that restricts no one; the owner's own approval of a finding over
//! an opted-out contact still applies in its own write.
//!
//! The approval with its rung unapplied is
//! `test_doors::curator_finding::approve_finding_unapplied`. The vault is
//! rooted under a host, as `tests/conflict_settle_restriction.rs` roots it.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test curator_approved_apply_restriction`.

#![cfg(oneiron_test_support)]

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::counterparty_contact::{
    CounterpartyContactRecord, CounterpartyOptOutReason,
    PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY,
};
use oneiron::memory::{ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::curator_finding::{
    approve_finding_unapplied, emit_retract_finding, run_curator_once,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, EdgeActorClass, EntityId, Vault,
    VaultConfig,
};

const LEARNED_AT: u64 = 1_780_000_000;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    // Dropped after the vault.
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
        let issuer = HostSlipIssuer::from_secret(b"curator-approved-apply-restriction")
            .expect("fixture host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("the host root binds the owner");
        // The Dreamer signs its findings and its rungs as a MACHINE; an
        // unsigned MACHINE write is refused.
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("the engine's machine signers");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            owner,
            owner_proof,
            _directory: directory,
        }
    }

    /// A counterparty contact for `counterparty`, standing. Returns the
    /// contact's id and its live `counterparty_contact.counterparty` head,
    /// the mapping.
    fn contact(&self, counterparty: &str) -> (EntityId, EntityId) {
        let id = EntityId::now();
        let record =
            CounterpartyContactRecord::user_introduction(EntityId::now(), counterparty, LEARNED_AT)
                .expect("a valid contact record");
        self.vault
            .create_counterparty_contact(&id, &record)
            .expect("the contact lands");
        let mapping = self
            .vault
            .claims_for_subject(&id)
            .expect("the contact's claims")
            .into_iter()
            .find(|claim| {
                self.vault
                    .get_claim(claim)
                    .expect("claim read")
                    .is_some_and(|body| {
                        body.predicate == PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY
                            && body.lifecycle == ClaimLifecycleStatus::Active
                            && !body.stale
                    })
            })
            .expect("the contact's live counterparty head");
        (id, mapping)
    }

    /// The contact opts out: its mapping now restricts someone's access.
    /// The opt-out writes the contact's own opt-out head and keeps the
    /// mapping's body, so a finding graded on it still applies to it.
    fn opts_out(&self, contact: EntityId, mapping: EntityId) {
        let before = self.stored(mapping);
        self.vault
            .opt_out_counterparty_contact(
                &contact,
                CounterpartyOptOutReason::Unsubscribe,
                LEARNED_AT + 1,
            )
            .expect("the contact opts out");
        assert_eq!(
            self.stored(mapping),
            before,
            "the opt-out keeps the mapping's body, the one the finding graded"
        );
    }

    /// The Dreamer's curator finding that retracts `target`, Proposed.
    fn retract_finding(&self, target: EntityId) -> EntityId {
        let finding = emit_retract_finding(&self.vault, target).expect("the curator's finding");
        assert_eq!(
            self.stored(finding).approval,
            ClaimApprovalStatus::Proposed,
            "the finding waits for an approval"
        );
        finding
    }

    /// `finding` approved, its rung not applied with the approval.
    fn approved_unapplied(&self, finding: EntityId, target: EntityId) {
        approve_finding_unapplied(&self.vault, finding).expect("the approval lands");
        assert_eq!(
            self.stored(finding).approval,
            ClaimApprovalStatus::Approved,
            "the finding stands approved"
        );
        assert_eq!(
            self.lifecycle(target),
            ClaimLifecycleStatus::Active,
            "the rung did not apply with the approval"
        );
    }

    /// The owner's own `vault.claims.review` then `vault.claims.settle`
    /// Approve of `finding`, which applies its rung in the approval's write.
    fn owner_approves(&self, finding: EntityId) {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        let review = memory
            .claim_review_as_owner(
                &self.owner_proof,
                &ClaimProposalReviewRequest {
                    claim_ref: finding.to_hex(),
                    grant_ref: None,
                },
            )
            .expect("the owner reviews the finding");
        memory
            .claim_settle_as_owner(
                &self.owner_proof,
                &ClaimSettleRequest {
                    claim_ref: finding.to_hex(),
                    review_id: review.review_id,
                    decision: ClaimSettleDecision::Approve,
                    grant_ref: None,
                },
            )
            .expect("the owner approves the finding");
    }

    fn nightly_pass(&self) {
        run_curator_once(&self.vault, self.vault.now_recorded_at()).expect("one curator pass");
    }

    fn stored(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("claim read")
            .expect("the claim is stored")
    }

    fn lifecycle(&self, id: EntityId) -> ClaimLifecycleStatus {
        self.stored(id).lifecycle
    }
}

/// The red: the contact opts out after the finding's approval, so its
/// mapping restricts someone's access since. The nightly pass judges the
/// rung again in its own write and leaves the mapping active; the finding
/// stays approved for a later pass, and a second pass holds it too.
#[test]
fn the_nightly_pass_never_retracts_a_contact_mapping_that_restricts_since_its_approval() {
    let f = Fixture::new();
    let (contact, mapping) = f.contact("ada@example.com");
    let finding = f.retract_finding(mapping);
    f.approved_unapplied(finding, mapping);
    f.opts_out(contact, mapping);
    f.nightly_pass();
    assert_eq!(
        f.lifecycle(mapping),
        ClaimLifecycleStatus::Active,
        "an approval given while the contact stood never retracts its mapping once it opted out"
    );
    assert_eq!(
        f.stored(finding).approval,
        ClaimApprovalStatus::Approved,
        "the finding waits approved"
    );
    f.nightly_pass();
    assert_eq!(
        f.lifecycle(mapping),
        ClaimLifecycleStatus::Active,
        "a later pass holds it while the contact stays opted out"
    );
}

/// Control: with no opt-out the mapping restricts no one, and the nightly
/// pass applies the approved rung as before.
#[test]
fn the_nightly_pass_still_retracts_an_approved_contact_mapping_that_restricts_no_one() {
    let f = Fixture::new();
    let (_contact, mapping) = f.contact("grace@example.com");
    let finding = f.retract_finding(mapping);
    f.approved_unapplied(finding, mapping);
    f.nightly_pass();
    assert_eq!(
        f.lifecycle(mapping),
        ClaimLifecycleStatus::Retracted,
        "the approved rung applies at the nightly pass"
    );
}

/// Control: the owner's own approval of a finding over an opted-out contact
/// applies its rung in the approval's write; the owner may lift the
/// restriction.
#[test]
fn the_owners_own_approval_still_retracts_a_contact_mapping_that_restricts() {
    let f = Fixture::new();
    let (contact, mapping) = f.contact("edsger@example.com");
    f.opts_out(contact, mapping);
    let finding = f.retract_finding(mapping);
    f.owner_approves(finding);
    assert_eq!(
        f.lifecycle(mapping),
        ClaimLifecycleStatus::Retracted,
        "the owner's approval applies with it"
    );
}
