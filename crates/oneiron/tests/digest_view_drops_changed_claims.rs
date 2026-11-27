//! A delivered proactivity digest shows a Dreamer finding to the owner only
//! while the proposed CLAIM still stands as the digest copied it. Deleting,
//! reviewing or withdrawing the finding removes it from both the view's
//! groups and its rendered text (PROACTIVITY-DIGEST-COPY-ERASURE).
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test digest_view_drops_changed_claims`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::DeleteReason;
use oneiron::dreamer_runner::maintenance::digest::ProactivityDigestView;
use oneiron::memory::{ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest};
use oneiron::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::curator_finding::emit_retract_finding;
use oneiron::test_doors::house_link::put_claim_made_by;
use oneiron::test_doors::source_audience_binding::{bound_row, reads};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EdgeKind, EntityId, Vault, VaultConfig,
};

const FACT_PREDICATE: &str = "profile.preference";
const SIGNER_SECRET: &[u8] = b"digest-view-drops-changed-claims";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    row: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn with_machine_signers(secret: &[u8]) -> Self {
        let dir = tempfile::tempdir().expect("FIXTURE: a temporary vault dir");
        let vault =
            Vault::open(dir.path(), VaultConfig::device()).expect("FIXTURE: open the vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("FIXTURE: this install's signing keys");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("FIXTURE: the embedded owner");
        let issuer = HostSlipIssuer::from_secret(secret).expect("FIXTURE: the host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("FIXTURE: the host root binds the owner");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("FIXTURE: the engine's machine signers");
        let proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("FIXTURE: the owner's proof");
        let (row, _policy) =
            bound_row(&vault, owner).expect("FIXTURE: a row of the owner's own mailbox");
        Self {
            vault,
            owner,
            proof,
            row,
            _dir: dir,
        }
    }

    fn fact_from_the_mailbox(&self, predicate: &str) -> EntityId {
        let at = self.vault.now_recorded_at();
        let mut body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(self.owner),
            rmpv::Value::from("The harbour survey's lantern list is kept in the owner's mail."),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("FIXTURE: an open CLAIM body");
        body.source = Some(ClaimSource::UserStated);
        let fact = EntityId::now();
        put_claim_made_by(
            &self.vault,
            fact,
            &body,
            MadeBy {
                inputs: vec![MadeByInput {
                    row: self.row,
                    role: MadeByInputRole::Input,
                }],
                process: MadeByProcess {
                    actor: self.owner,
                    class: MadeByClass::Stated,
                    identity: "digest_view_drops_changed_claims.fixture".to_owned(),
                    version: "1".to_owned(),
                    params_hash: "0".repeat(64),
                },
                at,
                trigger: None,
            },
        )
        .expect("FIXTURE: the fact and its birth");
        assert!(
            reads(&self.vault, fact, &[self.owner]).expect("FIXTURE: the owner's read"),
            "FIXTURE: the owner reads the fact learnt from the owner's own mailbox"
        );
        fact
    }

    fn digest_with_finding(&self, fact: EntityId) -> ([u8; 32], EntityId, String) {
        let finding =
            emit_retract_finding(&self.vault, fact).expect("FIXTURE: the Dreamer's finding");
        let digest = self
            .vault
            .proactivity_digest(&self.proof, self.vault.now_recorded_at(), None)
            .expect("FIXTURE: the owner's digest assembles")
            .expect("FIXTURE: a digest is due");
        let view = self.digest_view(digest.id);
        let proposal = view
            .groups
            .values()
            .flatten()
            .find(|proposal| proposal.claim_ref == finding)
            .expect("FIXTURE: the owner's digest view carries the finding");
        assert!(
            renders_proposal_line(&view, finding, &proposal.summary),
            "FIXTURE: the digest renders the finding's summary and ref on its line"
        );
        (digest.id, finding, proposal.summary.clone())
    }

    fn digest_view(&self, id: [u8; 32]) -> ProactivityDigestView {
        self.vault
            .proactivity_digest_view(&self.proof, id)
            .expect("the owner's digest view reads")
            .expect("the delivered digest still has a view")
    }
}

fn renders_proposal_line(view: &ProactivityDigestView, finding: EntityId, summary: &str) -> bool {
    let reference = finding.to_hex();
    view.rendered
        .lines()
        .any(|line| line.contains(reference.as_str()) && line.contains(summary))
}

fn assert_proposal_omitted(
    view: &ProactivityDigestView,
    finding: EntityId,
    summary: &str,
    proposal: &str,
) {
    assert!(
        !view
            .groups
            .values()
            .flatten()
            .any(|p| p.claim_ref == finding),
        "the owner's digest view still carries {proposal}"
    );
    assert!(
        !view.rendered.contains(finding.to_hex().as_str()),
        "the owner's digest still renders the ref of {proposal}"
    );
    assert!(
        !view.rendered.contains(summary),
        "the owner's digest still renders the summary of {proposal}"
    );
}

#[test]
fn a_standing_proposal_stays_in_the_owners_digest_view() {
    let fixture = Fixture::with_machine_signers(SIGNER_SECRET);
    let fact = fixture.fact_from_the_mailbox(FACT_PREDICATE);
    let (id, finding, summary) = fixture.digest_with_finding(fact);

    let view = fixture.digest_view(id);
    assert!(
        view.groups
            .values()
            .flatten()
            .any(|p| p.claim_ref == finding),
        "the owner's digest view lost the standing proposal"
    );
    assert!(
        renders_proposal_line(&view, finding, &summary),
        "the owner's digest lost the standing proposal's line"
    );
}

#[test]
fn a_deleted_proposal_leaves_the_owners_digest_view() {
    let fixture = Fixture::with_machine_signers(SIGNER_SECRET);
    let fact = fixture.fact_from_the_mailbox(FACT_PREDICATE);
    let (id, finding, summary) = fixture.digest_with_finding(fact);

    let outcome = fixture
        .vault
        .delete_entity_with_reason_as_owner(&fixture.proof, &finding, DeleteReason::UserHardDelete)
        .expect("FIXTURE: the owner hard-deletes the finding");
    assert!(outcome.existed, "FIXTURE: the deleted finding existed");

    assert_proposal_omitted(
        &fixture.digest_view(id),
        finding,
        &summary,
        "the deleted proposal",
    );
}

#[test]
fn a_reviewed_proposal_leaves_the_owners_digest_view() {
    let fixture = Fixture::with_machine_signers(SIGNER_SECRET);
    let fact = fixture.fact_from_the_mailbox(FACT_PREDICATE);
    let (id, finding, summary) = fixture.digest_with_finding(fact);

    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let review = memory
        .claim_review_as_owner(
            &fixture.proof,
            &ClaimProposalReviewRequest {
                claim_ref: finding.to_hex(),
                grant_ref: None,
            },
        )
        .expect("FIXTURE: the owner reviews the finding");
    memory
        .claim_settle_as_owner(
            &fixture.proof,
            &ClaimSettleRequest {
                claim_ref: finding.to_hex(),
                review_id: review.review_id,
                decision: ClaimSettleDecision::Approve,
                grant_ref: None,
            },
        )
        .expect("FIXTURE: the owner approves the finding");
    let reviewed = fixture
        .vault
        .get_claim(&finding)
        .expect("FIXTURE: read the reviewed finding")
        .expect("FIXTURE: the reviewed finding still reads");
    assert_eq!(
        reviewed.approval,
        ClaimApprovalStatus::Approved,
        "FIXTURE: the review changed the finding's approval"
    );

    assert_proposal_omitted(
        &fixture.digest_view(id),
        finding,
        &summary,
        "the proposal the owner reviewed",
    );
}

#[test]
fn a_withdrawn_proposal_leaves_the_owners_digest_view() {
    let fixture = Fixture::with_machine_signers(SIGNER_SECRET);
    let fact = fixture.fact_from_the_mailbox(FACT_PREDICATE);
    let (id, finding, summary) = fixture.digest_with_finding(fact);

    // The evidence citation is not a dependency registration.
    fixture
        .vault
        .put_edge(&finding, EdgeKind::DerivedFrom, &fact, 1.0)
        .expect("FIXTURE: the finding depends on the fact");
    assert!(
        fixture
            .vault
            .get_claim(&finding)
            .expect("FIXTURE: read the finding")
            .is_some(),
        "FIXTURE: the finding reads while the source stands"
    );
    assert!(
        fixture
            .vault
            .delete_entity(&fact)
            .expect("FIXTURE: delete the source fact"),
        "FIXTURE: the deleted fact existed"
    );
    assert!(
        fixture
            .vault
            .entity_exists(&finding)
            .expect("FIXTURE: check the finding's row"),
        "FIXTURE: withdrawal leaves the finding stored"
    );
    assert!(
        fixture
            .vault
            .get_claim(&finding)
            .expect("FIXTURE: read the finding after withdrawal")
            .is_none(),
        "FIXTURE: the stored finding no longer reads after its source was deleted"
    );

    assert_proposal_omitted(
        &fixture.digest_view(id),
        finding,
        &summary,
        "the withdrawn proposal",
    );
}
