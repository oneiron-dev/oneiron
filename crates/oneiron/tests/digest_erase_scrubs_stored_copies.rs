//! A CLAIM's hard or soft delete removes its proposal and rendered words
//! from the stored proactivity digest without changing its locator or
//! losing the other proposals (PROACTIVITY-DIGEST-COPY-ERASURE, disk half).
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test digest_erase_scrubs_stored_copies`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::DeleteReason;
use oneiron::dreamer_runner::maintenance::digest::ProactivityDigest;
use oneiron::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::curator_finding::emit_retract_finding;
use oneiron::test_doors::house_link::put_claim_made_by;
use oneiron::test_doors::source_audience_binding::{bound_row, reads};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    Vault, VaultConfig,
};

const FACT_PREDICATE: &str = "profile.preference";
const FACT_VALUE: &str = "The harbour survey's lantern list is kept in the owner's mail.";
const SIGNER_SECRET: &[u8] = b"digest-erase-scrubs-stored-copies";

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

    fn fact_from_the_mailbox(&self, value: &str) -> EntityId {
        let at = self.vault.now_recorded_at();
        let mut body = ClaimBody::new(
            FACT_PREDICATE,
            ClaimSubject::Entity(self.owner),
            rmpv::Value::from(value),
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
                    identity: "digest_erase_scrubs_stored_copies.fixture".to_owned(),
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

    fn digest_with_finding(&self, fact: EntityId) -> (ProactivityDigest, EntityId, String) {
        let finding =
            emit_retract_finding(&self.vault, fact).expect("FIXTURE: the Dreamer's finding");
        let stored = self.assemble_digest();
        let summary = stored_proposal_summary(&stored, finding).to_owned();
        (stored, finding, summary)
    }

    fn assemble_digest(&self) -> ProactivityDigest {
        let digest = self
            .vault
            .proactivity_digest(&self.proof, self.vault.now_recorded_at(), None)
            .expect("FIXTURE: the owner's digest assembles")
            .expect("FIXTURE: a digest is due");
        self.stored_digest(digest.id)
    }

    fn stored_digest(&self, id: [u8; 32]) -> ProactivityDigest {
        self.vault
            .read_proactivity_digest(id)
            .expect("the stored digest verifies")
            .expect("the digest is still stored under its locator")
    }
}

fn stored_proposal_summary(digest: &ProactivityDigest, finding: EntityId) -> &str {
    let proposal = digest
        .groups
        .values()
        .flatten()
        .find(|proposal| proposal.claim_ref == finding)
        .expect("FIXTURE: the stored digest carries the finding");
    let reference = finding.to_hex();
    let summary = proposal.summary.as_str();
    assert!(
        digest
            .rendered
            .lines()
            .any(|line| line.contains(reference.as_str()) && line.contains(summary)),
        "FIXTURE: the stored digest renders the finding's summary and ref on its line"
    );
    summary
}

fn assert_stored_proposal_erased(
    fixture: &Fixture,
    before: &ProactivityDigest,
    finding: EntityId,
    summary: &str,
) {
    let id = before.id;
    let stored = fixture.stored_digest(id);
    assert_eq!(stored.id, id, "the stored digest keeps its locator");
    assert_ne!(
        stored.content_hash, before.content_hash,
        "erasing a proposal changes the stored digest's content hash"
    );
    assert!(
        !stored
            .groups
            .values()
            .flatten()
            .any(|p| p.claim_ref == finding),
        "a stored group still carries the erased proposal"
    );

    let serialized = serde_json::to_string(&stored).expect("the stored digest serializes");
    let encoded_summary = serde_json::to_string(summary).expect("the proposal summary serializes");
    // Match the escaped summary inside any JSON string, including the rendered text.
    let escaped_summary = &encoded_summary[1..encoded_summary.len() - 1];
    assert!(
        !serialized.contains(finding.to_hex().as_str()) && !serialized.contains(escaped_summary),
        "the stored digest still carries the erased proposal's words"
    );
    assert!(
        fixture
            .vault
            .proactivity_digest_view(&fixture.proof, id)
            .expect("the owner's digest view reads")
            .is_some(),
        "the notification's digest still opens"
    );
}

#[test]
fn a_hard_deleted_proposal_leaves_the_stored_digest() {
    let fixture = Fixture::with_machine_signers(SIGNER_SECRET);
    let fact = fixture.fact_from_the_mailbox(FACT_VALUE);
    let (before, finding, summary) = fixture.digest_with_finding(fact);

    let outcome = fixture
        .vault
        .delete_entity_with_reason_as_owner(&fixture.proof, &finding, DeleteReason::UserHardDelete)
        .expect("the owner hard-deletes the finding");
    assert!(outcome.existed, "the hard-deleted finding existed");

    assert_stored_proposal_erased(&fixture, &before, finding, &summary);
}

#[test]
fn a_soft_deleted_proposal_leaves_the_stored_digest() {
    let fixture = Fixture::with_machine_signers(SIGNER_SECRET);
    let fact = fixture.fact_from_the_mailbox(FACT_VALUE);
    let (before, finding, summary) = fixture.digest_with_finding(fact);

    assert!(
        fixture
            .vault
            .delete_entity(&finding)
            .expect("the finding soft-deletes"),
        "the soft-deleted finding existed"
    );

    assert_stored_proposal_erased(&fixture, &before, finding, &summary);
}

#[test]
fn the_other_proposals_of_a_scrubbed_digest_stay() {
    let fixture = Fixture::with_machine_signers(SIGNER_SECRET);
    let first_fact = fixture.fact_from_the_mailbox(FACT_VALUE);
    let second_fact =
        fixture.fact_from_the_mailbox("The harbour survey's chart is in the owner's mail.");
    let erased =
        emit_retract_finding(&fixture.vault, first_fact).expect("FIXTURE: the first finding");
    let kept =
        emit_retract_finding(&fixture.vault, second_fact).expect("FIXTURE: the second finding");
    let before = fixture.assemble_digest();
    let erased_summary = stored_proposal_summary(&before, erased);
    let kept_summary = stored_proposal_summary(&before, kept);
    assert_ne!(
        erased_summary, kept_summary,
        "FIXTURE: the two summaries differ"
    );

    let outcome = fixture
        .vault
        .delete_entity_with_reason_as_owner(&fixture.proof, &erased, DeleteReason::UserHardDelete)
        .expect("the owner hard-deletes the first finding");
    assert!(outcome.existed, "the hard-deleted finding existed");

    let stored = fixture.stored_digest(before.id);
    assert!(
        stored
            .groups
            .values()
            .flatten()
            .any(|p| p.claim_ref == kept && p.summary.as_str() == kept_summary),
        "the stored digest lost the other proposal"
    );
    let kept_ref = kept.to_hex();
    assert!(
        stored
            .rendered
            .lines()
            .any(|line| line.contains(kept_ref.as_str()) && line.contains(kept_summary)),
        "the stored digest lost the other proposal's rendered ref or summary"
    );
}
