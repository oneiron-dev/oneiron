//! A CLAIM's hard or soft delete removes its proposal and rendered words
//! from the stored proactivity digest without changing its locator or
//! losing the other proposals (PROACTIVITY-DIGEST-COPY-ERASURE, disk half).
//! A value redaction of the proposal removes them too
//! (CLAIM-REDACTION-SKIPS-DERIVED-COPIES).
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test digest_erase_scrubs_stored_copies`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::DeleteReason;
use oneiron::dreamer_runner::maintenance::digest::ProactivityDigest;
use oneiron::policy_model::SecretScanMode;
use oneiron::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use oneiron::secret_custody::SecretCustodyStatus;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::claim_value_redaction::redact_claim_value_fields;
use oneiron::test_doors::curator_finding::emit_retract_finding;
use oneiron::test_doors::house_link::put_claim_made_by;
use oneiron::test_doors::proactivity_digest_index;
use oneiron::test_doors::source_audience_binding::{bound_row, reads};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    Vault, VaultConfig,
};

const FACT_PREDICATE: &str = "profile.preference";
const FACT_VALUE: &str = "The harbour survey's lantern list is kept in the owner's mail.";
const SIGNER_SECRET: &[u8] = b"digest-erase-scrubs-stored-copies";
const TOKEN_A: &str = "ghp_zyxwvutsrqponmlkjihgfedcba9876543210";
const TOKEN_B: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

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

    fn set_secret_scan(&self, mode: SecretScanMode) -> oneiron::Result<()> {
        self.vault
            .set_secret_scan_mode(&self.proof, mode, self.vault.now_recorded_at())?;
        Ok(())
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

#[test]
fn a_digest_stored_before_the_index_existed_is_scrubbed_by_the_first_erase() -> oneiron::Result<()>
{
    let fixture = Fixture::with_machine_signers(SIGNER_SECRET);
    let fact = fixture.fact_from_the_mailbox(FACT_VALUE);
    let (before, finding, summary) = fixture.digest_with_finding(fact);
    let id = before.id;
    let reference = finding.to_hex();
    let encoded_summary = serde_json::to_string(&summary).expect("the proposal summary serializes");
    let escaped_summary = &encoded_summary[1..encoded_summary.len() - 1];

    proactivity_digest_index::forget_claim_digest_index(&fixture.vault)?;
    assert!(
        !proactivity_digest_index::claim_digests_indexed(&fixture.vault)?,
        "the fixture vault still reads indexed"
    );
    let stored = fixture.stored_digest(id);
    let serialized = serde_json::to_string(&stored).expect("FIXTURE: the stored digest serializes");
    assert!(
        serialized.contains(reference.as_str()) && serialized.contains(escaped_summary),
        "FIXTURE: the unindexed digest still carries the finding's ref and summary"
    );

    let outcome = fixture
        .vault
        .delete_entity_with_reason_as_owner(&fixture.proof, &finding, DeleteReason::UserHardDelete)
        .expect("the owner hard-deletes the finding");
    assert!(outcome.existed, "the hard-deleted finding existed");

    let stored = fixture.stored_digest(id);
    assert_eq!(stored.id, id, "the stored digest keeps its locator");
    let serialized = serde_json::to_string(&stored).expect("the stored digest serializes");
    assert!(
        !serialized.contains(reference.as_str()) && !serialized.contains(escaped_summary),
        "the digest stored before the index still carries the erased proposal's words"
    );
    assert!(
        proactivity_digest_index::claim_digests_indexed(&fixture.vault)?,
        "the first erase left the stored digests unindexed"
    );
    Ok(())
}

#[test]
fn a_redacted_proposal_leaves_the_stored_digest() {
    let fixture = Fixture::with_machine_signers(SIGNER_SECRET);
    let fact = fixture.fact_from_the_mailbox(FACT_VALUE);
    let proposal = proactivity_digest_index::land_dreamer_proposal(
        &fixture.vault,
        fixture.owner,
        "profile.note",
        rmpv::Value::Map(vec![
            (
                rmpv::Value::from("secret_note"),
                rmpv::Value::from("the lantern key is under the boathouse step"),
            ),
            (
                rmpv::Value::from("public_note"),
                rmpv::Value::from("likes tea"),
            ),
        ]),
        fact,
    )
    .expect("FIXTURE: the Dreamer's proposal with a value map");
    let before = fixture.assemble_digest();
    let summary = stored_proposal_summary(&before, proposal).to_owned();

    redact_claim_value_fields(
        &fixture.vault,
        proposal,
        &["secret_note".to_owned()],
        fixture.owner,
    )
    .expect("the owner's courtesy redaction removes the proposal's field");

    assert_stored_proposal_erased(&fixture, &before, proposal, &summary);
}

#[test]
fn erasing_one_claim_masks_a_surviving_secret_stored_before_scanning() -> oneiron::Result<()> {
    let fixture = Fixture::with_machine_signers(SIGNER_SECRET);
    fixture.set_secret_scan(SecretScanMode::Off)?;
    let erased = proactivity_digest_index::put_digest_proposal(&fixture.vault, FACT_VALUE)?;
    let kept = proactivity_digest_index::put_digest_proposal(&fixture.vault, TOKEN_B)?;
    let before = fixture.assemble_digest();
    let erased_summary = stored_proposal_summary(&before, erased);
    assert!(stored_proposal_summary(&before, kept).contains(TOKEN_B));
    assert!(digest_bytes_contain(&fixture, before.id, TOKEN_B)?);

    // Leave the historical lift queued: the erase must admit the surviving value itself.
    fixture.set_secret_scan(SecretScanMode::On)?;
    let outcome = fixture
        .vault
        .delete_entity_with_reason_as_owner(&fixture.proof, &erased, DeleteReason::UserHardDelete)
        .expect("a surviving secret must not block the hard erase");
    assert!(outcome.existed, "the hard-deleted proposal existed");

    assert_stored_proposal_erased(&fixture, &before, erased, erased_summary);
    let stored = fixture.stored_digest(before.id);
    assert!(
        stored_proposal_summary(&stored, kept).contains("[secret "),
        "the surviving proposal is masked"
    );
    assert!(!digest_bytes_contain(&fixture, before.id, TOKEN_B)?);
    Ok(())
}

fn digest_bytes_contain(fixture: &Fixture, locator: [u8; 32], text: &str) -> oneiron::Result<bool> {
    let bytes = proactivity_digest_index::stored_digest_bytes(&fixture.vault, locator)?;
    Ok(bytes
        .windows(text.len())
        .any(|window| window == text.as_bytes()))
}

#[test]
fn erasing_the_claim_whose_secret_the_digest_masked_retires_its_custody() -> oneiron::Result<()> {
    let fixture = Fixture::with_machine_signers(SIGNER_SECRET);
    fixture.set_secret_scan(SecretScanMode::Off)?;
    let erased = proactivity_digest_index::put_digest_proposal(&fixture.vault, TOKEN_A)?;
    let kept = proactivity_digest_index::put_digest_proposal(&fixture.vault, TOKEN_B)?;
    // The source claims still hold raw tokens, but the digest assembles with scanning on.
    fixture.set_secret_scan(SecretScanMode::On)?;
    let before = fixture.assemble_digest();
    let erased_handle = proposal_handle(stored_proposal_summary(&before, erased));
    let kept_handle = proposal_handle(stored_proposal_summary(&before, kept));
    let erased_custody = proactivity_digest_index::digest_custody_id(
        &fixture.vault,
        &fixture.proof,
        before.id,
        erased_handle,
    )?
    .expect("FIXTURE: the digest minted custody for the erased proposal's token");
    let kept_custody = proactivity_digest_index::digest_custody_id(
        &fixture.vault,
        &fixture.proof,
        before.id,
        kept_handle,
    )?
    .expect("FIXTURE: the digest minted custody for the surviving proposal's token");
    assert_ne!(
        erased_custody, kept_custody,
        "FIXTURE: two separate custody records"
    );

    let outcome = fixture.vault.delete_entity_with_reason_as_owner(
        &fixture.proof,
        &erased,
        DeleteReason::UserHardDelete,
    )?;
    assert!(outcome.existed, "the hard-deleted proposal existed");

    let erased_meta = fixture
        .vault
        .get_secret_metadata(&erased_custody)?
        .expect("the revoked custody metadata remains");
    assert_eq!(
        erased_meta.status,
        SecretCustodyStatus::Revoked,
        "custody for the removed handle was not retired"
    );
    let kept_meta = fixture
        .vault
        .get_secret_metadata(&kept_custody)?
        .expect("the surviving custody record remains");
    assert_eq!(kept_meta.status, SecretCustodyStatus::Active);
    assert!(digest_bytes_contain(
        &fixture,
        before.id,
        &format!("[secret {kept_handle}]")
    )?);
    Ok(())
}

fn proposal_handle(summary: &str) -> &str {
    let (_, tail) = summary
        .split_once("[secret ")
        .expect("FIXTURE: the digest masked the raw token");
    let (handle, _) = tail.split_once(']').expect("FIXTURE: a complete handle");
    handle
}

#[test]
fn a_digest_row_with_a_malformed_key_is_deleted_by_the_first_erase() -> oneiron::Result<()> {
    let fixture = Fixture::with_machine_signers(SIGNER_SECRET);
    let fact = fixture.fact_from_the_mailbox(FACT_VALUE);
    let (before, finding, summary) = fixture.digest_with_finding(fact);

    proactivity_digest_index::copy_digest_under_malformed_key(&fixture.vault, before.id)?;
    proactivity_digest_index::forget_claim_digest_index(&fixture.vault)?;
    assert!(
        proactivity_digest_index::malformed_digest_bytes(&fixture.vault, before.id)?.is_some(),
        "FIXTURE: the malformed digest row is present"
    );
    assert!(!proactivity_digest_index::claim_digests_indexed(
        &fixture.vault
    )?);

    let outcome = fixture.vault.delete_entity_with_reason_as_owner(
        &fixture.proof,
        &finding,
        DeleteReason::UserHardDelete,
    )?;
    assert!(outcome.existed, "the hard-deleted finding existed");

    assert!(
        proactivity_digest_index::malformed_digest_bytes(&fixture.vault, before.id)?.is_none(),
        "the first erase left the malformed digest row on disk"
    );
    assert!(proactivity_digest_index::claim_digests_indexed(
        &fixture.vault
    )?);
    assert_stored_proposal_erased(&fixture, &before, finding, &summary);
    Ok(())
}

#[test]
fn a_credential_named_proposal_does_not_block_erasing_another_claim() -> oneiron::Result<()> {
    let fixture = Fixture::with_machine_signers(SIGNER_SECRET);
    fixture.set_secret_scan(SecretScanMode::Off)?;
    let erased = proactivity_digest_index::put_digest_proposal(&fixture.vault, FACT_VALUE)?;
    let predicate = "editor.api_key";
    let kept = proactivity_digest_index::put_digest_proposal_with_predicate(
        &fixture.vault,
        predicate,
        "The editor's pending proposal.",
    )?;
    // The shipped defaults group by facet and leave the group names unaliased.
    let before = fixture.assemble_digest();
    stored_proposal_summary(&before, erased);
    assert!(
        before
            .groups
            .get(predicate)
            .is_some_and(|proposals| proposals.iter().any(|p| p.claim_ref == kept)),
        "FIXTURE: the surviving proposal uses its credential-named predicate as the group key"
    );

    fixture.set_secret_scan(SecretScanMode::On)?;
    let outcome = fixture
        .vault
        .delete_entity_with_reason_as_owner(&fixture.proof, &erased, DeleteReason::UserHardDelete)
        .expect("erasing A was refused by B's digest copy");
    assert!(outcome.existed, "the hard-deleted proposal existed");
    assert!(
        matches!(
            proactivity_digest_index::stored_digest_bytes(&fixture.vault, before.id),
            Err(oneiron::Error::EntityNotFound)
        ),
        "a digest the wall refused is still stored"
    );
    assert!(
        !proactivity_digest_index::digest_has_live_custody(
            &fixture.vault,
            &fixture.proof,
            before.id
        )?,
        "custody minted from the refused digest was not retired"
    );
    Ok(())
}

#[test]
fn a_secret_and_its_encoded_spelling_are_masked_before_the_hash() -> oneiron::Result<()> {
    let fixture = Fixture::with_machine_signers(SIGNER_SECRET);
    fixture.set_secret_scan(SecretScanMode::Off)?;
    let erased = proactivity_digest_index::put_digest_proposal(&fixture.vault, FACT_VALUE)?;
    let encoded: String = TOKEN_B.bytes().map(|byte| format!("%{byte:02X}")).collect();
    let both_spellings = format!("{TOKEN_B} {encoded}");
    let kept = proactivity_digest_index::put_digest_proposal(&fixture.vault, &both_spellings)?;
    let before = fixture.assemble_digest();
    stored_proposal_summary(&before, erased);
    let summary = stored_proposal_summary(&before, kept);
    assert!(summary.contains(TOKEN_B) && summary.contains(encoded.as_str()));
    assert!(digest_bytes_contain(&fixture, before.id, TOKEN_B)?);
    assert!(digest_bytes_contain(&fixture, before.id, &encoded)?);

    fixture.set_secret_scan(SecretScanMode::On)?;
    let outcome = fixture
        .vault
        .delete_entity_with_reason_as_owner(&fixture.proof, &erased, DeleteReason::UserHardDelete)
        .expect("a surviving secret and its encoded spelling must not block the hard erase");
    assert!(outcome.existed, "the hard-deleted proposal existed");

    let stored = fixture
        .vault
        .read_proactivity_digest(before.id)
        .expect("the rewritten digest does not verify")
        .expect("the rewritten digest is not stored");
    assert!(
        stored
            .groups
            .values()
            .flatten()
            .any(|p| p.claim_ref == kept),
        "the surviving proposal was dropped"
    );
    assert!(
        !digest_bytes_contain(&fixture, before.id, TOKEN_B)?
            && !digest_bytes_contain(&fixture, before.id, &encoded)?,
        "a spelling of the secret is still stored"
    );
    Ok(())
}
