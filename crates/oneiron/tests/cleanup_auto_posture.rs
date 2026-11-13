//! L1-30 (FIX [SAFETYISM-CLEANUP-AUTO-ARM-409]; Engine ruling
//! L1-30-AUTO-POSTURE, Fri 13 Nov 22:39 = A): a vault cleans up
//! automatically from birth (owner 2026-10-18, ARCH-0073 #arm-ruled;
//! DEC-0006: no grant step, no holdout). A run takes its snapshot, archives
//! the husk and records one digest whose receipt carries ARCH-0066 teeth #5
//! and #9 as a proof badge, and the owner reverts the run. The owner may set
//! either posture, and a stored propose-first still only proposes.
//!
//! Every path is public, so this target needs no cfg flag. It reads the
//! badge through the receipt's string fields, so it also builds on a base
//! without the badge, where it fails on its assertions.

use oneiron::attempt_queue::AttemptId;
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::store::GateDecisionId;
use oneiron::vault_cleanup::{
    CleanupDecision, CleanupPosture, CleanupRevertOutcome, CleanupRunRevertAnswer, cleanup_digests,
    cleanup_posture, cleanup_proposals, cleanup_runs, is_vault_cleanup_receipt, run_vault_cleanup,
    set_cleanup_posture,
};
use oneiron::{ClaimSource, EntityId, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The receipt field of tooth #5 (read/fold verification coverage).
const TOOTH_READ_FOLD_COVERAGE: &str = "cleanup_tooth_read_fold_coverage";
/// The receipt field of tooth #9 (OS-level separation of the vault's files).
const TOOTH_OS_SEPARATION: &str = "cleanup_tooth_os_separation";

fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// A PERSON an extraction minted and never learned a fact about: the husk
/// the cleanup tripwire archives.
fn mint_husk(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    assert!(
        vault
            .put_extraction_minted_person(
                &id,
                ClaimSource::Generated,
                TimeRange { start: 1, end: 1 },
                1,
                b"a person nobody mentions again",
            )
            .expect("mint husk")
    );
    id
}

fn owner(vault: &Vault) -> oneiron::consent::AuthenticatedOwner {
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(actor, "principal:owner", true, GateDecisionId::now())
        .expect("authenticate owner")
}

/// Every cleanup digest receipt the vault projects, newest first.
fn cleanup_receipts(vault: &Vault) -> Vec<ReceiptRecord> {
    vault
        .receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))
        .expect("receipts")
        .into_iter()
        .filter(|receipt| is_vault_cleanup_receipt(receipt))
        .collect()
}

fn attempt_hex(attempt: &AttemptId) -> String {
    attempt
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A new vault runs the automatic posture: one run snapshots and archives
/// the husk, its digest receipt carries both teeth as open, and the owner's
/// revert brings the husk back. On a base where the posture waits on the
/// teeth, the posture reads propose-first and the run archives nothing.
#[test]
fn a_new_vault_archives_a_husk_and_badges_the_run() -> TestResult {
    let (_dir, vault) = open();
    let husk = mint_husk(&vault);
    assert_eq!(cleanup_posture(&vault)?, CleanupPosture::AutoWithDigest);

    let attempt = AttemptId::now();
    let report = run_vault_cleanup(&vault, &attempt)?;
    assert_eq!(report.posture, CleanupPosture::AutoWithDigest);
    assert_eq!(report.proposal, None);
    assert_eq!(report.archived, vec![Some(husk)]);
    let digest = report.digest.expect("an automatic run records a digest");
    assert!(vault.archived_entity(&husk)?.is_some());
    assert!(cleanup_proposals(&vault)?.is_empty());

    // The run's snapshot: one entry, the husk, under the automatic decision.
    let runs = cleanup_runs(&vault)?;
    assert_eq!(runs.runs.len(), 1);
    let run = &runs.runs[0];
    assert_eq!(run.attempt, attempt);
    assert_eq!(run.snapshot.decision, CleanupDecision::AutoArchived);
    assert_eq!(run.snapshot.digest, digest);
    assert_eq!(run.snapshot.entries.len(), 1);
    assert_eq!(
        run.snapshot.entries[0].as_ref().map(|entry| entry.entity),
        Some(husk)
    );

    // The digest, and its receipt with the proof badge.
    let digests = cleanup_digests(&vault)?;
    assert_eq!(digests.len(), 1);
    assert_eq!(digests[0].id, digest);
    assert_eq!(digests[0].decision, CleanupDecision::AutoArchived);
    assert_eq!(digests[0].archived, vec![Some(husk)]);
    let receipts = cleanup_receipts(&vault);
    assert_eq!(receipts.len(), 1, "{receipts:?}");
    let receipt = &receipts[0];
    assert_eq!(
        receipt.job_ref.as_deref(),
        Some(attempt_hex(&attempt).as_str())
    );
    assert_eq!(
        receipt
            .fields
            .get(TOOTH_READ_FOLD_COVERAGE)
            .map(String::as_str),
        Some("open"),
        "{receipt:?}"
    );
    assert_eq!(
        receipt.fields.get(TOOTH_OS_SEPARATION).map(String::as_str),
        Some("open"),
        "{receipt:?}"
    );

    // The owner reverts the whole run: the husk is back, the same record.
    let owner = owner(&vault);
    let CleanupRunRevertAnswer::Reverted(revert) = vault.revert_cleanup_run_as(&owner, attempt)?
    else {
        panic!("the run reverts");
    };
    assert_eq!(revert.entries.len(), 1);
    let entry = revert.entries[0].as_ref().expect("a live entry");
    assert_eq!(entry.entity, husk);
    assert_eq!(entry.outcome, CleanupRevertOutcome::Restored);
    assert!(vault.archived_entity(&husk)?.is_none());
    assert!(vault.get(&husk)?.is_some());
    Ok(())
}

/// The owner may set either posture; the open teeth refuse neither. On a
/// base where they gate the automatic posture, setting it is an
/// InvariantViolation.
#[test]
fn the_owner_may_set_the_auto_posture() -> TestResult {
    let (_dir, vault) = open();
    set_cleanup_posture(&vault, CleanupPosture::ProposeFirst)?;
    assert_eq!(cleanup_posture(&vault)?, CleanupPosture::ProposeFirst);
    set_cleanup_posture(&vault, CleanupPosture::AutoWithDigest)?;
    assert_eq!(cleanup_posture(&vault)?, CleanupPosture::AutoWithDigest);
    Ok(())
}

/// Control: an owner who stored propose-first keeps it. The run opens one
/// proposal, archives nothing and records no digest, so no receipt carries
/// a badge.
#[test]
fn an_owner_set_propose_first_still_only_proposes() -> TestResult {
    let (_dir, vault) = open();
    set_cleanup_posture(&vault, CleanupPosture::ProposeFirst)?;
    let husk = mint_husk(&vault);
    let report = run_vault_cleanup(&vault, &AttemptId::now())?;
    assert_eq!(report.posture, CleanupPosture::ProposeFirst);
    assert!(report.proposal.is_some());
    assert!(report.archived.is_empty());
    assert_eq!(report.digest, None);
    assert!(vault.archived_entity(&husk)?.is_none());
    assert_eq!(cleanup_proposals(&vault)?.len(), 1);
    assert!(cleanup_digests(&vault)?.is_empty());
    assert!(cleanup_receipts(&vault).is_empty());
    Ok(())
}
