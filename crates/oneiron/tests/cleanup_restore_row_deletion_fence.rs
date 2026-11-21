//! FIX [CLEANUP-RESTORE-DOOR-MISSES-ROW-DELETION-FENCE]: the cleanup's
//! restore door brings back no record whose row a delete still fences.
//!
//! A gated soft delete of an archived record commits its scrub, its `df:`
//! row fence and its pending tombstone; when the delete then loses its
//! authority before publication, the refusing transaction withdraws the
//! pending tombstone and keeps the fence (`deletion/publish.rs`,
//! `begin_tombstone_publish_txn`). The row stays deleted, and it holds
//! neither a hard-delete marker nor a pending or published tombstone. The
//! fixture writes that fence with the door a hard delete's publication uses
//! for the same marker (`test_doors::coach::fence_row_for_hard_delete`), on
//! a husk PERSON the vault's own cleanup run archived.
//!
//! - The plain restore and the owner's restore refuse it as they refuse a
//!   deleted record, commit nothing, and the record stays in the archive.
//! - The owner's revert of the run that archived it answers that a delete
//!   reached it, and lifts nothing.
//! - Without the fence the same record restores, on both doors (the
//!   fixture's control).
//!
//! Red without the fix (the first three tests; the two controls pass
//! with and without it): the door clears the
//! archive marker and answers Ok while the row stays deleted, and the
//! revert answers `restored`.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test cleanup_restore_row_deletion_fence`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::attempt_queue::AttemptId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::coach::{fence_row_for_hard_delete, last_committed_txn_id};
use oneiron::vault_cleanup::{
    CleanupPosture, CleanupRevertOutcome, CleanupRevertReason, CleanupRunRevertAnswer,
    cleanup_posture, run_vault_cleanup,
};
use oneiron::{ClaimSource, EntityId, ErrorKind, TimeRange, Vault, VaultConfig};

fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

fn owner(vault: &Vault) -> AuthenticatedOwner {
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(actor, "principal:owner", true, GateDecisionId::now())
        .expect("authenticate owner")
}

/// A PERSON an extraction minted and never learned a fact about, which one
/// automatic cleanup run archives: the husk and the run's attempt id.
fn archived_husk(vault: &Vault) -> (EntityId, AttemptId) {
    let husk = EntityId::now();
    assert!(
        vault
            .put_extraction_minted_person(
                &husk,
                ClaimSource::Generated,
                TimeRange { start: 1, end: 1 },
                1,
                b"a person nobody mentions again",
            )
            .expect("mint the husk")
    );
    assert_eq!(
        cleanup_posture(vault).expect("posture"),
        CleanupPosture::AutoWithDigest
    );
    let run = AttemptId::now();
    let report = run_vault_cleanup(vault, &run).expect("cleanup run");
    assert_eq!(
        report.archived,
        vec![Some(husk)],
        "the run archives the husk"
    );
    assert!(archived(vault, &husk), "the husk is in the archive");
    (husk, run)
}

/// The husk, archived, then fenced as a withdrawn delete leaves it.
fn fenced_husk(vault: &Vault) -> (EntityId, AttemptId) {
    let (husk, run) = archived_husk(vault);
    fence_row_for_hard_delete(vault, husk).expect("the delete's row fence");
    (husk, run)
}

fn archived(vault: &Vault, id: &EntityId) -> bool {
    vault.archived_entity(id).expect("archive read").is_some()
}

/// The refusal is the one a deleted record gets, nothing commits, and the
/// record stays in the archive as a deleted shell.
fn assert_refused(
    vault: &Vault,
    husk: &EntityId,
    before: usize,
    answer: oneiron::Result<()>,
    door: &str,
) {
    assert_eq!(
        answer.map_err(|error| error.kind()),
        Err(ErrorKind::VaultCleanupRestoreNotArchived),
        "{door}: a record a delete still fences is not restorable"
    );
    assert_eq!(
        last_committed_txn_id(vault),
        before,
        "{door}: the refusal commits nothing"
    );
    assert!(
        archived(vault, husk),
        "{door}: the record stays in the archive"
    );
    assert!(
        vault.is_deleted_shell(husk).expect("shell read"),
        "{door}: the record stays deleted"
    );
}

#[test]
fn the_restore_refuses_a_record_a_withdrawn_delete_still_fences() {
    let (_dir, vault) = open();
    let (husk, _run) = fenced_husk(&vault);
    let before = last_committed_txn_id(&vault);

    let answer = vault.restore_archived(&husk);

    assert_refused(&vault, &husk, before, answer, "restore_archived");
}

#[test]
fn the_owners_restore_refuses_a_record_a_withdrawn_delete_still_fences() {
    let (_dir, vault) = open();
    let (husk, _run) = fenced_husk(&vault);
    let owner = owner(&vault);
    let before = last_committed_txn_id(&vault);

    let answer = vault.restore_archived_as(&owner, &husk);

    assert_refused(&vault, &husk, before, answer, "restore_archived_as");
}

#[test]
fn the_run_revert_answers_deleted_for_a_record_a_withdrawn_delete_still_fences() {
    let (_dir, vault) = open();
    let (husk, run) = fenced_husk(&vault);
    let owner = owner(&vault);

    let CleanupRunRevertAnswer::Reverted(revert) = vault
        .revert_cleanup_run_as(&owner, run)
        .expect("the revert answers")
    else {
        panic!("the run reverts");
    };

    assert_eq!(revert.entries.len(), 1, "{revert:?}");
    let entry = revert.entries[0].as_ref().expect("a live entry");
    assert_eq!(entry.entity, husk);
    assert_eq!(
        entry.outcome,
        CleanupRevertOutcome::Unavailable(CleanupRevertReason::Deleted),
        "a delete reached the record after the run: {revert:?}"
    );
    assert!(archived(&vault, &husk), "the revert lifts nothing");
    assert!(
        vault.is_deleted_shell(&husk).expect("shell read"),
        "the record stays deleted"
    );
}

/// The fixture's control: the same archived husk with no fence restores,
/// and leaves the archive live again.
#[test]
fn an_archived_record_with_no_fence_restores() {
    let (_dir, vault) = open();
    let (husk, _run) = archived_husk(&vault);

    vault.restore_archived(&husk).expect("the restore");

    assert!(!archived(&vault, &husk), "the restore empties the archive");
    assert!(
        !vault.is_deleted_shell(&husk).expect("shell read"),
        "the restored record is live again"
    );
}

/// The control on the owner's door.
#[test]
fn the_owner_restores_an_archived_record_with_no_fence() {
    let (_dir, vault) = open();
    let (husk, _run) = archived_husk(&vault);
    let owner = owner(&vault);

    vault
        .restore_archived_as(&owner, &husk)
        .expect("the owner's restore");

    assert!(
        !archived(&vault, &husk),
        "the owner's restore empties the archive"
    );
    assert!(
        !vault.is_deleted_shell(&husk).expect("shell read"),
        "the owner's restored record is live again"
    );
}
