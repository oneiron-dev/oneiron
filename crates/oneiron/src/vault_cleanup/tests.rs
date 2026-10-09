//! ARCH-0073 vault auto-cleanup fixtures (ONE-1931).

use super::*;

use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::config::VaultConfig;
use crate::error::ErrorKind;
use crate::temporal::TimeRange;

// ─── fixtures ───────────────────────────────────────────────────────────

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn t(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

/// A fresh entity id.
///
/// UUIDv7 rather than a fixed byte pattern: an open vault already holds
/// engine records under deterministic ids (an `agent_def` row answers
/// `[0xA1; 16]`), and a fixture that collides with one gets
/// `EntityTypeImmutable` instead of the property it was testing.
fn fresh_id() -> EntityId {
    EntityId::from_bytes(uuid::Uuid::now_v7().into_bytes()).expect("valid id")
}

/// An extraction-minted PERSON row with a body and no claims about it.
fn put_person(vault: &Vault, person: &EntityId) {
    assert!(
        vault
            .put_extraction_minted_person(person, ClaimSource::Generated, t(1), 1, b"a person")
            .expect("mint person")
    );
}

/// One live claim about `subject`, carrying `source` as its declared
/// provenance.
///
/// The three permit-requiring sources (`imported`, `tool_output`,
/// `generated`) cannot be auto-admitted by a bare vault — the source-trust
/// door holds them pending without an explicit permit — so fixtures that only
/// need A claim pass `None`.
fn put_claim_about(
    vault: &Vault,
    claim: &EntityId,
    subject: &EntityId,
    source: Option<ClaimSource>,
) {
    let mut body = ClaimBody::new(
        "profile.hobby",
        ClaimSubject::Entity(*subject),
        Value::from("birdwatching"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.source = source;
    vault.put_claim(claim, &body, t(1), 1).expect("put claim");
}

fn archive_for_test(vault: &Vault, id: &EntityId) -> bool {
    vault
        .with_write_txn(|txn| {
            vault.archive_cleanup_candidate_in_txn(
                txn,
                id,
                &crate::deletion::TombstoneValueV2 {
                    reason: TombstoneReason::ArchivedByCleanup,
                    deleted_at: 2,
                    request_id: uuid::Uuid::now_v7().into_bytes(),
                },
            )
        })
        .expect("checked archive")
}

fn cleanup_receipt_records(vault: &Vault) -> Vec<ReceiptRecord> {
    vault
        .receipts(ReceiptQuery::new(64).with_kind(ReceiptKind::Gate))
        .expect("receipts")
        .into_iter()
        .filter(is_vault_cleanup_receipt)
        .collect()
}

// ─── propose lane ───────────────────────────────────────────────────────

/// THE STALE-CANDIDATE GUARD (NEG). A candidate that gains a live claim
/// between proposal and accept is NOT archived, and the skip is on the
/// digest receipt — a stale candidate silently dropped would be a proposal
/// the owner accepted and an outcome nobody could see.
#[test]
fn a_candidate_mutated_mid_flight_is_skipped_and_the_skip_is_receipted() {
    let (_tmp, vault) = temp_vault();
    let still_empty = fresh_id();
    let mutated = fresh_id();
    put_person(&vault, &still_empty);
    put_person(&vault, &mutated);

    let report = run_vault_cleanup(&vault, &AttemptId::now()).expect("run");
    let proposal = report.proposal.expect("proposal");
    assert_eq!(report.candidates.len(), 2, "both were proposed");

    // Mid-flight: somebody learns something about `mutated`.
    put_claim_about(&vault, &fresh_id(), &mutated, Some(ClaimSource::UserStated));

    let outcome = accept_cleanup_proposal(&vault, &proposal).expect("accept");
    assert_eq!(outcome.archived, vec![still_empty]);
    assert_eq!(outcome.skipped, vec![mutated]);
    assert!(
        !vault.is_deleted_shell(&mutated).expect("shell"),
        "a row that gained a fact must survive its own proposal"
    );
    assert!(vault.archived_entity(&mutated).expect("archived").is_none());

    let receipts = cleanup_receipt_records(&vault);
    assert_eq!(receipts.len(), 1, "one accept, one receipt");
    let receipt = &receipts[0];
    assert_eq!(receipt.outcome, CleanupDecision::ProposalAccepted.as_str());
    assert_eq!(
        receipt.fields.get(FIELD_CLEANUP_SKIPPED_IDS),
        Some(&mutated.to_hex())
    );
    assert_eq!(
        receipt.fields.get(FIELD_CLEANUP_SKIPPED_COUNT),
        Some(&"1".to_owned())
    );
    assert_eq!(
        receipt.fields.get(FIELD_CLEANUP_ARCHIVED_IDS),
        Some(&still_empty.to_hex())
    );
}

/// Reject archives nothing and leaves NO receipt: a refusal is not a decision
/// anyone needs a record of, and `receipt: false` is not a licence to receipt
/// the refusal instead.
#[test]
fn rejecting_a_proposal_archives_nothing_and_leaves_no_receipt() {
    let (_tmp, vault) = temp_vault();
    let person = fresh_id();
    put_person(&vault, &person);

    let report = run_vault_cleanup(&vault, &AttemptId::now()).expect("run");
    let proposal = report.proposal.expect("proposal");
    reject_cleanup_proposal(&vault, &proposal).expect("reject");

    assert!(!vault.is_deleted_shell(&person).expect("shell"));
    assert!(vault.archived_entities().expect("archived").is_empty());
    assert!(cleanup_receipt_records(&vault).is_empty());
    assert!(cleanup_proposals(&vault).expect("proposals").is_empty());
    assert!(matches!(
        reject_cleanup_proposal(&vault, &proposal).map_err(|e| e.kind()),
        Err(ErrorKind::VaultCleanupProposalNotFound)
    ));
}

// ─── auto posture ───────────────────────────────────────────────────────

/// The contracts row, asserted at the delete seam itself: the archive
/// tombstone writes NO receipt and queues NO sweep. This is the one call the
/// cron makes, so if this ever changes the cron changes with it.
#[test]
fn the_archive_tombstone_writes_no_receipt_and_queues_no_sweep() {
    let (_tmp, vault) = temp_vault();
    let person = fresh_id();
    put_person(&vault, &person);

    let existed = archive_for_test(&vault, &person);
    assert!(existed);
    assert!(cleanup_receipt_records(&vault).is_empty());
    let txn = vault.store.env.read_txn().expect("read txn");
    assert!(
        vault
            .store
            .sync_queue
            .prefix_iter(&txn, crate::deletion::HARD_ERASE_SWEEP_PREFIX)
            .expect("sweeps")
            .next()
            .is_none()
    );
    drop(txn);
    // The shell survives: hard-purge is false, so the row is still addressable.
    assert!(vault.is_deleted_shell(&person).expect("shell"));
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_PERSON)
            .expect("by type")
            .contains(&person),
        "an archived row stays REACHABLE — resolver-visible, not hidden"
    );
}

// ─── restore ────────────────────────────────────────────────────────────

/// The restore door revives the shell and mints NOTHING.
///
/// The "re-mention restores, never duplicates" half of ARCH-0024 :87 that
/// this ticket can actually assert: after a restore the vault holds exactly
/// the entities it held before, and the restored row is the SAME id.
#[test]
fn restore_archived_revives_the_row_without_minting_a_twin() {
    let (_tmp, vault) = temp_vault();
    rollout::close_blockers_for_test(&vault);
    set_cleanup_posture(&vault, CleanupPosture::AutoWithDigest).expect("set posture");
    let person = fresh_id();
    put_person(&vault, &person);
    let original = vault.get_raw(&person).expect("original entity").unwrap();
    let old_pin = vault.pinned_short_ref(&person).expect("pin before archive");
    let (old_ref, revision) = old_pin.rsplit_once('@').unwrap();
    let revision = crate::memory::RevisionRef::from_hex(revision).unwrap();
    let before = vault.entities_by_type(ENTITY_TYPE_PERSON).expect("by type");

    run_vault_cleanup(&vault, &AttemptId::now()).expect("run");
    assert!(vault.is_deleted_shell(&person).expect("shell"));

    vault.restore_archived(&person).expect("restore");
    // An archive is reversible, not erasure. Its retained history returns
    // with the same identity. Actual soft/hard erasure purges revision history.
    assert_eq!(
        vault
            .resolve_pinned_entity_reference(old_ref, revision)
            .expect("old pin lookup"),
        Some(person)
    );
    assert_eq!(
        vault
            .get_raw_with_mode(&person, crate::memory::ReadMode::Pinned(revision))
            .unwrap(),
        Some(original)
    );

    assert!(
        !vault.is_deleted_shell(&person).expect("shell"),
        "the shell is live again"
    );
    assert!(vault.archived_entity(&person).expect("archived").is_none());
    assert!(vault.archived_entities().expect("archived").is_empty());

    let after = vault.entities_by_type(ENTITY_TYPE_PERSON).expect("by type");
    assert_eq!(after, before, "restore creates no twin");
    let mut expected = vec![person, crate::vault::embedded_owner_actor_id().unwrap()];
    expected.sort_unstable();
    assert_eq!(after, expected);

    // The revived shell is not the extraction revision. Do not immediately
    // re-archive an owner-restored row using evidence for its old body.
    assert_eq!(zero_live_members(&vault, &person).expect("tripwire"), None);

    // Restoring twice refuses: by then there is no archive to undo.
    assert!(matches!(
        vault.restore_archived(&person).map_err(|e| e.kind()),
        Err(ErrorKind::VaultCleanupRestoreNotArchived)
    ));
}

/// The restore door is NOT an un-delete. A `user_delete` shell, a hard-purged
/// id and a live row all refuse — there is no path through this door to a
/// tombstone somebody asked for.
#[test]
fn restore_archived_refuses_everything_it_did_not_archive() {
    let (_tmp, vault) = temp_vault();

    let live = fresh_id();
    put_person(&vault, &live);
    assert!(matches!(
        vault.restore_archived(&live).map_err(|e| e.kind()),
        Err(ErrorKind::VaultCleanupRestoreNotArchived)
    ));

    let soft_deleted = fresh_id();
    put_person(&vault, &soft_deleted);
    vault
        .delete_entity_with_reason(&soft_deleted, DeleteReason::UserDelete)
        .expect("user delete");
    assert!(matches!(
        vault.restore_archived(&soft_deleted).map_err(|e| e.kind()),
        Err(ErrorKind::VaultCleanupRestoreNotArchived),
    ));

    let hard_deleted = fresh_id();
    put_person(&vault, &hard_deleted);
    vault
        .delete_entity_with_reason(&hard_deleted, DeleteReason::GdprDelete)
        .expect("gdpr delete");
    assert!(matches!(
        vault.restore_archived(&hard_deleted).map_err(|e| e.kind()),
        Err(ErrorKind::VaultCleanupRestoreNotArchived)
    ));

    let absent = fresh_id();
    assert!(matches!(
        vault.restore_archived(&absent).map_err(|e| e.kind()),
        Err(ErrorKind::VaultCleanupRestoreNotArchived)
    ));
}

/// A marker whose bytes do not read as an archive refuses the restore rather
/// than reviving a shell on a guess — the tombstone decode law, applied to
/// the marker that borrows its format.
#[test]
fn an_unreadable_archive_marker_refuses_the_restore() {
    let (_tmp, vault) = temp_vault();
    let person = fresh_id();
    put_person(&vault, &person);
    assert!(archive_for_test(&vault, &person));

    // Corrupt the marker in place: a legacy 8-byte value names no reason.
    vault
        .with_write_txn(|wtxn| {
            let key = format!("{ARCHIVE_TOMBSTONE_PREFIX}{}", person.to_hex());
            vault.store.sync_state.put(wtxn, &key, &[0_u8; 8])?;
            Ok(())
        })
        .expect("corrupt marker");

    assert!(matches!(
        vault.restore_archived(&person).map_err(|e| e.kind()),
        Err(ErrorKind::VaultCleanupArchiveMarkerUndecodable)
    ));
    assert!(
        vault.archived_entity(&person).expect("archived").is_none(),
        "an unreadable marker is not an archive record"
    );
}

// ─── review-level teeth ─────────────────────────────────────────────────

/// The smallest changed-behavior falsifier for this ticket.
///
/// Everything above could pass with the archive implemented as an ordinary
/// `user_delete`. THIS is what makes it an archive: the row carries wire byte
/// 5, it decodes SOFT, and the restore door can find it and undo it. Break
/// any one of the three — a reason byte that drifts, an `is_hard` that
/// flips, a marker written under the wrong prefix — and this fails while the
/// deletion suite stays green.
#[test]
fn falsifier_the_archived_row_carries_the_soft_archive_reason_and_undoes() {
    let (_tmp, vault) = temp_vault();
    let person = fresh_id();
    put_person(&vault, &person);
    assert!(archive_for_test(&vault, &person));

    let rtxn = vault.store.env.read_txn().expect("read txn");
    let decoded = vault
        .archive_tombstone_in_txn(&rtxn, &person)
        .expect("marker")
        .expect("marker present");
    drop(rtxn);

    assert_eq!(
        decoded.reason,
        Some(TombstoneReason::ArchivedByCleanup),
        "the marker decodes to the archive reason"
    );
    assert_eq!(
        TombstoneReason::ArchivedByCleanup.wire_byte(),
        5,
        "wire byte 5"
    );
    assert!(!decoded.is_hard(), "the archive reason is SOFT");
    assert!(
        !DeleteReason::ArchivedByCleanup.publishes_crdt_tombstone(),
        "the archive is local, which is what makes the restore door possible"
    );

    vault.restore_archived(&person).expect("restore");
    assert!(!vault.is_deleted_shell(&person).expect("shell"));
}
