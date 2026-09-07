//! ARCH-0073 vault auto-cleanup fixtures (ONE-1931).

use super::*;

use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::config::VaultConfig;
use crate::dreamer_runner::{DreamerRunnerStore, EnqueueDreamerVaultCleanupAttempt};
use crate::dreamer_wake::WakeTrigger;
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

/// A SUMMARY row with a body, no claims and no edges.
fn put_summary(vault: &Vault, summary: &EntityId) {
    vault
        .put_entity(summary, ENTITY_TYPE_SUMMARY, t(1), 1, b"a summary")
        .expect("put summary");
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
    );
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

// ─── the tripwire ───────────────────────────────────────────────────────

/// The PERSON arm, both directions. A claim-less extraction PERSON trips; the
/// SAME row with one live claim about it does not. Closed-form: adding a fact
/// is the entire difference.
#[test]
fn claimless_person_trips_the_tripwire_and_one_live_claim_does_not() {
    let (_tmp, vault) = temp_vault();
    let person = fresh_id();
    put_person(&vault, &person);

    assert_eq!(
        zero_live_members(&vault, &person).expect("tripwire"),
        Some(CleanupKind::ClaimlessExtractionPerson),
        "a PERSON nobody has said anything about is empty"
    );

    put_claim_about(&vault, &fresh_id(), &person, None);
    assert_eq!(
        zero_live_members(&vault, &person).expect("tripwire"),
        None,
        "ONE live claim of ANY source is enough to keep the row"
    );
}

/// The declared source does not soften the PERSON arm: every claim that can
/// be written into a bare vault keeps its subject, whatever it says about
/// where it came from. Mint-time provenance does not override live claims.
///
/// The three permit-requiring sources are absent because they cannot be
/// written here at all — the source-trust door holds `imported`,
/// `tool_output` and `generated` pending without an explicit permit, which
/// means a machine-minted claim already needs an owner decision before it
/// exists to keep anything.
#[test]
fn any_writable_claim_source_keeps_a_person_off_the_candidate_list() {
    for source in [
        None,
        Some(ClaimSource::UserStated),
        Some(ClaimSource::Observed),
        Some(ClaimSource::Inferred),
    ] {
        let (_tmp, vault) = temp_vault();
        let person = fresh_id();
        put_person(&vault, &person);
        put_claim_about(&vault, &fresh_id(), &person, source);
        assert_eq!(
            zero_live_members(&vault, &person).expect("tripwire"),
            None,
            "{source:?} claim must keep the person"
        );
    }
}

/// Both minting and eligibility use the pinned machine-minted source class.
#[test]
fn machine_minted_source_class_is_pinned() {
    assert_eq!(
        MACHINE_MINTED_CLAIM_SOURCES,
        [ClaimSource::Generated, ClaimSource::ToolOutput]
    );
    assert!(claim_source_is_machine_minted(ClaimSource::Generated));
    assert!(claim_source_is_machine_minted(ClaimSource::ToolOutput));
    for human in [
        ClaimSource::UserStated,
        ClaimSource::Observed,
        ClaimSource::Inferred,
        ClaimSource::Imported,
    ] {
        assert!(!claim_source_is_machine_minted(human), "{human:?}");
    }
}

/// The ratified SUMMARY arm, both directions. An unreferenced SUMMARY trips;
/// one member edge — in either direction, of any member kind — is enough to
/// keep it.
#[test]
fn empty_summary_trips_the_tripwire_and_a_referenced_one_does_not() {
    let (_tmp, vault) = temp_vault();
    let summary = fresh_id();
    put_summary(&vault, &summary);
    assert_eq!(
        zero_live_members(&vault, &summary).expect("tripwire"),
        Some(CleanupKind::EmptySummary)
    );

    let member = fresh_id();
    put_person(&vault, &member);
    vault
        .put_edge(&member, EdgeKind::PartOf, &summary, 1.0)
        .expect("put member edge");
    assert_eq!(
        zero_live_members(&vault, &summary).expect("tripwire"),
        None,
        "a summary something points at is not empty"
    );
}

/// A claim about a SUMMARY keeps it, on the same rule the PERSON arm uses.
#[test]
fn a_summary_with_a_live_claim_is_not_empty() {
    let (_tmp, vault) = temp_vault();
    let summary = fresh_id();
    put_summary(&vault, &summary);
    put_claim_about(&vault, &fresh_id(), &summary, None);
    assert_eq!(zero_live_members(&vault, &summary).expect("tripwire"), None);
}

/// Types outside the checker table are never candidates, whatever they look
/// like. The table is the whole scope.
#[test]
fn the_checker_table_is_the_whole_scope() {
    let (_tmp, vault) = temp_vault();
    let subject = fresh_id();
    put_person(&vault, &subject);
    let claim_row = fresh_id();
    put_claim_about(&vault, &claim_row, &subject, None);
    assert_eq!(
        zero_live_members(&vault, &claim_row).expect("tripwire"),
        None,
        "a CLAIM row is not in CLEANUP_CHECKS"
    );
    assert_eq!(
        zero_live_members(&vault, &fresh_id()).expect("tripwire"),
        None,
        "an absent id is not a candidate"
    );
}

// ─── posture ────────────────────────────────────────────────────────────

/// The safe default is the ABSENCE of a decision: a vault that never heard of
/// this feature proposes, it does not archive.
#[test]
fn default_posture_is_propose_first() {
    let (_tmp, vault) = temp_vault();
    assert_eq!(
        cleanup_posture(&vault).expect("posture"),
        CleanupPosture::ProposeFirst
    );
    rollout::close_blockers_for_test(&vault);
    set_cleanup_posture(&vault, CleanupPosture::AutoWithDigest).expect("set posture");
    assert_eq!(
        cleanup_posture(&vault).expect("posture"),
        CleanupPosture::AutoWithDigest
    );
    set_cleanup_posture(&vault, CleanupPosture::ProposeFirst).expect("set posture");
    assert_eq!(
        cleanup_posture(&vault).expect("posture"),
        CleanupPosture::ProposeFirst
    );
}

// ─── propose lane ───────────────────────────────────────────────────────

/// A propose-first run archives NOTHING and opens ONE proposal whose body IS
/// the impact preview: counts by kind, and the ids.
#[test]
fn a_propose_first_run_archives_nothing_and_carries_the_impact_preview() {
    let (_tmp, vault) = temp_vault();
    let person = fresh_id();
    let summary = fresh_id();
    put_person(&vault, &person);
    put_summary(&vault, &summary);

    let attempt = AttemptId::now();
    let report = run_vault_cleanup(&vault, &attempt).expect("run");
    assert_eq!(report.posture, CleanupPosture::ProposeFirst);
    assert_eq!(report.candidates.len(), 2);
    assert!(report.archived.is_empty(), "propose-first archives nothing");
    assert!(report.digest.is_none(), "no decision, no digest");
    assert!(report.proposal.is_some());

    let proposals = cleanup_proposals(&vault).expect("proposals");
    assert_eq!(proposals.len(), 1);
    let preview = proposals[0].impact_preview();
    assert_eq!(preview.total, 2);
    assert_eq!(preview.claimless_persons, 1);
    assert_eq!(preview.empty_summaries, 1);
    assert!(preview.entities.contains(&person));
    assert!(preview.entities.contains(&summary));

    // Nothing was touched.
    assert!(!vault.is_deleted_shell(&person).expect("shell"));
    assert!(vault.archived_entities().expect("archived").is_empty());
    assert!(cleanup_receipt_records(&vault).is_empty());
}

/// Accept archives the rows that are STILL empty, and the archive carries the
/// `archived_by_cleanup` reason.
#[test]
fn accepting_a_proposal_archives_rows_that_are_still_empty() {
    let (_tmp, vault) = temp_vault();
    let person = fresh_id();
    put_person(&vault, &person);

    let report = run_vault_cleanup(&vault, &AttemptId::now()).expect("run");
    let proposal = report.proposal.expect("proposal");

    let outcome = accept_cleanup_proposal(&vault, &proposal).expect("accept");
    assert_eq!(outcome.archived, vec![person]);
    assert!(outcome.skipped.is_empty());

    let archived = vault
        .archived_entity(&person)
        .expect("archived")
        .expect("row");
    assert_eq!(archived.entity, person);
    assert!(vault.is_deleted_shell(&person).expect("shell"));

    // The proposal is answered, not left open.
    assert!(cleanup_proposals(&vault).expect("proposals").is_empty());
    assert!(matches!(
        accept_cleanup_proposal(&vault, &proposal).map_err(|e| e.kind()),
        Err(ErrorKind::VaultCleanupProposalNotFound)
    ));
}

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

/// The post-teeth path: archive directly, then say so ONCE. One digest
/// receipt for the run, listing every archived id — never one receipt per
/// entity, which is what the ratified `receipt: false` row forbids.
#[test]
fn auto_posture_archives_and_mints_exactly_one_digest_receipt() {
    let (_tmp, vault) = temp_vault();
    rollout::close_blockers_for_test(&vault);
    set_cleanup_posture(&vault, CleanupPosture::AutoWithDigest).expect("set posture");
    let first = fresh_id();
    let second = fresh_id();
    let summary = fresh_id();
    put_person(&vault, &first);
    put_person(&vault, &second);
    put_summary(&vault, &summary);

    let attempt = AttemptId::now();
    let report = run_vault_cleanup(&vault, &attempt).expect("run");
    assert_eq!(report.posture, CleanupPosture::AutoWithDigest);
    assert_eq!(report.archived.len(), 3);
    assert!(report.proposal.is_none(), "auto opens no proposal");
    assert!(report.digest.is_some());
    assert!(cleanup_proposals(&vault).expect("proposals").is_empty());

    for entity in [first, second, summary] {
        assert!(vault.is_deleted_shell(&entity).expect("shell"));
        assert!(vault.archived_entity(&entity).expect("archived").is_some());
    }

    // EXACTLY ONE receipt for three archived rows.
    let receipts = cleanup_receipt_records(&vault);
    assert_eq!(
        receipts.len(),
        1,
        "one run, one digest — never one receipt per entity"
    );
    let receipt = &receipts[0];
    assert_eq!(receipt.receipt_kind, ReceiptKind::Gate);
    assert_eq!(receipt.actor.as_deref(), Some(VAULT_CLEANUP_ACTOR));
    assert_eq!(receipt.outcome, CleanupDecision::AutoArchived.as_str());
    let attempt_hex = hex_lower(attempt.as_bytes());
    assert_eq!(
        receipt.job_ref.as_deref(),
        Some(attempt_hex.as_str()),
        "the digest names the attempt that ran"
    );
    assert_eq!(
        receipt.fields.get(FIELD_CLEANUP_PHASE),
        Some(&CLEANUP_PHASE.to_owned())
    );
    assert_eq!(
        receipt.fields.get(FIELD_CLEANUP_ARCHIVED_COUNT),
        Some(&"3".to_owned())
    );
    assert_eq!(
        receipt.fields.get(FIELD_CLEANUP_TOMBSTONE_REASON),
        Some(&"archived_by_cleanup".to_owned())
    );
    let listed = receipt
        .fields
        .get(FIELD_CLEANUP_ARCHIVED_IDS)
        .expect("archived ids");
    for entity in [first, second, summary] {
        assert!(listed.contains(&entity.to_hex()), "digest lists {entity:?}");
    }

    // A second pass over an already-archived vault finds nothing: the
    // tripwire never re-archives its own output, so the digest count stays 1.
    let second_report = run_vault_cleanup(&vault, &AttemptId::now()).expect("second run");
    assert!(second_report.candidates.is_empty());
    assert_eq!(cleanup_receipt_records(&vault).len(), 1);
}

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
    let before = vault.entities_by_type(ENTITY_TYPE_PERSON).expect("by type");

    run_vault_cleanup(&vault, &AttemptId::now()).expect("run");
    assert!(vault.is_deleted_shell(&person).expect("shell"));

    vault.restore_archived(&person).expect("restore");

    assert!(
        !vault.is_deleted_shell(&person).expect("shell"),
        "the shell is live again"
    );
    assert!(vault.archived_entity(&person).expect("archived").is_none());
    assert!(vault.archived_entities().expect("archived").is_empty());

    let after = vault.entities_by_type(ENTITY_TYPE_PERSON).expect("by type");
    assert_eq!(after, before, "restore creates no twin");
    assert_eq!(after, vec![person]);

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

// ─── archived query ─────────────────────────────────────────────────────

/// The archived-aware query: archived rows stay REACHABLE and are FLAGGED.
#[test]
fn archived_entities_flags_archived_rows() {
    let (_tmp, vault) = temp_vault();
    rollout::close_blockers_for_test(&vault);
    set_cleanup_posture(&vault, CleanupPosture::AutoWithDigest).expect("set posture");
    let archived = fresh_id();
    let kept = fresh_id();
    put_person(&vault, &archived);
    put_person(&vault, &kept);
    put_claim_about(&vault, &fresh_id(), &kept, Some(ClaimSource::UserStated));

    run_vault_cleanup(&vault, &AttemptId::now()).expect("run");

    let rows = vault.archived_entities().expect("archived");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].entity, archived);
    assert!(rows[0].request_id.is_some(), "the archive is correlatable");
    assert!(
        rows[0].archived_at > 0,
        "the archive records when it happened"
    );

    // Both rows are still reachable by type; the flag is what tells them apart.
    let by_type = vault.entities_by_type(ENTITY_TYPE_PERSON).expect("by type");
    assert!(by_type.contains(&archived) && by_type.contains(&kept));
    assert!(vault.archived_entity(&kept).expect("archived").is_none());
}

// ─── wiring ─────────────────────────────────────────────────────────────

/// The cleanup pass registers on the TIMER wake and nowhere else: a
/// maintenance scan attached to any wake is one an interactive turn pays for.
#[test]
fn vault_cleanup_registers_on_the_timer_wake_only() {
    let (_tmp, vault) = temp_vault();
    let runner = DreamerRunnerStore::new(&vault);

    let enqueue = |trigger| EnqueueDreamerVaultCleanupAttempt {
        trigger,
        input: Value::Nil,
        parent_attempt: None,
        dedupe_key: None,
        run_id: None,
        now: 1,
    };

    for refused in [
        WakeTrigger::Compaction,
        WakeTrigger::SessionEnd,
        WakeTrigger::Event,
    ] {
        assert!(
            matches!(
                runner
                    .enqueue_vault_cleanup(enqueue(refused))
                    .map_err(|e| e.kind()),
                Err(ErrorKind::VaultCleanupWakeTriggerRejected)
            ),
            "{refused:?} must not register a cleanup pass"
        );
    }

    runner
        .enqueue_vault_cleanup(enqueue(WakeTrigger::Timer))
        .expect("timer registers");
    assert_eq!(
        WakeTrigger::Timer.default_scope(),
        crate::dreamer_runner::DreamerConsolidationScope::Macro,
        "ARCH-0073 puts the pass on the timer/Macro path"
    );
    assert_eq!(
        crate::dreamer_runner::DREAMER_VAULT_CLEANUP_ATTEMPT_KIND,
        "dreamer.vault_cleanup",
        "the queue kind doubles as the payload job_type"
    );
}

// ─── review-level teeth ─────────────────────────────────────────────────

#[path = "destructive_door_scan.rs"]
mod destructive_door_scan;

const MODULE_SOURCE: &str = include_str!("../vault_cleanup.rs");

/// The module's source with every comment line dropped.
///
/// The two teeth below are about what the CODE can reach, and the module's
/// prose necessarily names the doors it refuses to open ("hard deletion is
/// never automatic", "no thresholds, no weights"). Scanning the code alone is
/// what keeps the assertion about behavior instead of about vocabulary — and
/// it means the docs can stay plain-spoken.
fn module_code() -> String {
    MODULE_SOURCE
        .lines()
        .map(str::trim_start)
        .filter(|line| !line.starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// HARD DELETION IS NEVER AUTOMATIC — asserted against the module's own
/// source, because the property is "this code cannot reach that door", and
/// no runtime fixture can say that about a door it did not happen to call.
#[test]
fn the_cleanup_module_never_reaches_a_destructive_door() {
    let code = module_code();
    assert_eq!(
        destructive_door_scan::destructive_door(&code),
        None,
        "vault_cleanup must not reach a destructive door — hard deletion is never automatic"
    );
    assert!(
        code.contains("DeleteReason::ArchivedByCleanup"),
        "the archive reason is the only reason this module may name"
    );
}

/// NO SCORING — the other review-level requirement, asserted the same way. A
/// tripwire that grew a threshold would stop being closed-form, and the
/// difference would be invisible in any behavioral fixture that happened to
/// sit on the safe side of the number.
#[test]
fn the_tripwire_has_no_scoring_vocabulary() {
    let code = module_code();
    for forbidden in [
        "threshold",
        "f32",
        "f64",
        "score",
        "confidence",
        "salience",
        "weight",
        "rank",
    ] {
        assert!(
            !code.contains(forbidden),
            "vault_cleanup code must not use `{forbidden}` — the tripwire is closed-form"
        );
    }
    // The predicates return `bool`, which is the shape of a tripwire. A
    // predicate that started returning a number would fail here first.
    assert!(
        code.contains(
            "type EmptinessPredicate = fn(&Vault, &heed::RoTxn<'_>, &EntityId) -> Result<bool>;"
        ),
        "the checker table's predicate type is the closed-form pin"
    );
}

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
