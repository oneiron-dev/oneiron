//! Focused continuation fixtures for the three previously absent seams.

use super::*;
use crate::attempt_queue::AttemptQueue;
use crate::claim::ClaimSource;
use crate::config::VaultConfig;
use crate::dreamer_runner::{
    DREAMER_VAULT_CLEANUP_ATTEMPT_KIND, DreamerAttemptPayload, DreamerConsolidationScope,
    DreamerRunnerStore,
};
use crate::dreamer_wake::{WakeTrigger, request_wake, request_wake_in_txn};
use crate::temporal::TimeRange;

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn t(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn mint_person(vault: &Vault, source: ClaimSource) -> EntityId {
    let id = EntityId::now();
    assert!(
        vault
            .put_extraction_minted_person(&id, source, t(1), 1, b"person")
            .expect("mint extraction person")
    );
    id
}

fn cleanup_receipts(vault: &Vault) -> Vec<ReceiptRecord> {
    vault
        .receipts(ReceiptQuery::new(64).with_kind(ReceiptKind::Gate))
        .expect("receipts")
        .into_iter()
        .filter(is_vault_cleanup_receipt)
        .collect()
}

#[test]
fn person_requires_positive_extraction_provenance() {
    let (_tmp, vault) = temp_vault();
    let ordinary = EntityId::now();
    vault
        .put_entity(&ordinary, ENTITY_TYPE_PERSON, t(1), 1, b"person")
        .expect("ordinary person");
    assert_eq!(
        zero_live_members(&vault, &ordinary).expect("ordinary tripwire"),
        None
    );
    assert!(
        !vault
            .put_extraction_minted_person(&ordinary, ClaimSource::Generated, t(1), 1, b"person",)
            .expect("must not relabel an existing person")
    );
    for source in MACHINE_MINTED_CLAIM_SOURCES {
        let person = mint_person(&vault, source);
        assert_eq!(
            zero_live_members(&vault, &person).expect("extraction tripwire"),
            Some(CleanupKind::ClaimlessExtractionPerson)
        );
    }
    for source in [
        ClaimSource::UserStated,
        ClaimSource::Observed,
        ClaimSource::Inferred,
        ClaimSource::Imported,
    ] {
        let person = EntityId::now();
        assert!(
            !vault
                .put_extraction_minted_person(&person, source, t(1), 1, b"person")
                .expect("non-extraction refusal")
        );
        assert!(vault.get(&person).expect("missing person").is_none());
    }
}

#[test]
fn replaced_person_revision_is_not_an_extraction_candidate() {
    let (_tmp, vault) = temp_vault();
    let person = mint_person(&vault, ClaimSource::Generated);
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, t(2), 2, b"owner revision")
        .expect("replace person");
    assert_eq!(zero_live_members(&vault, &person).expect("tripwire"), None);
    assert!(
        !vault
            .put_extraction_minted_person(
                &person,
                ClaimSource::Generated,
                t(2),
                2,
                b"owner revision"
            )
            .expect("cannot relabel replacement")
    );
}

#[test]
fn missing_corrupt_or_non_machine_provenance_fails_closed() {
    let (_tmp, vault) = temp_vault();
    let person = mint_person(&vault, ClaimSource::Generated);
    let key = prefixed_key(b"vault_cleanup.extraction_person.v1:", &person);
    let original = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault
            .store
            .vault_meta
            .get(&rtxn, &key)
            .expect("evidence")
            .expect("present")
            .to_vec()
    };
    let mut human = original[..32].to_vec();
    human.extend_from_slice(b"user_stated");
    let mut unknown = original[..32].to_vec();
    unknown.extend_from_slice(b"future_source");
    for evidence in [Vec::new(), vec![0; 31], vec![255; 40], human, unknown] {
        vault
            .with_write_txn(|txn| {
                vault.store.vault_meta.put(txn, &key, &evidence)?;
                Ok(())
            })
            .expect("corrupt provenance");
        assert_eq!(zero_live_members(&vault, &person).expect("tripwire"), None);
    }
    vault
        .with_write_txn(|txn| {
            vault.store.vault_meta.delete(txn, &key)?;
            Ok(())
        })
        .expect("remove provenance");
    assert_eq!(zero_live_members(&vault, &person).expect("tripwire"), None);
}

#[test]
fn accept_skips_a_person_whose_mint_evidence_changed_mid_flight() {
    let (_tmp, vault) = temp_vault();
    let person = mint_person(&vault, ClaimSource::ToolOutput);
    let proposal = run_vault_cleanup(&vault, &AttemptId::now())
        .expect("propose")
        .proposal
        .expect("proposal");
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, t(2), 2, b"owner revision")
        .expect("replace");
    let accepted = accept_cleanup_proposal(&vault, &proposal).expect("accept");
    assert!(accepted.archived.is_empty());
    assert_eq!(accepted.skipped, vec![person]);
    let receipts = cleanup_receipts(&vault);
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].fields.get(FIELD_CLEANUP_SKIPPED_IDS),
        Some(&person.to_hex())
    );
    assert_eq!(
        vault.get(&person).expect("person"),
        Some(b"owner revision".to_vec())
    );
}

#[test]
fn accept_rechecks_uncommitted_summary_members_in_the_accept_transaction() {
    let (_tmp, vault) = temp_vault();
    let summary = EntityId::now();
    vault
        .put_entity(&summary, ENTITY_TYPE_SUMMARY, t(1), 1, b"summary")
        .expect("summary");
    let proposal = run_vault_cleanup(&vault, &AttemptId::now())
        .expect("propose")
        .proposal
        .expect("proposal");
    let member = mint_person(&vault, ClaimSource::Generated);
    let accepted = vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .edge(&member, EdgeKind::PartOf, &summary, 1.0)
                .apply(txn)?;
            accept_cleanup_proposal_in_txn(&vault, txn, &proposal)
        })
        .expect("atomic accept");
    assert!(accepted.archived.is_empty());
    assert_eq!(accepted.skipped, vec![summary]);
    assert!(!vault.is_deleted_shell(&summary).expect("summary live"));
    let receipts = cleanup_receipts(&vault);
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].fields.get(FIELD_CLEANUP_SKIPPED_IDS),
        Some(&summary.to_hex())
    );
}

#[test]
fn aborting_accept_rolls_back_archives_digest_and_proposal_consumption() {
    let (_tmp, vault) = temp_vault();
    let person = mint_person(&vault, ClaimSource::Generated);
    let summary = EntityId::now();
    vault
        .put_entity(&summary, ENTITY_TYPE_SUMMARY, t(1), 1, b"summary")
        .expect("summary");
    let proposal = run_vault_cleanup(&vault, &AttemptId::now())
        .expect("propose")
        .proposal
        .expect("proposal");
    let aborted: Result<()> = vault.with_write_txn(|txn| {
        let accepted = accept_cleanup_proposal_in_txn(&vault, txn, &proposal)?;
        assert_eq!(accepted.archived.len(), 2);
        assert!(vault.archive_tombstone_in_txn(txn, &person)?.is_some());
        assert!(
            vault
                .store
                .vault_meta
                .get(txn, &digest_key(&accepted.digest))?
                .is_some()
        );
        assert!(
            vault
                .store
                .vault_meta
                .get(txn, &proposal_key(&proposal))?
                .is_none()
        );
        Err(Error::CorruptedIndex("abort accept fixture"))
    });
    assert!(aborted.is_err());
    for id in [person, summary] {
        assert!(!vault.is_deleted_shell(&id).expect("row live"));
        assert!(vault.archived_entity(&id).expect("archive query").is_none());
    }
    assert_eq!(
        vault.get(&person).expect("person"),
        Some(b"person".to_vec())
    );
    assert_eq!(
        vault.get(&summary).expect("summary"),
        Some(b"summary".to_vec())
    );
    assert!(
        cleanup_proposal(&vault, &proposal)
            .expect("proposal")
            .is_some()
    );
    assert!(cleanup_receipts(&vault).is_empty());
    assert_eq!(
        accept_cleanup_proposal(&vault, &proposal)
            .expect("retry accept")
            .archived
            .len(),
        2
    );
    assert_eq!(cleanup_receipts(&vault).len(), 1);
}

#[test]
fn auto_decision_reads_posture_in_txn_and_rolls_back_with_its_digest() {
    let (_tmp, vault) = temp_vault();
    rollout::close_blockers_for_test(&vault);
    let person = mint_person(&vault, ClaimSource::Generated);
    let candidates = scan_cleanup_candidates(&vault).expect("scan");
    let aborted: Result<()> = vault.with_write_txn(|txn| {
        vault
            .store
            .vault_meta
            .put(txn, VAULT_CLEANUP_POSTURE_KEY, b"auto_with_digest")?;
        let report = run_cleanup_candidates_in_txn(&vault, txn, &AttemptId::now(), candidates)?;
        assert_eq!(report.posture, CleanupPosture::AutoWithDigest);
        assert_eq!(report.archived, vec![person]);
        assert!(
            vault
                .store
                .vault_meta
                .get(txn, &digest_key(&report.digest.expect("digest")))?
                .is_some()
        );
        Err(Error::CorruptedIndex("abort auto fixture"))
    });
    assert!(aborted.is_err());
    assert_eq!(
        cleanup_posture(&vault).expect("posture"),
        CleanupPosture::ProposeFirst
    );
    assert!(!vault.is_deleted_shell(&person).expect("person live"));
    assert!(cleanup_receipts(&vault).is_empty());
    assert!(cleanup_proposals(&vault).expect("proposals").is_empty());
}

#[test]
fn posture_and_mint_provenance_survive_reopen() {
    let (tmp, vault) = temp_vault();
    let person = mint_person(&vault, ClaimSource::Generated);
    rollout::close_blockers_for_test(&vault);
    set_cleanup_posture(&vault, CleanupPosture::AutoWithDigest).expect("set posture");
    drop(vault);
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("reopen");
    assert_eq!(
        cleanup_posture(&vault).expect("posture"),
        CleanupPosture::AutoWithDigest
    );
    assert_eq!(
        zero_live_members(&vault, &person).expect("tripwire"),
        Some(CleanupKind::ClaimlessExtractionPerson)
    );
    for bytes in [b"unknown".as_slice(), &[255], b""] {
        vault
            .with_write_txn(|txn| {
                vault
                    .store
                    .vault_meta
                    .put(txn, VAULT_CLEANUP_POSTURE_KEY, bytes)?;
                Ok(())
            })
            .expect("unreadable posture");
        assert_eq!(
            cleanup_posture(&vault).expect("posture"),
            CleanupPosture::ProposeFirst
        );
    }
}

fn wake_payload() -> DreamerAttemptPayload {
    DreamerAttemptPayload {
        attempt_type: "wake".to_owned(),
        input: Value::Nil,
        parent_attempt: None,
    }
}

#[test]
fn actual_wake_entry_enqueues_cleanup_only_for_timer_macro() {
    for (trigger, scope, cleanup_count) in [
        (WakeTrigger::Compaction, DreamerConsolidationScope::Micro, 0),
        (WakeTrigger::SessionEnd, DreamerConsolidationScope::Meso, 0),
        (WakeTrigger::Event, DreamerConsolidationScope::Macro, 0),
        (WakeTrigger::Timer, DreamerConsolidationScope::Micro, 0),
        (WakeTrigger::Timer, DreamerConsolidationScope::Macro, 1),
    ] {
        let (_tmp, vault) = temp_vault();
        let runner = DreamerRunnerStore::new(&vault);
        for _ in 0..2 {
            request_wake(
                &runner,
                trigger,
                scope,
                wake_payload(),
                Some("same-wake".to_owned()),
                Some("timer-run".to_owned()),
                1,
            )
            .expect("request wake");
        }
        let queued = AttemptQueue::new(&vault).list().expect("queue");
        assert_eq!(
            queued
                .iter()
                .filter(|row| row.kind == DREAMER_VAULT_CLEANUP_ATTEMPT_KIND)
                .count(),
            cleanup_count
        );
        assert_eq!(
            queued
                .iter()
                .filter(|row| row.kind == scope.attempt_kind())
                .count(),
            1
        );
        assert_eq!(queued.len(), 1 + cleanup_count);
    }
}

#[test]
fn transactional_timer_wake_rolls_back_both_queue_lanes() {
    let (_tmp, vault) = temp_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let aborted: Result<()> = vault.with_write_txn(|txn| {
        request_wake_in_txn(
            &runner,
            txn,
            WakeTrigger::Timer,
            wake_payload(),
            Some("timer".to_owned()),
            None,
            1,
        )?;
        Err(Error::CorruptedIndex("abort wake fixture"))
    });
    assert!(aborted.is_err());
    assert!(AttemptQueue::new(&vault).list().expect("queue").is_empty());
    vault
        .with_write_txn(|txn| {
            request_wake_in_txn(
                &runner,
                txn,
                WakeTrigger::Timer,
                wake_payload(),
                Some("timer".to_owned()),
                None,
                1,
            )
        })
        .expect("commit wake");
    let queued = AttemptQueue::new(&vault).list().expect("queue");
    assert_eq!(queued.len(), 2);
    assert_eq!(
        queued
            .iter()
            .filter(|row| row.kind == DREAMER_VAULT_CLEANUP_ATTEMPT_KIND)
            .count(),
        1
    );
}

#[test]
fn unreadable_archive_marker_is_not_overwritten_by_cleanup() {
    let (_tmp, vault) = temp_vault();
    let person = mint_person(&vault, ClaimSource::Generated);
    for reason in [0, 6, 255] {
        let mut marker = [0_u8; crate::deletion::TOMBSTONE_VALUE_V2_LEN];
        marker[0] = reason;
        let key = format!("ac:{}", person.to_hex());
        vault
            .with_write_txn(|txn| {
                vault.store.sync_state.put(txn, &key, &marker)?;
                Ok(())
            })
            .expect("unknown archive marker");
        assert_eq!(zero_live_members(&vault, &person).expect("tripwire"), None);
        assert!(vault.restore_archived(&person).is_err());
        let rtxn = vault.store.env.read_txn().expect("read txn");
        let stored = vault
            .store
            .sync_state
            .get(&rtxn, &key)
            .expect("marker")
            .expect("present");
        assert_eq!(&stored[..], marker.as_slice());
        assert!(crate::deletion::decode_tombstone_value(&stored).is_hard());
    }
}

#[test]
fn accept_rechecks_an_uncommitted_person_claim_and_receipts_the_skip() {
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};

    let (_tmp, vault) = temp_vault();
    let person = mint_person(&vault, ClaimSource::Generated);
    let proposal = run_vault_cleanup(&vault, &AttemptId::now())
        .expect("propose")
        .proposal
        .expect("proposal");
    let body = ClaimBody::new(
        "profile.hobby",
        ClaimSubject::Entity(person),
        Value::from("birdwatching"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    let accepted = vault
        .with_write_txn(|txn| {
            vault.put_claim_in_txn(txn, &EntityId::now(), &body, t(2), 2)?;
            accept_cleanup_proposal_in_txn(&vault, txn, &proposal)
        })
        .expect("atomic accept");
    assert!(accepted.archived.is_empty());
    assert_eq!(accepted.skipped, vec![person]);
    assert!(!vault.is_deleted_shell(&person).expect("person live"));
    let receipts = cleanup_receipts(&vault);
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].fields.get(FIELD_CLEANUP_SKIPPED_IDS),
        Some(&person.to_hex())
    );
}
