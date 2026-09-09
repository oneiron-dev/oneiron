//! Correctness regressions for the Qodo cleanup repair. No test needs sync.

use super::*;
use crate::config::VaultConfig;
use crate::temporal::TimeRange;

fn test_config() -> VaultConfig {
    VaultConfig {
        dimensions: 4,
        embedding_model: Some("test/cleanup@v1".to_owned()),
        ..VaultConfig::default()
    }
}

fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("regression fixture");
    let vault = Vault::open(dir.path(), test_config()).expect("regression fixture");
    (dir, vault)
}

fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}

fn summary(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_SUMMARY, at(1), 1, b"retained summary")
        .expect("regression fixture");
    id
}

#[test]
fn open_rollout_blockers_refuse_owner_auto_and_ignore_persisted_auto() {
    let (dir, vault) = open();
    let id = summary(&vault);
    assert!(set_cleanup_posture(&vault, CleanupPosture::AutoWithDigest).is_err());
    vault
        .with_write_txn(|txn| {
            vault
                .store
                .vault_meta
                .put(txn, VAULT_CLEANUP_POSTURE_KEY, b"auto_with_digest")?;
            Ok(())
        })
        .expect("regression fixture");
    drop(vault);
    let vault = Vault::open(dir.path(), test_config()).expect("regression fixture");
    assert_eq!(
        cleanup_posture(&vault).expect("regression fixture"),
        CleanupPosture::ProposeFirst
    );
    let report = run_vault_cleanup(&vault, &AttemptId::now()).expect("regression fixture");
    assert!(report.proposal.is_some());
    assert!(report.archived.is_empty());
    assert!(!vault.is_deleted_shell(&id).expect("regression fixture"));
}

// Exact persisted index bytes, not only an identifier that looks live.
type IndexSnapshot = Vec<(Vec<u8>, Vec<u8>)>;

fn retained_indexes(vault: &Vault) -> Vec<IndexSnapshot> {
    let txn = vault.store.env.read_txn().expect("regression fixture");
    macro_rules! snapshot {
        ($($db:ident),+ $(,)?) => {
            vec![$(vault.store.$db.iter(&txn).expect("regression fixture").map(|row| {
                let (key, value) = row.expect("regression fixture");
                (key.to_vec(), value.to_vec())
            }).collect()),+]
        };
    }
    snapshot!(
        type_index,
        vectors,
        hnsw_neighbors,
        hnsw_meta,
        text_postings,
        text_meta,
        text_forward,
        text_bm25_field_stats,
        text_doc_field_lengths,
        phonetic_index,
        phonetic_forward,
        temporal_occurred_start,
        temporal_occurred_end,
        temporal_learned,
        edges_in,
        edges_out
    )
}

#[test]
fn archive_restore_preserves_payload_and_all_seeded_indexes_across_reopen() {
    let (dir, vault) = open();
    let person = EntityId::now();
    assert!(
        vault
            .put_extraction_minted_person(
                &person,
                ClaimSource::Generated,
                at(1),
                1,
                b"retained person",
            )
            .expect("regression fixture")
    );
    let summary = summary(&vault);
    let vector = vec![1.0; vault.config.dimensions];
    for id in [person, summary] {
        vault
            .batch()
            .text(&id, &[("name", "zebracleanup")])
            .phonetic(&id, &["Z162"])
            .commit()
            .expect("regression fixture");
        vault.put_vector(&id, &vector).expect("regression fixture");
    }
    let before = retained_indexes(&vault);
    let bodies = [
        vault.get_raw(&person).expect("regression fixture"),
        vault.get_raw(&summary).expect("regression fixture"),
    ];
    let proposal = run_vault_cleanup(&vault, &AttemptId::now())
        .expect("regression fixture")
        .proposal
        .expect("regression fixture");
    let accepted = accept_cleanup_proposal(&vault, &proposal).expect("regression fixture");
    assert_eq!(accepted.archived.len(), 2);
    assert_eq!(retained_indexes(&vault), before);
    assert!(
        vault
            .search_text("zebracleanup", 10)
            .expect("regression fixture")
            .is_empty()
    );
    assert!(
        vault
            .search_vector(&vector, 10)
            .expect("regression fixture")
            .is_empty()
    );
    assert!(
        vault
            .query()
            .search_phonetic(&["Z162"])
            .run()
            .expect("phonetic search")
            .is_empty()
    );
    assert!(
        vault
            .query()
            .search_temporal(1, 1, 10)
            .filter_types(&[ENTITY_TYPE_PERSON, ENTITY_TYPE_SUMMARY])
            .run()
            .expect("temporal search")
            .is_empty()
    );
    for id in [person, summary] {
        assert!(vault.get(&id).expect("regression fixture").is_none());
        assert!(vault.get_vector(&id).expect("archived vector").is_none());
        let reader = vault
            .scoped_read(crate::claim::ScopedReadActorKey::new("cleanup-reader").expect("reader"));
        assert!(reader.get(&id).expect("scoped archived body").is_none());
        assert!(matches!(
            vault.live_entity_row(&id).expect("regression fixture"),
            LiveEntityRow::DeletedShell
        ));
    }
    drop(vault);
    let vault = Vault::open(dir.path(), test_config()).expect("regression fixture");
    for (index, id) in [person, summary].iter().enumerate() {
        assert_eq!(
            vault.get_raw(id).expect("regression fixture"),
            bodies[index]
        );
        vault.restore_archived(id).expect("regression fixture");
        assert!(vault.get(id).expect("regression fixture").is_some());
        assert_eq!(
            vault.get_vector(id).expect("restored vector"),
            Some(vector.clone())
        );
    }
    assert_eq!(retained_indexes(&vault), before);
    assert_eq!(
        vault
            .search_text("zebracleanup", 10)
            .expect("regression fixture")
            .len(),
        2
    );
    assert_eq!(
        vault
            .search_vector(&vector, 10)
            .expect("regression fixture")
            .len(),
        2
    );
    assert_eq!(
        vault
            .query()
            .search_phonetic(&["Z162"])
            .run()
            .expect("phonetic search")
            .len(),
        2
    );
    assert_eq!(
        vault
            .query()
            .search_temporal(1, 1, 10)
            .filter_types(&[ENTITY_TYPE_PERSON, ENTITY_TYPE_SUMMARY])
            .run()
            .expect("temporal search")
            .len(),
        2
    );
    assert_eq!(
        vault
            .count_entities_by_type(ENTITY_TYPE_SUMMARY)
            .expect("regression fixture"),
        1
    );
}

#[test]
fn generic_delete_cannot_use_cleanup_reason_for_any_row_or_missing_id() {
    let (_dir, vault) = open();
    let person = EntityId::now();
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, at(1), 1, b"owner person")
        .expect("regression fixture");
    let other = EntityId::now();
    vault
        .put_entity(
            &other,
            crate::registry::ENTITY_TYPE_EVENT,
            at(1),
            1,
            b"event",
        )
        .expect("regression fixture");
    for id in [person, summary(&vault), other, EntityId::now()] {
        let before = vault.get_raw(&id).expect("regression fixture");
        assert!(
            vault
                .delete_entity_with_reason(&id, DeleteReason::ArchivedByCleanup)
                .is_err()
        );
        assert_eq!(vault.get_raw(&id).expect("regression fixture"), before);
        assert!(
            vault
                .archived_entity(&id)
                .expect("regression fixture")
                .is_none()
        );
    }
}

#[test]
fn archive_door_rechecks_person_provenance_without_trusting_its_caller() {
    let (_dir, vault) = open();
    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, at(1), 1, b"owner person")
        .expect("regression fixture");
    let archived = vault
        .with_write_txn(|txn| {
            vault.archive_cleanup_candidate_in_txn(
                txn,
                &id,
                &crate::deletion::TombstoneValueV2 {
                    reason: TombstoneReason::ArchivedByCleanup,
                    deleted_at: 2,
                    request_id: Uuid::now_v7().into_bytes(),
                },
            )
        })
        .expect("regression fixture");
    assert!(!archived);
    assert_eq!(
        vault.get(&id).expect("regression fixture"),
        Some(b"owner person".to_vec())
    );
}

#[test]
fn bounded_scans_resume_after_retained_archives_and_wrap_after_reopen() {
    let (dir, vault) = open();
    let mut ids: Vec<_> = (0..5).map(|_| summary(&vault)).collect();
    ids.sort();
    let first = scan::run_with_limit(&vault, &AttemptId::now(), 2).expect("regression fixture");
    assert_eq!(
        first
            .candidates
            .iter()
            .map(|c| c.entity)
            .collect::<Vec<_>>(),
        ids[..2]
    );
    accept_cleanup_proposal(&vault, &first.proposal.expect("regression fixture"))
        .expect("regression fixture");
    drop(vault);
    let vault = Vault::open(dir.path(), test_config()).expect("regression fixture");
    let second = scan::run_with_limit(&vault, &AttemptId::now(), 2).expect("regression fixture");
    assert_eq!(
        second
            .candidates
            .iter()
            .map(|c| c.entity)
            .collect::<Vec<_>>(),
        ids[2..4]
    );
    let third = scan::run_with_limit(&vault, &AttemptId::now(), 2).expect("regression fixture");
    assert_eq!(
        third
            .candidates
            .iter()
            .map(|c| c.entity)
            .collect::<Vec<_>>(),
        ids[4..]
    );
    // Wrapped to the archived prefix: it is examined but never re-archived.
    assert!(
        scan::run_with_limit(&vault, &AttemptId::now(), 2)
            .expect("regression fixture")
            .candidates
            .is_empty()
    );
    assert_eq!(
        scan::run_with_limit(&vault, &AttemptId::now(), 2)
            .expect("regression fixture")
            .candidates
            .len(),
        2
    );
}

#[test]
fn user_delete_after_archive_is_not_restorable() {
    let (_dir, vault) = open();
    let id = summary(&vault);
    let proposal = run_vault_cleanup(&vault, &AttemptId::now())
        .expect("regression fixture")
        .proposal
        .expect("regression fixture");
    accept_cleanup_proposal(&vault, &proposal).expect("regression fixture");
    vault
        .delete_entity_with_reason(&id, DeleteReason::UserDelete)
        .expect("regression fixture");
    assert!(vault.restore_archived(&id).is_err());
    assert!(vault.is_deleted_shell(&id).expect("regression fixture"));
}

#[test]
fn deletion_replay_cannot_turn_cleanup_reason_into_destructive_soft_erase() {
    let (_dir, vault) = open();
    let id = summary(&vault);
    let vector = vec![1.0; vault.config.dimensions];
    vault
        .batch()
        .text(&id, &[("name", "replayarchive")])
        .phonetic(&id, &["R141"])
        .commit()
        .expect("regression fixture");
    vault.put_vector(&id, &vector).expect("regression fixture");
    let body = vault.get_raw(&id).expect("regression fixture");
    let indexes = retained_indexes(&vault);
    let wire = crate::deletion::TombstoneValueV2 {
        reason: TombstoneReason::ArchivedByCleanup,
        deleted_at: 2,
        request_id: Uuid::now_v7().into_bytes(),
    }
    .encode();
    // No proposal or eligibility check can be bypassed through the replay door.
    assert!(vault.apply_replayed_tombstone(&id, &wire).is_err());
    assert_eq!(vault.get_raw(&id).expect("regression fixture"), body);
    assert_eq!(retained_indexes(&vault), indexes);
    assert!(
        vault
            .archived_entity(&id)
            .expect("regression fixture")
            .is_none()
    );

    let proposal = run_vault_cleanup(&vault, &AttemptId::now())
        .expect("regression fixture")
        .proposal
        .expect("regression fixture");
    accept_cleanup_proposal(&vault, &proposal).expect("regression fixture");
    assert!(vault.apply_replayed_tombstone(&id, &wire).is_err());
    assert_eq!(vault.get_raw(&id).expect("regression fixture"), body);
    assert_eq!(retained_indexes(&vault), indexes);
    vault.restore_archived(&id).expect("regression fixture");
    assert_eq!(vault.get_raw(&id).expect("regression fixture"), body);
    assert_eq!(
        vault.search_vector(&vector, 1).expect("regression fixture")[0].id,
        id
    );
}

#[test]
fn extraction_cannot_remint_a_hard_deleted_id_in_a_different_window() {
    let (_dir, vault) = open();
    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, at(1), 1, b"owner person")
        .expect("regression fixture");
    vault
        .delete_entity_with_reason(&id, DeleteReason::UserHardDelete)
        .expect("regression fixture");
    let next_window = 4_000_000_000;
    assert!(
        !vault
            .put_extraction_minted_person(
                &id,
                ClaimSource::Generated,
                at(next_window),
                next_window,
                b"extracted person",
            )
            .expect("regression fixture")
    );
    assert!(vault.get_raw(&id).expect("regression fixture").is_none());
    assert_eq!(
        zero_live_members(&vault, &id).expect("regression fixture"),
        None
    );
}

#[test]
fn archived_nearest_nodes_do_not_fill_the_live_vector_beam() {
    let dir = tempfile::tempdir().expect("regression fixture");
    let config = VaultConfig {
        hnsw: crate::config::HnswConfig {
            ef_search: 1,
            ..crate::config::HnswConfig::default()
        },
        ..test_config()
    };
    let vault = Vault::open(dir.path(), config).expect("regression fixture");
    let archived = summary(&vault);
    let live = EntityId::now();
    vault
        .put_entity(&live, ENTITY_TYPE_PERSON, at(1), 1, b"owner person")
        .expect("regression fixture");
    let query = vec![1.0; vault.config.dimensions];
    let mut farther = query.clone();
    farther[0] = -1.0;
    vault
        .put_vector(&archived, &query)
        .expect("regression fixture");
    vault
        .put_vector(&live, &farther)
        .expect("regression fixture");
    let proposal = run_vault_cleanup(&vault, &AttemptId::now())
        .expect("regression fixture")
        .proposal
        .expect("regression fixture");
    accept_cleanup_proposal(&vault, &proposal).expect("regression fixture");
    let found = vault.search_vector(&query, 1).expect("regression fixture");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, live);
    vault
        .restore_archived(&archived)
        .expect("regression fixture");
    assert_eq!(
        vault.search_vector(&query, 1).expect("regression fixture")[0].id,
        archived
    );
}

#[test]
fn retry_after_job_commit_replays_the_result_without_advancing_the_scan() {
    let (dir, vault) = open();
    let mut ids: Vec<_> = (0..3).map(|_| summary(&vault)).collect();
    ids.sort();
    let attempt = AttemptId::now();
    let first = scan::run_with_limit(&vault, &attempt, 1).expect("regression fixture");
    assert_eq!(first.candidates[0].entity, ids[0]);
    accept_cleanup_proposal(&vault, &first.proposal.expect("regression fixture"))
        .expect("regression fixture");
    drop(vault);
    let vault = Vault::open(dir.path(), test_config()).expect("regression fixture");
    // Models a crash after the job transaction but before queue completion.
    assert_eq!(
        scan::run_with_limit(&vault, &attempt, 1).expect("regression fixture"),
        first
    );
    assert!(
        cleanup_proposals(&vault)
            .expect("regression fixture")
            .is_empty()
    );
    let next = scan::run_with_limit(&vault, &AttemptId::now(), 1).expect("regression fixture");
    assert_eq!(next.candidates[0].entity, ids[1]);
}

#[test]
fn retry_of_auto_or_empty_run_never_produces_another_decision() {
    let (_dir, vault) = open();
    let empty_attempt = AttemptId::now();
    let empty = run_vault_cleanup(&vault, &empty_attempt).expect("regression fixture");
    assert!(empty.candidates.is_empty());
    let first = summary(&vault);
    assert_eq!(
        run_vault_cleanup(&vault, &empty_attempt).expect("regression fixture"),
        empty
    );
    assert!(
        cleanup_proposals(&vault)
            .expect("regression fixture")
            .is_empty()
    );

    rollout::close_blockers_for_test(&vault);
    set_cleanup_posture(&vault, CleanupPosture::AutoWithDigest).expect("regression fixture");
    let auto_attempt = AttemptId::now();
    let auto = run_vault_cleanup(&vault, &auto_attempt).expect("regression fixture");
    assert_eq!(auto.archived, vec![first]);
    let later = summary(&vault);
    assert_eq!(
        run_vault_cleanup(&vault, &auto_attempt).expect("regression fixture"),
        auto
    );
    assert!(!vault.is_deleted_shell(&later).expect("regression fixture"));
    assert_eq!(
        cleanup_digests(&vault).expect("regression fixture").len(),
        1
    );
    let next = run_vault_cleanup(&vault, &AttemptId::now()).expect("regression fixture");
    assert_eq!(next.archived, vec![later]);
    assert_eq!(
        cleanup_digests(&vault).expect("regression fixture").len(),
        2
    );
}

#[test]
fn failed_scan_keeps_the_cursor_and_has_no_durable_run_result() {
    let (dir, vault) = open();
    let mut people = Vec::new();
    for _ in 0..3 {
        let id = EntityId::now();
        assert!(
            vault
                .put_extraction_minted_person(&id, ClaimSource::Generated, at(1), 1, b"person",)
                .expect("mint person")
        );
        people.push(id);
    }
    people.sort();
    let first = scan::run_with_limit(&vault, &AttemptId::now(), 1).expect("first scan");
    assert_eq!(first.candidates[0].entity, people[0]);
    let summary = summary(&vault);
    let raw = vault
        .get_raw(&summary)
        .expect("summary read")
        .expect("summary row");
    vault
        .with_write_txn(|txn| {
            vault
                .store
                .entities
                .put(txn, summary.as_bytes(), b"bad header")?;
            Ok(())
        })
        .expect("corrupt summary");
    let attempt = AttemptId::now();
    assert!(scan::run_with_limit(&vault, &attempt, 1).is_err());
    assert_eq!(cleanup_proposals(&vault).expect("proposals").len(), 1);
    vault
        .with_write_txn(|txn| {
            vault.store.entities.put(txn, summary.as_bytes(), &raw)?;
            Ok(())
        })
        .expect("repair summary fixture");
    drop(vault);
    let vault = Vault::open(dir.path(), test_config()).expect("regression fixture");
    let retried = scan::run_with_limit(&vault, &attempt, 1).expect("retry scan");
    assert_eq!(retried.candidates.len(), 2);
    assert_eq!(retried.candidates[0].entity, people[1]);
    assert_eq!(retried.candidates[1].entity, summary);
    let proposal_id = retried.proposal.expect("retry proposal");
    let proposal = cleanup_proposal(&vault, &proposal_id)
        .expect("read retry proposal")
        .expect("open retry proposal");
    assert_eq!(proposal.attempt, attempt);
    assert_eq!(proposal.candidates.len(), 2);
    assert_eq!(proposal.candidates[0].entity, people[1]);
    assert_eq!(proposal.candidates[1].entity, summary);
    assert_eq!(cleanup_proposals(&vault).expect("proposals").len(), 2);
}
