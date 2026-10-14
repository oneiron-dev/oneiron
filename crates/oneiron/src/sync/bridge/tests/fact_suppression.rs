//! F24 round 7 (H219): a task whose authority fact was tombstoned before it
//! arrived keeps reading as a refusal through every door that carries the
//! fact or the task, and a fact that arrives after a delete's read-only
//! precheck is still never erased.
use super::*;
use crate::deletion::TombstoneReason;
use crate::recovery::{RecoveryBudget, capture_canonical_window, recover_vault_window};
use crate::task_authority::{
    TaskAuthorityFact, TaskAuthorityFactKind, encode_task_authority_fact_body,
};

const LEARNED_AT: u64 = 1_772_400_000; // 2026-03 window

const fn at() -> TimeRange {
    TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    }
}

fn cancellation(task: EntityId, owner: EntityId) -> Vec<u8> {
    encode_task_authority_fact_body(&TaskAuthorityFact {
        task_ref: task,
        kind: TaskAuthorityFactKind::Cancelled,
        actor_ref: owner,
        assigned_ref: None,
        actor_generation: None,
        assigned_generation: None,
        occurred_at: LEARNED_AT,
    })
}

fn reads_suppressed(vault: &Vault, task: EntityId) -> bool {
    matches!(
        vault.task_authority_state(task),
        Err(Error::InvariantViolation("task authority fact suppressed"))
    )
}

fn owner_and_cancelled(vault: &Vault, task: EntityId) -> Option<(EntityId, bool)> {
    vault
        .task_authority_state(task)
        .unwrap()
        .map(|state| (state.owner_ref, state.cancelled))
}

/// A hard tombstone for `fact`, then `fact` itself, a cancellation of `task`,
/// through Observer B, as a peer's window delivers them.
fn suppress_a_cancellation(vault: &Arc<Vault>, fact: EntityId, task: EntityId, owner: EntityId) {
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, vault, &materializer, "2026-03");
    let tombstone = forged_update_against(&doc, |fork| {
        map_insert_bytes(
            &fork.get_map("tombstones"),
            &fact.to_hex(),
            &tombstone_value(TombstoneReason::UserHardDelete, LEARNED_AT),
        )
        .unwrap();
    });
    import_doc(&doc, &tombstone).unwrap();
    let row = forged_update_against(&doc, |fork| {
        map_insert_bytes(
            &fork.get_map("entities"),
            &fact.to_hex(),
            &entity_blob(
                ENTITY_TYPE_TASK,
                at(),
                LEARNED_AT,
                &cancellation(task, owner),
            ),
        )
        .unwrap();
    });
    import_doc(&doc, &row).unwrap();
    assert!(reads_suppressed(vault, task), "precondition: suppressed");
}

/// The explicit-tier import door refuses a fact whose id was deleted here, as
/// before, and its task reads as a refusal, as after window ingest.
#[test]
fn an_explicit_tier_replay_of_a_fact_deleted_here_marks_its_task() {
    let vault = test_vault();
    let (owner, tasks) = owned_tasks_for_fact_replay(&vault, LEARNED_AT, 2);
    let (task, other) = (tasks[0].0, tasks[1].0);
    let fact = EntityId::now();
    vault
        .apply_replayed_tombstone(
            &fact,
            &tombstone_value(TombstoneReason::UserDelete, LEARNED_AT),
        )
        .unwrap();

    let body = cancellation(task, owner);
    let replayed = crate::sync::replay::replay_entity(
        &vault,
        crate::sync::replay::ReplicatedEntity {
            id: fact,
            entity_type: ENTITY_TYPE_TASK,
            occurred: at(),
            learned_at: LEARNED_AT,
            body: &body,
        },
        crate::sync::client::ImportTier::OwnDevice,
    );
    assert!(replayed.is_err(), "a row deleted here is not restored");
    assert!(
        reads_suppressed(&vault, task),
        "the refused cancellation reads as a refusal"
    );
    assert_eq!(
        owner_and_cancelled(&vault, other),
        Some((owner, false)),
        "positive control: a task with no suppressed fact still reads"
    );
}

/// A restore over the vault from a checkpoint taken before the suppression
/// keeps the refusal, even of a task the live vault deleted since, which the
/// restore's authority comparison never asks about.
#[test]
fn a_restore_keeps_the_refusal_of_a_task_deleted_since() {
    let vault = test_vault();
    let (owner, tasks) = owned_tasks_for_fact_replay(&vault, LEARNED_AT, 2);
    let (task, other) = (tasks[0].0, tasks[1].0);
    let backups = tempfile::tempdir().unwrap();
    let image = backups.path().join("backup");
    vault.snapshot_checkpoint(&image, 100).unwrap();

    suppress_a_cancellation(&vault, EntityId::now(), task, owner);
    vault.batch().delete(&task).commit().unwrap();
    let (restored, _report) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &backups.path().join("restored"),
        vault.config.clone(),
        &vault,
        200,
    )
    .unwrap();

    assert!(
        reads_suppressed(&restored, task),
        "the restored task reads as a refusal"
    );
    assert_eq!(
        owner_and_cancelled(&restored, other),
        Some((owner, false)),
        "positive control: a task with no suppressed fact still reads"
    );
}

/// A canonical window snapshot carries the refusal: the hard tombstone takes
/// the fact's body out of the snapshot, and a fresh vault recovered from it
/// reads the task as a refusal, not as never cancelled.
#[test]
fn a_recovered_window_keeps_the_refusal_of_a_suppressed_fact() {
    let source = test_vault();
    let (owner, tasks) = owned_tasks_for_fact_replay(&source, LEARNED_AT, 2);
    let (task, other) = (tasks[0].0, tasks[1].0);
    let fact = EntityId::now();
    suppress_a_cancellation(&source, fact, task, owner);

    let window = LoroDoc::new();
    let mut ids = vec![owner];
    for (task, owner_fact) in &tasks {
        ids.extend([*task, *owner_fact]);
    }
    for id in &ids {
        map_insert_bytes(
            &window.get_map("entities"),
            &id.to_hex(),
            &source.get_raw(id).unwrap().unwrap(),
        )
        .unwrap();
    }
    {
        let txn = source.store.env.read_txn().unwrap();
        for (_, owner_fact) in &tasks {
            for row in source
                .store
                .edges_out
                .prefix_iter(&txn, owner_fact.as_bytes())
                .unwrap()
            {
                let (key, value) = row.unwrap();
                let target = EntityId::from_bytes(key[17..].try_into().unwrap()).unwrap();
                let key = format!("{}:{:02}:{}", owner_fact.to_hex(), key[16], target.to_hex());
                map_insert_bytes(&window.get_map("edges"), &key, &value).unwrap();
            }
        }
    }
    map_insert_bytes(
        &window.get_map("tombstones"),
        &fact.to_hex(),
        &tombstone_value(TombstoneReason::UserHardDelete, LEARNED_AT),
    )
    .unwrap();
    let snapshot = capture_canonical_window(&source, "2026-03", &window).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let recovered = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    recover_vault_window(
        &recovered,
        &Materializer::new(),
        dir.path().join("manifest"),
        &snapshot,
        RecoveryBudget::default(),
    )
    .unwrap();

    assert!(
        reads_suppressed(&recovered, task),
        "the recovered task reads as a refusal"
    );
    assert_eq!(
        owner_and_cancelled(&recovered, other),
        Some((owner, false)),
        "positive control: a task with no suppressed fact still reads"
    );
}

/// A fact that lands after the delete facade's read-only precheck meets the
/// refusal again in the transaction that would erase it.
#[test]
fn a_fact_that_arrives_after_a_delete_precheck_is_never_erased() {
    let vault = test_vault();
    let (owner, tasks) = owned_tasks_for_fact_replay(&vault, LEARNED_AT, 1);
    let task = tasks[0].0;
    let fact = EntityId::now();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");
    let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
    vault.test_hooks().install_delete_rendezvous(
        crate::deletion::DeleteRendezvous::AfterProtectedRecordPrecheck,
        fact,
        arrived_tx,
        resume_rx,
    );

    std::thread::scope(|scope| {
        let deleter = scope.spawn(|| vault.delete_entity(&fact));
        arrived_rx.recv().expect("the deleter passed its precheck");
        let row = forged_update_against(&doc, |fork| {
            map_insert_bytes(
                &fork.get_map("entities"),
                &fact.to_hex(),
                &entity_blob(
                    ENTITY_TYPE_TASK,
                    at(),
                    LEARNED_AT,
                    &cancellation(task, owner),
                ),
            )
            .unwrap();
        });
        import_doc(&doc, &row).unwrap();
        assert!(
            crate::task_authority::reject_fact_delete(
                &vault.store,
                &vault.store.env.read_txn().unwrap(),
                &fact,
            )
            .is_err(),
            "precondition: the fact landed"
        );
        resume_tx.send(()).expect("resume the deleter");
        assert_matches!(
            deleter.join().expect("deleter thread"),
            Err(Error::Record(crate::error::RecordError::InvalidTaskBody(
                "task authority facts are immutable"
            ))),
            "the erase refuses the fact"
        );
    });
    assert!(
        vault.live_entity_row(&fact).unwrap().is_live(),
        "the fact row stays"
    );
}

/// The five local paths that remove a window carrier because its id was
/// deleted here (Engine ruling, round 7) mark the task of an authority fact
/// the carrier holds that this vault never admitted.
mod removed_carriers {
    use super::*;
    use crate::sync::loro_support::{doc_version_vector, export_snapshot};
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window_rows::{PENDING_TOMBSTONE, WindowEntityHexKey};

    /// A window document whose entities map holds `fact`, a cancellation of
    /// `task`, that no observer ever ingested.
    fn window_carrying(window: &str, fact: EntityId, task: EntityId, owner: EntityId) -> LoroDoc {
        let doc = create_window_doc("local", &WindowKey::new(window));
        map_insert_bytes(
            &doc.get_map("entities"),
            &fact.to_hex(),
            &entity_blob(
                ENTITY_TYPE_TASK,
                at(),
                LEARNED_AT,
                &cancellation(task, owner),
            ),
        )
        .unwrap();
        doc.commit();
        doc
    }

    fn persist(vault: &Vault, window: &str, doc: &LoroDoc) {
        let snapshot = export_snapshot(doc).unwrap();
        vault
            .with_write_txn(|wtxn| {
                crate::sync::window::persist_window_doc_in_txn(
                    vault,
                    wtxn,
                    &WindowKey::new(window),
                    &snapshot,
                    &doc_version_vector(doc),
                )
            })
            .unwrap();
    }

    fn assert_marked_and_control(vault: &Vault, owner: EntityId, tasks: &[(EntityId, EntityId)]) {
        assert!(
            reads_suppressed(vault, tasks[0].0),
            "the removed fact's task reads as a refusal"
        );
        assert_eq!(
            owner_and_cancelled(vault, tasks[1].0),
            Some((owner, false)),
            "positive control: a task with no suppressed fact still reads"
        );
    }

    #[test]
    fn a_replayed_pending_tombstone_marks_an_unadmitted_fact() {
        let vault = test_vault();
        let (owner, tasks) = owned_tasks_for_fact_replay(&vault, LEARNED_AT, 2);
        let fact = EntityId::now();
        let doc = window_carrying("2026-03", fact, tasks[0].0, owner);
        vault
            .with_write_txn(|wtxn| {
                PENDING_TOMBSTONE.put(
                    &vault.store,
                    wtxn,
                    &WindowEntityHexKey {
                        window: "2026-03".to_owned(),
                        id: fact,
                    },
                    &tombstone_value(TombstoneReason::UserDelete, LEARNED_AT),
                )
            })
            .unwrap();

        let replayed = crate::sync::window::replay_pending_tombstones(
            &vault,
            &doc,
            &WindowKey::new("2026-03"),
        )
        .unwrap();
        assert_eq!(replayed, 1);
        assert_marked_and_control(&vault, owner, &tasks);
    }

    #[test]
    fn a_reasserted_tombstone_marks_an_unadmitted_fact() {
        let vault = test_vault();
        let (owner, tasks) = owned_tasks_for_fact_replay(&vault, LEARNED_AT, 2);
        let fact = EntityId::now();
        persist(
            &vault,
            "2026-03",
            &window_carrying("2026-03", fact, tasks[0].0, owner),
        );
        vault
            .apply_replayed_tombstone(
                &fact,
                &tombstone_value(TombstoneReason::UserHardDelete, LEARNED_AT),
            )
            .unwrap();
        assert!(
            crate::sync::quarantine::enqueue_tombstone_reassert_marker(&vault, "2026-03", &fact)
                .unwrap(),
            "precondition: a hard delete here to reassert"
        );

        let manager = Arc::new(crate::sync::manager::WindowManager::new(
            vault.clone(),
            Arc::new(Materializer::new()),
            "local",
        ));
        crate::sync::quarantine::drain_reassert_markers_for_window(
            &vault,
            "local",
            &manager,
            &WindowKey::new("2026-03"),
        )
        .unwrap();
        assert_marked_and_control(&vault, owner, &tasks);
    }

    #[test]
    fn the_withdrawn_delete_scrub_marks_an_unadmitted_fact() {
        let vault = test_vault();
        let (owner, tasks) = owned_tasks_for_fact_replay(&vault, LEARNED_AT, 2);
        let fact = EntityId::now();
        vault
            .apply_replayed_tombstone(
                &fact,
                &tombstone_value(TombstoneReason::UserDelete, LEARNED_AT),
            )
            .unwrap();
        let doc = window_carrying("2026-03", fact, tasks[0].0, owner);

        crate::sync::window::export_scrubbed_window_snapshot(
            &vault,
            &WindowKey::new("2026-03"),
            &doc,
        )
        .unwrap();
        assert!(
            doc.get_map("entities").get(&fact.to_hex()).is_none(),
            "the scrub removed the carrier"
        );
        assert_marked_and_control(&vault, owner, &tasks);
    }

    #[test]
    fn a_local_delete_publication_marks_an_unadmitted_fact() {
        let vault = test_vault();
        let (owner, tasks) = owned_tasks_for_fact_replay(&vault, LEARNED_AT, 2);
        let fact = EntityId::now();
        // Index residue of a row whose header is gone is local delete scope,
        // so the delete publishes a tombstone without a header to read.
        vault
            .put_entity(&fact, ENTITY_TYPE_TASK, at(), LEARNED_AT, &task_body())
            .unwrap();
        {
            let mut wtxn = vault.store.env.write_txn().unwrap();
            assert!(
                vault
                    .store
                    .entities
                    .delete(&mut wtxn, fact.as_bytes())
                    .unwrap()
            );
            wtxn.commit().unwrap();
        }
        let window =
            crate::deletion::window_label_from_timestamp(vault.store.clock.now_recorded_at());
        persist(
            &vault,
            &window,
            &window_carrying(&window, fact, tasks[0].0, owner),
        );

        vault.delete_entity(&fact).unwrap();
        assert_marked_and_control(&vault, owner, &tasks);
    }
}
