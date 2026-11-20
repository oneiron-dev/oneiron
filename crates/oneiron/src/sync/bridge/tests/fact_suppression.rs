//! F24 round 7 (H219): a task whose authority fact was tombstoned before it
//! arrived keeps reading as a refusal through every door that carries the
//! fact or the task, and a fact that arrives after a delete's read-only
//! precheck is still never erased.
use super::*;
use crate::deletion::TombstoneReason;
use crate::recovery::{
    CanonicalRefusedTaskFact, RecoveryBudget, capture_canonical_window, recover_vault_window,
};
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

fn cancellation(task: EntityId, owner: EntityId) -> TaskAuthorityFact {
    TaskAuthorityFact {
        task_ref: task,
        kind: TaskAuthorityFactKind::Cancelled,
        actor_ref: owner,
        assigned_ref: None,
        actor_generation: None,
        assigned_generation: None,
        answered_heads: None,
        occurred_at: LEARNED_AT,
        maker: None,
    }
}

/// `fact`, a cancellation of `task`, as the row a peer delivers at `fact`: this
/// vault's own install signs it under that row id, and the vault's fold admits
/// the machine it enrolled, so the row proves itself here as a peer's signed
/// row does (`crate::task_authority::fact_proof`).
fn signed_cancellation(vault: &Vault, fact: EntityId, task: EntityId, owner: EntityId) -> Vec<u8> {
    signed_task_fact_body(vault, &fact, &cancellation(task, owner))
}

/// A peer's UNSIGNED cancellation of `task`, delivered at a fresh id deleted
/// here first: the refusal keeps no row it cannot prove, so `task` still reads
/// as it did (rule 3).
fn assert_unsigned_fact_at_a_deleted_id_leaves_task_readable(
    vault: &Vault,
    task: EntityId,
    owner: EntityId,
) {
    let fact = EntityId::now();
    vault
        .apply_replayed_tombstone(
            &fact,
            &tombstone_value(TombstoneReason::UserDelete, LEARNED_AT),
        )
        .unwrap();
    let body = encode_task_authority_fact_body(&cancellation(task, owner));
    let replayed = crate::sync::replay::replay_entity(
        vault,
        crate::sync::replay::ReplicatedEntity {
            id: fact,
            entity_type: ENTITY_TYPE_TASK,
            occurred: at(),
            learned_at: LEARNED_AT,
            row_version: 0,
            body: &body,
        },
        crate::sync::client::ImportTier::OwnDevice,
    );
    assert!(replayed.is_err(), "a row deleted here is not restored");
    assert_eq!(
        owner_and_cancelled(vault, task),
        Some((owner, false)),
        "an unsigned peer fact at a deleted id leaves the task readable"
    );
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
    observe_a_deleted_cancellation(vault, fact, task, owner);
    assert!(reads_suppressed(vault, task), "precondition: suppressed");
}

/// [`suppress_a_cancellation`] for a `task` that may be any row.
fn observe_a_deleted_cancellation(
    vault: &Arc<Vault>,
    fact: EntityId,
    task: EntityId,
    owner: EntityId,
) {
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
    let body = signed_cancellation(vault, fact, task, owner);
    let row = forged_update_against(&doc, |fork| {
        map_insert_bytes(
            &fork.get_map("entities"),
            &fact.to_hex(),
            &entity_blob(ENTITY_TYPE_TASK, at(), LEARNED_AT, &body),
        )
        .unwrap();
    });
    import_doc(&doc, &row).unwrap();
}

/// A window holding the owner, each task and its owner fact, and the owner
/// facts' edges, as `source` stores them.
fn window_of(source: &Vault, owner: EntityId, tasks: &[(EntityId, EntityId)]) -> LoroDoc {
    let window = LoroDoc::new();
    let mut ids = vec![owner];
    for (task, owner_fact) in tasks {
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
    let txn = source.store.env.read_txn().unwrap();
    for (_, owner_fact) in tasks {
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
    window
}

/// A fresh vault recovered from `snapshot`, holding `source`'s signed authority
/// history: the same root and the machine profiles that signed its facts, so a
/// carried fact proves itself here as it does there.
fn recovered_from(
    source: &Vault,
    snapshot: &crate::recovery::CanonicalSnapshot,
) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let recovered = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    recovered.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    recovered
        .import_signed_authority_history(&source.export_signed_authority_history().unwrap())
        .unwrap();
    recover_vault_window(
        &recovered,
        &Materializer::new(),
        dir.path().join("manifest"),
        snapshot,
        RecoveryBudget::default(),
    )
    .unwrap();
    (dir, recovered)
}

/// The explicit-tier import door refuses a fact whose id was deleted here, as
/// before, and its task reads as a refusal, as after window ingest.
/// The receiving install signs the cancellation. Its fold admits the signer,
/// so the refused replica row counts.
#[test]
fn an_explicit_tier_replay_of_a_fact_deleted_here_marks_its_task() {
    let (_dir_vault, vault) = test_vault();
    let (owner, tasks) = owned_tasks_for_fact_replay(&vault, LEARNED_AT, 2);
    let (task, other) = (tasks[0].0, tasks[1].0);
    let fact = EntityId::now();
    vault
        .apply_replayed_tombstone(
            &fact,
            &tombstone_value(TombstoneReason::UserDelete, LEARNED_AT),
        )
        .unwrap();

    let body = signed_cancellation(&vault, fact, task, owner);
    let replayed = crate::sync::replay::replay_entity(
        &vault,
        crate::sync::replay::ReplicatedEntity {
            id: fact,
            entity_type: ENTITY_TYPE_TASK,
            occurred: at(),
            learned_at: LEARNED_AT,
            row_version: 0,
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
    assert_unsigned_fact_at_a_deleted_id_leaves_task_readable(&vault, other, owner);
}

/// A restore over the vault from a checkpoint taken before the suppression
/// keeps the refusal, even of a task the live vault deleted since, which the
/// restore's authority comparison never asks about.
/// The live install signs the cancellation. Its machine profile stands in
/// the live fold that the restore carries, so the restored vault counts it.
#[test]
fn a_restore_keeps_the_refusal_of_a_task_deleted_since() {
    let (_dir_vault, vault) = test_vault();
    let (owner, tasks) = owned_tasks_for_fact_replay(&vault, LEARNED_AT, 2);
    let (task, other) = (tasks[0].0, tasks[1].0);
    let backups = tempfile::tempdir().unwrap();
    let image = backups.path().join("backup");
    vault.ensure_vault_key().expect("mint the vault data key");
    vault.snapshot_checkpoint(&image, 100).unwrap();

    suppress_a_cancellation(&vault, EntityId::now(), task, owner);
    assert_unsigned_fact_at_a_deleted_id_leaves_task_readable(&vault, other, owner);
    vault.batch().delete(&task).commit().unwrap();
    let key = vault.checkpoint_key().unwrap();
    let (restored, _report) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &key,
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

/// A canonical window snapshot carries the refusal: the capture keeps the
/// signed row it refused as a row (`refused_task_facts`), and a vault of the
/// same root recovered from it reads the task as a refusal, not as never
/// cancelled.
/// The source install signs the cancellation. Both folds admit it because
/// the recovering vault imports the source's signed authority history.
#[test]
fn a_recovered_window_keeps_the_refusal_of_a_suppressed_fact() {
    let (_dir_source, source) = test_vault();
    let (owner, tasks) = owned_tasks_for_fact_replay(&source, LEARNED_AT, 2);
    let (task, other) = (tasks[0].0, tasks[1].0);
    let fact = EntityId::now();
    suppress_a_cancellation(&source, fact, task, owner);
    assert_unsigned_fact_at_a_deleted_id_leaves_task_readable(&source, other, owner);

    let window = window_of(&source, owner, &tasks);
    map_insert_bytes(
        &window.get_map("tombstones"),
        &fact.to_hex(),
        &tombstone_value(TombstoneReason::UserHardDelete, LEARNED_AT),
    )
    .unwrap();
    let snapshot = capture_canonical_window(&source, "2026-03", &window).unwrap();
    assert!(
        snapshot.suppressed_tasks.is_empty(),
        "a carried refused row is captured as a row, not as a mark"
    );
    assert_eq!(
        snapshot.refused_task_facts.len(),
        1,
        "the artifact carries the refused row"
    );
    assert_eq!(
        (
            snapshot.refused_task_facts[0].task,
            snapshot.refused_task_facts[0].fact,
        ),
        (*task.as_bytes(), *fact.as_bytes())
    );
    let (_dir, recovered) = recovered_from(&source, &snapshot);

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

/// Capture leaves the deleted cancellation out of the live entity blobs but
/// keeps its signed body in `refused_task_facts`, without a suppression mark.
/// When the window is recovered, the task reads as a refusal.
/// The source install signs the cancellation. Its profile stands in the
/// source fold and in the history imported by the recovering vault.
#[test]
fn a_captured_window_carries_the_refusal_of_a_deleted_fact_never_admitted() {
    let (_dir_source, source) = test_vault();
    let (owner, tasks) = owned_tasks_for_fact_replay(&source, LEARNED_AT, 2);
    let (task, other) = (tasks[0].0, tasks[1].0);
    let fact = EntityId::now();
    let body = signed_cancellation(&source, fact, task, owner);
    let window = window_of(&source, owner, &tasks);
    map_insert_bytes(
        &window.get_map("entities"),
        &fact.to_hex(),
        &entity_blob(ENTITY_TYPE_TASK, at(), LEARNED_AT, &body),
    )
    .unwrap();
    map_insert_bytes(
        &window.get_map("tombstones"),
        &fact.to_hex(),
        &tombstone_value(TombstoneReason::UserHardDelete, LEARNED_AT),
    )
    .unwrap();
    assert_unsigned_fact_at_a_deleted_id_leaves_task_readable(&source, other, owner);

    let snapshot = capture_canonical_window(&source, "2026-03", &window).unwrap();
    assert!(
        reads_suppressed(&source, task),
        "the capturing vault's task reads as a refusal"
    );
    assert!(
        snapshot.suppressed_tasks.is_empty(),
        "a carried refused row is captured as a row, not as a mark"
    );
    assert_eq!(
        snapshot.refused_task_facts,
        vec![CanonicalRefusedTaskFact {
            task: *task.as_bytes(),
            fact: *fact.as_bytes(),
            body,
        }],
        "the artifact carries the signed refused row"
    );
    assert!(
        snapshot
            .entity_blobs
            .iter()
            .all(|row| row.id != *fact.as_bytes()),
        "the deleted cancellation is not a live entity blob"
    );
    let (_dir, recovered) = recovered_from(&source, &snapshot);
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

/// A forged fact may name any row as its task. Its refusal, kept under a row
/// that is no TASK, never reaches the artifact, so the window still captures
/// and recovers.
/// The source install signs the cancellation, so its fold can prove the
/// carrier. Capture must still exclude the refusal because the subject is a PERSON.
#[test]
fn a_forged_fact_naming_a_row_that_is_no_task_never_blocks_a_capture() {
    let (_dir_source, source) = test_vault();
    let (owner, tasks) = owned_tasks_for_fact_replay(&source, LEARNED_AT, 2);
    observe_a_deleted_cancellation(&source, EntityId::now(), owner, owner);
    {
        let txn = source.store.env.read_txn().unwrap();
        assert_eq!(
            crate::task_authority::refused_facts_in(&source.store, &txn, &owner)
                .unwrap()
                .len(),
            1,
            "precondition: the forged fact is kept refused under the owner's PERSON row"
        );
    }
    assert_unsigned_fact_at_a_deleted_id_leaves_task_readable(&source, tasks[0].0, owner);

    let snapshot =
        capture_canonical_window(&source, "2026-03", &window_of(&source, owner, &tasks)).unwrap();
    assert!(snapshot.suppressed_tasks.is_empty());
    assert!(
        snapshot.refused_task_facts.is_empty(),
        "a refused fact under no TASK row never reaches the artifact"
    );
    let (_dir, recovered) = recovered_from(&source, &snapshot);
    assert_eq!(
        owner_and_cancelled(&recovered, tasks[0].0),
        Some((owner, false)),
        "the recovered window's tasks still read"
    );
}

/// A fact that lands after the delete facade's read-only precheck meets the
/// refusal again in the transaction that would erase it.
/// The receiving install signs the incoming row and its fold admits that
/// signer. The race only needs the fact row, not its link to the task.
#[test]
fn a_fact_that_arrives_after_a_delete_precheck_is_never_erased() {
    let (_dir_vault, vault) = test_vault();
    let (owner, tasks) = owned_tasks_for_fact_replay(&vault, LEARNED_AT, 2);
    let (task, other) = (tasks[0].0, tasks[1].0);
    let fact = EntityId::now();
    let body = signed_cancellation(&vault, fact, task, owner);
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
                &entity_blob(ENTITY_TYPE_TASK, at(), LEARNED_AT, &body),
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
    assert_unsigned_fact_at_a_deleted_id_leaves_task_readable(&vault, other, owner);
}

/// The local paths that remove a window carrier because its id was deleted
/// here (Engine ruling, round 7) mark the task of an authority fact
/// the carrier holds that this vault never admitted.
mod removed_carriers {
    use super::*;
    use crate::sync::loro_support::{doc_version_vector, export_snapshot};
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window::{
        CarrierRemoval, arm_fail_after_carrier_mark, disarm_fail_after_carrier_mark,
    };
    use crate::sync::window_rows::{PENDING_TOMBSTONE, WindowEntityHexKey};

    /// A window document whose entities map holds `fact`, a cancellation of
    /// `task` signed by `vault`'s own install, that no observer ever ingested.
    fn window_carrying(
        vault: &Vault,
        window: &str,
        fact: EntityId,
        task: EntityId,
        owner: EntityId,
    ) -> LoroDoc {
        let doc = create_window_doc("local", &WindowKey::new(window));
        map_insert_bytes(
            &doc.get_map("entities"),
            &fact.to_hex(),
            &entity_blob(
                ENTITY_TYPE_TASK,
                at(),
                LEARNED_AT,
                &signed_cancellation(vault, fact, task, owner),
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
                    false,
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
        assert_unsigned_fact_at_a_deleted_id_leaves_task_readable(vault, tasks[1].0, owner);
    }

    /// The receiving install signs the window's cancellation. Its fold admits
    /// the signer even though the pending replay never admits the fact row.
    #[test]
    fn a_replayed_pending_tombstone_marks_an_unadmitted_fact() {
        let (_dir_vault, vault) = test_vault();
        let (owner, tasks) = owned_tasks_for_fact_replay(&vault, LEARNED_AT, 2);
        let fact = EntityId::now();
        let doc = window_carrying(&vault, "2026-03", fact, tasks[0].0, owner);
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

    /// The receiving install signs the persisted cancellation. Its fold
    /// admits that signer when the reassertion keeps the refused row.
    #[test]
    fn a_reasserted_tombstone_marks_an_unadmitted_fact() {
        let (_dir_vault, vault) = test_vault();
        let (owner, tasks) = owned_tasks_for_fact_replay(&vault, LEARNED_AT, 2);
        let fact = EntityId::now();
        persist(
            &vault,
            "2026-03",
            &window_carrying(&vault, "2026-03", fact, tasks[0].0, owner),
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

    /// The receiving install signs the cancellation. Its fold admits the
    /// signer, so the task refuses after the scrub removes the row.
    #[test]
    fn the_withdrawn_delete_scrub_marks_an_unadmitted_fact() {
        let (_dir_vault, vault) = test_vault();
        let (owner, tasks) = owned_tasks_for_fact_replay(&vault, LEARNED_AT, 2);
        let fact = EntityId::now();
        vault
            .apply_replayed_tombstone(
                &fact,
                &tombstone_value(TombstoneReason::UserDelete, LEARNED_AT),
            )
            .unwrap();
        let doc = window_carrying(&vault, "2026-03", fact, tasks[0].0, owner);

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

    /// F24 round 9 (Astra r8 R8-2): the local-claim scrub reads the stored
    /// row at each id, so a peer's carrier of an unadmitted fact at the id of
    /// a CLAIM soft-deleted here goes with the CLAIM's shell. The scrub marks
    /// the fact's task first, and the refusal outlives the scrubbed persist.
    /// The receiving install signs the cancellation, and its fold admits
    /// that signer even though the local row at the fact id is a CLAIM shell.
    #[test]
    fn the_local_claim_scrub_marks_an_unadmitted_fact_at_a_deleted_claim_id() {
        let (_dir_vault, vault) = test_vault();
        let (owner, tasks) = owned_tasks_for_fact_replay(&vault, LEARNED_AT, 2);
        let fact = EntityId::now();
        deleted_claim_shell(&vault, fact, owner);
        let doc = window_carrying(&vault, "2026-03", fact, tasks[0].0, owner);

        let snapshot = crate::sync::window::export_scrubbed_window_snapshot(
            &vault,
            &WindowKey::new("2026-03"),
            &doc,
        )
        .unwrap();
        assert!(!carries(&doc, fact), "the scrub removed the carrier");
        let exported = LoroDoc::new();
        exported.import(&snapshot).unwrap();
        assert!(!carries(&exported, fact), "the export ships no carrier");
        assert_marked_and_control(&vault, owner, &tasks);
    }

    /// The publishing install signs the cancellation, and its fold admits
    /// the signer even though the cancellation sits only in the window.
    #[test]
    fn a_local_delete_publication_marks_an_unadmitted_fact() {
        let (_dir_vault, vault) = test_vault();
        let (owner, tasks) = owned_tasks_for_fact_replay(&vault, LEARNED_AT, 2);
        let fact = EntityId::now();
        headerless_residue(&vault, fact);
        let window =
            crate::deletion::window_label_from_timestamp(vault.store.clock.now_recorded_at());
        persist(
            &vault,
            &window,
            &window_carrying(&vault, &window, fact, tasks[0].0, owner),
        );

        vault.delete_entity(&fact).unwrap();
        assert_marked_and_control(&vault, owner, &tasks);
    }

    /// A CLAIM at `fact` about `subject`, soft-deleted here: its 33-byte
    /// shell and deletion fence are the stored row at that id.
    fn deleted_claim_shell(vault: &Vault, fact: EntityId, subject: EntityId) {
        let mut body = crate::claim::ClaimBody::new(
            "sync.egress_control",
            crate::claim::ClaimSubject::Entity(subject),
            rmpv::Value::from("ordinary claim"),
            1.0,
            ClaimApprovalStatus::Proposed,
            crate::claim::ClaimLifecycleStatus::Active,
        )
        .unwrap();
        body.source = Some(ClaimSource::Observed);
        vault.put_claim(&fact, &body, at(), LEARNED_AT).unwrap();
        vault.delete_entity(&fact).unwrap();
        let txn = vault.store.env.read_txn().unwrap();
        let shell = vault.store.entities.get(&txn, fact.as_bytes()).unwrap();
        assert_eq!(
            shell.as_deref().map(|raw| (raw.len(), raw[0])),
            Some((
                ENTITY_METADATA_HEADER_LEN,
                crate::registry::ENTITY_TYPE_CLAIM
            )),
            "precondition: the stored row is the CLAIM's shell"
        );
    }

    /// Index residue of a row whose header is gone is local delete scope, so
    /// a delete of `fact` publishes a tombstone without a header to read.
    fn headerless_residue(vault: &Vault, fact: EntityId) {
        vault
            .put_entity(&fact, ENTITY_TYPE_TASK, at(), LEARNED_AT, &task_body())
            .unwrap();
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

    /// A signed cancellation put into a live window in a commit Observer B skips.
    /// Observer A persists it, but the vault never admits its fact row.
    fn carry_unadmitted(
        vault: &Vault,
        doc: &LoroDoc,
        fact: EntityId,
        task: EntityId,
        owner: EntityId,
    ) {
        map_insert_bytes(
            &doc.get_map("entities"),
            &fact.to_hex(),
            &entity_blob(
                ENTITY_TYPE_TASK,
                at(),
                LEARNED_AT,
                &signed_cancellation(vault, fact, task, owner),
            ),
        )
        .unwrap();
        doc.commit_with(loro::CommitOptions::new().origin(crate::sync::bridge::BRIDGE_ORIGIN));
    }

    fn carries(doc: &LoroDoc, fact: EntityId) -> bool {
        doc.get_map("entities").get(&fact.to_hex()).is_some()
    }

    fn persisted_carries(vault: &Vault, key: &WindowKey, fact: EntityId) -> bool {
        carries(
            &crate::sync::window::load_window_from_state(vault, "local", key).unwrap(),
            fact,
        )
    }

    fn live_manager(vault: &Arc<Vault>) -> Arc<crate::sync::manager::WindowManager> {
        Arc::new(crate::sync::manager::WindowManager::new(
            vault.clone(),
            Arc::new(Materializer::new()),
            "local",
        ))
    }

    /// A live window carries a fact this vault never admitted, and the local
    /// delete of its id fails after the live doc commit. The mark committed
    /// before the doc was touched, so the later persist that makes the
    /// removal durable leaves the task reading as a refusal.
    /// This install signs the window's cancellation. Its fold admits the
    /// signer, so the task refuses even when publication has to retry.
    #[test]
    fn a_failed_live_publication_keeps_its_mark_through_a_later_persist() {
        let (_dir_vault, vault) = test_vault();
        let (owner, tasks) = owned_tasks_for_fact_replay(&vault, LEARNED_AT, 2);
        let fact = EntityId::now();
        let key = WindowKey::new(crate::deletion::window_label_from_timestamp(
            vault.store.clock.now_recorded_at(),
        ));
        let manager = live_manager(&vault);
        let window = manager.open_window(&key).unwrap();
        headerless_residue(&vault, fact);
        carry_unadmitted(&vault, &window.doc, fact, tasks[0].0, owner);

        crate::deletion::arm_fail_live_tombstone_persist();
        vault
            .delete_entity(&fact)
            .expect_err("the publish txn fails after the live doc commit");
        assert!(
            !carries(&window.doc, fact),
            "the live doc keeps its removal"
        );
        window.persist_state(&vault).unwrap();
        assert!(
            !persisted_carries(&vault, &key, fact),
            "the persist made the removal durable"
        );
        assert_marked_and_control(&vault, owner, &tasks);
    }

    /// Runs `path`, live or not, over a carrier of `fact` (a cancellation of
    /// `task`) with a failure armed right after the path's marks commit.
    /// Returns whether the path failed there, and whether the carrier was
    /// still in place when it did.
    fn fail_after_the_mark(
        vault: &Arc<Vault>,
        path: CarrierRemoval,
        live: bool,
        fact: EntityId,
        task: EntityId,
        owner: EntityId,
    ) -> (bool, bool) {
        let key = WindowKey::new("2026-03");
        match path {
            CarrierRemoval::PendingTombstoneReplay => {
                let doc = window_carrying(vault, "2026-03", fact, task, owner);
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
                arm_fail_after_carrier_mark(path);
                let failed =
                    crate::sync::window::replay_pending_tombstones(vault, &doc, &key).is_err();
                (failed, carries(&doc, fact))
            }
            CarrierRemoval::ReassertDrain => {
                vault
                    .apply_replayed_tombstone(
                        &fact,
                        &tombstone_value(TombstoneReason::UserHardDelete, LEARNED_AT),
                    )
                    .unwrap();
                assert!(
                    crate::sync::quarantine::enqueue_tombstone_reassert_marker(
                        vault, "2026-03", &fact
                    )
                    .unwrap()
                );
                let manager = live_manager(vault);
                let window = live.then(|| manager.open_window(&key).unwrap());
                match &window {
                    Some(window) => carry_unadmitted(vault, &window.doc, fact, task, owner),
                    None => persist(
                        vault,
                        "2026-03",
                        &window_carrying(vault, "2026-03", fact, task, owner),
                    ),
                }
                arm_fail_after_carrier_mark(path);
                let failed = crate::sync::quarantine::drain_reassert_markers_for_window(
                    vault, "local", &manager, &key,
                )
                .is_err();
                let carried = match &window {
                    Some(window) => carries(&window.doc, fact),
                    None => persisted_carries(vault, &key, fact),
                };
                (failed, carried)
            }
            CarrierRemoval::WithdrawnDeleteScrub => {
                vault
                    .apply_replayed_tombstone(
                        &fact,
                        &tombstone_value(TombstoneReason::UserDelete, LEARNED_AT),
                    )
                    .unwrap();
                let doc = window_carrying(vault, "2026-03", fact, task, owner);
                arm_fail_after_carrier_mark(path);
                let failed =
                    crate::sync::window::export_scrubbed_window_snapshot(vault, &key, &doc)
                        .is_err();
                (failed, carries(&doc, fact))
            }
            CarrierRemoval::LocalPublication => {
                let key = WindowKey::new(crate::deletion::window_label_from_timestamp(
                    vault.store.clock.now_recorded_at(),
                ));
                let manager = live_manager(vault);
                let window = live.then(|| manager.open_window(&key).unwrap());
                headerless_residue(vault, fact);
                match &window {
                    Some(window) => carry_unadmitted(vault, &window.doc, fact, task, owner),
                    None => persist(
                        vault,
                        key.as_str(),
                        &window_carrying(vault, key.as_str(), fact, task, owner),
                    ),
                }
                arm_fail_after_carrier_mark(path);
                let failed = vault.delete_entity(&fact).is_err();
                let carried = match &window {
                    Some(window) => carries(&window.doc, fact),
                    None => persisted_carries(vault, &key, fact),
                };
                (failed, carried)
            }
            CarrierRemoval::HardEraseSweep => {
                persist(
                    vault,
                    "2026-03",
                    &window_carrying(vault, "2026-03", fact, task, owner),
                );
                arm_fail_after_carrier_mark(path);
                let failed = crate::sweep::compact_window_for_test(
                    vault,
                    &key,
                    &std::collections::BTreeSet::from([fact]),
                )
                .is_err();
                (failed, persisted_carries(vault, &key, fact))
            }
            CarrierRemoval::LocalClaimScrub => {
                deleted_claim_shell(vault, fact, owner);
                let doc = window_carrying(vault, "2026-03", fact, task, owner);
                arm_fail_after_carrier_mark(path);
                let failed =
                    crate::sync::window::export_scrubbed_window_snapshot(vault, &key, &doc)
                        .is_err();
                (failed, carries(&doc, fact))
            }
            CarrierRemoval::CanonicalCapture => {
                let doc = LoroDoc::new();
                map_insert_bytes(
                    &doc.get_map("entities"),
                    &fact.to_hex(),
                    &entity_blob(
                        ENTITY_TYPE_TASK,
                        at(),
                        LEARNED_AT,
                        &signed_cancellation(vault, fact, task, owner),
                    ),
                )
                .unwrap();
                map_insert_bytes(
                    &doc.get_map("tombstones"),
                    &fact.to_hex(),
                    &tombstone_value(TombstoneReason::UserHardDelete, LEARNED_AT),
                )
                .unwrap();
                arm_fail_after_carrier_mark(path);
                let failed = capture_canonical_window(vault, "2026-03", &doc).is_err();
                (failed, carries(&doc, fact))
            }
        }
    }

    /// The order every local removal of a deleted id's carrier keeps, over
    /// the code's own list of them, each branch that has a live doc both
    /// ways: the mark commits before the path touches the doc. A path that
    /// fails right after its mark fails with the carrier still in place and
    /// leaves the task reading as a refusal, never as open.
    /// The receiving install signs each cancellation. Its fold admits the
    /// signer, so keeping the refused row is enough to make the read refuse.
    #[test]
    fn every_carrier_removal_marks_its_task_before_it_touches_the_doc() {
        let mut failures = Vec::new();
        for path in CarrierRemoval::ALL {
            let branches: &[bool] = match path {
                CarrierRemoval::ReassertDrain | CarrierRemoval::LocalPublication => &[false, true],
                CarrierRemoval::PendingTombstoneReplay
                | CarrierRemoval::WithdrawnDeleteScrub
                | CarrierRemoval::LocalClaimScrub
                | CarrierRemoval::HardEraseSweep
                | CarrierRemoval::CanonicalCapture => &[false],
            };
            for &live in branches {
                let (_dir_vault, vault) = test_vault();
                let (owner, tasks) = owned_tasks_for_fact_replay(&vault, LEARNED_AT, 2);
                assert_unsigned_fact_at_a_deleted_id_leaves_task_readable(
                    &vault, tasks[1].0, owner,
                );
                let (failed, carried) =
                    fail_after_the_mark(&vault, path, live, EntityId::now(), tasks[0].0, owner);
                let failed = failed && !disarm_fail_after_carrier_mark();
                let suppressed = reads_suppressed(&vault, tasks[0].0);
                if !(failed && carried && suppressed) {
                    failures.push(format!(
                        "{path:?} live={live}: failed after its mark {failed}, carrier still in \
                         place {carried}, task reads as a refusal {suppressed}"
                    ));
                }
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }
}
