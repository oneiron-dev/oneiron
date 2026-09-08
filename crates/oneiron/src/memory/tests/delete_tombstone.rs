//! Safe-delete receipts, crash recovery, tombstone publish boundary, and soft-erase edge cases.

#[cfg(not(feature = "sync"))]
use super::support::*;
use super::*;

#[test]
fn safe_delete_requires_named_reason_and_returns_receipt() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xB5);
    let facade = facade_for(&vault, actor);

    let soft_target = put_person(&vault, 0xB6);
    let receipt = facade
        .safe_delete(&soft_target.to_hex(), SafeDeleteReason::UserDelete)
        .expect("user delete");
    assert!(receipt.existed);
    assert_eq!(receipt.reason, "user_delete");
    assert!(
        receipt.receipt_ref.is_none(),
        "tombstone path writes no receipt entity"
    );

    let hard_target = put_person(&vault, 0xB7);
    let receipt = facade
        .safe_delete(&hard_target.to_hex(), SafeDeleteReason::UserHardDelete)
        .expect("hard delete");
    assert!(receipt.existed);
    let receipt_ref = receipt
        .receipt_ref
        .expect("hard delete writes a redaction receipt");
    assert!(receipt_ref.starts_with("redaction:"));
    let receipt_id = EntityId::from_hex(
        receipt_ref
            .strip_prefix("redaction:")
            .expect("redaction receipt prefix"),
    )
    .expect("receipt id");
    let raw = vault
        .get_raw(&receipt_id)
        .expect("read receipt")
        .expect("receipt exists");
    let audit = crate::deletion::decode_redaction_audit_receipt(
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )
    .expect("decode redaction audit receipt");
    let request_id = audit.request_id.replace('-', "");
    let actor_hex = actor.to_hex();
    let decision = vault
        .gate_decisions(50)
        .expect("gate decisions")
        .into_iter()
        .find(|decision| decision.decision_id.to_hex() == request_id)
        .expect("deletion decision keyed by redaction request id");
    assert_eq!(decision.outcome, "allow");
    assert_eq!(decision.content_kind, "deletion");
    assert_eq!(decision.actor_class, "human");
    assert_eq!(decision.actor_ref.as_deref(), Some(actor_hex.as_str()));
    assert_eq!(decision.reason_codes, ["gate.allow.owner_delete"]);
    assert!(
        decision.claim_id.is_none(),
        "deletion authority must remain distinct from claim receipts"
    );
    assert!(
        facade
            .get_entity(&hard_target.to_hex())
            .expect("read back")
            .is_none(),
        "hard-deleted entity is purged"
    );

    let gdpr_target = put_person(&vault, 0xB8);
    let receipt = facade
        .safe_delete(&gdpr_target.to_hex(), SafeDeleteReason::GdprDelete)
        .expect("gdpr delete");
    assert!(receipt.receipt_ref.is_some());
}

/// DA-C/DA-E/DA-F: a crash after tombstone-first TXN1 leaves the subject
/// untouched until startup recovery executes the purge; TXN1's request-keyed
/// recovery sidecar lets that TXN3 append the authority record exactly once.
#[cfg(feature = "sync")]
#[test]
fn safe_delete_txn1_crash_recovers_purge_with_one_authority_record() {
    use std::sync::Arc;

    use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
    use crate::sync::{WindowKey, WindowManager, bridge::Materializer};

    let dir = tempfile::tempdir().expect("tempdir");
    let (victim, gate_decision_id) = {
        let vault = Arc::new(
            crate::Vault::open(dir.path(), VaultConfig::default()).expect("open first vault"),
        );
        let actor = put_person(&vault, 0xBC);
        let victim = put_person(&vault, 0xBD);
        // Keep the deletion window live so TXN1 covers the observer-A
        // suppression path as well as the transient document path.
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            Arc::new(Materializer::new()),
            "facade-crash-live-window",
        ));
        manager
            .open_window(&WindowKey::from_timestamp(1))
            .expect("open live deletion window");
        let facade = facade_for(&vault, actor);

        crate::deletion::arm_fail_after_tombstone_before_purge();
        facade
            .safe_delete(&victim.to_hex(), SafeDeleteReason::UserHardDelete)
            .expect_err("test crash after durable TXN1");

        assert!(
            vault.get_raw(&victim).expect("read victim").is_some(),
            "TXN1 tombstone must precede, not perform, the active-store purge"
        );
        let deletion = vault
            .entity_deletion_metadata(&victim, 1)
            .expect("read tombstone metadata")
            .expect("TXN1 persisted tombstone metadata");
        let request_id = uuid::Uuid::parse_str(
            deletion
                .request_id
                .as_deref()
                .expect("tombstone request id"),
        )
        .expect("request id UUID")
        .into_bytes();
        let gate_decision_id = crate::store::GateDecisionId::from_bytes(request_id);
        let rtxn = vault.store.env.read_txn().expect("read transaction");
        let staged = vault
            .store
            .pending_deletion_gate_decision_in_txn(&rtxn, gate_decision_id)
            .expect("read TXN1 authority sidecar")
            .expect("TXN1 staged request-keyed authority data");
        assert_eq!(staged.content_kind, "deletion");
        drop(rtxn);
        let unrelated_target = EntityId::from_bytes([0xBE; 16]).expect("unrelated target id");
        let consumed = vault
            .with_write_txn(|wtxn| {
                vault.store.append_pending_deletion_gate_decision_in_txn(
                    wtxn,
                    gate_decision_id,
                    unrelated_target.as_bytes(),
                    crate::deletion::TombstoneReason::UserHardDelete.wire_byte(),
                )
            })
            .expect("mismatched tombstone must not consume sidecar");
        assert!(
            consumed.is_none(),
            "a different target may not consume this request-keyed sidecar"
        );
        assert!(
            vault
                .gate_decisions(50)
                .expect("gate decisions")
                .iter()
                .all(|decision| decision.decision_id != gate_decision_id),
            "TXN1 must not append the final GateDecisionRecord before TXN3"
        );
        assert_eq!(
            vault
                .count_entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
                .expect("receipt count"),
            0,
            "the execution receipt belongs to the later purge transaction"
        );
        drop(manager);
        (victim, gate_decision_id)
    };

    let recovered = Arc::new(
        crate::Vault::open(dir.path(), VaultConfig::default()).expect("reopen after crash"),
    );
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&recovered),
        Arc::new(Materializer::new()),
        "facade-crash-recovery",
    ));
    manager
        .open_window(&WindowKey::from_timestamp(1))
        .expect("startup recovery drives the pending purge");
    assert!(
        recovered
            .get_raw(&victim)
            .expect("read recovered victim")
            .is_none(),
        "the TXN1 tombstone must drive TXN3 purge completion on recovery"
    );
    assert_eq!(
        recovered
            .gate_decisions(50)
            .expect("gate decisions after recovery")
            .iter()
            .filter(|decision| decision.decision_id == gate_decision_id)
            .count(),
        1,
        "recovery must not multiply the request-keyed authority record"
    );
    assert_eq!(
        recovered
            .count_entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .expect("receipt count after recovery"),
        1,
        "recovery performs the one delayed execution attestation"
    );

    drop(manager);
    drop(recovered);
    let recovered_again = Arc::new(
        crate::Vault::open(dir.path(), VaultConfig::default()).expect("reopen idempotently"),
    );
    let manager_again = Arc::new(WindowManager::new(
        Arc::clone(&recovered_again),
        Arc::new(Materializer::new()),
        "facade-crash-recovery",
    ));
    manager_again
        .open_window(&WindowKey::from_timestamp(1))
        .expect("second recovery is idempotent");
    assert_eq!(
        recovered_again
            .gate_decisions(50)
            .expect("gate decisions after second recovery")
            .iter()
            .filter(|decision| decision.decision_id == gate_decision_id)
            .count(),
        1,
        "double recovery must preserve exactly once authority evidence"
    );
    assert_eq!(
        recovered_again
            .count_entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .expect("receipt count after second recovery"),
        1,
        "double recovery must not mint a second execution attestation"
    );
}

/// F1: suppressing Observer A for the authority-atomic tombstone commit must
/// not suppress the steady-state route to an already-connected peer.
#[cfg(feature = "sync")]
#[test]
fn safe_delete_live_tombstone_reaches_attached_outbound_channel() {
    use std::sync::Arc;

    use crate::sync::{WindowKey, WindowManager, bridge::Materializer};

    let dir = tempfile::tempdir().expect("tempdir");
    let vault =
        Arc::new(crate::Vault::open(dir.path(), VaultConfig::default()).expect("open vault"));
    let actor = put_person(&vault, 0xC1);
    let victim = put_person(&vault, 0xC2);
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "facade-live-route",
    ));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    manager.outbound().attach(tx);
    let window = manager
        .open_window(&WindowKey::from_timestamp(1))
        .expect("open deletion window");
    let receiver_base = crate::sync::loro_support::export_snapshot(&window.doc)
        .expect("receiver starts from the sender's pre-delete state");

    facade_for(&vault, actor)
        .safe_delete(&victim.to_hex(), SafeDeleteReason::UserHardDelete)
        .expect("safe delete");

    let update = rx
        .try_recv()
        .expect("connected peer receives tombstone without reconnect");
    assert_eq!(update.window_key, WindowKey::from_timestamp(1).as_str());
    let remote = crate::sync::schema::create_window_doc("remote", &WindowKey::from_timestamp(1));
    remote
        .import(&receiver_base)
        .expect("import receiver base state");
    remote
        .import(&update.update_bytes)
        .expect("live-routed update imports");
    assert!(
        remote.get_map("tombstones").get(&victim.to_hex()).is_some(),
        "the live route carries the deletion tombstone"
    );
}

/// F3: a live-doc commit that outlives a failed persistence transaction is
/// already protected by a durable authority-required marker + complete
/// sidecar. If the sidecar is missing, recovery refuses the purge and leaves
/// its durable retry marker;
/// ordinary remote tombstones remain a legitimate sidecar-free control.
#[cfg(feature = "sync")]
#[test]
fn live_tombstone_persist_failure_requires_complete_authority_sidecar() {
    use std::sync::Arc;

    use loro::{LoroValue, ValueOrContainer};

    use crate::sync::{WindowKey, WindowManager, bridge::Materializer};

    let dir = tempfile::tempdir().expect("tempdir");
    let (victim, decision_id) = {
        let vault = Arc::new(
            crate::Vault::open(dir.path(), VaultConfig::default()).expect("open first vault"),
        );
        let actor = put_person(&vault, 0xC3);
        let victim = put_person(&vault, 0xC4);
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            Arc::new(Materializer::new()),
            "facade-live-txn1-failure",
        ));
        let window = manager
            .open_window(&WindowKey::from_timestamp(1))
            .expect("open live deletion window");

        crate::deletion::arm_fail_live_tombstone_persist();
        facade_for(&vault, actor)
            .safe_delete(&victim.to_hex(), SafeDeleteReason::UserHardDelete)
            .expect_err("live commit survives a failed persistence transaction");
        assert!(
            vault.get_raw(&victim).expect("read victim").is_some(),
            "failed TXN1 must not reach the purge"
        );
        let raw = match window.doc.get_map("tombstones").get(&victim.to_hex()) {
            Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => bytes.to_vec(),
            other => panic!("committed live tombstone missing: {other:?}"),
        };
        let request_id: [u8; 16] = raw[9..25].try_into().expect("request id bytes");
        let decision_id = crate::store::GateDecisionId::from_bytes(request_id);
        let rtxn = vault.store.env.read_txn().expect("read transaction");
        assert!(
            vault
                .store
                .pending_deletion_gate_decision_in_txn(&rtxn, decision_id)
                .expect("read staged sidecar")
                .is_some(),
            "authority sidecar is durable before the live tombstone commit"
        );
        drop(rtxn);

        // Model the orphan live commit being persisted later by an ordinary
        // full-state flush, then remove only the sidecar while retaining the
        // separate authority-required marker.
        window
            .persist_state(&vault)
            .expect("persist orphan live commit");
        vault
            .with_write_txn(|wtxn| {
                vault
                    .store
                    .remove_pending_deletion_gate_sidecar_for_test(wtxn, decision_id)
            })
            .expect("simulate lost authority sidecar");
        drop(window);
        drop(manager);
        (victim, decision_id)
    };

    let recovered = Arc::new(
        crate::Vault::open(dir.path(), VaultConfig::default()).expect("reopen after failed TXN1"),
    );
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&recovered),
        Arc::new(Materializer::new()),
        "facade-live-txn1-recovery",
    ));
    manager
        .open_window(&WindowKey::from_timestamp(1))
        .expect("recovery keeps the window available while marking the failed purge for retry");
    assert!(
        recovered.get_raw(&victim).expect("read victim").is_some(),
        "failed authority recovery rolls the purge back"
    );
    assert!(
        crate::sync::pending_remat_windows(&recovered)
            .expect("pending recovery markers")
            .contains(&WindowKey::from_timestamp(1).as_str().to_owned()),
        "refused purge remains durably queued for fail-closed retry"
    );
    assert!(
        recovered
            .gate_decisions(50)
            .expect("gate decisions")
            .iter()
            .all(|decision| decision.decision_id != decision_id),
        "no authority record is fabricated from an incomplete sidecar"
    );

    // Legitimate remote control: no local required marker exists, so the
    // same replay boundary accepts and purges a peer-authored hard tombstone.
    let remote_victim = put_person(&recovered, 0xC5);
    let remote = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserHardDelete,
        deleted_at: 42,
        request_id: [0xD5; 16],
    };
    recovered
        .apply_replayed_tombstone_for_sync(&remote_victim, &remote.encode())
        .expect("sidecar-free remote tombstone remains valid");
    assert!(
        recovered
            .get_raw(&remote_victim)
            .expect("read remote victim")
            .is_none(),
        "legitimate remote hard tombstone purges normally"
    );
}

/// fix-leg 9 P1: on the NON-PUBLISHING path the soft erase and the `pt:`
/// propagation intent are ONE transaction.
///
/// fix-8 put the conditional re-fold in the gdpr/policy soft-erase txn, and that
/// txn commits — but the replayable `pt:` marker was only written later, in the
/// purge txn. Between those two commits the erasure had a shape no compliance
/// path may have: the body was scrubbed locally and irreversibly, every peer
/// still held the full data, and NO durable record of the intent to propagate
/// the delete existed. A crash there — or any error on the purge path, which is
/// the ordinary failure this reaches through — silently downgraded a GDPR /
/// policy erasure to a local-only scrub. Nothing would ever heal it: a retry
/// captures the bodiless 25 B shell, and the sync-enabled boot that would have
/// replayed the deletion finds no marker to replay.
///
/// Driven by failing the marker write itself, which is the strongest available
/// statement of atomicity: whatever the transaction had done up to that point
/// must vanish with it. Both reasons that take the soft-erase phase, because
/// they are one arm and a future edit could split them.
///
/// MUTATION PROBE: move the `pt:` write back to the purge txn (drop it from the
/// scrub txn) and this test fails — the injection never fires, the delete
/// SUCCEEDS, and `expect_err` panics.
#[cfg(not(feature = "sync"))]
#[test]
fn a_failed_first_txn_pending_tombstone_rolls_back_the_soft_erase() {
    for reason in [SafeDeleteReason::GdprDelete, SafeDeleteReason::PolicyDelete] {
        let case = format!("{reason:?}");

        // Control, on its OWN vault: unarmed, the same delete completes and
        // leaves the marker. It runs separately so the armed leg's
        // "no artifacts at all" assertion stays absolute — a control delete in
        // the same vault would leave a legitimate receipt and pt: row.
        let (control_dir, control_vault) = open_nonpublishing_delete_vault();
        let control_owner = put_person(&control_vault, 0x50);
        let control_subject = put_person(&control_vault, 0x51);
        root_vault_binding(&control_vault, 0x52, control_owner, "human");
        facade_for(&control_vault, control_owner)
            .safe_delete(&control_subject.to_hex(), reason)
            .unwrap_or_else(|err| panic!("{case} control: {}: {}", err.code, err.message));
        assert!(
            first_txn_pending_tombstone_exists(&control_vault, &control_subject),
            "{case} control: a completed sync-OFF erasure keeps its replayable \
             pt: propagation intent, written in the scrub txn"
        );
        drop(control_dir);

        let (_dir, vault) = open_nonpublishing_delete_vault();
        let owner = put_person(&vault, 0x53);
        let subject = put_person(&vault, 0x54);
        // The soft erase deletes the vector row too, so a surviving vector is
        // independent evidence that the scrub itself rolled back — not merely
        // that the entity body was left alone.
        let vector = [0.5_f32, 0.6, 0.7, 0.8];
        vault
            .put_vector(&subject, &vector)
            .expect("put subject vector");
        root_vault_binding(&vault, 0x55, owner, "human");

        crate::deletion::arm_fail_first_txn_pending_tombstone();
        let err = facade_for(&vault, owner)
            .safe_delete(&subject.to_hex(), reason)
            .expect_err(
                "the pt: marker is written INSIDE the re-verified soft-erase \
                 txn, so failing it must fail the whole delete",
            );
        assert_eq!(err.code, MEMORY_CODE_INTERNAL, "{case}");

        // The scrub rolled back with the marker: body whole, vector whole.
        assert_eq!(
            vault
                .get_raw(&subject)
                .expect("get raw")
                .expect("subject row survives")
                .len(),
            crate::batch::ENTITY_METADATA_HEADER_LEN + b"facade person".len(),
            "{case}: a 25 B shell would mean the scrub committed without the \
             marker — the exact split fix-leg 9 closes"
        );
        assert_eq!(
            vault.get_vector(&subject).expect("get vector"),
            Some(
                vector
                    .iter()
                    .map(|v| half::f16::from_f32(*v).to_f32())
                    .collect::<Vec<_>>()
            ),
            "{case}: the soft erase deletes the vector row, so it must return"
        );
        assert_no_local_delete_artifacts(&vault, &subject, &case);
    }
}

/// fix-leg 9, the `existed` half of the guard: a soft erase that found NOTHING
/// still writes no `pt:`.
///
/// Moving the marker into the scrub txn put a `pt:` write on a path that had
/// none, so it inherits ONE-1149's rule and must be pinned there: a delete whose
/// scope raced away between the header read and the scrub txn erased nothing,
/// and a `pt:` marker is a claim that this delete has data to propagate away.
/// Emitting one would replay a deletion for an id this call never touched.
/// `assert_no_erasure_audit_artifacts` pins the same law for the purge txn's
/// marker; nothing covered the new site, because the pre-existing headerful
/// raced test uses `user_hard_delete`, which has no soft-erase phase at all.
///
/// MUTATION PROBE: drop `existed &&` from the scrub txn's marker guard and this
/// test fails — the raced delete reports `missing()` while leaving a replayable
/// `pt:` behind.
#[cfg(not(feature = "sync"))]
#[test]
fn a_soft_erase_that_erased_nothing_writes_no_pending_tombstone() {
    for reason in [DeleteReason::GdprDelete, DeleteReason::PolicyDelete] {
        let case = format!("{reason:?}");
        let learned_at = 1_772_000_000;

        for attempt in 0..3 {
            let (_dir, vault) = open_nonpublishing_delete_vault();
            let id = EntityId::from_bytes([0x56; 16]).expect("victim id");
            vault
                .batch()
                .put(
                    &id,
                    ENTITY_TYPE_PERSON,
                    TimeRange {
                        start: learned_at,
                        end: learned_at,
                    },
                    learned_at,
                    b"raced-away-before-the-scrub",
                )
                .commit()
                .expect("put victim");

            // The eraser stages the full-scope erase in a HELD write txn, so the
            // deleter's lock-free header read still sees the entity; the commit
            // lands while the deleter blocks on the write lock, and its scrub txn
            // then finds nothing. Identical construction to the ONE-1149
            // raced-to-nothing legs.
            let (tx, rx) = std::sync::mpsc::sync_channel::<()>(0);
            crate::deletion::install_after_header_read_signal(tx);
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let outcome = std::thread::scope(|scope| {
                let mut wtxn = vault.store.env.write_txn().expect("write txn");
                crate::batch::deindex_entity(&vault.store, &mut wtxn, &id).expect("stage erase");
                let deleter_barrier = std::sync::Arc::clone(&barrier);
                let vault_ref = &vault;
                let deleter = scope.spawn(move || {
                    deleter_barrier.wait();
                    vault_ref.delete_entity_with_reason(&id, reason)
                });
                barrier.wait();
                rx.recv()
                    .expect("deleter must signal after the header read");
                wtxn.commit().expect("commit the racing erase");
                deleter.join().expect("deleter thread must not panic")
            })
            .expect("a raced delete is not an error");

            if vault.get_raw(&id).expect("get raw").is_some() {
                // Scheduling miss: the deleter never reached the raced branch.
                assert!(attempt < 2, "{case}: raced branch never constructed");
                continue;
            }
            assert!(
                !outcome.existed,
                "{case}: a delete that erased nothing must not claim it did"
            );
            assert!(
                !first_txn_pending_tombstone_exists(&vault, &id),
                "{case}: the scrub txn erased nothing, so it must stage no \
                 replayable pt: propagation intent for it"
            );
            break;
        }
    }
}

/// fix-leg 10 P1: an EMPTY commit settles nothing, so it must not latch
/// `authority_settled`.
///
/// fix-8 latched the flag unconditionally the moment the soft-erase txn ran, on
/// the theory that a committed destructive transaction is this delete's
/// linearization point. It is — when it actually erased something. When the
/// delete's scope raced away between the header read and the scrub txn
/// (`existed == false`, ONE-1149's shape), that transaction commits nothing at
/// all: no body scrubbed, no vector dropped, no `pt:` staged. Latching on it
/// declared a linearization point that does not exist, and the purge txn then
/// asked NO authority question.
///
/// What that bought an attacker: a `RevokeActor` AND a same-id re-put both
/// landing in the window before the purge were ignored wholesale. The purge tore
/// the REPLACEMENT state — data the revoked actor was never authorized to touch
/// and that this delete never even read — wrote the `dt:` marker that bricks the
/// id forever, committed the replayable `pt:` propagation intent, and appended
/// the stale `allow` gate decision minted from a snapshot two commits stale.
///
/// Fully deterministic, using the rendezvous slot TWICE: the deleter parks
/// before its scrub txn while the harness races the scope away, then parks again
/// at `BeforeHardPurge` while the harness commits the revocation and the re-put.
/// No `AFTER_HEADER_READ` contention with the other raced tests, and no retry
/// loop — LMDB's single writer does the ordering.
///
/// MUTATION PROBE: latch unconditionally again (`authority_settled = true;`) and
/// this test fails — the purge re-folds nothing, the delete SUCCEEDS, and
/// `expect_err` panics with the replacement torn and `dt:`/`pt:`/receipt/gate
/// artifacts on disk.
#[cfg(not(feature = "sync"))]
#[test]
fn a_raced_to_nothing_scrub_leaves_authority_unsettled_for_the_purge() {
    const REPLACEMENT: &[u8] = b"state re-put after the empty scrub";
    let _serial = lock_delete_rendezvous();

    for reason in [SafeDeleteReason::GdprDelete, SafeDeleteReason::PolicyDelete] {
        let case = format!("{reason:?}");
        let (_dir, vault) = open_nonpublishing_delete_vault();
        let owner = put_person(&vault, 0x57);
        let revoke = root_binding_with_pending_revocation(&vault, 0x58, owner);
        let subject = EntityId::from_bytes([0x59; 16]).expect("subject id");
        vault
            .put_entity(&subject, ENTITY_TYPE_PERSON, test_time(1), 1, b"original")
            .expect("put the original scope");

        // Park #1: after the entry gate and the no-op publish, BEFORE the scrub
        // txn opens — the deleter holds no write lock here.
        let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel::<()>(0);
        crate::deletion::install_delete_rendezvous(
            crate::deletion::DeleteRendezvous::AfterTombstonePublish,
            subject,
            arrived_tx,
            resume_rx,
        );

        let replacement_vector = [0.9_f32, 0.8, 0.7, 0.6];
        let result = std::thread::scope(|scope| {
            let vault_ref = &vault;
            let deleter = scope
                .spawn(move || facade_for(vault_ref, owner).safe_delete(&subject.to_hex(), reason));
            arrived_rx
                .recv()
                .expect("the deleter must park before its scrub txn");

            // Race the ORIGINAL scope to nothing. The scrub txn below will find
            // `existed == false` and commit empty.
            let mut wtxn = vault.store.env.write_txn().expect("write txn");
            crate::batch::deindex_entity(&vault.store, &mut wtxn, &subject)
                .expect("race the scope away");
            wtxn.commit().expect("commit the racing erase");
            assert!(
                vault.get_raw(&subject).expect("get raw").is_none(),
                "{case}: precondition — the scrub must find nothing"
            );

            // Park #2, installed while the deleter is still held at park #1: the
            // slot was `take`n when it fired, so this is the next one it hits.
            let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
            let (resume_purge_tx, resume_purge_rx) = std::sync::mpsc::sync_channel::<()>(0);
            crate::deletion::install_delete_rendezvous(
                crate::deletion::DeleteRendezvous::BeforeHardPurge,
                subject,
                arrived_tx,
                resume_purge_rx,
            );
            resume_tx.send(()).expect("release into the empty scrub");
            arrived_rx
                .recv()
                .expect("the deleter must park after the empty scrub commits");

            // The two commits the empty scrub falsely claimed to have ordered
            // behind it: authority is gone, and the id carries NEW state.
            vault
                .put_authority_log_entries(&[(revoke, test_time(3), 3)])
                .expect("commit the revocation");
            vault
                .put_entity(&subject, ENTITY_TYPE_PERSON, test_time(4), 4, REPLACEMENT)
                .expect("re-put the same id");
            vault
                .put_vector(&subject, &replacement_vector)
                .expect("re-put a vector");
            resume_purge_tx.send(()).expect("release into the purge");
            deleter.join().expect("deleter thread must not panic")
        });

        let err = result.expect_err(&format!(
            "{case}: the empty scrub linearized nothing, so the purge is this \
             delete's first irreversible act and MUST re-prove authority"
        ));
        assert_eq!(err.code, MEMORY_CODE_FORBIDDEN, "{case}");
        assert!(
            err.message.contains("no active owner binding"),
            "{case}: the parked pre-gate error must survive, not degrade to a \
             generic concurrency code: {}",
            err.message
        );
        // The replacement is whole — the purge must not tear state this delete
        // never read, on an authority that no longer exists.
        assert_eq!(
            vault
                .get_raw(&subject)
                .expect("get raw")
                .expect("the replacement row survives")
                .len(),
            crate::batch::ENTITY_METADATA_HEADER_LEN + REPLACEMENT.len(),
            "{case}: the re-put body must be untouched"
        );
        assert_eq!(
            vault.get_vector(&subject).expect("get vector"),
            Some(
                replacement_vector
                    .iter()
                    .map(|v| half::f16::from_f32(*v).to_f32())
                    .collect::<Vec<_>>()
            ),
            "{case}: the re-put vector must be untouched"
        );
        assert_no_local_delete_artifacts(&vault, &subject, &case);
    }
}

#[test]
fn napi_schedule_outbound_forwards_timezone_context() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x78);
    let facade = facade_for(&vault, actor);
    let draft = OutboundDraftInput {
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        target: "test@example.com".to_owned(),
        on_behalf_of: None,
        content_ref: Some("content:napi-timezone".to_owned()),
        idempotency_key: Some("napi-timezone-forward".to_owned()),
        dedupe_key: None,
        trigger: "agent_immediate".to_owned(),
        trigger_ref: "session:napi".to_owned(),
        job_ref: None,
        occurred_at: Some(3_600),
    };
    let receipt = facade
        .schedule_outbound_with_context(
            &draft,
            &OutboundScheduleContext {
                utc_offset_minutes: Some(60),
                iana_timezone: Some("Europe/Paris".to_owned()),
                human_explicit_instant: false,
                apns_interruption_level: None,
                resolved_level: None,
            },
        )
        .expect("timezone context schedules");
    assert!(receipt.intent_ref.starts_with("intent:"));
    assert!(receipt.gate_decision_ref.is_some());
    // The schedule-only Hold window is what admits the durable TASK; assert the
    // precondition explicitly so the round-trip below can never pass vacuously.
    assert_eq!(receipt.outcome, "held");

    // The context does not merely validate: it reaches the shared TASK and is
    // readable back off the public row.
    let scheduled = vault
        .connector_send_tasks()
        .expect("connector tasks")
        .into_iter()
        .find(|task| task.intent.idempotency_key.as_deref() == Some("napi-timezone-forward"))
        .expect("context-aware schedule writes a TASK");
    assert_eq!(scheduled.utc_offset_minutes, Some(60));
    assert_eq!(scheduled.iana_timezone.as_deref(), Some("Europe/Paris"));
    assert!(!scheduled.human_explicit_instant);
    assert_eq!(scheduled.apns_interruption_level, None);
    assert_eq!(scheduled.resolved_level, None);

    // An omitted context preserves hostless behavior: no clock is invented.
    let hostless_draft = OutboundDraftInput {
        idempotency_key: Some("napi-timezone-hostless".to_owned()),
        ..draft.clone()
    };
    facade
        .schedule_outbound(&hostless_draft)
        .expect("hostless schedule still works");
    let hostless = vault
        .connector_send_tasks()
        .expect("connector tasks")
        .into_iter()
        .find(|task| task.intent.idempotency_key.as_deref() == Some("napi-timezone-hostless"))
        .expect("hostless task");
    assert_eq!(hostless.utc_offset_minutes, None);
    assert_eq!(hostless.iana_timezone, None);

    // Fail-closed: every invalid clock authority is rejected BEFORE any TASK or
    // attempt write, so the row count cannot move.
    let before = vault.connector_send_tasks().expect("connector tasks").len();
    for (context, expected) in [
        (
            OutboundScheduleContext {
                iana_timezone: Some("Europe/Paris".to_owned()),
                ..Default::default()
            },
            "iana_timezone requires utc_offset_minutes",
        ),
        (
            OutboundScheduleContext {
                utc_offset_minutes: Some(841),
                ..Default::default()
            },
            "utc_offset_minutes must be in -840..=840",
        ),
        (
            OutboundScheduleContext {
                utc_offset_minutes: Some(-841),
                ..Default::default()
            },
            "utc_offset_minutes must be in -840..=840",
        ),
        (
            OutboundScheduleContext {
                utc_offset_minutes: Some(60),
                iana_timezone: Some("   ".to_owned()),
                ..Default::default()
            },
            "iana_timezone must be non-blank and contain no controls",
        ),
        (
            OutboundScheduleContext {
                utc_offset_minutes: Some(60),
                iana_timezone: Some("Europe/\u{7}Paris".to_owned()),
                ..Default::default()
            },
            "iana_timezone must be non-blank and contain no controls",
        ),
        (
            // An APNs level on a non-APNs send is a category error.
            OutboundScheduleContext {
                utc_offset_minutes: Some(60),
                apns_interruption_level: Some(
                    crate::delivery_window::DeliveryWindowApnsInterruptionLevel::Critical,
                ),
                ..Default::default()
            },
            "APNs interruption level requires an APNs push",
        ),
    ] {
        let rejected_draft = OutboundDraftInput {
            idempotency_key: Some(format!("napi-timezone-reject:{expected}")),
            ..draft.clone()
        };
        let err = facade
            .schedule_outbound_with_context(&rejected_draft, &context)
            .expect_err("invalid clock authority must not schedule");
        assert!(
            err.to_string().contains(expected),
            "expected {expected:?}, got {err}"
        );
    }
    assert_eq!(
        vault.connector_send_tasks().expect("connector tasks").len(),
        before,
        "a rejected schedule writes no TASK"
    );

    // The offset range is inclusive at both civil edges.
    for (edge, key) in [(-840_i16, "napi-timezone-min"), (840, "napi-timezone-max")] {
        let edge_draft = OutboundDraftInput {
            idempotency_key: Some(key.to_owned()),
            ..draft.clone()
        };
        facade
            .schedule_outbound_with_context(
                &edge_draft,
                &OutboundScheduleContext {
                    utc_offset_minutes: Some(edge),
                    ..Default::default()
                },
            )
            .unwrap_or_else(|err| panic!("offset {edge} must be accepted: {err}"));
    }
}
