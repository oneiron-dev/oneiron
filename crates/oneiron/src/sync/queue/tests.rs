use super::*;
use crate::config::VaultConfig;
use crate::deletion::{
    HardEraseSweepExtras, LAST_HARD_ERASE_SWEEP_SEQ_KEY, RedactionScope, TombstoneReason,
    TombstoneValueV2, encode_hard_erase_sweep_job, encode_hard_erase_sweep_key,
};
use crate::registry::ENTITY_TYPE_TASK;
use crate::sync::WindowKey;
use crate::sync::bridge::{self, Materializer};
use crate::sync::quarantine;
use crate::sync::schema::create_window_doc;
use crate::sync::window::forward_rematerialize;
use crate::temporal::TimeRange;
use core::assert_matches;

const RECEIVER_SCRUB_WINDOW: &str = "2026-03";
const RECEIVER_SCRUB_LEARNED_AT: u64 = 1_772_400_000;

struct ReceiverOutboxFixture {
    queue: SyncQueue,
    victim_payload_seq: u64,
    other_payload_seq: u64,
    delete_bearing_seq: u64,
}

struct PurgeFailureReset;

impl Drop for PurgeFailureReset {
    fn drop(&mut self) {
        quarantine::INJECT_PURGE_FAILURES.with(|cell| cell.set(0));
    }
}

struct ReceiverScrubFailureReset;

impl Drop for ReceiverScrubFailureReset {
    fn drop(&mut self) {
        INJECT_RECEIVER_SCRUB_FAILURES.with(|cell| cell.set(0));
    }
}

fn test_vault() -> Arc<Vault> {
    let dir = tempfile::tempdir().unwrap();
    let config = VaultConfig::device();
    Arc::new(Vault::open(dir.path(), config).unwrap())
}

fn arm_purge_failures(count: u32) -> PurgeFailureReset {
    quarantine::INJECT_PURGE_FAILURES.with(|cell| cell.set(count));
    PurgeFailureReset
}

fn arm_receiver_scrub_failures(count: u32) -> ReceiverScrubFailureReset {
    INJECT_RECEIVER_SCRUB_FAILURES.with(|cell| cell.set(count));
    ReceiverScrubFailureReset
}

fn receiver_hard_tombstone_value() -> [u8; crate::deletion::TOMBSTONE_VALUE_V2_LEN] {
    TombstoneValueV2 {
        reason: TombstoneReason::GdprDelete,
        deleted_at: RECEIVER_SCRUB_LEARNED_AT,
        request_id: [0xA5; 16],
    }
    .encode()
}

fn receiver_soft_tombstone_value() -> [u8; crate::deletion::TOMBSTONE_VALUE_V2_LEN] {
    TombstoneValueV2 {
        reason: TombstoneReason::UserDelete,
        deleted_at: RECEIVER_SCRUB_LEARNED_AT,
        request_id: [0x5A; 16],
    }
    .encode()
}

fn task_body() -> Vec<u8> {
    crate::habit::task_body_for_test(crate::habit::TaskRole::Task)
}

fn put_receiver_entity(vault: &Vault, id: &EntityId, _body: &[u8]) {
    vault
        .put_entity(
            id,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: RECEIVER_SCRUB_LEARNED_AT,
                end: RECEIVER_SCRUB_LEARNED_AT,
            },
            RECEIVER_SCRUB_LEARNED_AT,
            &task_body(),
        )
        .unwrap();
}

fn seed_receiver_outbox(vault: &Arc<Vault>) -> ReceiverOutboxFixture {
    let queue = SyncQueue::new(Arc::clone(vault)).unwrap();
    let victim_payload_seq = queue
        .push(RECEIVER_SCRUB_WINDOW, b"queued victim payload")
        .unwrap();
    let other_payload_seq = queue
        .push(RECEIVER_SCRUB_WINDOW, b"queued unrelated payload")
        .unwrap();
    let delete_bearing_seq = queue
        .push_delete_bearing(RECEIVER_SCRUB_WINDOW, b"queued delete delta")
        .unwrap();
    ReceiverOutboxFixture {
        queue,
        victim_payload_seq,
        other_payload_seq,
        delete_bearing_seq,
    }
}

fn queued_update_seqs(queue: &SyncQueue) -> Vec<u64> {
    queue
        .drain_updates()
        .unwrap()
        .iter()
        .map(|update| update.seq)
        .collect()
}

fn assert_receiver_outbox_scrubbed(vault: &Vault, outbox: &ReceiverOutboxFixture) {
    let seqs = queued_update_seqs(&outbox.queue);
    assert!(
        !seqs.contains(&outbox.victim_payload_seq),
        "victim payload q: row must be scrubbed"
    );
    assert!(
        !seqs.contains(&outbox.other_payload_seq),
        "receiver scrub is window-granular: unrelated same-window q: row is over-dropped"
    );
    assert!(
        seqs.contains(&outbox.delete_bearing_seq),
        "delete-bearing q: row must survive the receiver scrub"
    );
    assert_eq!(
        vault
            .sync_state_get(&format!("fr:w:{RECEIVER_SCRUB_WINDOW}"))
            .unwrap()
            .as_deref(),
        Some([1_u8].as_slice()),
        "fr:w marker must heal over-dropped non-deleted ops"
    );
}

fn assert_receiver_outbox_intact(vault: &Vault, outbox: &ReceiverOutboxFixture) {
    let seqs = queued_update_seqs(&outbox.queue);
    assert!(
        seqs.contains(&outbox.victim_payload_seq),
        "victim payload q: row must remain"
    );
    assert!(
        seqs.contains(&outbox.other_payload_seq),
        "unrelated same-window q: row must remain"
    );
    assert!(
        seqs.contains(&outbox.delete_bearing_seq),
        "delete-bearing q: row must remain"
    );
    assert!(
        vault
            .sync_state_get(&format!("fr:w:{RECEIVER_SCRUB_WINDOW}"))
            .unwrap()
            .is_none(),
        "fr:w is HARD-success-only"
    );
}

#[test]
fn push_and_drain_roundtrip() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault).unwrap();

    queue.push("2026-03", &[1, 2, 3]).unwrap();
    queue.push("2026-02", &[4, 5, 6]).unwrap();

    let updates = queue.drain_updates().unwrap();
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[0].seq, 1);
    assert_eq!(updates[0].window_key, "2026-03");
    assert_eq!(updates[0].encoded, vec![1, 2, 3]);
    assert_eq!(updates[1].seq, 2);
    assert_eq!(updates[1].window_key, "2026-02");
    assert_eq!(updates[1].encoded, vec![4, 5, 6]);
}

#[test]
fn clear_through_removes_up_to_seq() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault).unwrap();

    queue.push("2026-03", &[1]).unwrap();
    queue.push("2026-03", &[2]).unwrap();
    queue.push("2026-03", &[3]).unwrap();

    queue.clear_through(2).unwrap();

    let updates = queue.drain_updates().unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].seq, 3);
}

#[test]
fn push_rejects_invalid_window_key_without_burning_sequence() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault).unwrap();

    let err = queue
        .push("", &[1])
        .expect_err("empty window key must fail");
    assert_matches!(err, Error::InvalidKey);

    let overlong = "x".repeat(MAX_WINDOW_KEY_LEN + 1);
    let err = queue
        .push(&overlong, &[2])
        .expect_err("overlong window key must fail");
    assert_matches!(err, Error::InvalidKey);

    for invalid in [
        "2026-13", "2026-00", "abcdefg", "2026-3", "1969-12", "0000-01",
    ] {
        let err = queue
            .push(invalid, &[9])
            .expect_err("invalid calendar window key must fail");
        assert_matches!(err, Error::InvalidKey);
    }

    let seq = queue.push("2026-03", &[3]).unwrap();
    assert_eq!(seq, 1);

    let updates = queue.drain_updates().unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].seq, 1);
    assert_eq!(updates[0].window_key, "2026-03");
    assert_eq!(updates[0].encoded, vec![3]);
}

#[test]
fn clear_all_resets_queue() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault).unwrap();

    queue.push("2026-03", &[1]).unwrap();
    queue.push("2026-03", &[2]).unwrap();

    queue.clear_all().unwrap();

    assert_eq!(queue.len().unwrap(), 0);
    assert!(!queue.is_full().unwrap());

    let seq = queue.push("2026-03", &[3]).unwrap();
    assert_eq!(seq, 3);
}

#[test]
fn clear_all_preserves_hard_erase_sweeps_and_metadata_counters() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault.clone()).unwrap();

    let update_seq = queue.push("2026-03", &[1]).unwrap();
    let embed_id = EntityId::now();
    queue.push_embed_job(&embed_id, 1).unwrap();

    let sweep_seq = 7_u64;
    let sweep_key = encode_hard_erase_sweep_key(sweep_seq);
    let sweep_value = encode_hard_erase_sweep_job(
        RedactionScope::entity(&EntityId::now()),
        HardEraseSweepExtras::default(),
        1_772_000_000,
    )
    .unwrap();
    let embed_key = encode_embed_key(&embed_id);

    // An UNKNOWN key family (`zz:`) the queue does not own: every clear
    // and scrub must leave foreign families untouched (ONE-1135). NOTE:
    // `x:` no longer qualifies — it is the quarantine family (ONE-1124)
    // whose retention pass evicts rows that do not parse as x:{seq}.
    let unknown_key = b"zz:future-family";
    let unknown_value = b"opaque";

    let mut wtxn = vault.store.env.write_txn().unwrap();
    vault
        .store
        .sync_queue
        .put(&mut wtxn, &sweep_key, &sweep_value)
        .unwrap();
    vault
        .store
        .sync_queue
        .put(
            &mut wtxn,
            LAST_HARD_ERASE_SWEEP_SEQ_KEY,
            &sweep_seq.to_le_bytes(),
        )
        .unwrap();
    vault
        .store
        .sync_queue
        .put(&mut wtxn, unknown_key.as_slice(), unknown_value.as_slice())
        .unwrap();
    wtxn.commit().unwrap();

    // ONE-1124 AC6 — quarantine rows (x:) and their m: counters live in
    // the same DB and must survive every queue clear path.
    let quarantine_seq = quarantine::quarantine_rejected_op(
        &vault,
        "2026-03",
        quarantine::QuarantineContainer::Entities,
        "deadbeef",
        &Error::InvalidKey,
        b"payload",
    )
    .unwrap();
    let quarantine_key = quarantine::encode_quarantine_key(quarantine_seq);

    queue.clear_all().unwrap();

    let rtxn = vault.store.env.read_txn().unwrap();
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &encode_update_key(update_seq))
            .unwrap()
            .is_none(),
        "clear_all must drop queued update rows",
    );
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &embed_key)
            .unwrap()
            .is_none(),
        "clear_all must drop queued embed-job rows",
    );
    assert_eq!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &sweep_key)
            .unwrap()
            .as_deref(),
        Some(sweep_value.as_slice()),
        "clear_all must preserve hard-erase sweep jobs",
    );
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &quarantine_key)
            .unwrap()
            .is_some(),
        "clear_all must preserve quarantine rows (x:)",
    );
    assert_eq!(
        vault
            .store
            .sync_queue
            .get(&rtxn, quarantine::LAST_QUARANTINE_SEQ_KEY)
            .unwrap()
            .as_deref(),
        Some(quarantine_seq.to_le_bytes().as_slice()),
        "clear_all must preserve the quarantine sequence cursor",
    );
    assert_eq!(
        vault
            .store
            .sync_queue
            .get(&rtxn, LAST_UPDATE_SEQ_KEY)
            .unwrap()
            .as_deref(),
        Some(update_seq.to_le_bytes().as_slice()),
        "clear_all must preserve the update sequence cursor",
    );
    assert_eq!(
        vault
            .store
            .sync_queue
            .get(&rtxn, LAST_HARD_ERASE_SWEEP_SEQ_KEY)
            .unwrap()
            .as_deref(),
        Some(sweep_seq.to_le_bytes().as_slice()),
        "clear_all must preserve the hard-erase sweep cursor",
    );
    assert_eq!(
        vault
            .store
            .sync_queue
            .get(&rtxn, unknown_key.as_slice())
            .unwrap()
            .as_deref(),
        Some(unknown_value.as_slice()),
        "clear_all must preserve unknown key families",
    );
    drop(rtxn);

    // ONE-1091 durability closure: surviving the overflow re-bootstrap
    // byte-identically is not enough — the preserved obligation must
    // still be ACTIONABLE. The sweep executor consumes it end-to-end
    // (decode → execute → row deleted) after the clear.
    let report = vault.maintain().run_hard_erase_sweep().run().unwrap();
    assert_eq!(
        report.sweep_jobs_processed, 1,
        "the h: row preserved across clear_all must still execute"
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &sweep_key)
            .unwrap()
            .is_none(),
        "the executed obligation row is consumed"
    );
}

/// ONE-1135: `push_delete_bearing` writes the `q:` row AND the pinned
/// `d:{seq:8BE}` sidecar marker. The marker key bytes are asserted as
/// LITERALS (`d`, `:`, 8-byte big-endian sequence), not via the
/// encoder.
#[test]
fn push_delete_bearing_writes_literal_sidecar_marker() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault.clone()).unwrap();

    queue.push("2026-03", &[1]).unwrap();
    let seq = queue.push_delete_bearing("2026-03", &[9, 9]).unwrap();
    assert_eq!(seq, 2);

    let expected_marker: Vec<u8> = [b'd', b':', 0, 0, 0, 0, 0, 0, 0, 2].to_vec();
    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &expected_marker)
            .unwrap()
            .as_deref(),
        Some([1u8].as_slice()),
        "delete-bearing sidecar marker must be d: + seq u64 BE",
    );
    // The q: row itself replays like any other update.
    drop(rtxn);
    let updates = queue.drain_updates().unwrap();
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[1].seq, 2);
    assert_eq!(updates[1].encoded, vec![9, 9]);
}

/// ONE-1135 AC3: delete-bearing rows are EXEMPT from the optimistic
/// `clear_through` (kept until VV-confirmed); the VV-confirmed variant
/// removes the row AND its sidecar marker. An implementation that
/// optimistically clears delete rows FAILS here — that is a silently
/// lost offline GDPR delete.
#[test]
fn clear_through_keeps_delete_bearing_until_confirmed() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault.clone()).unwrap();

    queue.push("2026-03", &[1]).unwrap();
    let delete_seq = queue.push_delete_bearing("2026-03", &[2]).unwrap();
    queue.push("2026-03", &[3]).unwrap();

    // Optimistic clear after an unconfirmed replay.
    queue.clear_through(3).unwrap();
    let updates = queue.drain_updates().unwrap();
    assert_eq!(
        updates.len(),
        1,
        "non-delete rows cleared, delete-bearing row kept"
    );
    assert_eq!(updates[0].seq, delete_seq);
    assert_eq!(updates[0].encoded, vec![2]);

    let marker = encode_delete_bearing_key(delete_seq);
    let rtxn = vault.store.env.read_txn().unwrap();
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &marker)
            .unwrap()
            .is_some(),
        "sidecar marker survives the optimistic clear"
    );
    drop(rtxn);

    // Sequence allocation continues monotonically past the kept row.
    let next = queue.push("2026-03", &[4]).unwrap();
    assert_eq!(next, 4);

    // VV-confirmed clear removes the delete row and its marker.
    queue.clear_through_confirmed(delete_seq).unwrap();
    let updates = queue.drain_updates().unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].seq, 4);
    let rtxn = vault.store.env.read_txn().unwrap();
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &marker)
            .unwrap()
            .is_none(),
        "confirmed clear must remove the sidecar marker too"
    );
}

/// ONE-1135: the unconfirmed bulk clears (`clear_updates`, `clear_all`)
/// preserve delete-bearing rows and their markers too.
#[test]
fn bulk_clears_preserve_delete_bearing_rows() {
    for clear in ["clear_updates", "clear_all"] {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        queue.push("2026-03", &[1]).unwrap();
        let delete_seq = queue.push_delete_bearing("2026-03", &[2]).unwrap();

        match clear {
            "clear_updates" => queue.clear_updates().unwrap(),
            _ => queue.clear_all().unwrap(),
        }

        let updates = queue.drain_updates().unwrap();
        assert_eq!(updates.len(), 1, "{clear} must keep the delete row");
        assert_eq!(updates[0].seq, delete_seq, "{clear}");
        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &encode_delete_bearing_key(delete_seq))
                .unwrap()
                .is_some(),
            "{clear} must keep the sidecar marker"
        );
    }
}

/// ONE-1135 review item 14: ordinary pushes can NEVER acquire a
/// delete-bearing marker. The `d:` family is written exclusively by
/// the tombstone-commit path (`push_delete_bearing_in_txn` taking a
/// `DeleteBearingUpdate`, constructible only by
/// `export_tombstone_commit_delta`); `SyncQueue::push` writes the `q:`
/// row alone, so its rows keep ZERO clear/scrub exemptions.
#[test]
fn ordinary_push_never_acquires_delete_bearing_marker() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault.clone()).unwrap();

    queue.push("2026-03", &[1]).unwrap();
    queue.push("2026-04", &[2]).unwrap();

    let rtxn = vault.store.env.read_txn().unwrap();
    let markers = vault
        .store
        .sync_queue
        .prefix_iter(&rtxn, DELETE_BEARING_PREFIX)
        .unwrap()
        .count();
    assert_eq!(markers, 0, "ordinary q: rows must have no d: sidecar");
    drop(rtxn);

    // Consequently the unconfirmed clear drops them all.
    queue.clear_updates().unwrap();
    assert_eq!(queue.len().unwrap(), 0);
}

/// ONE-1135 review item 15: a `d:{seq}` sidecar marker must never
/// outlive its `q:{seq}` row. When the malformed-row prune drops a
/// delete-bearing `q:` row (key decodes, value no longer does), the
/// matching `d:` marker is deleted in the SAME write txn — a stale
/// orphan marker would otherwise grant the delete-bearing clear/scrub
/// exemptions to a future unrelated row at a reused sequence.
#[test]
fn prune_removes_sidecar_marker_with_its_malformed_q_row() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault.clone()).unwrap();

    queue.push("2026-03", &[1]).unwrap();
    let delete_seq = queue.push_delete_bearing("2026-03", &[2]).unwrap();

    // Corrupt the delete-bearing row's VALUE in place (torn write /
    // bitrot shape): the key still decodes, the value does not.
    let mut wtxn = vault.store.env.write_txn().unwrap();
    vault
        .store
        .sync_queue
        .put(&mut wtxn, &encode_update_key(delete_seq), &[0])
        .unwrap();
    wtxn.commit().unwrap();

    // drain_updates prunes rows whose decode fails.
    let updates = queue.drain_updates().unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].seq, 1);

    let rtxn = vault.store.env.read_txn().unwrap();
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &encode_update_key(delete_seq))
            .unwrap()
            .is_none(),
        "malformed q: row must be pruned"
    );
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &encode_delete_bearing_key(delete_seq))
            .unwrap()
            .is_none(),
        "d: sidecar must be deleted in the same txn as its q: row"
    );
}

/// ONE-1135 review item 15, fail-closed leg: an orphan `d:` marker
/// with no matching `q:` row (legacy prune before this fix, crash
/// window) must never see its sequence reused. Sequence recovery
/// includes marker seqs, so after metadata loss a later unrelated `q:`
/// row cannot land on the marked seq and inherit the delete-bearing
/// exemptions. The orphan marker itself is KEPT (it protects nothing,
/// but its presence keeps the seq out of circulation — fail closed).
#[test]
fn orphan_sidecar_marker_never_poisons_a_reused_seq() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault.clone()).unwrap();

    // Inject an orphan d:1 with NO q: rows and NO metadata cursor —
    // the post-crash shape where pre-fix recovery rebuilt the cursor
    // from q: rows alone and handed out seq 1 again.
    let mut wtxn = vault.store.env.write_txn().unwrap();
    vault
        .store
        .sync_queue
        .put(&mut wtxn, &encode_delete_bearing_key(1), &[1u8])
        .unwrap();
    wtxn.commit().unwrap();

    let seq = queue.push("2026-03", &[7]).unwrap();
    assert_eq!(seq, 2, "orphan marker seq must never be reused");

    // The new ordinary row is NOT delete-bearing: the optimistic clear
    // drops it (pre-fix, at the reused seq 1, the orphan marker
    // exempted it — a silently undeletable garbage row).
    queue.clear_through(seq).unwrap();
    assert_eq!(
        queue.len().unwrap(),
        0,
        "ordinary row must not inherit the delete-bearing exemption"
    );

    let rtxn = vault.store.env.read_txn().unwrap();
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &encode_delete_bearing_key(1))
            .unwrap()
            .is_some(),
        "orphan marker kept — fail closed, seq stays blocked"
    );
}

/// ONE-1135 AC4 (carrier-15 scrub): only the target window's
/// non-delete-bearing `q:` rows are dropped. Delete-bearing rows,
/// other windows' rows, and the `e:` / `h:` / `m:` / unknown (`x:`)
/// families are untouched.
#[test]
fn scrub_window_updates_drops_only_target_window_payload_rows() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault.clone()).unwrap();

    let target_payload = queue.push("2026-02", &[0xAA]).unwrap();
    let other_window = queue.push("2026-03", &[0xBB]).unwrap();
    let target_delete = queue.push_delete_bearing("2026-02", &[0xCC]).unwrap();

    let embed_id = EntityId::now();
    queue.push_embed_job(&embed_id, 2).unwrap();

    let sweep_key = encode_hard_erase_sweep_key(1);
    let sweep_value = encode_hard_erase_sweep_job(
        RedactionScope::entity(&EntityId::now()),
        HardEraseSweepExtras::default(),
        1_772_000_000,
    )
    .unwrap();
    let mut wtxn = vault.store.env.write_txn().unwrap();
    vault
        .store
        .sync_queue
        .put(&mut wtxn, &sweep_key, &sweep_value)
        .unwrap();
    vault
        .store
        .sync_queue
        .put(
            &mut wtxn,
            b"x:future-family".as_slice(),
            b"opaque".as_slice(),
        )
        .unwrap();
    wtxn.commit().unwrap();

    let scrubbed = vault
        .with_write_txn(|wtxn| scrub_window_updates_in_txn(&vault, wtxn, "2026-02"))
        .unwrap();
    assert_eq!(scrubbed, 1, "exactly the target payload row is dropped");

    let updates = queue.drain_updates().unwrap();
    let seqs: Vec<u64> = updates.iter().map(|u| u.seq).collect();
    assert!(
        !seqs.contains(&target_payload),
        "target-window payload row must be scrubbed (carrier 15)"
    );
    assert!(
        seqs.contains(&other_window),
        "other windows' rows must survive"
    );
    assert!(
        seqs.contains(&target_delete),
        "delete-bearing rows must NEVER be scrubbed — dropping one loses a prior delete"
    );

    let rtxn = vault.store.env.read_txn().unwrap();
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &encode_embed_key(&embed_id))
            .unwrap()
            .is_some(),
        "e: family untouched"
    );
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &sweep_key)
            .unwrap()
            .is_some(),
        "h: family untouched"
    );
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, LAST_UPDATE_SEQ_KEY)
            .unwrap()
            .is_some(),
        "m: family untouched"
    );
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, b"x:future-family".as_slice())
            .unwrap()
            .is_some(),
        "unknown families untouched"
    );
}

#[test]
fn receiver_live_hard_tombstone_scrubs_window_outbox_and_sets_fr() {
    let vault = test_vault();
    let outbox = seed_receiver_outbox(&vault);
    let victim = EntityId::now();
    put_receiver_entity(&vault, &victim, b"payload to erase");

    let window_key = WindowKey::new(RECEIVER_SCRUB_WINDOW);
    let doc = create_window_doc("remote", &window_key);
    let materializer = Arc::new(Materializer::new());
    let _subs = bridge::register_observer_b(&doc, &vault, &materializer, RECEIVER_SCRUB_WINDOW);

    let hard = receiver_hard_tombstone_value();
    doc.get_map("tombstones")
        .insert(&victim.to_hex(), hard.as_slice())
        .unwrap();
    doc.commit();

    assert!(
        vault.get(&victim).unwrap().is_none(),
        "live hard tombstone must purge the active store first"
    );
    assert_receiver_outbox_scrubbed(&vault, &outbox);
}

#[test]
fn receiver_forward_remat_hard_tombstone_scrubs_window_outbox_and_sets_fr() {
    let vault = test_vault();
    let outbox = seed_receiver_outbox(&vault);
    let victim = EntityId::now();
    put_receiver_entity(&vault, &victim, b"payload to erase");

    let window_key = WindowKey::new(RECEIVER_SCRUB_WINDOW);
    let doc = create_window_doc("remote", &window_key);
    let hard = receiver_hard_tombstone_value();
    doc.get_map("tombstones")
        .insert(&victim.to_hex(), hard.as_slice())
        .unwrap();
    doc.commit();

    let materializer = Materializer::new();
    forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();

    assert!(
        vault.get(&victim).unwrap().is_none(),
        "recovery hard tombstone must purge the active store first"
    );
    assert_receiver_outbox_scrubbed(&vault, &outbox);
}

#[test]
fn receiver_forward_remat_scrub_failure_keeps_outbox_and_sets_rm_retry() {
    let vault = test_vault();
    let outbox = seed_receiver_outbox(&vault);
    let victim = EntityId::now();
    put_receiver_entity(&vault, &victim, b"payload purged before scrub failure");

    let window_key = WindowKey::new(RECEIVER_SCRUB_WINDOW);
    let doc = create_window_doc("remote", &window_key);
    let hard = receiver_hard_tombstone_value();
    doc.get_map("tombstones")
        .insert(&victim.to_hex(), hard.as_slice())
        .unwrap();
    doc.commit();

    let _reset = arm_receiver_scrub_failures(1);
    let materializer = Materializer::new();
    forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();

    assert!(
        vault.get(&victim).unwrap().is_none(),
        "hard tombstone purge should not roll back when scrub bookkeeping fails"
    );
    assert_receiver_outbox_intact(&vault, &outbox);
    assert_eq!(
        vault
            .sync_state_get(&format!("rm:w:{RECEIVER_SCRUB_WINDOW}:{}", victim.to_hex()))
            .unwrap()
            .as_deref(),
        Some([1_u8].as_slice()),
        "scrub failure must set rm: so recovery retries the receiver outbox scrub"
    );
}

#[test]
fn receiver_live_soft_tombstone_keeps_outbox_and_does_not_set_fr() {
    let vault = test_vault();
    let outbox = seed_receiver_outbox(&vault);
    let victim = EntityId::now();
    put_receiver_entity(&vault, &victim, b"payload kept as soft shell");

    let window_key = WindowKey::new(RECEIVER_SCRUB_WINDOW);
    let doc = create_window_doc("remote", &window_key);
    let materializer = Arc::new(Materializer::new());
    let _subs = bridge::register_observer_b(&doc, &vault, &materializer, RECEIVER_SCRUB_WINDOW);

    let soft = receiver_soft_tombstone_value();
    doc.get_map("tombstones")
        .insert(&victim.to_hex(), soft.as_slice())
        .unwrap();
    doc.commit();

    assert!(
        vault.get(&victim).unwrap().is_some(),
        "soft tombstone keeps the local shell"
    );
    assert_receiver_outbox_intact(&vault, &outbox);
}

#[test]
fn receiver_live_failed_hard_apply_keeps_outbox_and_sets_rm_retry() {
    let vault = test_vault();
    let outbox = seed_receiver_outbox(&vault);
    let victim = EntityId::now();
    put_receiver_entity(&vault, &victim, b"payload still live on injected failure");

    let window_key = WindowKey::new(RECEIVER_SCRUB_WINDOW);
    let doc = create_window_doc("remote", &window_key);
    let materializer = Arc::new(Materializer::new());
    let _subs = bridge::register_observer_b(&doc, &vault, &materializer, RECEIVER_SCRUB_WINDOW);

    let _reset = arm_purge_failures(1);
    let hard = receiver_hard_tombstone_value();
    doc.get_map("tombstones")
        .insert(&victim.to_hex(), hard.as_slice())
        .unwrap();
    doc.commit();

    assert!(
        vault.get(&victim).unwrap().is_some(),
        "failed hard replay must not purge active state"
    );
    assert_receiver_outbox_intact(&vault, &outbox);
    assert_eq!(
        vault
            .sync_state_get(&format!("rm:w:{RECEIVER_SCRUB_WINDOW}:{}", victim.to_hex()))
            .unwrap()
            .as_deref(),
        Some([1_u8].as_slice()),
        "failed hard replay must durably flag rm: retry"
    );
}

/// Fail-closed: a malformed `q:` row cannot prove which window it
/// belongs to, so the carrier-15 scrub drops it (over-dropping is
/// healed by the full resync; leaking is not healable).
#[test]
fn scrub_window_updates_drops_malformed_rows() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault.clone()).unwrap();
    queue.push("2026-03", &[1]).unwrap();

    let bad_key = b"q:\x00".to_vec();
    let well_formed_key = encode_update_key(7);
    let mut wtxn = vault.store.env.write_txn().unwrap();
    vault
        .store
        .sync_queue
        .put(&mut wtxn, &bad_key, &[1, b'x'])
        .unwrap();
    vault
        .store
        .sync_queue
        .put(&mut wtxn, &well_formed_key, &[0])
        .unwrap();
    wtxn.commit().unwrap();

    vault
        .with_write_txn(|wtxn| scrub_window_updates_in_txn(&vault, wtxn, "2026-02"))
        .unwrap();

    let rtxn = vault.store.env.read_txn().unwrap();
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &bad_key)
            .unwrap()
            .is_none(),
        "malformed key must be dropped by the scrub"
    );
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &well_formed_key)
            .unwrap()
            .is_none(),
        "row with undecodable value must be dropped by the scrub"
    );
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &encode_update_key(1))
            .unwrap()
            .is_some(),
        "well-formed rows of OTHER windows survive"
    );
}

#[test]
fn own_device_sync_cap_counts_clearable_rows_at_capacity() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault.clone()).unwrap();
    let value = encode_update_value("2026-03", &[9]).unwrap();
    let mut wtxn = vault.store.env.write_txn().unwrap();
    for seq in 1..=(MAX_QUEUE_SIZE as u64) {
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &encode_update_key(seq), &value)
            .unwrap();
    }
    vault
        .store
        .sync_queue
        .put(
            &mut wtxn,
            LAST_UPDATE_SEQ_KEY,
            &(MAX_QUEUE_SIZE as u64).to_le_bytes(),
        )
        .unwrap();
    wtxn.commit().unwrap();

    assert!(queue.is_full().unwrap());
    queue.clear_all().unwrap();
    assert!(!queue.is_full().unwrap());
    assert_eq!(queue.len().unwrap(), 0);
}

/// ONE-1135 review rider: delete-bearing rows are exempt from every
/// unconfirmed clear, so they must also be exempt from the capacity
/// accounting that TRIGGERS the re-bootstrap (`is_full` → `clear_all`).
/// Pre-fix, a queue holding `MAX_QUEUE_SIZE` delete-bearing rows
/// reported full forever: `clear_all` preserved every row, the overflow
/// check re-fired on each reconnect, and nothing was ever freed — a
/// permanent re-bootstrap loop.
#[test]
fn is_full_excludes_delete_bearing_rows_from_capacity() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault.clone()).unwrap();

    // Seed MAX_QUEUE_SIZE delete-bearing rows in ONE txn (the public
    // push would be 10k commits) — exact row + marker bytes the delete
    // path writes.
    let value = encode_update_value("2026-03", &[9]).unwrap();
    let mut wtxn = vault.store.env.write_txn().unwrap();
    for seq in 1..=(MAX_QUEUE_SIZE as u64) {
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &encode_update_key(seq), &value)
            .unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &encode_delete_bearing_key(seq), &[1u8])
            .unwrap();
    }
    vault
        .store
        .sync_queue
        .put(
            &mut wtxn,
            LAST_UPDATE_SEQ_KEY,
            &(MAX_QUEUE_SIZE as u64).to_le_bytes(),
        )
        .unwrap();
    wtxn.commit().unwrap();

    assert_eq!(
        queue.len().unwrap(),
        MAX_QUEUE_SIZE,
        "len still counts every replayable row"
    );
    assert!(
        !queue.is_full().unwrap(),
        "unconfirmed-clear-exempt rows must not count toward overflow capacity"
    );

    // The re-bootstrap path frees clearable rows and converges to
    // not-full instead of looping.
    let normal_seq = queue.push("2026-03", &[1]).unwrap();
    queue.clear_all().unwrap();
    assert!(!queue.is_full().unwrap());
    assert_eq!(
        queue.len().unwrap(),
        MAX_QUEUE_SIZE,
        "delete-bearing rows preserved, the normal row dropped"
    );
    let drained = queue.drain_updates().unwrap();
    assert!(!drained.iter().any(|u| u.seq == normal_seq));

    // VV-confirmed clear is what actually frees the delete rows.
    queue
        .clear_through_confirmed(MAX_QUEUE_SIZE as u64)
        .unwrap();
    assert_eq!(queue.len().unwrap(), 0);
    assert!(!queue.is_full().unwrap());
}

/// ONE-1124 AC6 — `clear_updates` and `clear_through` (including its
/// malformed-row pruning) never touch quarantine rows or counters.
#[test]
fn clear_updates_and_clear_through_preserve_quarantine_rows() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault.clone()).unwrap();

    let quarantine_seq = quarantine::quarantine_rejected_op(
        &vault,
        "2026-03",
        quarantine::QuarantineContainer::Edges,
        "some-edge-key",
        &Error::InvalidEdgeWeight { value: 1.5 },
        b"edge-bytes",
    )
    .unwrap();
    let quarantine_key = quarantine::encode_quarantine_key(quarantine_seq);
    let evictions_value = 3u64.to_le_bytes();
    let mut wtxn = vault.store.env.write_txn().unwrap();
    vault
        .store
        .sync_queue
        .put(
            &mut wtxn,
            quarantine::QUARANTINE_EVICTIONS_KEY,
            &evictions_value,
        )
        .unwrap();
    wtxn.commit().unwrap();

    let assert_quarantine_intact = |label: &str| {
        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &quarantine_key)
                .unwrap()
                .is_some(),
            "{label} must preserve quarantine rows (x:)",
        );
        assert_eq!(
            vault
                .store
                .sync_queue
                .get(&rtxn, quarantine::LAST_QUARANTINE_SEQ_KEY)
                .unwrap()
                .as_deref(),
            Some(quarantine_seq.to_le_bytes().as_slice()),
            "{label} must preserve the quarantine sequence cursor",
        );
        assert_eq!(
            vault
                .store
                .sync_queue
                .get(&rtxn, quarantine::QUARANTINE_EVICTIONS_KEY)
                .unwrap()
                .as_deref(),
            Some(evictions_value.as_slice()),
            "{label} must preserve the quarantine eviction counter",
        );
    };

    queue.push("2026-03", &[1]).unwrap();
    queue.clear_updates().unwrap();
    assert_eq!(queue.len().unwrap(), 0);
    assert_quarantine_intact("clear_updates");

    let seq = queue.push("2026-03", &[2]).unwrap();
    queue.clear_through(seq).unwrap();
    assert_eq!(queue.len().unwrap(), 0);
    assert_quarantine_intact("clear_through");

    queue.push("2026-03", &[3]).unwrap();
    queue.clear_all().unwrap();
    assert_eq!(queue.len().unwrap(), 0);
    assert_quarantine_intact("clear_all");
}

#[test]
fn seq_ordering_preserved() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault).unwrap();

    for i in 0..10u8 {
        queue.push("2026-03", &[i]).unwrap();
    }

    let updates = queue.drain_updates().unwrap();
    assert_eq!(updates.len(), 10);
    for (i, u) in updates.iter().enumerate() {
        assert_eq!(u.seq, (i + 1) as u64);
        assert_eq!(u.encoded, vec![i as u8]);
    }
}

#[test]
fn multiple_handles_allocate_distinct_sequences() {
    let vault = test_vault();
    let queue_a = SyncQueue::new(vault.clone()).unwrap();
    let queue_b = SyncQueue::new(vault).unwrap();

    let first = queue_a.push("2026-03", &[1]).unwrap();
    let second = queue_b.push("2026-03", &[2]).unwrap();

    assert_eq!(first, 1);
    assert_eq!(second, 2);
    let updates = queue_a.drain_updates().unwrap();
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[0].seq, 1);
    assert_eq!(updates[1].seq, 2);
}

#[test]
fn sequence_metadata_self_heals() {
    // 2x2 table: (corruption shape) x (entry point) — every cell asserts
    // the next push assigns max_existing_seq+1, regardless of what the
    // metadata key holds or whether clear_all ran first.
    #[derive(Copy, Clone)]
    enum Corruption {
        Missing,
        Malformed,
    }
    #[derive(Copy, Clone)]
    enum Entry {
        Push,
        ClearAll,
    }

    let cases: &[(&str, Corruption, Entry, u64, u64)] = &[
        // (case_name, corruption, entry, existing_seq, expected_next_seq)
        ("missing_then_push", Corruption::Missing, Entry::Push, 7, 8),
        (
            "missing_then_clear_all",
            Corruption::Missing,
            Entry::ClearAll,
            7,
            8,
        ),
        (
            "malformed_then_push",
            Corruption::Malformed,
            Entry::Push,
            4,
            5,
        ),
        (
            "malformed_then_clear_all",
            Corruption::Malformed,
            Entry::ClearAll,
            9,
            10,
        ),
    ];

    for (case_name, corruption, entry, existing_seq, expected_next) in cases {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        let mut wtxn = vault.store.env.write_txn().unwrap();
        if matches!(corruption, Corruption::Malformed) {
            vault
                .store
                .sync_queue
                .put(&mut wtxn, LAST_UPDATE_SEQ_KEY, &[1, 2, 3])
                .unwrap();
        }
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &encode_update_key(*existing_seq), &[7, b'x'])
            .unwrap();
        wtxn.commit().unwrap();

        match entry {
            Entry::Push => {
                let next = queue.push("2026-03", &[1]).unwrap();
                assert_eq!(next, *expected_next, "case {case_name}: push seq mismatch");
            }
            Entry::ClearAll => {
                queue.clear_all().unwrap();
                assert_eq!(
                    queue.len().unwrap(),
                    0,
                    "case {case_name}: clear_all left rows behind"
                );
                let seq = queue.push("2026-03", &[1]).unwrap();
                assert_eq!(
                    seq, *expected_next,
                    "case {case_name}: post-clear push seq mismatch"
                );
            }
        }
    }
}

#[test]
fn decode_last_update_seq_metadata_rejects_bad_len_without_panic() {
    let decoded = decode_last_update_seq_metadata(&42_u64.to_le_bytes()).unwrap();
    assert_eq!(decoded, 42);

    let short =
        decode_last_update_seq_metadata(&[1, 2, 3]).expect_err("short metadata must be rejected");
    assert_matches!(short, Error::CorruptedIndex("sync queue metadata"));

    let overlong = decode_last_update_seq_metadata(&[0_u8; 9])
        .expect_err("overlong metadata must be rejected");
    assert_matches!(overlong, Error::CorruptedIndex("sync queue metadata"));
}

#[test]
fn clear_all_preserves_sequence_generation_for_stale_clear_through() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault).unwrap();

    for seq in 1..=5u8 {
        queue.push("2026-03", &[seq]).unwrap();
    }

    queue.clear_all().unwrap();

    let fresh_seq = queue.push("2026-03", &[9]).unwrap();
    assert_eq!(fresh_seq, 6);

    queue.clear_through(5).unwrap();

    let updates = queue.drain_updates().unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].seq, 6);
    assert_eq!(updates[0].encoded, vec![9]);
}

#[test]
fn stale_but_parseable_metadata_repairs_upward_before_push() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault.clone()).unwrap();

    for seq in 1..=5u8 {
        queue.push("2026-03", &[seq]).unwrap();
    }

    let mut wtxn = vault.store.env.write_txn().unwrap();
    vault
        .store
        .sync_queue
        .put(&mut wtxn, LAST_UPDATE_SEQ_KEY, &1_u64.to_le_bytes())
        .unwrap();
    wtxn.commit().unwrap();

    let next = queue.push("2026-03", &[9]).unwrap();
    assert_eq!(next, 6);

    let updates = queue.drain_updates().unwrap();
    assert_eq!(updates.len(), 6);
    assert_eq!(updates[1].seq, 2);
    assert_eq!(updates[1].encoded, vec![2]);
    assert_eq!(updates[5].seq, 6);
    assert_eq!(updates[5].encoded, vec![9]);
}

#[test]
fn push_self_heals_missing_metadata_without_update_rows() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault.clone()).unwrap();

    let seq = queue.push("2026-03", &[1]).unwrap();
    assert_eq!(seq, 1);

    let mut wtxn = vault.store.env.write_txn().unwrap();
    vault
        .store
        .sync_queue
        .delete(&mut wtxn, LAST_UPDATE_SEQ_KEY)
        .unwrap();
    vault
        .store
        .sync_queue
        .delete(&mut wtxn, &encode_update_key(1))
        .unwrap();
    wtxn.commit().unwrap();

    let seq = queue.push("2026-03", &[2]).unwrap();
    assert_eq!(seq, 1);
}

#[test]
fn clear_updates_self_heals_malformed_metadata_without_update_rows() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault.clone()).unwrap();

    let mut wtxn = vault.store.env.write_txn().unwrap();
    vault
        .store
        .sync_queue
        .put(&mut wtxn, LAST_UPDATE_SEQ_KEY, &[1, 2, 3])
        .unwrap();
    wtxn.commit().unwrap();

    queue.clear_updates().unwrap();

    let seq = queue.push("2026-03", &[1]).unwrap();
    assert_eq!(seq, 1);
}

#[test]
fn len_ignores_malformed_update_rows() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault.clone()).unwrap();

    queue.push("2026-03", &[1]).unwrap();

    let mut bad_key = UPDATE_PREFIX.to_vec();
    bad_key.push(0);
    let mut wtxn = vault.store.env.write_txn().unwrap();
    vault
        .store
        .sync_queue
        .put(&mut wtxn, &bad_key, &[1, b'x'])
        .unwrap();
    vault
        .store
        .sync_queue
        .put(&mut wtxn, &encode_update_key(2), &[0])
        .unwrap();
    wtxn.commit().unwrap();

    assert_eq!(queue.len().unwrap(), 1);

    let updates = queue.drain_updates().unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].seq, 1);
    assert_eq!(updates[0].window_key, "2026-03");
    assert_eq!(updates[0].encoded, vec![1]);
}

#[test]
fn drain_updates_prunes_corrupt_rows() {
    // Three corruption shapes get pruned by drain_updates:
    //   (case_name, bad_key, bad_value)
    // - malformed_value: well-formed key, value too short to decode
    // - overlong_key: key with trailing bytes (length != 10)
    // - invalid_calendar_or_pre_epoch: well-formed key, value carries a
    //   window_key string that fails parse_window_key_str (calendar OOB
    //   or pre-epoch year). Both share the same code path.
    let well_formed_key = encode_update_key(2).to_vec();
    let mut overlong_key = Vec::from(encode_update_key(2));
    overlong_key.push(0xAA);

    let mut invalid_calendar_value = vec![7u8];
    invalid_calendar_value.extend_from_slice(b"2026-13");
    invalid_calendar_value.extend_from_slice(&[9, 9]);

    let mut pre_epoch_value = vec![7u8];
    pre_epoch_value.extend_from_slice(b"1969-12");
    pre_epoch_value.extend_from_slice(&[9, 9]);

    let cases: &[(&str, Vec<u8>, Vec<u8>)] = &[
        ("malformed_value", well_formed_key.clone(), vec![0]),
        ("overlong_key", overlong_key, vec![7, b'x']),
        (
            "invalid_calendar_window_key",
            well_formed_key.clone(),
            invalid_calendar_value,
        ),
        ("pre_epoch_window_key", well_formed_key, pre_epoch_value),
    ];

    for (case_name, bad_key, bad_value) in cases {
        let vault = test_vault();
        let queue = SyncQueue::new(vault.clone()).unwrap();

        queue.push("2026-03", &[1]).unwrap();

        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, bad_key, bad_value)
            .unwrap();
        wtxn.commit().unwrap();

        let updates = queue.drain_updates().unwrap();
        assert_eq!(updates.len(), 1, "case {case_name}: should keep valid row");
        assert_eq!(updates[0].seq, 1, "case {case_name}");

        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(
            vault
                .store
                .sync_queue
                .get(&rtxn, bad_key)
                .unwrap()
                .is_none(),
            "case {case_name}: corrupt row should be pruned",
        );
    }
}

#[test]
fn clear_through_prunes_malformed_update_keys() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault.clone()).unwrap();

    queue.push("2026-03", &[1]).unwrap();

    let bad_key = b"q:\x00".to_vec();
    let mut wtxn = vault.store.env.write_txn().unwrap();
    vault
        .store
        .sync_queue
        .put(&mut wtxn, &bad_key, &[1, b'x'])
        .unwrap();
    wtxn.commit().unwrap();

    queue.clear_through(1).unwrap();

    let rtxn = vault.store.env.read_txn().unwrap();
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &bad_key)
            .unwrap()
            .is_none()
    );
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &encode_update_key(1))
            .unwrap()
            .is_none()
    );
}

#[test]
fn embed_job_roundtrip() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault).unwrap();

    let id = EntityId::now();
    queue.push_embed_job(&id, 1).unwrap();

    let jobs = queue.drain_embed_jobs().unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].entity_id, id);
    assert_eq!(jobs[0].priority, 1);
    assert!(jobs[0].queued_at > 0);
}

#[test]
fn drain_embed_jobs_prunes_corrupt_rows() {
    // Three corruption shapes get pruned by drain_embed_jobs:
    //   (case_name, bad_key, bad_value)
    // - malformed_key: zeroed entity id portion fails EntityId::from_bytes
    // - overlong_key: key has trailing byte (length != 18)
    // - overlong_value: value has trailing byte (length != 9)
    let mut zero_key = [0u8; 18];
    zero_key[..2].copy_from_slice(EMBED_PREFIX);

    let mut overlong_key = Vec::from(encode_embed_key(&EntityId::now()));
    overlong_key.push(0xAA);

    let proper_key = encode_embed_key(&EntityId::now());

    let mut valid_value = Vec::with_capacity(9);
    valid_value.push(2);
    valid_value.extend_from_slice(&123u64.to_be_bytes());

    let mut overlong_value = valid_value.clone();
    overlong_value.push(0xAA);

    let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        ("malformed_key", zero_key.to_vec(), valid_value.clone()),
        ("overlong_key", overlong_key, valid_value),
        ("overlong_value", proper_key.to_vec(), overlong_value),
    ];

    for (case_name, bad_key, bad_value) in &cases {
        let vault = test_vault();
        let queue = SyncQueue::new(vault).unwrap();

        let valid_id = EntityId::now();
        queue.push_embed_job(&valid_id, 1).unwrap();

        let mut wtxn = queue.vault.store.env.write_txn().unwrap();
        queue
            .vault
            .store
            .sync_queue
            .put(&mut wtxn, bad_key, bad_value)
            .unwrap();
        wtxn.commit().unwrap();

        let jobs = queue.drain_embed_jobs().unwrap();
        assert_eq!(jobs.len(), 1, "case {case_name}: should keep valid job");
        assert_eq!(jobs[0].entity_id, valid_id, "case {case_name}");

        let rtxn = queue.vault.store.env.read_txn().unwrap();
        assert!(
            queue
                .vault
                .store
                .sync_queue
                .get(&rtxn, bad_key)
                .unwrap()
                .is_none(),
            "case {case_name}: corrupt row should be pruned",
        );
    }
}

#[test]
fn prune_malformed_rows_keeps_repaired_embed_row() {
    let vault = test_vault();
    let queue = SyncQueue::new(vault).unwrap();

    let id = EntityId::now();
    let key = encode_embed_key(&id);

    let mut wtxn = queue.vault.store.env.write_txn().unwrap();
    queue
        .vault
        .store
        .sync_queue
        .put(&mut wtxn, &key, &[1, 2, 3])
        .unwrap();
    wtxn.commit().unwrap();

    let stale_candidates = vec![key.to_vec()];

    let mut repaired = Vec::with_capacity(9);
    repaired.push(2);
    repaired.extend_from_slice(&456u64.to_be_bytes());
    let mut wtxn = queue.vault.store.env.write_txn().unwrap();
    queue
        .vault
        .store
        .sync_queue
        .put(&mut wtxn, &key, &repaired)
        .unwrap();
    wtxn.commit().unwrap();

    queue
        .prune_malformed_rows(&stale_candidates, decode_embed_job_row)
        .unwrap();

    let rtxn = queue.vault.store.env.read_txn().unwrap();
    assert!(
        queue
            .vault
            .store
            .sync_queue
            .get(&rtxn, &key)
            .unwrap()
            .is_some()
    );
    drop(rtxn);

    let jobs = queue.drain_embed_jobs().unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].entity_id, id);
    assert_eq!(jobs[0].priority, 2);
    assert_eq!(jobs[0].queued_at, 456);
}

#[test]
fn seq_resumes_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let config = VaultConfig::device();

    // Open vault and push entries
    {
        let vault = Arc::new(Vault::open(dir.path(), config.clone()).unwrap());
        let queue = SyncQueue::new(vault).unwrap();
        queue.push("2026-03", &[1]).unwrap();
        queue.push("2026-03", &[2]).unwrap();
    }

    // Reopen vault and verify seq resumes
    {
        let vault = Arc::new(Vault::open(dir.path(), config).unwrap());
        let queue = SyncQueue::new(vault).unwrap();
        let seq = queue.push("2026-03", &[3]).unwrap();
        assert_eq!(seq, 3, "sequence should resume from persisted max");

        let updates = queue.drain_updates().unwrap();
        assert_eq!(updates.len(), 3);
    }
}

#[test]
fn key_encoding_roundtrip() {
    // Two key families round-trip through their encode/decode pair.
    // Update keys carry a u64 sequence (boundary values: 0, 1, 255,
    // 65535, u64::MAX). Embed keys carry an EntityId.
    for seq in [0u64, 1, 255, 65535, u64::MAX] {
        let encoded = encode_update_key(seq);
        let decoded = decode_update_key(&encoded)
            .unwrap_or_else(|e| panic!("update_key seq={seq}: decode failed: {e:?}"));
        assert_eq!(decoded, seq, "update_key seq={seq}");
    }

    let id = EntityId::now();
    let encoded = encode_embed_key(&id);
    let decoded = decode_embed_key(&encoded)
        .unwrap_or_else(|e| panic!("embed_key id={id:?}: decode failed: {e:?}"));
    assert_eq!(decoded, id, "embed_key roundtrip");
}
