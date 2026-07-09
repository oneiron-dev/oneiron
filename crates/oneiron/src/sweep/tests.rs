use super::*;
use crate::deletion::{
    DeleteReason, HardEraseSweepExtras, RedactionScope, encode_hard_erase_sweep_job,
    encode_hard_erase_sweep_key,
};
use crate::temporal::TimeRange;
use crate::types::{HnswConfig, VaultConfig};
#[cfg(feature = "sync")]
use core::assert_matches;

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test-model-v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    config
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(test_config())
}

fn put_entity(vault: &Vault, id: &EntityId, learned_at: u64, body: &[u8]) {
    vault
        .batch()
        .put(
            id,
            1,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            body,
        )
        .commit()
        .expect("put entity");
}

fn h_rows(vault: &Vault) -> Vec<(Vec<u8>, Vec<u8>)> {
    let rtxn = vault.store.env.read_txn().unwrap();
    let mut rows = Vec::new();
    for row in vault
        .store
        .sync_queue
        .prefix_iter(&rtxn, HARD_ERASE_SWEEP_PREFIX)
        .unwrap()
    {
        let (key, value) = row.unwrap();
        rows.push((key.to_vec(), value.to_vec()));
    }
    rows
}

fn receipt_sweep_complete_at(vault: &Vault, receipt_id: &EntityId) -> Option<u64> {
    let raw = vault.get_raw(receipt_id).unwrap().expect("receipt raw");
    let receipt = decode_redaction_audit_receipt(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
        .expect("receipt decode");
    receipt.sweep_complete_at
}

fn write_h_row(vault: &Vault, seq: u64, value: &[u8]) -> Vec<u8> {
    let key = encode_hard_erase_sweep_key(seq);
    let mut wtxn = vault.store.env.write_txn().unwrap();
    vault.store.sync_queue.put(&mut wtxn, &key, value).unwrap();
    wtxn.commit().unwrap();
    key.to_vec()
}

/// Writes a type-120 REDACTION_AUDIT entity (entities row + type-index
/// row) whose body is deliberately UNDECODABLE — the on-disk
/// accountability-corruption shape Finding 2 / the audit must surface.
fn write_corrupt_redaction_receipt(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    let mut blob = Vec::new();
    blob.push(ENTITY_TYPE_REDACTION_AUDIT);
    for _ in 0..3 {
        blob.extend_from_slice(&1_771_027_200u64.to_be_bytes());
    }
    // 0xc1 is the msgpack "never used" byte — guarantees a decode error.
    blob.extend_from_slice(&[0xc1, 0x00, 0x01]);
    let mut type_key = Vec::with_capacity(17);
    type_key.push(ENTITY_TYPE_REDACTION_AUDIT);
    type_key.extend_from_slice(id.as_bytes());
    let mut wtxn = vault.store.env.write_txn().unwrap();
    vault
        .store
        .entities
        .put(&mut wtxn, id.as_bytes(), &blob)
        .unwrap();
    vault
        .store
        .type_index
        .put(&mut wtxn, &type_key, &[])
        .unwrap();
    wtxn.commit().unwrap();
    id
}

#[cfg(feature = "sync")]
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Byte-scans every persisted `sync_state` value and every `sync_queue`
/// key+value for `needle` — the delete-safety carrier scan.
#[cfg(feature = "sync")]
fn sync_rows_contain(vault: &Vault, needle: &[u8]) -> bool {
    let rtxn = vault.store.env.read_txn().unwrap();
    for entry in vault.store.sync_state.iter(&rtxn).unwrap() {
        let (_, value) = entry.unwrap();
        if contains(value, needle) {
            return true;
        }
    }
    for entry in vault.store.sync_queue.iter(&rtxn).unwrap() {
        let (key, value) = entry.unwrap();
        if contains(key, needle) || contains(value, needle) {
            return true;
        }
    }
    false
}

/// Per-job independence (ONE-1087 retry semantics): a job whose
/// `next_attempt_at` is in the future is skipped — byte-identical row,
/// no retry_state consumption — while a due job in the same run
/// completes (h: row deleted LAST, receipt finalized to the pinned
/// `sweep_complete_at = Some(_)` shape).
#[test]
fn sweep_skips_not_due_job_while_processing_due_job() {
    let (_dir, vault) = open_vault();
    let id = EntityId::now();
    put_entity(&vault, &id, 1_771_027_200, b"due-job-body");
    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    let receipt_id = outcome.receipt_id.expect("receipt id");
    let due_key = outcome.sweep_key.expect("sweep key");

    // A NOT-due crafted job: queued_at (= next_attempt_at) in the future.
    let future = crate::unix_seconds_now() + 86_400;
    let not_due_value = encode_hard_erase_sweep_job(
        RedactionScope::entity(&EntityId::now()),
        HardEraseSweepExtras::default(),
        future,
    )
    .unwrap();
    let not_due_key = write_h_row(&vault, 1_000, &not_due_value);

    let run = run_hard_erase_sweep(&vault).unwrap();
    assert_eq!(run.jobs_processed, 1, "the due job must complete");
    assert!(run.jobs_deferred >= 1, "the not-due job must defer");
    assert_eq!(run.receipts_finalized, 1);
    assert!(
        receipt_sweep_complete_at(&vault, &receipt_id).is_some(),
        "receipt sweep_complete_at must be populated"
    );

    let rows = h_rows(&vault);
    assert!(
        !rows.iter().any(|(k, _)| *k == due_key),
        "completed job's h: row must be deleted"
    );
    let kept: Vec<_> = rows.iter().filter(|(k, _)| *k == not_due_key).collect();
    assert_eq!(kept.len(), 1, "not-due job row must survive");
    assert_eq!(
        kept[0].1, not_due_value,
        "not-due job row must be BYTE-IDENTICAL (no retry_state consumption)"
    );
}

/// A job past `deadline_at` (queued_at + 30 d, deletion.rs pin) is a
/// loud SLA breach: counted every run, never silent — and still
/// executed when due (a breach must not park the obligation).
#[test]
fn sweep_deadline_breach_is_loud_and_counted() {
    let (_dir, vault) = open_vault();
    let queued_at = crate::unix_seconds_now() - crate::deletion::HARD_ERASE_SWEEP_SLA_SECS - 10;
    let value = encode_hard_erase_sweep_job(
        RedactionScope::entity(&EntityId::now()),
        HardEraseSweepExtras::default(),
        queued_at,
    )
    .unwrap();
    let key = write_h_row(&vault, 7, &value);

    let run = run_hard_erase_sweep(&vault).unwrap();
    assert_eq!(run.deadline_breaches, 1, "SLA breach must be counted");
    assert_eq!(run.jobs_processed, 1, "a breached due job still executes");
    assert!(
        !h_rows(&vault).iter().any(|(k, _)| *k == key),
        "the executed job's row is deleted"
    );
}

/// ONE-1091 audit: a receipt with `sweep_queued_at` set, no
/// `sweep_complete_at`, and NO covering pending `h:` row is a DROPPED
/// erasure obligation — detected and counted. With the row present the
/// audit is quiet (the run that consumes it also finalizes the receipt,
/// so post-run state is clean either way).
#[test]
fn sweep_audit_detects_dropped_obligation() {
    // Dropped: the h: row vanishes before any sweep ran.
    let (_dir, vault) = open_vault();
    let id = EntityId::now();
    put_entity(&vault, &id, 1_771_027_200, b"dropped-obligation-body");
    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    let receipt_id = outcome.receipt_id.expect("receipt id");
    let sweep_key = outcome.sweep_key.expect("sweep key");
    {
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .delete(&mut wtxn, &sweep_key)
            .unwrap();
        wtxn.commit().unwrap();
    }
    let run = run_hard_erase_sweep(&vault).unwrap();
    assert_eq!(
        run.obligations_missing, 1,
        "a queued-but-unswept receipt without an h: row must be flagged"
    );
    assert_eq!(run.jobs_processed, 0);
    assert!(
        receipt_sweep_complete_at(&vault, &receipt_id).is_none(),
        "the audit must never fabricate completion"
    );

    // Intact: the obligation row is present and consumed — audit quiet.
    let (_dir2, vault2) = open_vault();
    let id2 = EntityId::now();
    put_entity(&vault2, &id2, 1_771_027_200, b"intact-obligation-body");
    vault2
        .delete_entity_with_reason(&id2, DeleteReason::GdprDelete)
        .unwrap();
    let run2 = run_hard_erase_sweep(&vault2).unwrap();
    assert_eq!(run2.obligations_missing, 0);
    assert_eq!(run2.jobs_processed, 1);
}

/// Crash-safety ordering (h: row deletion LAST): a crash between window
/// compaction and job finalization must leave the obligation row AND
/// the unfinalized receipt in place; the re-run is idempotent and
/// completes.
#[cfg(feature = "sync")]
#[test]
fn sweep_crash_between_compaction_and_finalization_keeps_obligation() {
    let (_dir, vault) = open_vault();
    let id = EntityId::now();
    put_entity(&vault, &id, 1_771_027_200, b"crash-window-body");
    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    let receipt_id = outcome.receipt_id.expect("receipt id");
    let sweep_key = outcome.sweep_key.expect("sweep key");

    INJECT_CRASH_BEFORE_FINALIZE.with(|cell| cell.set(true));
    let err = run_hard_erase_sweep(&vault).expect_err("injected crash");
    assert_matches!(err, Error::InvariantViolation(_));

    // Obligation survives the crash window; the compaction already
    // committed (the d:w: row is now a shallow doc).
    assert!(
        h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
        "h: row must survive a crash before finalization"
    );
    assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_none());
    let window = crate::deletion::window_label_from_timestamp(1_771_027_200);
    let snapshot = vault
        .sync_state_get(&format!("d:w:{window}"))
        .unwrap()
        .expect("window snapshot");
    let doc = loro::LoroDoc::from_snapshot(&snapshot).unwrap();
    assert!(doc.is_shallow(), "compaction committed before the crash");

    // Re-run: idempotent, completes the obligation.
    let run = run_hard_erase_sweep(&vault).unwrap();
    assert_eq!(run.jobs_processed, 1);
    assert_eq!(run.receipts_finalized, 1);
    assert!(!h_rows(&vault).iter().any(|(k, _)| *k == sweep_key));
    assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_some());
}

/// Per-job failure semantics: an unreadable window FAILS the run's
/// completion gate (fail closed — id→window attribution cannot be
/// trusted), the job row is REWRITTEN in place (attempt_count,
/// last_error_code, capped backoff; queued_at/deadline_at untouched),
/// never deleted, and healthy windows still compact. After healing,
/// a due re-run completes.
#[cfg(feature = "sync")]
#[test]
fn sweep_failure_updates_retry_state_in_place_and_keeps_obligation() {
    let (_dir, vault) = open_vault();
    let id = EntityId::now();
    put_entity(&vault, &id, 1_771_027_200, b"retry-window-body");
    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    let receipt_id = outcome.receipt_id.expect("receipt id");
    let sweep_key = outcome.sweep_key.expect("sweep key");
    let original_job = decode_hard_erase_sweep_job(
        &h_rows(&vault)
            .iter()
            .find(|(k, _)| *k == sweep_key)
            .expect("job row")
            .1,
    )
    .unwrap();

    // A corrupt FOREIGN window snapshot: unreadable ⇒ run-level failure.
    vault
        .sync_state_put("d:w:2027-01", b"not-a-loro-snapshot")
        .unwrap();

    let before = crate::unix_seconds_now();
    let run = run_hard_erase_sweep(&vault).unwrap();
    assert_eq!(run.jobs_failed, 1, "the due job must be marked failed");
    assert_eq!(run.jobs_processed, 0);
    assert!(
        run.windows_compacted >= 1,
        "healthy windows still compact in a failing run"
    );
    assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_none());

    let rows = h_rows(&vault);
    let (_, value) = rows
        .iter()
        .find(|(k, _)| *k == sweep_key)
        .expect("failed job row must be REWRITTEN, never deleted");
    let job = decode_hard_erase_sweep_job(value).unwrap();
    assert_eq!(job.retry_state.attempt_count, 1);
    assert_eq!(
        job.retry_state.last_error_code.as_deref(),
        Some("CrdtDecodeError"),
        "last_error_code carries the failing ErrorKind name"
    );
    assert!(job.retry_state.next_attempt_at > before, "backoff applied");
    assert!(
        job.retry_state.next_attempt_at <= before + RETRY_BACKOFF_CAP_SECS + 60,
        "backoff capped at 24h"
    );
    assert_eq!(
        job.retry_state.queued_at, original_job.retry_state.queued_at,
        "queued_at untouched"
    );
    assert_eq!(
        job.retry_state.deadline_at, original_job.retry_state.deadline_at,
        "backoff never extends the 30-day SLA clock"
    );

    // Heal the window, make the job due again, re-run: completes.
    assert!(vault.sync_state_delete("d:w:2027-01").unwrap());
    let mut due_again = job;
    due_again.retry_state.next_attempt_at = crate::unix_seconds_now();
    let value = encode_hard_erase_sweep_job_value(&due_again).unwrap();
    {
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &sweep_key, &value)
            .unwrap();
        wtxn.commit().unwrap();
    }
    let run = run_hard_erase_sweep(&vault).unwrap();
    assert_eq!(run.jobs_processed, 1);
    assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_some());
    assert!(!h_rows(&vault).iter().any(|(k, _)| *k == sweep_key));
}

/// OPEN windows defer (pinned): a live registry doc holds the full
/// history in memory and would clobber the shallow row on its next
/// persist. The obligation stays queued without retry consumption;
/// after unload the sweep completes.
#[cfg(feature = "sync")]
#[test]
fn sweep_defers_open_windows_and_completes_after_unload() {
    use crate::sync::bridge::Materializer;
    use crate::sync::manager::WindowManager;
    use crate::sync::types::WindowKey;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), test_config()).unwrap());
    let id = EntityId::now();
    put_entity(&vault, &id, 1_771_027_200, b"live-window-body");

    let materializer = Arc::new(Materializer::new());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        materializer,
        "sweep-test",
    ));
    let window_key = WindowKey::from_timestamp(1_771_027_200);
    let window = manager.open_window(&window_key).unwrap();

    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    let receipt_id = outcome.receipt_id.expect("receipt id");
    let sweep_key = outcome.sweep_key.expect("sweep key");
    let job_value_before = h_rows(&vault)
        .iter()
        .find(|(k, _)| *k == sweep_key)
        .expect("job row")
        .1
        .clone();

    let run = run_hard_erase_sweep(&vault).unwrap();
    assert!(run.windows_deferred_live >= 1, "open window must defer");
    assert_eq!(run.jobs_processed, 0);
    assert!(run.jobs_deferred >= 1);
    assert_eq!(run.jobs_failed, 0, "a deferral is not a failed attempt");
    let job_value_after = h_rows(&vault)
        .iter()
        .find(|(k, _)| *k == sweep_key)
        .expect("obligation kept")
        .1
        .clone();
    assert_eq!(
        job_value_before, job_value_after,
        "deferral must not consume retry_state"
    );
    assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_none());

    drop(window);
    assert!(manager.unload_window(&window_key).unwrap());
    let run = run_hard_erase_sweep(&vault).unwrap();
    assert_eq!(run.jobs_processed, 1);
    assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_some());
}

/// ONE-1162: a retained `Arc<LoadedWindow>` can persist a full-history
/// snapshot after `discard_window` removes the registry entry. The sweep
/// must still defer while that handle exists, so no finalized shallow row
/// can be clobbered by a late `persist_state`.
#[cfg(feature = "sync")]
#[test]
fn retained_handle_cannot_resurrect_after_finalize() {
    use crate::sync::bridge::Materializer;
    use crate::sync::manager::WindowManager;
    use crate::sync::types::WindowKey;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), test_config()).unwrap());
    let id = EntityId::now();
    let learned_at = 1_771_027_200;
    put_entity(&vault, &id, learned_at, b"retained-window-body");

    let materializer = Arc::new(Materializer::new());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        materializer,
        "retained-sweep-test",
    ));
    let window_key = WindowKey::from_timestamp(learned_at);
    let window = manager.open_window(&window_key).unwrap();
    window.persist_state(&vault).unwrap();

    let retained = Arc::clone(&window);
    drop(window);
    assert!(manager.discard_window(&window_key));
    assert!(
        manager.loaded_keys().is_empty(),
        "the registry entry is gone while the external handle remains"
    );

    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    let receipt_id = outcome.receipt_id.expect("receipt id");
    let sweep_key = outcome.sweep_key.expect("sweep key");

    let run = run_hard_erase_sweep(&vault).unwrap();
    assert_eq!(run.jobs_processed, 0, "retained handle must not finalize");
    assert!(
        run.windows_deferred_live >= 1,
        "orphaned retained handle must defer the window"
    );
    assert_eq!(run.windows_compacted, 0);
    assert!(run.jobs_deferred >= 1);
    assert_eq!(run.jobs_failed, 0);
    assert!(
        h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
        "h: obligation must be kept while the handle can persist"
    );
    assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_none());

    retained.persist_state(&vault).unwrap();
    assert!(
        h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
        "late persist cannot clobber a finalized shallow row because no finalization happened"
    );
    assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_none());

    drop(retained);
    let run = run_hard_erase_sweep(&vault).unwrap();
    assert_eq!(run.jobs_processed, 1);
    assert!(run.windows_compacted >= 1);
    assert!(
        !h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
        "h: obligation is removed only after the handle is gone"
    );
    assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_some());
}

/// Non-`sync` builds fail closed: with NO CRDT carrier rows the
/// obligation finalizes (the active carriers were erased in the delete
/// txn itself), but the moment any `d:w:` row exists the executor
/// defers EVERYTHING — it cannot parse Loro docs without the feature.
#[cfg(not(feature = "sync"))]
#[test]
fn sweep_without_sync_completes_clean_vault_and_defers_on_crdt_rows() {
    let (_dir, vault) = open_vault();
    let id = EntityId::now();
    put_entity(&vault, &id, 1_771_027_200, b"non-sync-body");
    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    let receipt_id = outcome.receipt_id.expect("receipt id");
    let run = run_hard_erase_sweep(&vault).unwrap();
    assert_eq!(run.jobs_processed, 1, "no CRDT carriers ⇒ jobs finalize");
    assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_some());

    // Same vault, new delete — but now a CRDT carrier row exists
    // (e.g. written by an earlier sync-enabled boot): defer, loudly.
    let id2 = EntityId::now();
    put_entity(&vault, &id2, 1_771_027_200, b"non-sync-body-two");
    let outcome2 = vault
        .delete_entity_with_reason(&id2, DeleteReason::GdprDelete)
        .unwrap();
    let receipt_id2 = outcome2.receipt_id.expect("receipt id");
    let sweep_key2 = outcome2.sweep_key.expect("sweep key");
    {
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_state
            .put(&mut wtxn, "d:w:2026-02", b"opaque-crdt-snapshot")
            .unwrap();
        wtxn.commit().unwrap();
    }
    let run = run_hard_erase_sweep(&vault).unwrap();
    assert_eq!(run.jobs_processed, 0, "CRDT rows present ⇒ fail closed");
    assert!(run.jobs_deferred >= 1);
    assert!(
        h_rows(&vault).iter().any(|(k, _)| *k == sweep_key2),
        "obligation kept"
    );
    assert!(receipt_sweep_complete_at(&vault, &receipt_id2).is_none());
}

/// Pins the ONE-1087 replay-door exception comparator to EXACTLY the
/// monotone finalization shape: identical envelope + fields, local
/// `sweep_complete_at = Some(_)`, incoming nil. Every other pair —
/// reversed direction (only craftable), a differing sibling field, a
/// differing envelope byte — must stay on the quarantine path.
#[cfg(feature = "sync")]
#[test]
fn stale_finalization_echo_comparator_pins_monotone_shape() {
    use crate::deletion::{
        RedactionReceiptInput, encode_redaction_audit_receipt,
        redaction_receipt_is_stale_finalization_echo,
    };

    let envelope = |body: &[u8]| -> Vec<u8> {
        let mut blob = Vec::with_capacity(25 + body.len());
        blob.push(ENTITY_TYPE_REDACTION_AUDIT);
        for _ in 0..3 {
            blob.extend_from_slice(&1_771_027_200_u64.to_be_bytes());
        }
        blob.extend_from_slice(body);
        blob
    };
    let input = |requested_at: u64| RedactionReceiptInput {
        request_id: uuid::Uuid::now_v7().to_string(),
        scope: RedactionScope::entity(&EntityId::now()),
        reason: DeleteReason::GdprDelete,
        requested_at,
        soft_complete_at: requested_at + 1,
        hard_purge_complete_at: requested_at + 1,
        sweep_queued_at: Some(requested_at + 1),
    };

    let identity = crate::identity::DeviceIdentity {
        client_id: 0x0123_4567_89ab_cdef,
        signing_key: ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
    };
    let receipt_id = EntityId::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    let base = input(1_771_027_200);
    let pre =
        envelope(&encode_redaction_audit_receipt(base.clone(), &receipt_id, &identity).unwrap());
    // Finalize exactly the way the sweep does: decode → Some → re-encode.
    let mut rec =
        decode_redaction_audit_receipt(&pre[crate::batch::ENTITY_METADATA_HEADER_LEN..]).unwrap();
    rec.sweep_complete_at = Some(1_771_113_600);
    let body = rmp_serde::to_vec_named(&rec).unwrap();
    validate_redaction_receipt_body(&body).expect("finalized body must stay door-valid");
    let finalized = envelope(&body);

    assert!(
        redaction_receipt_is_stale_finalization_echo(&finalized, &pre),
        "local finalized vs incoming pre-finalization echo: skip"
    );
    assert!(
        !redaction_receipt_is_stale_finalization_echo(&pre, &finalized),
        "incoming Some over local nil is only craftable: quarantine"
    );
    assert!(
        !redaction_receipt_is_stale_finalization_echo(&pre, &pre),
        "both nil is not the finalization shape"
    );

    // A sibling-field divergence (different request) must NOT match.
    let mut other = base;
    other.request_id = uuid::Uuid::now_v7().to_string();
    let other_pre =
        envelope(&encode_redaction_audit_receipt(other, &receipt_id, &identity).unwrap());
    assert!(!redaction_receipt_is_stale_finalization_echo(
        &finalized, &other_pre
    ));

    // A differing envelope byte must NOT match.
    let mut shifted = pre;
    shifted[1] ^= 0x01;
    assert!(!redaction_receipt_is_stale_finalization_echo(
        &finalized, &shifted
    ));
}

/// Finding 1 (anti-clobber, carrier completeness): a `u:w:` row that
/// appears AFTER the read phase — caught by the in-txn full set-equality
/// re-read — DEFERS the window. The compaction write txn aborts
/// uncommitted: the obligation is kept, the receipt stays nil, and the
/// `d:w:` snapshot is NOT replaced by a shallow blob. A wrong impl that
/// only flips `svf=0` and finalizes would delete the h: row.
#[cfg(feature = "sync")]
#[test]
fn sweep_defers_when_uw_row_appears_after_read_phase() {
    let (_dir, vault) = open_vault();
    let id = EntityId::now();
    put_entity(&vault, &id, 1_771_027_200, b"raced-uw-body");
    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    let receipt_id = outcome.receipt_id.expect("receipt id");
    let sweep_key = outcome.sweep_key.expect("sweep key");
    let window = crate::deletion::window_label_from_timestamp(1_771_027_200);
    let dw_before = vault.sync_state_get(&format!("d:w:{window}")).unwrap();

    INJECT_RACE_BEFORE_COMPACT_WRITE.with(|c| c.set(RaceInjection::AppendUpdateRow));
    let run = run_hard_erase_sweep(&vault).unwrap();

    assert_eq!(run.jobs_processed, 0, "a raced window must not finalize");
    assert!(
        run.windows_deferred_raced >= 1,
        "the raced-in u:w: row must defer the window"
    );
    assert!(run.jobs_deferred >= 1, "the obligation defers, not fails");
    assert_eq!(run.jobs_failed, 0);
    assert!(
        h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
        "h: row must survive a raced defer"
    );
    assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_none());
    let dw_after = vault.sync_state_get(&format!("d:w:{window}")).unwrap();
    assert_eq!(
        dw_after, dw_before,
        "the raced window's d:w: snapshot must be untouched (no shallow clobber)"
    );
}

/// Finding 4 (anti-clobber re-read): a DIFFERENT `d:w:` snapshot written
/// between the read phase and the write txn must NOT be overwritten by
/// the sweep's stale-based shallow. The run defers; the externally
/// written snapshot (carrying a distinctive benign marker the shallow
/// would not) survives byte-present. A wrong impl with the unconditional
/// put clobbers it.
#[cfg(feature = "sync")]
#[test]
fn sweep_defers_when_dw_snapshot_changes_between_read_and_write() {
    let (_dir, vault) = open_vault();
    let id = EntityId::now();
    put_entity(&vault, &id, 1_771_027_200, b"raced-dw-body");
    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    let receipt_id = outcome.receipt_id.expect("receipt id");
    let sweep_key = outcome.sweep_key.expect("sweep key");
    let window = crate::deletion::window_label_from_timestamp(1_771_027_200);

    INJECT_RACE_BEFORE_COMPACT_WRITE.with(|c| c.set(RaceInjection::ReplaceSnapshot));
    let run = run_hard_erase_sweep(&vault).unwrap();

    assert_eq!(run.jobs_processed, 0);
    assert!(
        run.windows_deferred_raced >= 1,
        "the changed d:w: snapshot must defer the window"
    );
    assert!(
        h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
        "h: row must survive"
    );
    assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_none());
    let dw_after = vault
        .sync_state_get(&format!("d:w:{window}"))
        .unwrap()
        .expect("d:w: present");
    assert!(
        contains(&dw_after, RACE_BENIGN_MARKER),
        "the externally-written snapshot must survive (no shallow clobber)"
    );
}

/// Finding 2 (fail closed): an UNDECODABLE REDACTION_AUDIT receipt body
/// encountered during a job's finalize txn aborts the WHOLE txn — the
/// h: row is KEPT, the job is routed to retry (jobs_failed), and a
/// CO-SCOPED valid receipt's `sweep_complete_at` ALSO stays nil
/// (all-or-nothing). The audit counts the unreadable receipt.
#[cfg(feature = "sync")]
#[test]
fn sweep_undecodable_receipt_keeps_h_row_and_does_not_finalize() {
    let (_dir, vault) = open_vault();
    let id = EntityId::now();
    put_entity(&vault, &id, 1_771_027_200, b"undecodable-finalize-body");
    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    // The real receipt is the CO-SCOPED valid receipt (scope == the due
    // job's scope) that would be finalized but for the abort.
    let valid_receipt_id = outcome.receipt_id.expect("receipt id");
    let sweep_key = outcome.sweep_key.expect("sweep key");

    // A separate, undecodable type-120 receipt finalize_job will hit.
    write_corrupt_redaction_receipt(&vault);

    let run = run_hard_erase_sweep(&vault).unwrap();
    assert_eq!(
        run.jobs_processed, 0,
        "no job finalizes past a corrupt receipt"
    );
    assert!(run.jobs_failed >= 1, "the job routes to retry");
    assert!(
        run.obligations_undecodable >= 1,
        "the unreadable receipt is a counted accountability signal"
    );
    assert!(
        h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
        "the obligation row must be kept on an undecodable-receipt abort"
    );
    assert!(
        receipt_sweep_complete_at(&vault, &valid_receipt_id).is_none(),
        "the co-scoped valid receipt must stay nil — all-or-nothing finalize"
    );
}

/// Finding 2 (audit half): an undecodable receipt body — even with a
/// (not-due) covering h: row present — is NEVER silently "covered". The
/// audit counts it in the SIBLING `obligations_undecodable`, distinct
/// from `obligations_missing`.
#[test]
fn sweep_audit_counts_undecodable_receipt_as_missing() {
    let (_dir, vault) = open_vault();
    write_corrupt_redaction_receipt(&vault);
    // A not-due h: row: present (covering) but never reaches finalize.
    let future = crate::unix_seconds_now() + 86_400;
    let value = encode_hard_erase_sweep_job(
        RedactionScope::entity(&EntityId::now()),
        HardEraseSweepExtras::default(),
        future,
    )
    .unwrap();
    write_h_row(&vault, 4_242, &value);

    let run = run_hard_erase_sweep(&vault).unwrap();
    assert_eq!(run.jobs_processed, 0);
    assert!(
        run.obligations_undecodable >= 1,
        "an unreadable receipt must be counted by the audit, never silently covered"
    );
    assert_eq!(
        run.obligations_missing, 0,
        "present-but-corrupt is NOT a dropped obligation"
    );
}

/// Finding 3 (kept-and-loud): a decodable job whose `scope.entity_ids`
/// fails `EntityId::from_hex` is NEVER compacted-and-finalized. Its h:
/// row survives BYTE-IDENTICAL (no retry_state consumption), it defers,
/// and nothing is finalized. The inverse of the undecodable-h:-row case.
#[test]
fn sweep_malformed_scope_job_kept_loud_not_finalized() {
    let (_dir, vault) = open_vault();
    let bad_scope = RedactionScope {
        entity_ids: vec!["zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_owned()],
        revision_ids: Vec::new(),
    };
    let now = crate::unix_seconds_now();
    let value =
        encode_hard_erase_sweep_job(bad_scope, HardEraseSweepExtras::default(), now).unwrap();
    let key = write_h_row(&vault, 55, &value);

    let run = run_hard_erase_sweep(&vault).unwrap();
    assert_eq!(
        run.jobs_processed, 0,
        "a malformed-scope job must not finalize"
    );
    assert_eq!(run.receipts_finalized, 0);
    assert!(
        run.jobs_deferred >= 1,
        "the malformed job is kept and counted"
    );
    let rows = h_rows(&vault);
    let kept: Vec<_> = rows.iter().filter(|(k, _)| *k == key).collect();
    assert_eq!(kept.len(), 1, "the obligation row must survive");
    assert_eq!(
        kept[0].1, value,
        "the kept row must be BYTE-IDENTICAL (no retry_state consumption)"
    );
}

/// Finding 1/4 idempotency: once the race resolves (no further
/// concurrent writes), a clean re-run compacts the previously-raced
/// window, finalizes the receipt, deletes the h: row, and leaves ZERO
/// erased-payload bytes — defer-and-retry never strands the obligation.
#[cfg(feature = "sync")]
#[test]
fn sweep_raced_window_completes_on_clean_rerun() {
    use crate::sync::bridge::Materializer;
    use crate::sync::manager::WindowManager;
    use crate::sync::types::WindowKey;
    use std::sync::Arc;

    const UNIT_SENTINEL: &[u8] = b"UNIT-SWEEP-SENTINEL-3a9f17e2";

    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), test_config()).unwrap());
    let id = EntityId::now();
    put_entity(&vault, &id, 1_771_027_200, UNIT_SENTINEL);

    // Mirror the entity into the CRDT so the persisted history is a REAL
    // sentinel carrier, then close the window so it is compactable.
    let materializer = Arc::new(Materializer::new());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        materializer,
        "sweep-rerun",
    ));
    let window_key = WindowKey::from_timestamp(1_771_027_200);
    let window = manager.open_window(&window_key).unwrap();
    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    let receipt_id = outcome.receipt_id.expect("receipt id");
    let sweep_key = outcome.sweep_key.expect("sweep key");
    drop(window);
    assert!(manager.unload_window(&window_key).unwrap());

    // First run: the injected concurrent u:w: row defers the window.
    INJECT_RACE_BEFORE_COMPACT_WRITE.with(|c| c.set(RaceInjection::AppendUpdateRow));
    let run1 = run_hard_erase_sweep(&vault).unwrap();
    assert!(run1.windows_deferred_raced >= 1, "the race must defer");
    assert_eq!(run1.jobs_processed, 0);
    assert!(h_rows(&vault).iter().any(|(k, _)| *k == sweep_key));
    assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_none());

    // Clean re-run (injection is one-shot): the quiesced window compacts.
    let run2 = run_hard_erase_sweep(&vault).unwrap();
    assert_eq!(
        run2.jobs_processed, 1,
        "the re-run completes the obligation"
    );
    assert_eq!(run2.receipts_finalized, 1);
    assert!(
        !h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
        "the h: row is deleted on the clean re-run"
    );
    assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_some());
    assert!(
        !sync_rows_contain(&vault, UNIT_SENTINEL),
        "no erased-payload bytes may survive the idempotent re-run"
    );
}

/// R5 (ONE-1087/1091 final carrier fence — the SECOND TOCTOU): a `u:w:`
/// row that appears AFTER window compaction committed (state =
/// AllCompacted ⇒ zero u:w: rows anywhere) but BEFORE the finalize txn
/// must DEFER the job. The in-txn fence (the FIRST step of the same write
/// txn that would delete the h: row) sees the post-compaction carrier and
/// aborts with NO mutation: the h: row is KEPT, the receipt stays nil,
/// `jobs_deferred` is incremented, and — crucially — the job is NOT
/// routed to retry (a transient race must never burn a retry attempt). A
/// no-fence impl deletes the h: row and finalizes the receipt → fails.
#[cfg(feature = "sync")]
#[test]
fn sweep_defers_when_uw_carrier_appears_after_compaction_before_finalize() {
    use crate::sync::bridge::Materializer;
    use crate::sync::manager::WindowManager;
    use crate::sync::types::WindowKey;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), test_config()).unwrap());
    let id = EntityId::now();
    put_entity(&vault, &id, 1_771_027_200, b"final-fence-body");

    // Mirror the entity into a real CRDT window, then close it so the
    // sweep can compact it to AllCompacted (zero u:w: rows). This is the
    // ONLY state that reaches finalize_job — the fence's precondition.
    let materializer = Arc::new(Materializer::new());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        materializer,
        "final-fence",
    ));
    let window_key = WindowKey::from_timestamp(1_771_027_200);
    let window = manager.open_window(&window_key).unwrap();
    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    let receipt_id = outcome.receipt_id.expect("receipt id");
    let sweep_key = outcome.sweep_key.expect("sweep key");
    let job_value_before = h_rows(&vault)
        .iter()
        .find(|(k, _)| *k == sweep_key)
        .expect("job row")
        .1
        .clone();
    drop(window);
    assert!(manager.unload_window(&window_key).unwrap());

    // Arm the seam: a valid u:w: row lands in the gap between
    // compaction-commit and the finalize txn (its own committed txn).
    let window_label = crate::deletion::window_label_from_timestamp(1_771_027_200);
    INJECT_UW_ROW_BEFORE_FINALIZE.with(|cell| *cell.borrow_mut() = Some(window_label.clone()));

    let run = run_hard_erase_sweep(&vault).unwrap();

    assert_eq!(
        run.jobs_processed, 0,
        "a post-compaction carrier must defer, not finalize"
    );
    assert_eq!(run.receipts_finalized, 0);
    assert!(
        run.jobs_deferred >= 1,
        "the raced-in u:w: carrier must defer the job"
    );
    assert_eq!(
        run.jobs_failed, 0,
        "a transient post-compaction race is NOT a failure (no retry consumed)"
    );

    // The h: row survives BYTE-IDENTICAL: the defer must not consume
    // retry_state (no rewrite_job_for_retry).
    let rows = h_rows(&vault);
    let kept: Vec<_> = rows.iter().filter(|(k, _)| *k == sweep_key).collect();
    assert_eq!(kept.len(), 1, "the obligation row must survive the fence");
    assert_eq!(
        kept[0].1, job_value_before,
        "deferral must not consume retry_state (byte-identical row)"
    );
    assert!(
        receipt_sweep_complete_at(&vault, &receipt_id).is_none(),
        "the receipt must stay nil — the fence aborts before any mutation"
    );
}

/// R6 (ONE-1087/1091 raw receipt validation before decode): a stored
/// type-120 REDACTION_AUDIT body that carries every required field PLUS
/// one UNKNOWN key decodes fine via Serde (which drops unknown fields)
/// but is rejected by the raw `validate_redaction_receipt_body` — which
/// `finalize_job` now runs on the STORED bytes BEFORE decode. The
/// validator's `InvalidRedactionReceiptBody` is mapped to the exact
/// `CorruptedIndex("redaction audit receipt body")` literal so the
/// per-job retry arm catches it: the h: row is KEPT, the receipt stays
/// nil, the job routes to retry, and the WHOLE run does NOT hard-error.
/// The buggy re-encode-then-validate impl (validating only the
/// already-stripped body) finalizes and deletes the h: row → fails.
#[test]
fn sweep_unknown_field_receipt_keeps_h_row_not_finalized() {
    use rmpv::Value;

    let (_dir, vault) = open_vault();
    let id = EntityId::now();
    put_entity(&vault, &id, 1_771_027_200, b"unknown-field-receipt-body");
    let outcome = vault
        .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
        .unwrap();
    let receipt_id = outcome.receipt_id.expect("receipt id");
    let sweep_key = outcome.sweep_key.expect("sweep key");

    // Sanity: the receipt is a pending sweep target (queued, not yet
    // swept) — exactly what finalize_job would otherwise finalize.
    assert!(
        receipt_sweep_complete_at(&vault, &receipt_id).is_none(),
        "receipt must start unswept"
    );

    // Rewrite the STORED receipt body to add one UNKNOWN key. Start from
    // the real, valid body (so all required fields + types are present
    // and Serde still decodes it), then append a key outside the pinned
    // RECEIPT_BODY_KEYS set — the discriminator the raw validator rejects.
    let header_len = crate::batch::ENTITY_METADATA_HEADER_LEN;
    let raw = vault.get_raw(&receipt_id).unwrap().expect("receipt raw");
    let mut cursor = std::io::Cursor::new(&raw[header_len..]);
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).unwrap() else {
        panic!("receipt body must be a map");
    };
    entries.push((
        Value::String("smuggled_unknown_field".into()),
        Value::Boolean(true),
    ));
    let mut tampered_body = Vec::new();
    rmpv::encode::write_value(&mut tampered_body, &Value::Map(entries)).unwrap();
    // The tampered body still Serde-decodes (unknown field ignored)...
    assert!(
        decode_redaction_audit_receipt(&tampered_body).is_ok(),
        "Serde must still decode (unknown field dropped) — the gap R6 closes"
    );
    // ...but the raw validator rejects it (the only safety net).
    assert!(
        validate_redaction_receipt_body(&tampered_body).is_err(),
        "the raw validator must reject the unknown field"
    );
    let mut rewritten = Vec::with_capacity(header_len + tampered_body.len());
    rewritten.extend_from_slice(&raw[..header_len]);
    rewritten.extend_from_slice(&tampered_body);
    {
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .entities
            .put(&mut wtxn, receipt_id.as_bytes(), &rewritten)
            .unwrap();
        wtxn.commit().unwrap();
    }

    // The run must NOT hard-error (the .map_err keeps it a per-job retry).
    let run = run_hard_erase_sweep(&vault).expect("run must not hard-abort");
    assert_eq!(
        run.jobs_processed, 0,
        "an unknown-field receipt must not finalize"
    );
    assert_eq!(run.receipts_finalized, 0);
    assert!(run.jobs_failed >= 1, "the job must route to retry");

    // The obligation row is KEPT (fail-closed, undecodable-receipt
    // posture) and the receipt stays nil.
    assert!(
        h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
        "the h: row must be kept when the stored receipt body is invalid"
    );
    assert!(
        receipt_sweep_complete_at(&vault, &receipt_id).is_none(),
        "the receipt must stay nil — finalize aborts before mutation"
    );
}
