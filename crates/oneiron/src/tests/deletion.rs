//! Entity deletion: soft/hard erase, redaction receipts, hard-erase sweep, raced deletes.

use super::*;

#[test]
fn user_delete_soft_erases_active_payload_without_receipt_or_sweep() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let secret = b"soft-erase-active-secret";

    vault
        .batch()
        .put(&id, 1, test_time_range(10, 10), 20, secret)
        .text(&id, &[("body", "soft-erase-active-secret")])
        .commit()?;

    assert_eq!(vault.get(&id)?.as_deref(), Some(secret.as_slice()));
    assert_eq!(vault.search_text("active-secret", 10)?.len(), 1);

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserDelete)?;

    assert!(outcome.existed);
    assert!(outcome.receipt_id.is_none());
    assert!(outcome.sweep_key.is_none());
    assert_eq!(vault.get(&id)?.as_deref(), Some([].as_slice()));
    assert!(vault.search_text("active-secret", 10)?.is_empty());
    assert!(vault.entities_by_type(1)?.contains(&id));
    assert!(redaction_audit_receipts(&vault)?.is_empty());
    assert!(hard_erase_sweep_rows(&vault)?.is_empty());
    Ok(())
}

#[test]
fn user_hard_delete_writes_opaque_redaction_audit_receipt() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let payload = b"Alice secret body predicate should never enter receipt";

    vault.put_entity(&id, 1, test_time_range(100, 100), 101, payload)?;

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserHardDelete)?;
    let receipt_id = outcome
        .receipt_id
        .expect("user_hard_delete must write REDACTION_AUDIT receipt");
    assert_eq!(
        vault.get_entity_type(&receipt_id)?,
        Some(ENTITY_TYPE_REDACTION_AUDIT)
    );

    let raw = vault
        .get_raw(&receipt_id)?
        .expect("receipt entity should be persisted");
    assert_no_receipt_payload_leak(&raw, &[b"Alice", b"secret body", b"predicate"]);

    let receipt = receipt_body(&raw);
    assert_receipt_fields(&receipt);
    assert_eq!(receipt["reason"], "user_hard_delete");
    assert_eq!(receipt["scope"]["entity_ids"][0], id.to_hex());
    assert_eq!(
        receipt["scope"]["revision_ids"].as_array().unwrap().len(),
        0
    );
    assert!(
        receipt["affected_revision_ids"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(receipt["sweep_queued_at"].as_u64().is_some());
    assert!(receipt["sweep_complete_at"].is_null());
    // ONE-1140 (OD-6) versions the M4 "verification empty" pin: every
    // minted receipt now carries EXACTLY the four att_ attestation entries
    // (lowercase hex strings, pinned lengths). Still opaque — hex
    // identifiers and a signature, never content.
    let verification = receipt["verification"].as_object().unwrap();
    let mut keys: Vec<&str> = verification.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["att_client", "att_pk", "att_sig", "att_v"]);
    let is_lower_hex = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let att_client = verification["att_client"].as_str().unwrap();
    assert_eq!(att_client.len(), 16);
    assert!(is_lower_hex(att_client));
    let att_pk = verification["att_pk"].as_str().unwrap();
    assert_eq!(att_pk.len(), 64);
    assert!(is_lower_hex(att_pk));
    let att_sig = verification["att_sig"].as_str().unwrap();
    assert_eq!(att_sig.len(), 128);
    assert!(is_lower_hex(att_sig));
    assert_eq!(verification["att_v"], "1");
    Ok(())
}

#[test]
fn redaction_receipt_indexes_temporal_occurred_start_as_point_event() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    // Seed the to-be-deleted subject as TURN (type 1), a non-claim type whose
    // body stays opaque: type 0 is CLAIM and gains a validated body ABI
    // (ONE-1104), which would reject this seed before the hard delete runs.
    vault.put_entity(&id, 1, test_time_range(300, 300), 301, b"index-me")?;

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserHardDelete)?;
    let receipt_id = outcome.receipt_id.expect("receipt id");

    // The `hard_purge_complete_at` timestamp inside the receipt BODY is the
    // independent oracle: the receipt writer sets occurred_start ==
    // occurred_end == learned_at == hard_purge_complete_at (point event).
    let raw = vault.get_raw(&receipt_id)?.expect("receipt record");
    let receipt = receipt_body(&raw);
    let purge_at = receipt["hard_purge_complete_at"]
        .as_u64()
        .expect("hard_purge_complete_at");

    // contracts.ts dbManifest n:18 — temporal_occurred_start key is
    // (timestamp, entity_id) with value (): timestamp u64 BE (8 B) followed
    // by the entity id (16 B), exactly the shape apply_put writes.
    let mut expected_key = [0_u8; 24];
    expected_key[..8].copy_from_slice(&purge_at.to_be_bytes());
    expected_key[8..].copy_from_slice(receipt_id.as_bytes());

    let rtxn = vault.store.env.read_txn()?;
    let lower = purge_at.to_be_bytes();
    let upper = purge_at.checked_add(1).expect("range upper").to_be_bytes();
    let mut matches = 0_usize;
    for entry in vault.store.temporal_occurred_start.range(
        &rtxn,
        &(
            std::ops::Bound::Included(&lower[..]),
            std::ops::Bound::Excluded(&upper[..]),
        ),
    )? {
        let (key, value) = entry?;
        assert_eq!(key.len(), 24, "temporal_occurred_start key must be 24 B");
        if key[8..] == receipt_id.as_bytes()[..] {
            assert_eq!(key, expected_key.as_slice());
            assert!(value.is_empty(), "n:18 value must be ()");
            matches += 1;
        }
    }
    assert_eq!(
        matches, 1,
        "receipt must be discoverable via a temporal_occurred_start range scan"
    );

    // Point-event semantics IDENTICAL to apply_put (start == end): no
    // temporal_occurred_end row and no temporal_long_intervals row may exist
    // for the receipt anywhere in either DB.
    for entry in vault.store.temporal_occurred_end.iter(&rtxn)? {
        let (key, _) = entry?;
        assert_eq!(key.len(), 24, "temporal_occurred_end key must be 24 B");
        assert!(
            key[8..] != receipt_id.as_bytes()[..],
            "point-event receipt must not write a temporal_occurred_end row"
        );
    }
    for entry in vault.store.temporal_long_intervals.iter(&rtxn)? {
        let (key, _) = entry?;
        assert_eq!(key.len(), 24, "temporal_long_intervals key must be 24 B");
        assert!(
            key[8..] != receipt_id.as_bytes()[..],
            "zero-span receipt must not write a temporal_long_intervals row"
        );
    }

    // Pre-existing receipt index footprint is unchanged.
    let learned_key = Store::encode_temporal_key(purge_at, &receipt_id);
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &learned_key)?
            .is_some()
    );
    let type_key = Store::encode_type_key(ENTITY_TYPE_REDACTION_AUDIT, &receipt_id);
    assert!(vault.store.type_index.get(&rtxn, &type_key)?.is_some());
    // Maintenance kinds carry no short ID.
    assert!(
        vault
            .store
            .short_ids
            .get(&rtxn, receipt_id.as_bytes())?
            .is_none()
    );
    Ok(())
}

#[test]
fn hard_delete_enqueues_bounded_historical_carrier_sweep() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault.put_entity(&id, 1, test_time_range(200, 200), 201, b"sweep-me")?;

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserHardDelete)?;
    let sweep_key = outcome
        .sweep_key
        .expect("user_hard_delete must enqueue historical-carrier sweep");
    assert!(sweep_key.starts_with(b"h:"));

    let rows = hard_erase_sweep_rows(&vault)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, sweep_key);

    let job: serde_json::Value = rmp_serde::from_slice(&rows[0].1).expect("decode sweep job");
    let mut job_fields: Vec<&str> = job
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    job_fields.sort_unstable();
    assert_eq!(job_fields, vec!["retry_state", "scope"]);
    assert_eq!(job["scope"]["entity_ids"][0], id.to_hex());
    assert_eq!(
        job["scope"]["carrier_classes"],
        serde_json::json!([
            "historical_loro_updates",
            "historical_loro_snapshots",
            "derived_carriers",
            "redirect_table"
        ])
    );
    assert_eq!(job["retry_state"]["attempt_count"], 0);
    assert!(job["retry_state"]["last_error_code"].is_null());
    let queued_at = job["retry_state"]["queued_at"].as_u64().unwrap();
    let deadline_at = job["retry_state"]["deadline_at"].as_u64().unwrap();
    assert!(deadline_at >= queued_at);
    assert!(deadline_at <= queued_at + 30 * 86_400);

    let receipt_id = outcome.receipt_id.expect("receipt id");
    let receipt_raw = vault.get_raw(&receipt_id)?.expect("receipt");
    let receipt = receipt_body(&receipt_raw);
    assert_eq!(receipt["sweep_queued_at"].as_u64(), Some(queued_at));
    assert!(receipt["sweep_complete_at"].is_null());
    Ok(())
}

/// ARCH-0055 §9 (r6) end to end: hard-erasing a canonical head empties its
/// redirect shell, widens the erasure's sweep scope to cover the shell's
/// historical carriers, drops the author stamp from the type-76 event the
/// walk touched — and does NOT turn the shell into a deletion (§10:
/// merge-away is not deletion).
#[test]
fn hard_erase_of_a_merge_head_cascades_to_its_redirect_shell() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let survivor = EntityId::now();
    let loser = EntityId::now();
    for id in [&actor, &survivor, &loser] {
        vault.put_entity(
            id,
            ENTITY_TYPE_PERSON,
            test_time_range(200, 200),
            201,
            b"cascade fixture body",
        )?;
    }

    let event = match vault.apply_identity_topology_op(
        &crate::identity_topology::IdentityTopologyOp::Merge(crate::identity_topology::MergeOp {
            sources: vec![loser],
            survivor,
            evidence: crate::identity_topology::IdentityOpEvidence::default(),
            survivorship_plan: crate::identity_topology::SurvivorshipPlan::ReadThrough,
        }),
        &crate::identity_topology::IdentityOpWrite::auto(ClaimSource::Inferred)
            .with_actor(WriteActor::new(actor, EdgeActorClass::Human)),
        202,
    )? {
        crate::identity_topology::IdentityOpOutcome::Applied { event, .. } => event,
        outcome => panic!("auto merge must apply, got {outcome:?}"),
    };
    assert_eq!(vault.resolve_entity(&loser)?, vec![survivor]);
    assert!(!vault.get(&loser)?.expect("shell body").is_empty());

    let outcome = vault.delete_entity_with_reason(&survivor, DeleteReason::UserHardDelete)?;
    assert!(outcome.existed);

    // The leak r6 §9 names: neither the head nor its shell may still read.
    assert_eq!(vault.get(&survivor)?, None);
    assert_eq!(vault.get(&loser)?.expect("shell row").len(), 0);
    assert_eq!(vault.count_dangling_redirect_payloads()?, 0);

    // §10: the shell was EMPTIED, not deleted — its row survives and it
    // carries no hard-delete marker of its own.
    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.local_hard_delete_marker_exists_in_txn(&rtxn, &survivor)?);
    assert!(!vault.local_hard_delete_marker_exists_in_txn(&rtxn, &loser)?);
    drop(rtxn);

    // The shell rides the head's `h:` row, or its historical carriers are
    // never swept and the bytes survive in history.
    let rows = hard_erase_sweep_rows(&vault)?;
    assert_eq!(rows.len(), 1);
    let job: serde_json::Value = rmp_serde::from_slice(&rows[0].1).expect("decode sweep job");
    let scoped: BTreeSet<String> = job["scope"]["entity_ids"]
        .as_array()
        .expect("entity_ids array")
        .iter()
        .map(|hex| hex.as_str().expect("hex string").to_owned())
        .collect();
    assert_eq!(scoped, BTreeSet::from([survivor.to_hex(), loser.to_hex()]));

    // The author-stamp rider: the touched merge event loses its actor while
    // staying the same effective ledger event (same seq, same action, and a
    // shell state the fold still speaks for).
    let raw = vault.get_raw(&event)?.expect("ledger event");
    let stored = crate::identity_topology::decode_identity_topology_event_body(
        &raw[ENTITY_METADATA_HEADER_LEN..],
    )?;
    assert_eq!(stored.actor, None);
    assert_eq!(
        stored.action,
        crate::identity_topology::StoredIdentityOpAction::Merge {
            sources: vec![loser],
            survivor,
        }
    );
    Ok(())
}

#[test]
fn hard_delete_sweep_sequence_self_heals_stale_cursor_on_collision() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(
        &id,
        1,
        test_time_range(250, 250),
        251,
        b"repair-sweep-cursor",
    )?;

    let stale_seq = 6_u64;
    let existing_seq = 7_u64;
    let repaired_seq = 8_u64;
    let existing_key = encode_hard_erase_sweep_key(existing_seq);
    let existing_value = encode_hard_erase_sweep_job(
        RedactionScope::entity(&EntityId::now()),
        HardEraseSweepExtras::default(),
        1_772_000_000,
    )?;

    vault.with_write_txn(|wtxn| {
        vault.store.sync_queue.put(
            wtxn,
            LAST_HARD_ERASE_SWEEP_SEQ_KEY,
            &stale_seq.to_le_bytes(),
        )?;
        vault
            .store
            .sync_queue
            .put(wtxn, &existing_key, &existing_value)?;
        Ok(())
    })?;

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserHardDelete)?;
    assert_eq!(
        outcome.sweep_key.as_deref(),
        Some(encode_hard_erase_sweep_key(repaired_seq).as_slice())
    );

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault
            .store
            .sync_queue
            .get(&rtxn, LAST_HARD_ERASE_SWEEP_SEQ_KEY)?
            .as_deref(),
        Some(repaired_seq.to_le_bytes().as_slice())
    );
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &encode_hard_erase_sweep_key(repaired_seq))?
            .is_some(),
        "new sweep job should be written after repairing the stale cursor",
    );
    Ok(())
}

#[test]
fn gdpr_and_policy_deletes_soft_erase_then_active_purge_with_receipts() -> Result<()> {
    for reason in [DeleteReason::GdprDelete, DeleteReason::PolicyDelete] {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();
        vault
            .batch()
            .put(&id, 1, test_time_range(300, 300), 301, b"regulated secret")
            .text(&id, &[("body", "regulated secret")])
            .commit()?;

        let outcome = vault.delete_entity_with_reason(&id, reason)?;

        assert!(outcome.existed);
        assert!(vault.get(&id)?.is_none());
        assert!(vault.search_text("regulated", 10)?.is_empty());
        assert!(outcome.receipt_id.is_some());
        assert!(outcome.sweep_key.is_some());

        let receipt_raw = vault
            .get_raw(&outcome.receipt_id.unwrap())?
            .expect("receipt should be persisted");
        let receipt = receipt_body(&receipt_raw);
        assert_eq!(receipt["reason"], reason.as_str());
        assert!(
            receipt["soft_complete_at"].as_u64().unwrap()
                <= receipt["hard_purge_complete_at"].as_u64().unwrap()
        );
    }
    Ok(())
}

#[test]
fn receipt_reason_purges_orphan_vector_with_receipt_and_sweep() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    assert!(vault.get(&id)?.is_none());
    assert!(vault.get_vector(&id)?.is_some());

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::GdprDelete)?;

    assert!(
        !outcome.existed,
        "orphan cleanup should not report an entity payload"
    );
    assert!(
        outcome.receipt_id.is_some(),
        "receipt-writing delete must account for orphan active data"
    );
    assert!(
        outcome.sweep_key.is_some(),
        "orphan active purge still queues the bounded historical-carrier sweep"
    );
    assert!(vault.get_vector(&id)?.is_none());

    let receipt_raw = vault
        .get_raw(&outcome.receipt_id.unwrap())?
        .expect("orphan purge receipt should be persisted");
    let receipt = receipt_body(&receipt_raw);
    assert_eq!(receipt["reason"], "gdpr_delete");
    assert_eq!(receipt["scope"]["entity_ids"][0], id.to_hex());
    assert!(receipt["sweep_complete_at"].is_null());

    let rows = hard_erase_sweep_rows(&vault)?;
    assert_eq!(rows.len(), 1);
    Ok(())
}

/// ONE-1149 FULLY-MISSING case: an id that NEVER had a delete scope is a
/// STRICT no-op for every reason — `missing()` outcome and ZERO side
/// effects, not even a propagating tombstone: no CRDT tombstone publish
/// (`d:w:` snapshot), no `q:`/`d:` queue rows, no `dt:` marker, no `pt:`
/// marker, no receipt, no sweep row. This is the deliberate contrast to the
/// RACED-TO-NOTHING case (`*_raced_to_nothing_*` below), where the scope
/// existed at the read-probe and only raced away before the purge txn, so
/// the already-published CRDT tombstone + `d:`/`q:` propagation rows + a
/// guarded `dt:` marker legitimately survive as idempotent propagation
/// intent. A wrong implementation that mints/publishes the tombstone before
/// proving there is something to erase leaves a `d:w:` row or queue rows
/// behind and fails this test.
#[test]
fn delete_missing_id_is_strict_noop_for_every_reason() -> Result<()> {
    for reason in [
        DeleteReason::UserDelete,
        DeleteReason::UserHardDelete,
        DeleteReason::GdprDelete,
        DeleteReason::PolicyDelete,
    ] {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();

        let outcome = vault.delete_entity_with_reason(&id, reason)?;

        assert_eq!(
            outcome,
            DeleteEntityOutcome {
                existed: false,
                receipt_id: None,
                sweep_key: None,
            },
            "{reason:?}: a fully-missing id must report missing()"
        );
        assert_no_erasure_audit_artifacts(&vault)?;
        assert!(
            sync_state_value(&vault, &format!("dt:{}", id.to_hex()))?.is_none(),
            "{reason:?}: a fully-missing id must not gain a dt: hard-delete marker"
        );
        assert!(
            sync_state_keys_with_prefix_raw(&vault, "d:w:")?.is_empty(),
            "{reason:?}: no CRDT tombstone may be published for a fully-missing id"
        );
        assert_eq!(
            sync_queue_row_count_with_prefix(&vault, b"q:")?,
            0,
            "{reason:?}: no update queue row may exist for a fully-missing id"
        );
        assert_eq!(
            sync_queue_row_count_with_prefix(&vault, b"d:")?,
            0,
            "{reason:?}: no delete-bearing queue row may exist for a fully-missing id"
        );
    }
    Ok(())
}

/// ONE-1149 headerless RACED-TO-NOTHING leg: a hard delete of orphan
/// residue whose scope existed at the read probe but is raced away before
/// the purge txn must NOT emit a receipt, sweep row, or `pt:` marker (the
/// pre-fix code emitted all three — a false GDPR audit). Only the guarded
/// `dt:` marker and the already-published idempotent CRDT tombstone (with
/// its `d:`/`q:` propagation rows) legitimately survive.
#[test]
fn headerless_delete_raced_to_nothing_emits_no_receipt_sweep_or_pt() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    for attempt in 0..3 {
        let id = EntityId::now();
        vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;

        let outcome = run_raced_delete(&vault, &id, DeleteReason::GdprDelete, |wtxn| {
            crate::hnsw::hnsw_deindex(&vault.store, wtxn, &id)?;
            vault.store.vectors.delete(wtxn, id.as_bytes())?;
            Ok(())
        })?;

        let Some(dt_marker) = sync_state_value(&vault, &format!("dt:{}", id.to_hex()))? else {
            // Scheduling miss: the deleter probed after the commit and took
            // the strict-noop path. Verify it wrote nothing, then retry.
            assert_eq!(outcome, DeleteEntityOutcome::missing());
            assert_no_erasure_audit_artifacts(&vault)?;
            assert!(
                attempt < 2,
                "raced branch was never constructed in 3 attempts"
            );
            continue;
        };

        // gdpr_delete pinned wire byte = 3.
        assert_raced_delete_artifacts(&vault, &outcome, &dt_marker, 3)?;
        return Ok(());
    }
    unreachable!("the attempt loop either returns or panics");
}

/// ONE-1149 headerful RACED-TO-NOTHING leg: a hard delete whose entity (and
/// full delete scope) existed at the header read but is raced away before
/// the purge txn must NOT emit a receipt, sweep row, or `pt:` marker. Only
/// the guarded `dt:` marker and the already-published idempotent CRDT
/// tombstone (with its `d:`/`q:` propagation rows) legitimately survive.
#[test]
fn headerful_delete_raced_to_nothing_emits_no_receipt_sweep_or_pt() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let learned_at = 1_772_000_000;

    for attempt in 0..3 {
        let id = EntityId::now();
        vault
            .batch()
            .put(
                &id,
                1,
                test_time_range(learned_at, learned_at),
                learned_at,
                b"raced-away-before-purge",
            )
            .commit()?;

        let outcome = run_raced_delete(&vault, &id, DeleteReason::UserHardDelete, |wtxn| {
            // Erase the FULL delete scope the way a racing hard delete would.
            crate::batch::deindex_entity(&vault.store, wtxn, &id)?;
            Ok(())
        })?;

        let Some(dt_marker) = sync_state_value(&vault, &format!("dt:{}", id.to_hex()))? else {
            assert_eq!(outcome, DeleteEntityOutcome::missing());
            assert_no_erasure_audit_artifacts(&vault)?;
            assert!(
                attempt < 2,
                "raced branch was never constructed in 3 attempts"
            );
            continue;
        };

        // user_hard_delete pinned wire byte = 2.
        assert_raced_delete_artifacts(&vault, &outcome, &dt_marker, 2)?;
        return Ok(());
    }
    unreachable!("the attempt loop either returns or panics");
}

/// ONE-1149 false-NEGATIVE guard (delete-safety): the headerful delete's
/// IN-TXN ownership probe checks the FULL delete scope, not just the
/// entities row. A headerful entity whose entities row is raced away while a
/// vector + a BM25 posting survive keeps `active_delete_scope_exists_in_txn`
/// TRUE, so the purge runs, the residue IS erased, and a REAL receipt is
/// emitted even though the outcome reports `existed:false` (the entities row
/// was already gone — the two meanings of "existed": entities-row erased vs
/// any-scope erased). A "gate the receipt on the entities-row `existed`" /
/// "return early on the missing header" implementation would skip the
/// receipt and silently erase the residue with NO audit — the mirror of the
/// raced-to-nothing false-POSITIVE this ticket also closes. `UserHardDelete`
/// is used deliberately: unlike `GdprDelete`/`PolicyDelete` it runs no
/// pre-purge SoftErase, so the vector + BM25 residue survives to the in-txn
/// probe.
///
/// DETERMINISM (ONE-1149 round-2): the deleter now races through the
/// `run_raced_delete_rendezvous` seam, which orders its lock-free
/// `read_entity_header` read BEFORE the eraser commit, so the HEADERFUL leg
/// runs EVERY run (the bare-barrier variant could rarely lose the
/// read-vs-commit race and divert to the headerless path, leaving this test
/// nondeterministic). With the headerful leg pinned, a DISCRIMINATOR assertion
/// proves the published CRDT tombstone landed in the HEADERFUL window
/// `window_label_from_timestamp(header.learned_at)` (computed from the entity's
/// stored `learned_at`), NOT the now-derived window the headerless leg
/// addresses (`window_label_from_timestamp(now)`). A wrong impl that takes the
/// headerless path lands the tombstone in the now-window and fails; a wrong
/// impl that early-returns on the missing header emits no receipt and fails the
/// receipt assertion — non-tautological in both directions.
#[test]
fn headerful_delete_partial_residue_survives_emits_receipt_existed_false() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let learned_at = 1_772_000_000;
    let id = EntityId::now();
    vault
        .batch()
        .put(
            &id,
            1,
            test_time_range(learned_at, learned_at),
            learned_at,
            b"partial-residue",
        )
        .text(&id, &[("body", "partial-residue")])
        .commit()?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    assert_eq!(vault.search_text("partial-residue", 10)?.len(), 1);

    // DISCRIMINATOR setup: the headerful leg addresses the tombstone window by
    // the entity's stored `learned_at`; the headerless leg would address it by
    // `now`. Assert the two windows are genuinely different so the
    // discriminator below is meaningful (a same-window fixture would make the
    // assertion vacuous).
    let headerful_window = crate::deletion::window_label_from_timestamp(learned_at);
    let now_window = crate::deletion::window_label_from_timestamp(crate::unix_seconds_now());
    assert_ne!(
        headerful_window, now_window,
        "fixture invariant: learned_at must fall in a different window than now, \
         else the headerful-vs-headerless window discriminator is vacuous"
    );

    // The race erases ONLY the entities row (header), the way a concurrent
    // delete that lost the purge race would, leaving the vector + BM25
    // posting as live residue the in-txn full-scope probe must still catch.
    // The rendezvous seam forces the deleter's header read to win, so the
    // HEADERFUL leg runs deterministically every run.
    let outcome = run_raced_delete_rendezvous(&vault, &id, DeleteReason::UserHardDelete, |wtxn| {
        vault.store.entities.delete(wtxn, id.as_bytes())?;
        Ok(())
    })?;

    // existed:false (the entities row was raced away) BUT a real erasure
    // happened and is audited.
    assert!(
        !outcome.existed,
        "the entities row was raced away ⇒ outcome reports existed:false"
    );
    assert!(
        outcome.receipt_id.is_some(),
        "surviving residue ⇒ a REAL receipt is emitted (false-NEGATIVE guard)"
    );
    assert!(
        outcome.sweep_key.is_some(),
        "surviving residue ⇒ an h: sweep row is queued"
    );
    assert_eq!(
        redaction_audit_receipts(&vault)?.len(),
        1,
        "exactly one REDACTION_AUDIT receipt for the erased residue"
    );
    assert_eq!(
        hard_erase_sweep_rows(&vault)?.len(),
        1,
        "exactly one h: sweep row for the erased residue"
    );
    // The residue is actually erased — no leak past the audit.
    assert!(
        vault.get_vector(&id)?.is_none(),
        "the surviving vector residue must be purged"
    );
    assert!(
        vault.search_text("partial-residue", 10)?.is_empty(),
        "the surviving BM25 posting must be purged"
    );

    // DISCRIMINATOR: the published tombstone is addressed by the HEADERFUL
    // window (`learned_at`), proving the headerful leg ran. In sync builds the
    // CRDT tombstone snapshot is a `d:w:{window}` row; in non-sync builds
    // `write_crdt_tombstone` is a no-op so the surviving `pt:{window}:{id}`
    // pending-tombstone marker (kept because `crdt_persisted` is false) is the
    // window witness. Either way the window segment MUST be the headerful
    // window and never the now-window.
    #[cfg(feature = "sync")]
    {
        // The persisted snapshot key is exactly `d:w:{window}` (no trailing
        // colon — that's the `u:w:{window}:` update-row grammar).
        let dw_keys = sync_state_keys_with_prefix_raw(&vault, "d:w:")?;
        assert_eq!(
            dw_keys.len(),
            1,
            "exactly one CRDT tombstone snapshot row for the headerful delete"
        );
        assert_eq!(
            dw_keys[0],
            format!("d:w:{headerful_window}"),
            "the CRDT tombstone must land in the HEADERFUL window \
             (window_label_from_timestamp(header.learned_at)); a headerless-path \
             execution would key it to the now-window (d:w:{now_window}) instead"
        );
        assert_ne!(
            dw_keys[0],
            format!("d:w:{now_window}"),
            "the CRDT tombstone must NOT land in the now-window (the headerless leg's address)"
        );
    }
    #[cfg(not(feature = "sync"))]
    {
        let pt_keys = sync_state_keys_with_prefix_raw(&vault, "pt:")?;
        assert_eq!(
            pt_keys.len(),
            1,
            "non-sync: the pending-tombstone marker survives (crdt_persisted=false) \
             and is the headerful-window witness"
        );
        assert_eq!(
            pt_keys[0],
            format!("pt:{headerful_window}:{}", id.to_hex()),
            "the pt: marker must be keyed to the HEADERFUL window \
             (window_label_from_timestamp(header.learned_at)), never the now-window"
        );
    }
    Ok(())
}

/// ONE-1149 end-to-end convergence — the anti-(A) invariant (delete-safety).
/// A `GdprDelete` that LOSES the race to a tombstone-LESS full-scope batch
/// erase (`vault.batch().delete(E)` ⇒ `BatchOp::Delete` ⇒ `deindex_entity`,
/// which publishes NO CRDT tombstone) erases nothing locally — so it emits
/// no receipt / sweep / `pt:` (RACED-TO-NOTHING) — but it STILL publishes
/// its own CRDT tombstone + `d:`/`q:` propagation rows BEFORE claiming write
/// ownership. That published tombstone is the ONLY convergence net: the
/// rejected "reorder to `dt:`-only / suppress the tombstone publish"
/// implementation would leave NO propagating record, and a peer that still
/// holds E would keep it forever — a silently dropped GDPR delete. This test
/// pins that the origin's window, applied to a peer that still holds E,
/// purges E. (A wrong `dt:`-only impl FAILS the convergence assertion.)
#[cfg(feature = "sync")]
#[test]
fn raced_gdpr_delete_against_batch_delete_still_converges() -> Result<()> {
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_contains_binary;
    use crate::sync::types::WindowKey;
    use crate::sync::window;

    let learned_at = 1_772_000_000;
    let window_key = WindowKey::from_timestamp(learned_at);
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault
        .batch()
        .put(
            &id,
            1,
            test_time_range(learned_at, learned_at),
            learned_at,
            b"converge-secret",
        )
        .commit()?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;

    // The bare barrier did not order the header read before the erase commit;
    // Linux could take the FULLY-MISSING path on every retry. The existing
    // post-header-read rendezvous forces the HEADERFUL path while the eraser
    // holds LMDB's write lock. Its commit then releases tombstone publication
    // followed by GDPR soft-erase and purge, both of which find no local scope.
    let outcome = run_raced_delete_rendezvous(&vault, &id, DeleteReason::GdprDelete, |wtxn| {
        crate::batch::deindex_entity(&vault.store, wtxn, &id)?;
        Ok(())
    })?;
    let dt_marker = sync_state_value(&vault, &format!("dt:{}", id.to_hex()))?
        .expect("the rendezvous must construct the raced-to-nothing branch");

    // Origin RACED-TO-NOTHING: no false audit, but the convergent CRDT
    // tombstone + exactly one d:/q: propagation pair survive. gdpr_delete
    // pinned wire byte = 3.
    assert_raced_delete_artifacts(&vault, &outcome, &dt_marker, 3)?;
    assert!(vault.get_raw(&id)?.is_none());
    assert!(vault.get_vector(&id)?.is_none());
    let origin_doc = window::load_window_from_state(&vault, "origin", &window_key)?;
    assert!(
        map_contains_binary(&origin_doc.get_map("tombstones"), id.to_hex().as_str()),
        "the raced GdprDelete must still publish a convergent CRDT tombstone"
    );

    // A fresh peer still holds E; applying the origin window must
    // converge it away (the dropped-GDPR-delete net the anti-(A)
    // invariant guarantees).
    let (_peer_dir, peer) = open_test_vault();
    peer.batch()
        .put(
            &id,
            1,
            test_time_range(learned_at, learned_at),
            learned_at,
            b"converge-secret",
        )
        .commit()?;
    peer.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    assert!(
        peer.get_raw(&id)?.is_some(),
        "peer fixture must hold E before convergence"
    );
    assert!(peer.get_vector(&id)?.is_some());
    assert_eq!(peer.search_vector(&[0.1, 0.2, 0.3, 0.4], 10)?.len(), 1);

    let materializer = Materializer::new();
    window::forward_rematerialize(&peer, &origin_doc, &materializer, &window_key)?;
    assert!(
        peer.get_raw(&id)?.is_none(),
        "applying the origin window to the peer must purge E (convergence net)"
    );
    assert!(peer.get_vector(&id)?.is_none());
    assert!(peer.search_vector(&[0.1, 0.2, 0.3, 0.4], 10)?.is_empty());
    assert_eq!(redaction_audit_receipts(&peer)?.len(), 1);
    assert_eq!(hard_erase_sweep_rows(&peer)?.len(), 1);
    Ok(())
}
