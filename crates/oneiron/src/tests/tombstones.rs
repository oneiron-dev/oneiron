//! CRDT tombstone replay and sync-pending tombstone markers (sync / not-sync gated).

use super::*;

#[test]
fn replayed_soft_tombstone_keeps_shell_and_deindexes_without_receipt_or_sweep() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault
        .batch()
        .put(&id, 1, test_time_range(10, 10), 20, b"replay-soft-secret")
        .text(&id, &[("body", "replay-soft-secret")])
        .commit()?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    assert_eq!(vault.search_text("replay-soft-secret", 10)?.len(), 1);

    // reason byte 1 = user_delete (the ONLY soft wire reason).
    let outcome = vault.apply_replayed_tombstone(&id, &wire_tombstone(1, 1_771_027_200, 0x5A))?;
    assert_eq!(
        outcome,
        ReplayedTombstoneOutcome::SoftErased { changed: true }
    );

    // Shell-preserving SoftErase: the 25 B header row SURVIVES (a hard
    // purge of the row FAILS here), the payload and every retrieval index
    // entry are gone.
    let raw = vault
        .get_raw(&id)?
        .expect("user_delete replay must keep the 25 B shell");
    assert_eq!(raw.len(), ENTITY_METADATA_HEADER_LEN);
    assert_eq!(vault.get(&id)?.as_deref(), Some([].as_slice()));
    assert!(vault.search_text("replay-soft-secret", 10)?.is_empty());
    assert!(vault.get_vector(&id)?.is_none());
    assert!(vault.entities_by_type(1)?.contains(&id));

    // contracts.ts user_delete: receipt = false, historicalSweepQueued =
    // false — NO local receipt, NO h: sweep row.
    assert!(redaction_audit_receipts(&vault)?.is_empty());
    assert!(hard_erase_sweep_rows(&vault)?.is_empty());

    // Idempotent: re-applying the same soft value over the shell reports
    // no change (every-boot forward remat must not count it forever).
    let again = vault.apply_replayed_tombstone(&id, &wire_tombstone(1, 1_771_027_200, 0x5A))?;
    assert_eq!(
        again,
        ReplayedTombstoneOutcome::SoftErased { changed: false }
    );
    Ok(())
}

#[test]
fn replayed_hard_tombstone_purges_and_writes_local_receipt_and_sweep_row() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault
        .batch()
        .put(&id, 1, test_time_range(30, 30), 40, b"Alice replay secret")
        .text(&id, &[("body", "Alice replay secret")])
        .commit()?;

    // reason byte 3 = gdpr_delete; deleted_at and request_id are literals.
    let value = wire_tombstone(3, 1_771_027_200, 0xAB);
    let outcome = vault.apply_replayed_tombstone(&id, &value)?;
    let ReplayedTombstoneOutcome::HardPurged {
        erased: true,
        receipt_id: Some(receipt_id),
        sweep_key: Some(sweep_key),
    } = outcome
    else {
        panic!("hard replay over local state must erase + receipt + sweep, got {outcome:?}");
    };

    // Destructive purge: row AND index entries gone (a shell-keeping
    // implementation FAILS here).
    assert!(vault.get_raw(&id)?.is_none());
    assert!(vault.search_text("replay", 10)?.is_empty());
    assert!(!vault.entities_by_type(1)?.contains(&id));

    // LOCAL receipt: request_id comes from the WIRE value (Art. 5(2)
    // correlation across replicas), reason from the wire byte, requested_at
    // from the wire deleted_at; minimization = opaque ids + timestamps only.
    let receipt_raw = vault.get_raw(&receipt_id)?.expect("local receipt");
    assert_no_receipt_payload_leak(&receipt_raw, &[b"Alice", b"replay secret"]);
    let receipt = receipt_body(&receipt_raw);
    assert_receipt_fields(&receipt);
    assert_eq!(receipt["reason"], "gdpr_delete");
    assert_eq!(
        receipt["request_id"], "abababab-abab-abab-abab-abababababab",
        "receipt request_id must be the wire value's UUID, hyphenated"
    );
    assert_eq!(receipt["requested_at"].as_u64(), Some(1_771_027_200));
    assert_eq!(receipt["scope"]["entity_ids"][0], id.to_hex());

    // LOCAL h:{seq:8BE} sweep row, deadline_at ≤ queued_at + 30 d
    // (GDPR Art. 12(3) one-month anchor — the ≤30 d clock must run on THIS
    // replica, not only on the origin device).
    assert!(sweep_key.starts_with(b"h:"));
    let rows = hard_erase_sweep_rows(&vault)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, sweep_key);
    let job: serde_json::Value = rmp_serde::from_slice(&rows[0].1).expect("decode sweep job");
    assert_eq!(job["scope"]["entity_ids"][0], id.to_hex());
    let queued_at = job["retry_state"]["queued_at"].as_u64().unwrap();
    let deadline_at = job["retry_state"]["deadline_at"].as_u64().unwrap();
    assert!(deadline_at >= queued_at);
    assert!(deadline_at <= queued_at + 30 * 86_400);
    assert_eq!(receipt["sweep_queued_at"].as_u64(), Some(queued_at));

    // Idempotent: nothing local remains, so re-applying the same tombstone
    // is a receipt-free no-op (every-boot replay must not multiply
    // receipts or sweep rows on one replica).
    let again = vault.apply_replayed_tombstone(&id, &value)?;
    assert_eq!(
        again,
        ReplayedTombstoneOutcome::HardPurged {
            erased: false,
            receipt_id: None,
            sweep_key: None,
        }
    );
    assert_eq!(redaction_audit_receipts(&vault)?.len(), 1);
    assert_eq!(hard_erase_sweep_rows(&vault)?.len(), 1);
    Ok(())
}

/// Every non-soft wire shape — legacy 8-byte, reserved byte 0, unknown
/// reason byte, malformed length — replays as a DESTRUCTIVE purge
/// (fail-closed: ambiguity resolves to MORE deletion, never less), with the
/// pinned receipt fallbacks: reason = `user_hard_delete` (the engine's
/// destructive default) and request_id = the wire UUID when the value
/// carried one, else the NIL UUID (never a fabricated identifier).
#[test]
fn replayed_ambiguous_tombstones_hard_purge_with_fail_closed_receipt() -> Result<()> {
    struct Case {
        name: &'static str,
        value: Vec<u8>,
        want_request_id: &'static str,
        want_requested_at: u64,
    }
    let cases = [
        Case {
            name: "legacy 8-byte",
            value: 1_771_000_000_u64.to_le_bytes().to_vec(),
            want_request_id: "00000000-0000-0000-0000-000000000000",
            want_requested_at: 1_771_000_000,
        },
        Case {
            name: "reserved byte 0",
            value: wire_tombstone(0, 1_771_000_111, 0x11),
            want_request_id: "11111111-1111-1111-1111-111111111111",
            want_requested_at: 1_771_000_111,
        },
        Case {
            name: "unknown reason byte 9",
            value: wire_tombstone(9, 1_771_000_222, 0x22),
            want_request_id: "22222222-2222-2222-2222-222222222222",
            want_requested_at: 1_771_000_222,
        },
        Case {
            name: "malformed 26-byte",
            value: vec![7_u8; 26],
            want_request_id: "00000000-0000-0000-0000-000000000000",
            want_requested_at: 0,
        },
    ];

    for case in cases {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();
        vault.put_entity(&id, 1, test_time_range(50, 50), 60, b"ambiguous-target")?;

        let outcome = vault.apply_replayed_tombstone(&id, &case.value)?;
        let ReplayedTombstoneOutcome::HardPurged {
            erased: true,
            receipt_id: Some(receipt_id),
            sweep_key: Some(_),
        } = outcome
        else {
            panic!(
                "{}: must hard-purge with receipt, got {outcome:?}",
                case.name
            );
        };
        assert!(vault.get_raw(&id)?.is_none(), "{}", case.name);

        let receipt = receipt_body(&vault.get_raw(&receipt_id)?.expect("receipt"));
        assert_eq!(receipt["reason"], "user_hard_delete", "{}", case.name);
        assert_eq!(receipt["request_id"], case.want_request_id, "{}", case.name);
        assert_eq!(
            receipt["requested_at"].as_u64(),
            Some(case.want_requested_at),
            "{}",
            case.name
        );
        assert_eq!(hard_erase_sweep_rows(&vault)?.len(), 1, "{}", case.name);
    }
    Ok(())
}

/// Never-downgrade on receive: a SOFT tombstone replayed for an id this
/// replica already hard-purged is a strict no-op — it must NOT recreate a
/// shell, mint a receipt, or queue a sweep row.
#[test]
fn replayed_soft_tombstone_after_hard_purge_is_noop() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(70, 70), 80, b"downgrade-target")?;

    // Hard apply first (reason byte 2 = user_hard_delete).
    let hard = vault.apply_replayed_tombstone(&id, &wire_tombstone(2, 1_771_100_000, 0xDD))?;
    assert!(hard.changed_local_state());
    assert!(vault.get_raw(&id)?.is_none());
    assert_eq!(redaction_audit_receipts(&vault)?.len(), 1);
    assert_eq!(hard_erase_sweep_rows(&vault)?.len(), 1);

    // Stale/concurrent soft value arrives after the hard purge.
    let soft = vault.apply_replayed_tombstone(&id, &wire_tombstone(1, 1_771_200_000, 0x99))?;
    assert_eq!(
        soft,
        ReplayedTombstoneOutcome::SoftErased { changed: false }
    );
    assert!(
        vault.get_raw(&id)?.is_none(),
        "a replayed soft tombstone must never resurrect a shell for a hard-purged id"
    );
    assert_eq!(redaction_audit_receipts(&vault)?.len(), 1);
    assert_eq!(hard_erase_sweep_rows(&vault)?.len(), 1);
    assert!(!vault.entities_by_type(1)?.contains(&id));
    Ok(())
}

/// ARCH-0038 D16 on the REPLAY path (the M2-flagged replica staleness bug):
/// a replayed tombstone on an `edge.provenance` Claim refreshes the subject
/// edge in the SAME transaction — winner restamp on hard, downgrade-to-bare
/// when the soft erase scrubs the last live Claim. The sweep row carries the
/// pre-purge captured opaque refs.
#[test]
fn replayed_tombstone_on_provenance_claim_runs_d16_refresh() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;
    let person2 = EntityId::now();
    vault.put_entity(&person2, 4, test_time_range(1, 1), 1, b"person2")?;

    // Live tie cohort @ learned_at 2000: `winner` (conf 0.6,
    // confirmed/system) outranks `runner_up` (conf 0.4, disputed/agent).
    let winner = EntityId::now();
    let mut winner_body =
        EdgeProvenanceClaimBody::new(fx.machine, 0.6, SupersessionStatus::Confirmed);
    winner_body.source_revision_ref = Some([0x61; 16]);
    winner_body.body_snapshot_ref = Some([0x62; 16]);
    vault.put_edge_provenance(
        &winner,
        &subject,
        &winner_body,
        EdgeActorClass::System,
        2_000,
    )?;
    let runner_up = EntityId::now();
    vault.put_edge_provenance(
        &runner_up,
        &subject,
        &EdgeProvenanceClaimBody::new(person2, 0.4, SupersessionStatus::Disputed),
        EdgeActorClass::Agent,
        2_000,
    )?;
    let (before, _) = raw_edge_values(vault, &subject)?;
    let before = before.expect("stamped edge");
    assert_eq!((before[24], before[25]), (1, 2), "winner stamps pre-replay");

    // Remote HARD tombstone for the WINNER claim: purge + D16 restamp from
    // the surviving runner-up in the same txn. A bare-purge replay (the
    // pre-ONE-1133 behavior) leaves the stale (1, 2) stamp and FAILS here.
    let outcome =
        vault.apply_replayed_tombstone(&winner, &wire_tombstone(2, 1_771_300_000, 0xC1))?;
    assert!(outcome.changed_local_state());
    assert!(vault.get(&winner)?.is_none(), "claim entity hard-purged");
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edges_out row survives the claim replay");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(
        (out[24], out[25]),
        (2, 1),
        "restamped from the surviving runner-up (disputed/agent)"
    );
    assert_eq!(&out[..24], &before[..24], "first 24 bytes preserved");
    assert_eq!(inn.as_deref(), Some(out.as_slice()));

    // The queued sweep row rode the PRE-purge captured opaque refs
    // (ARCH-0038 delete-interplay: refs are only readable before the purge).
    let rows = hard_erase_sweep_rows(vault)?;
    assert_eq!(rows.len(), 1);
    let job: serde_json::Value = rmp_serde::from_slice(&rows[0].1).expect("decode sweep job");
    assert_eq!(
        job["scope"]["revision_ids"][0],
        crate::entity_id::bytes_to_hex_lower(&[0x61; 16])
    );
    assert_eq!(
        job["scope"]["body_snapshot_refs"][0],
        crate::entity_id::bytes_to_hex_lower(&[0x62; 16])
    );

    // Remote SOFT tombstone for the RUNNER-UP: shell + D16 downgrade-to-bare
    // (no live Claim of any lifecycle survives) — still no NEW receipt.
    let outcome =
        vault.apply_replayed_tombstone(&runner_up, &wire_tombstone(1, 1_771_300_100, 0xC2))?;
    assert_eq!(
        outcome,
        ReplayedTombstoneOutcome::SoftErased { changed: true }
    );
    assert_eq!(
        vault.get(&runner_up)?.as_deref(),
        Some([].as_slice()),
        "soft replay keeps the 25 B Claim shell"
    );
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edges_out row survives");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_LEN, "26 B → 24 B downgrade");
    assert_eq!(out.as_slice(), &before[..24]);
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    assert_eq!(
        redaction_audit_receipts(vault)?.len(),
        1,
        "the soft replay must not mint a second receipt"
    );
    assert_eq!(hard_erase_sweep_rows(vault)?.len(), 1);
    Ok(())
}

/// ONE-1090 write side (ONE-1132 AC3) — CONTRACT CORRECTION: replaces
/// `user_delete_soft_shell_survives_sync_rematerialization`, which pinned
/// the pre-ONE-1090 gap where a soft delete left NO CRDT record at all (so
/// the deleted body stayed live on every other device forever).
///
/// `user_delete` now writes a reason=user_delete v2 tombstone into the
/// window doc and removes the live `entities[id]` map copy (the full body
/// bytes in that map are an ACTIVE carrier of content the user deleted).
/// Local shell semantics are unchanged: the body scrub keeps the 25 B
/// shell. The receiver-side soft/hard branch is ONE-1133
/// (`Vault::apply_replayed_tombstone`): a known-soft value keeps the remote
/// replica's 25 B shell; everything else stays a fail-closed hard purge.
#[cfg(feature = "sync")]
#[test]
fn user_delete_writes_soft_v2_tombstone_into_crdt() -> Result<()> {
    use crate::sync::loro_support::{map_contains_binary, map_get_bytes};
    use crate::sync::types::WindowKey;
    use crate::sync::window;

    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let learned_at = 1_772_000_000;

    vault
        .batch()
        .put(
            &id,
            1,
            test_time_range(learned_at, learned_at),
            learned_at,
            b"soft-delete-sync-body",
        )
        .commit()?;

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserDelete)?;
    assert!(outcome.existed);
    assert_eq!(
        vault.get(&id)?.as_deref(),
        Some([].as_slice()),
        "user_delete keeps the local 25 B shell (D16 scrub semantics unchanged)"
    );

    let window_key = WindowKey::from_timestamp(learned_at);
    let doc = window::load_window_from_state(&vault, "local", &window_key)?;

    let tombstones = doc.get_map("tombstones");
    let value = map_get_bytes(&tombstones, id.to_hex().as_str())
        .expect("user_delete must write a CRDT tombstone (ONE-1090 write side)");
    assert_eq!(value.len(), 25, "tombstone value must be the v2 layout");
    assert_eq!(
        value[0], 1,
        "reason must be the pinned user_delete wire byte (soft)"
    );
    assert!(
        !map_contains_binary(&doc.get_map("entities"), id.to_hex().as_str()),
        "the live entities-map copy is an active carrier and must be removed"
    );

    // The pt: crash marker is cleared once the CRDT record is persisted.
    let pt_key = format!("pt:{window_key}:{}", id.to_hex());
    assert!(
        vault.sync_state_get(&pt_key)?.is_none(),
        "pending-tombstone marker must be cleared after CRDT persistence"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn hard_delete_persists_crdt_tombstone_before_active_purge() -> Result<()> {
    use crate::sync::loro_support::map_contains_binary;
    use crate::sync::types::WindowKey;
    use crate::sync::window;

    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let target = EntityId::now();
    let learned_at = 1_772_000_000;

    vault
        .batch()
        .put(
            &id,
            1,
            test_time_range(learned_at, learned_at),
            learned_at,
            b"must-tombstone-before-purge",
        )
        .commit()?;
    vault.with_write_txn(|wtxn| {
        let key = Store::encode_edge_key(&id, EdgeKind::Supports, &target);
        vault.store.edges_out.put(wtxn, &key, &[0_u8; 3])?;
        Ok(())
    })?;

    let err = vault
        .delete_entity_with_reason(&id, DeleteReason::UserHardDelete)
        .expect_err("corrupted edge record should fail active purge");
    assert_matches!(err, Error::CorruptedIndex(_));
    assert!(
        vault.entity_exists(&id)?,
        "active purge failed, so entity payload should remain for retry"
    );

    let window_key = WindowKey::from_timestamp(learned_at);
    let doc = window::load_window_from_state(&vault, "local", &window_key)?;
    let tombstones = doc.get_map("tombstones");
    assert!(
        map_contains_binary(&tombstones, id.to_hex().as_str()),
        "CRDT tombstone must persist before destructive purge starts"
    );
    Ok(())
}

/// Regression: `learned_at` is caller-supplied, and the hard-delete
/// tombstone path routes it through `WindowKey::from_timestamp`. A
/// far-future timestamp previously either hung (one loop iteration per
/// year toward ~year 292e9) or produced a window key outside the pinned
/// ARCH-0023b `YYYY-MM` format, so the tombstone-first guarantee silently
/// broke: the `d:w:…` row landed under a key every validated reader
/// rejects. The delete must complete promptly and persist its tombstone in
/// the clamped, format-valid "9999-12" window.
#[cfg(feature = "sync")]
#[test]
fn hard_delete_with_far_future_learned_at_tombstones_into_valid_window() -> Result<()> {
    use crate::sync::loro_support::map_contains_binary;
    use crate::sync::types::WindowKey;
    use crate::sync::window;

    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(
            &id,
            1,
            test_time_range(u64::MAX, u64::MAX),
            u64::MAX,
            b"far-future-learned-at",
        )
        .commit()?;

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::GdprDelete)?;
    assert!(outcome.existed);
    assert!(outcome.receipt_id.is_some());
    assert!(vault.get(&id)?.is_none());

    let window_key = WindowKey::from_timestamp(u64::MAX);
    assert_eq!(window_key.as_str(), "9999-12");
    let doc = window::load_window_from_state(&vault, "local", &window_key)?;
    let tombstones = doc.get_map("tombstones");
    assert!(
        map_contains_binary(&tombstones, id.to_hex().as_str()),
        "tombstone must land in the clamped format-valid window"
    );
    Ok(())
}

/// ONE-1132 OWNER-DECISION (cfg-off durability): a build WITHOUT the `sync`
/// feature cannot write the CRDT tombstone, so the purge txn's
/// CRDT-independent `pt:` marker must SURVIVE the delete — it is the
/// deletion's only durable propagation intent until a sync-enabled boot
/// replays it. Asserts the exact pinned v2 value layout and that the
/// embedded request_id correlates with the REDACTION_AUDIT receipt.
#[cfg(not(feature = "sync"))]
#[test]
fn hard_delete_without_sync_feature_leaves_pending_tombstone_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    // 2026-02-15 ≈ unix 1_771_027_200 ⇒ window label "2026-02".
    let learned_at = 1_771_027_200;
    vault.put_entity(
        &id,
        1,
        test_time_range(learned_at, learned_at),
        learned_at,
        b"cfg-off-durability",
    )?;

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserHardDelete)?;
    assert!(outcome.existed);
    let receipt_raw = vault
        .get_raw(&outcome.receipt_id.expect("receipt id"))?
        .expect("receipt raw");
    let receipt = receipt_body(&receipt_raw);

    let value = pending_tombstone_row(&vault, "2026-02", &id)?
        .expect("pt: marker must survive a hard delete in a sync-OFF build");
    assert_eq!(value.len(), 25, "marker value must be the v2 layout");
    assert_eq!(
        value[0], 2,
        "reason must be the pinned user_hard_delete wire byte"
    );
    let deleted_at = u64::from_le_bytes(value[1..9].try_into().expect("8-byte slice"));
    assert_eq!(
        deleted_at,
        receipt["requested_at"].as_u64().expect("requested_at"),
        "deleted_at must be the deletion request time (u64 LE at offset 1)"
    );
    let receipt_request_hex = receipt["request_id"]
        .as_str()
        .expect("request_id")
        .replace('-', "");
    let marker_request_hex: String = value[9..25].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        marker_request_hex, receipt_request_hex,
        "tombstone request_id must correlate with the receipt's request_id"
    );
    Ok(())
}

/// ONE-1132: `user_delete` in a sync-OFF build leaves a SOFT (reason byte 1)
/// pending-tombstone marker in the same txn as the shell scrub, while the
/// local shell semantics stay unchanged.
#[cfg(not(feature = "sync"))]
#[test]
fn user_delete_without_sync_feature_leaves_soft_pending_tombstone_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let learned_at = 1_771_027_200;
    vault.put_entity(
        &id,
        1,
        test_time_range(learned_at, learned_at),
        learned_at,
        b"cfg-off-soft-delete",
    )?;

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserDelete)?;
    assert!(outcome.existed);
    assert_eq!(
        vault.get(&id)?.as_deref(),
        Some([].as_slice()),
        "shell semantics unchanged"
    );

    let value = pending_tombstone_row(&vault, "2026-02", &id)?
        .expect("pt: marker must survive a user_delete in a sync-OFF build");
    assert_eq!(value.len(), 25);
    assert_eq!(
        value[0], 1,
        "reason must be the pinned user_delete wire byte"
    );
    Ok(())
}
