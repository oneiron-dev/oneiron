use super::*;

use crate::attempt_queue::AttemptQueue;
use crate::dreamer_consolidation::{decode_partition_payload, enqueue_partition_attempts};
use crate::dreamer_runner::decode_dreamer_attempt_payload;

fn length_policy(threshold: f32) -> PrefilterConfig {
    PrefilterConfig {
        enabled: true,
        threshold,
        weights: PrefilterWeights {
            len: 1.0,
            ttr: 0.0,
            entity_density: 0.0,
            novelty: 0.0,
            role: 0.0,
        },
    }
}

fn queued_turns(vault: &Vault, scope: DreamerConsolidationScope) -> BTreeSet<EntityId> {
    AttemptQueue::new(vault)
        .list()
        .expect("attempts")
        .into_iter()
        .filter(|attempt| attempt.kind == scope.attempt_kind())
        .map(|attempt| decode_dreamer_attempt_payload(&attempt.payload).expect("payload"))
        .filter(|payload| payload.attempt_type == scope.as_str())
        .flat_map(|payload| {
            decode_partition_payload(&payload.input)
                .expect("partition")
                .1
        })
        .collect()
}

fn skip_ids(receipts: &[ReceiptRecord]) -> BTreeSet<String> {
    receipts
        .iter()
        .filter(|row| row.outcome == PREFILTER_DECISION_SKIP)
        .map(|row| row.fields[FIELD_PREFILTER_TURN].clone())
        .collect()
}

fn replace_body(vault: &Vault, turn: &EntityId, text: rmpv::Value) {
    // Deliberately keep the metadata and temporal index byte-identical. This
    // discriminates body drift from the already-covered ID/watermark fence.
    let raw = vault.get_raw(turn).expect("read").expect("turn");
    let mut replacement = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
    rmpv::encode::write_value(
        &mut replacement,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("spkr"), rmpv::Value::from("user")),
            (rmpv::Value::from("txt"), text),
        ]),
    )
    .expect("body");
    vault
        .with_write_txn(|txn| {
            vault
                .store
                .entities
                .put(txn, turn.as_bytes(), &replacement)?;
            Ok(())
        })
        .expect("replace body only");
}

fn assert_drift_is_replanned(session_close: bool) {
    let rich = "detail ".repeat(40);
    // Tighten, loosen, short -> long, long -> short. Every case changes the
    // committed decision while keeping the pre-screen IDs and watermark fixed.
    for (before, after, original, replacement, was_kept, is_kept) in [
        (0.0, 0.5, "ok", None, true, false),
        (0.5, 0.0, "ok", None, false, true),
        (0.5, 0.5, "ok", Some(rich.as_str()), false, true),
        (0.5, 0.5, rich.as_str(), Some("ok"), true, false),
    ] {
        let (_dir, vault) = open_vault();
        let conversation = seed_conversation(&vault, 0x51);
        let target = seed_turn(&vault, &conversation, "user", original, 900);
        let filler = seed_turn(&vault, &conversation, "user", "ok", 901);
        vault
            .set_prefilter_config(length_policy(before))
            .expect("policy");
        let session = minted(vault.mint_session(1_000).expect("mint"));
        let wake = meso_wake(&vault);
        assert_eq!(planned_turn_ids(&wake.plans).contains(&target), was_kept);
        let watermark = read_watermark(&vault, MESO).expect("watermark");
        let dirty = scan_dirty_turns(&vault, MESO, &watermark, usize::MAX).expect("scan");
        vault
            .set_prefilter_config(length_policy(after))
            .expect("policy drift");
        if let Some(text) = replacement {
            replace_body(&vault, &target, rmpv::Value::from(text));
        }
        assert_eq!(meso_wake(&vault).planned_turn_ids, wake.planned_turn_ids);
        if session_close {
            vault
                .end_session_with_wake(&session, SessionClosePredicate::Explicit, 2_000, &wake)
                .expect("close")
                .expect("ended");
            assert_eq!(
                read_watermark(&vault, MESO)
                    .expect("settled")
                    .last_learned_at,
                901
            );
        } else {
            enqueue_partition_attempts(&vault, MESO, &dirty, &watermark, "drift", 2_000)
                .expect("atomic public enqueue");
            assert_eq!(
                read_watermark(&vault, MESO).expect("not settled"),
                watermark
            );
        }
        let queued = queued_turns(&vault, MESO);
        assert_eq!(
            queued.contains(&target),
            is_kept,
            "preview must not control enqueue"
        );
        assert_eq!(queued.contains(&filler), after == 0.0);
        let expected_skips: BTreeSet<_> = [target, filler]
            .into_iter()
            .filter(|turn| !queued.contains(turn))
            .map(|turn| turn.to_hex())
            .collect();
        let receipts = extraction_receipts(&vault);
        assert_eq!(skip_ids(&receipts), expected_skips);
        if expected_skips.is_empty() {
            assert!(receipts.is_empty(), "no per-pass receipt expansion");
        } else {
            let rollup = receipts
                .iter()
                .find(|row| row.outcome == PREFILTER_OUTCOME_SCREENED)
                .expect("even an all-skipped public round is receipted");
            assert_eq!(rollup.fields[FIELD_PREFILTER_SCANNED], "2");
            assert_eq!(
                rollup.fields[FIELD_PREFILTER_PASSED],
                queued.len().to_string()
            );
            assert_eq!(
                rollup.fields[FIELD_PREFILTER_SKIPPED],
                expected_skips.len().to_string()
            );
        }
    }
}

#[test]
fn session_close_replans_policy_and_body_drift() {
    assert_drift_is_replanned(true);
}

#[test]
fn public_enqueue_replans_policy_and_body_drift_and_receipts_all_skipped_rounds() {
    assert_drift_is_replanned(false);
}

#[test]
fn corrupt_planned_turns_abort_public_enqueue_and_fence_session_progress() {
    for corruption in ["missing", "header", "type"] {
        let (_dir, vault) = open_vault();
        let conversation = seed_conversation(&vault, 0x55);
        seed_turn(&vault, &conversation, "user", &"detail ".repeat(40), 900);
        let broken = seed_turn(&vault, &conversation, "user", "ok", 901);
        vault
            .set_prefilter_config(length_policy(0.5))
            .expect("lossy");
        let session = minted(vault.mint_session(1_000).expect("mint"));
        let wake = meso_wake(&vault);
        let watermark = read_watermark(&vault, MESO).expect("watermark");
        let turns = scan_dirty_turns(&vault, MESO, &watermark, usize::MAX).expect("scan");
        vault
            .with_write_txn(|txn| {
                match corruption {
                    "missing" => {
                        vault.store.entities.delete(txn, broken.as_bytes())?;
                    }
                    "header" => {
                        vault.store.entities.put(txn, broken.as_bytes(), b"bad")?;
                    }
                    "type" => {
                        let raw = vault.get_raw_in(txn, &conversation)?.expect("non-TURN row");
                        vault.store.entities.put(txn, broken.as_bytes(), &raw)?;
                    }
                    _ => unreachable!(),
                }
                Ok(())
            })
            .expect("corrupt fixture without changing the temporal key");
        assert!(matches!(
            enqueue_partition_attempts(&vault, MESO, &turns, &watermark, "broken", 2_000),
            Err(Error::CorruptedIndex(_))
        ));
        assert!(AttemptQueue::new(&vault).list().expect("queue").is_empty());
        assert!(extraction_receipts(&vault).is_empty());
        assert_eq!(read_watermark(&vault, MESO).expect("watermark"), watermark);
        // The existing close fence excludes the corrupt row, so the close may
        // commit but MUST NOT settle or enqueue this stale lossy round.
        vault
            .end_session_with_wake(&session, SessionClosePredicate::Explicit, 2_000, &wake)
            .expect("stale close")
            .expect("ended");
        assert!(queued_turns(&vault, MESO).is_empty());
        assert!(extraction_receipts(&vault).is_empty());
        assert_eq!(read_watermark(&vault, MESO).expect("unsettled"), watermark);
    }
}

#[test]
fn receipt_failure_rolls_back_session_close_attempts_and_watermark() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x56);
    seed_turn(&vault, &conversation, "user", "ok", 900);
    let watermark = read_watermark(&vault, MESO).expect("watermark");
    let turns = scan_dirty_turns(&vault, MESO, &watermark, usize::MAX).expect("scan");
    vault
        .set_prefilter_config(length_policy(0.5))
        .expect("lossy");
    enqueue_partition_attempts(&vault, MESO, &turns, &watermark, "old", 100).expect("skip");
    let receipts = extraction_receipts(&vault);
    // The audit projection remains readable; only its membership pointer is
    // corrupt. Settlement must fail even though new attempts were staged first.
    vault
        .with_write_txn(|txn| {
            let key = vault
                .store
                .vault_meta
                .prefix_iter(txn, b"dreamer:prefilter:member:v1:")?
                .next()
                .transpose()?
                .expect("membership")
                .0
                .to_vec();
            vault.store.vault_meta.put(txn, &key, &[0; 32])?;
            Ok(())
        })
        .expect("dangling membership fixture");
    vault
        .set_prefilter_config(length_policy(0.0))
        .expect("rescue");
    let session = minted(vault.mint_session(1_000).expect("mint"));
    let wake = meso_wake(&vault);
    assert!(!wake.plans.is_empty());
    assert!(matches!(
        vault.end_session_with_wake(&session, SessionClosePredicate::Explicit, 2_000, &wake),
        Err(Error::CorruptedIndex(_))
    ));
    assert_eq!(
        vault
            .open_session()
            .expect("open session")
            .map(|open| open.session),
        Some(session)
    );
    assert!(AttemptQueue::new(&vault).list().expect("queue").is_empty());
    assert_eq!(read_watermark(&vault, MESO).expect("watermark"), watermark);
    assert_eq!(extraction_receipts(&vault), receipts);
}

#[test]
fn checkpoint_preserves_prefilter_receipts_and_rescan_membership() {
    use crate::recovery::checkpoint::RestoreReason;

    let (dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x56);
    for second in 10..12 {
        seed_turn(&vault, &conversation, "user", "ok", second);
    }
    let watermark = read_watermark(&vault, MESO).expect("watermark");
    let turns = scan_dirty_turns(&vault, MESO, &watermark, usize::MAX).expect("scan");
    vault
        .set_prefilter_config(length_policy(0.5))
        .expect("lossy policy");
    enqueue_partition_attempts(&vault, MESO, &turns, &watermark, "original", 100)
        .expect("screened round");
    let before = extraction_receipts(&vault);
    assert_eq!(before.len(), 3, "two skip receipts and their round");
    let image = dir.path().join("checkpoint");
    vault.snapshot_checkpoint(&image, 110).expect("checkpoint");
    let (restored, _) = Vault::restore_checkpoint(
        &image,
        &dir.path().join("restored"),
        VaultConfig::device(),
        RestoreReason::Restore,
        120,
    )
    .expect("restore");
    assert_eq!(extraction_receipts(&restored), before);

    // Restored membership must still retire just the overlapping decision,
    // not retain its old skip or discard the unrescanned turn's audit.
    restored
        .set_prefilter_config(length_policy(0.0))
        .expect("rescue policy");
    enqueue_partition_attempts(&restored, MESO, &turns[..1], &watermark, "rescan", 200)
        .expect("rescan after restore");
    let after = extraction_receipts(&restored);
    assert_eq!(
        skip_ids(&after),
        BTreeSet::from([turns[1].turn_id.to_hex()])
    );
    assert_eq!(after.len(), 2);
    let rollup = after
        .iter()
        .find(|row| row.outcome == PREFILTER_OUTCOME_SCREENED)
        .expect("residual round");
    assert_eq!(rollup.fields[FIELD_PREFILTER_SCANNED], "1");
    assert_eq!(rollup.fields[FIELD_PREFILTER_SKIPPED], "1");
    assert_eq!(rollup.fields[FIELD_PREFILTER_PASSED], "0");
}
