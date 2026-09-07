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

#[test]
fn aggregate_weight_overflow_is_rejected_before_persistence_and_on_decode() {
    let (_dir, vault) = open_vault();
    let good = length_policy(0.5);
    vault.set_prefilter_config(good).expect("initial policy");
    for enabled in [true, false] {
        let bad = PrefilterConfig {
            enabled,
            weights: PrefilterWeights {
                len: f32::MAX,
                ttr: f32::MAX,
                ..good.weights
            },
            ..good
        };
        assert!(
            bad.weights
                .axes()
                .iter()
                .all(|(_, weight)| weight.is_finite())
        );
        assert!(!bad.weights.total().is_finite());
        assert!(matches!(
            validate_prefilter_config(&bad),
            Err(Error::InvalidConfig(_))
        ));
        assert!(matches!(
            vault.set_prefilter_config(bad),
            Err(Error::InvalidConfig(_))
        ));
        assert_eq!(vault.prefilter_config().expect("unchanged policy"), good);
        let raw = encode_prefilter_config(&bad).expect("encode unchecked fixture");
        assert!(matches!(
            decode_prefilter_config(&raw),
            Err(Error::InvalidConfig(_))
        ));
    }
    // Large is not itself invalid. A finite aggregate must remain usable.
    let large = PrefilterConfig {
        weights: PrefilterWeights {
            len: f32::MAX,
            ..good.weights
        },
        ..good
    };
    vault.set_prefilter_config(large).expect("finite aggregate");
    for text in [String::new(), "ok".to_owned(), "detail ".repeat(40)] {
        let verdict = prefilter_turn(
            &large,
            &text,
            DreamerTurnRole::User,
            &BTreeSet::new(),
            &NoveltyWindow::new(),
        );
        assert!(verdict.score.is_finite());
        assert!((0.0..=1.0).contains(&verdict.score));
    }
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
fn changed_batch_rescans_retire_only_overlapping_decisions() {
    for shape in ["subset", "superset", "reordered"] {
        let (_dir, vault) = open_vault();
        let conversation = seed_conversation(&vault, 0x52);
        for second in 10..14 {
            seed_turn(&vault, &conversation, "user", "ok", second);
        }
        let watermark = read_watermark(&vault, MESO).expect("watermark");
        let turns = scan_dirty_turns(&vault, MESO, &watermark, usize::MAX).expect("scan");
        vault
            .set_prefilter_config(length_policy(0.5))
            .expect("lossy");
        enqueue_partition_attempts(&vault, MESO, &turns[..2], &watermark, "old", 100)
            .expect("original round");
        enqueue_partition_attempts(&vault, MESO, &turns[3..], &watermark, "unrelated", 101)
            .expect("disjoint history");
        let before = extraction_receipts(&vault);
        let unrelated: Vec<_> = before
            .iter()
            .filter(|row| row.occurred_at == 101)
            .cloned()
            .collect();
        assert_eq!(unrelated.len(), 2);
        vault
            .set_prefilter_config(length_policy(0.0))
            .expect("rescue");
        reopen_prefilter_rescan(&vault, MESO, 0).expect("rewind");
        let rescanned = match shape {
            "subset" => turns[..1].to_vec(),
            "superset" => turns[..3].to_vec(),
            "reordered" => vec![turns[1], turns[0]],
            _ => unreachable!(),
        };
        enqueue_partition_attempts(&vault, MESO, &rescanned, &watermark, "rescan", 200)
            .expect("changed batch");
        let after = extraction_receipts(&vault);
        for row in unrelated {
            assert!(
                after.contains(&row),
                "disjoint audit must be byte-for-byte unchanged"
            );
        }
        let mut expected = BTreeSet::from([turns[3].turn_id.to_hex()]);
        if shape == "subset" {
            expected.insert(turns[1].turn_id.to_hex());
            let residual = after
                .iter()
                .find(|row| row.occurred_at == 100 && row.outcome == PREFILTER_OUTCOME_SCREENED)
                .expect("unrescanned member keeps its rollup");
            assert_eq!(residual.fields[FIELD_PREFILTER_SCANNED], "1");
            assert_eq!(residual.fields[FIELD_PREFILTER_SKIPPED], "1");
            assert_eq!(residual.fields[FIELD_PREFILTER_PASSED], "0");
        }
        assert_eq!(
            skip_ids(&after),
            expected,
            "{shape}: no obsolete overlapping skips"
        );
        assert_eq!(after.len(), expected.len() * 2);
        let skip_tokens: u64 = after
            .iter()
            .filter(|row| row.outcome == PREFILTER_DECISION_SKIP)
            .map(|row| {
                row.fields[FIELD_PREFILTER_TOKENS_SAVED]
                    .parse::<u64>()
                    .expect("tokens")
            })
            .sum();
        let round_tokens: u64 = after
            .iter()
            .filter(|row| row.outcome == PREFILTER_OUTCOME_SCREENED)
            .map(|row| {
                row.fields[FIELD_PREFILTER_TOKENS_SAVED]
                    .parse::<u64>()
                    .expect("tokens")
            })
            .sum();
        assert_eq!(skip_tokens, round_tokens, "residual savings must reconcile");
    }
}

#[test]
fn rescanning_a_pass_updates_the_residual_rollup_without_erasing_skips() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x53);
    let skipped = seed_turn(&vault, &conversation, "user", "ok", 10);
    seed_turn(&vault, &conversation, "user", &"detail ".repeat(40), 11);
    let watermark = read_watermark(&vault, MESO).expect("watermark");
    let turns = scan_dirty_turns(&vault, MESO, &watermark, usize::MAX).expect("scan");
    vault
        .set_prefilter_config(length_policy(0.5))
        .expect("lossy");
    enqueue_partition_attempts(&vault, MESO, &turns, &watermark, "mixed", 100).expect("mixed");
    enqueue_partition_attempts(&vault, MESO, &turns[1..], &watermark, "pass", 200).expect("pass");
    let receipts = extraction_receipts(&vault);
    assert_eq!(skip_ids(&receipts), BTreeSet::from([skipped.to_hex()]));
    let rollup = receipts
        .iter()
        .find(|row| row.outcome == PREFILTER_OUTCOME_SCREENED)
        .expect("rollup");
    assert_eq!(rollup.fields[FIELD_PREFILTER_SCANNED], "1");
    assert_eq!(rollup.fields[FIELD_PREFILTER_PASSED], "0");
    assert_eq!(rollup.fields[FIELD_PREFILTER_SKIPPED], "1");
}

#[test]
fn a_rescan_preserves_the_same_turns_audit_in_another_scope() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x54);
    seed_turn(&vault, &conversation, "user", "ok", 10);
    let watermark = read_watermark(&vault, MESO).expect("watermark");
    let turns = scan_dirty_turns(&vault, MESO, &watermark, usize::MAX).expect("scan");
    vault
        .set_prefilter_config(length_policy(0.5))
        .expect("lossy");
    let micro = DreamerConsolidationScope::Micro;
    enqueue_partition_attempts(&vault, micro, &turns, &watermark, "micro", 100).expect("micro");
    let other_scope = extraction_receipts(&vault);
    enqueue_partition_attempts(&vault, MESO, &turns, &watermark, "meso", 101).expect("meso");
    assert_eq!(extraction_receipts(&vault).len(), 4);
    vault
        .set_prefilter_config(length_policy(0.0))
        .expect("rescue");
    enqueue_partition_attempts(&vault, MESO, &turns, &watermark, "rescan", 200).expect("rescan");
    assert_eq!(extraction_receipts(&vault), other_scope);
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
fn unreadable_text_passes_without_losing_other_turns_skip_receipts() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x57);
    let unreadable = seed_turn(&vault, &conversation, "user", "ok", 900);
    let skipped = seed_turn(&vault, &conversation, "user", "ok", 901);
    replace_body(&vault, &unreadable, rmpv::Value::Binary(vec![0xff]));
    vault
        .set_prefilter_config(length_policy(0.5))
        .expect("lossy");
    let watermark = read_watermark(&vault, MESO).expect("watermark");
    let turns = scan_dirty_turns(&vault, MESO, &watermark, usize::MAX).expect("scan");
    enqueue_partition_attempts(&vault, MESO, &turns, &watermark, "unreadable", 2_000)
        .expect("complete safe fallback");
    assert_eq!(queued_turns(&vault, MESO), BTreeSet::from([unreadable]));
    assert_eq!(
        skip_ids(&extraction_receipts(&vault)),
        BTreeSet::from([skipped.to_hex()])
    );
}

#[test]
fn a_partial_overlap_replaces_skips_and_retains_unrescanned_history() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x58);
    for second in 10..13 {
        seed_turn(&vault, &conversation, "user", "ok", second);
    }
    let watermark = read_watermark(&vault, MESO).expect("watermark");
    let turns = scan_dirty_turns(&vault, MESO, &watermark, usize::MAX).expect("scan");
    vault
        .set_prefilter_config(length_policy(0.5))
        .expect("lossy");
    enqueue_partition_attempts(&vault, MESO, &turns[..2], &watermark, "old", 100)
        .expect("original skips");
    enqueue_partition_attempts(&vault, MESO, &turns[1..], &watermark, "new", 200)
        .expect("overlapping skips");
    let receipts = extraction_receipts(&vault);
    assert_eq!(
        receipts.len(),
        5,
        "three current skips and two residual rollups"
    );
    for (index, turn) in turns.iter().enumerate() {
        let skip = receipts
            .iter()
            .find(|row| row.fields.get(FIELD_PREFILTER_TURN) == Some(&turn.turn_id.to_hex()))
            .expect("current skip");
        assert_eq!(skip.occurred_at, if index == 0 { 100 } else { 200 });
    }
    for (time, count) in [(100, "1"), (200, "2")] {
        let rollup = receipts
            .iter()
            .find(|row| row.occurred_at == time && row.outcome == PREFILTER_OUTCOME_SCREENED)
            .expect("current rollup");
        assert_eq!(rollup.fields[FIELD_PREFILTER_SCANNED], count);
        assert_eq!(rollup.fields[FIELD_PREFILTER_SKIPPED], count);
    }
}
