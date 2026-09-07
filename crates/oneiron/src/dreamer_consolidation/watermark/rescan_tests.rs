use super::*;

use crate::config::VaultConfig;
use crate::dreamer_prefilter::reopen_prefilter_rescan;
use crate::temporal::TimeRange;
use crate::test_util::open_test_vault_with;

const MESO: DreamerConsolidationScope = DreamerConsolidationScope::Meso;

fn seed_turn(vault: &Vault, ordinal: u64, learned_at: u64) -> EntityId {
    // Ordinal zero is the smallest valid EntityId, not merely a typical UUID.
    // A made-up exact-key sentinel must not swallow this time-zero turn.
    let mut bytes = [0_u8; 16];
    bytes[8..].copy_from_slice(&(ordinal + 1).to_be_bytes());
    let id = EntityId::from_bytes(bytes).expect("turn id");
    let body = encode_value(&Value::Map(vec![
        (Value::from("spkr"), Value::from("user")),
        (Value::from("txt"), Value::from("rescan fixture")),
    ]))
    .expect("turn body");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        )
        .expect("seed turn");
    id
}

fn dirty_ids(vault: &Vault, scope: DreamerConsolidationScope) -> Vec<EntityId> {
    let watermark = read_watermark(vault, scope).expect("watermark");
    scan_dirty_turns(vault, scope, &watermark, usize::MAX)
        .expect("scan")
        .into_iter()
        .map(|turn| turn.turn_id)
        .collect()
}

#[test]
fn prefilter_rescan_zero_includes_time_zero_and_survives_reopen() {
    let (dir, vault) = open_test_vault_with(VaultConfig::device());
    let first = seed_turn(&vault, 0, 0);
    let same_second = seed_turn(&vault, 1, 0);
    let later = seed_turn(&vault, 2, 1);
    assert_eq!(
        dirty_ids(&vault, MESO),
        vec![later],
        "bootstrap is unchanged"
    );
    advance_watermark(&vault, MESO, 10).expect("consume all turns");
    assert!(dirty_ids(&vault, MESO).is_empty());

    reopen_prefilter_rescan(&vault, MESO, 0).expect("full rescan");
    let reset = read_watermark(&vault, MESO).expect("persisted reset");
    assert!(reset.before_first);
    assert_ne!(reset, ConsolidationWatermark::bootstrap());
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("reopen vault");
    assert_eq!(read_watermark(&vault, MESO).expect("durable reset"), reset);
    assert_eq!(dirty_ids(&vault, MESO), vec![first, same_second, later]);

    // An administrative complete-second zero is still different from a reset.
    advance_watermark(&vault, MESO, 0).expect("complete second zero");
    assert!(!read_watermark(&vault, MESO).expect("complete").before_first);
    assert_eq!(dirty_ids(&vault, MESO), vec![later]);
}

#[test]
fn prefilter_rescan_is_inclusive_and_scope_local() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    let seconds = [0, 0, 1, 6, 7, 7, 8, u64::MAX];
    let ids: Vec<_> = seconds
        .iter()
        .enumerate()
        .map(|(ordinal, second)| seed_turn(&vault, ordinal as u64, *second))
        .collect();
    let scopes = [
        DreamerConsolidationScope::Micro,
        MESO,
        DreamerConsolidationScope::Macro,
    ];
    for scope in scopes {
        for from in [0, 1, 7, u64::MAX] {
            for other in scopes {
                advance_watermark(&vault, other, u64::MAX).expect("consume all");
            }
            reopen_prefilter_rescan(&vault, scope, from).expect("inclusive rescan");
            let reset = read_watermark(&vault, scope).expect("reset");
            assert_eq!(reset.before_first, from == 0);
            assert_eq!(reset.last_learned_at, if from == 0 { 0 } else { from - 1 });
            assert_eq!(reset.last_turn_id, None);
            let expected: Vec<_> = seconds
                .iter()
                .zip(&ids)
                .filter_map(|(second, id)| (*second >= from).then_some(*id))
                .collect();
            assert_eq!(dirty_ids(&vault, scope), expected, "{scope:?} from {from}");
            for other in scopes {
                if other != scope {
                    assert!(dirty_ids(&vault, other).is_empty(), "scope-local rewind");
                }
            }
        }
    }
}

#[test]
fn prefilter_rescan_zero_keeps_cap_fence_and_compound_settlement() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    let ids: Vec<_> = (0..DEFAULT_MESO_ROUND_TURN_CAP + 2)
        .map(|ordinal| seed_turn(&vault, ordinal as u64, 0))
        .collect();
    let later = seed_turn(&vault, ids.len() as u64, 1);
    advance_watermark(&vault, MESO, 10).expect("consume all");
    reopen_prefilter_rescan(&vault, MESO, 0).expect("full rescan");
    let reset = read_watermark(&vault, MESO).expect("reset");
    assert!(
        scan_dirty_turns(&vault, MESO, &reset, 0)
            .expect("zero limit")
            .is_empty()
    );
    assert_eq!(
        scan_dirty_turns(&vault, MESO, &reset, 1).expect("one turn")[0].turn_id,
        ids[0]
    );
    assert_eq!(dirty_ids(&vault, MESO), ids[..DEFAULT_MESO_ROUND_TURN_CAP]);
    for scope in [
        DreamerConsolidationScope::Micro,
        DreamerConsolidationScope::Macro,
    ] {
        assert_eq!(
            scan_dirty_turns(&vault, scope, &reset, usize::MAX)
                .expect("uncapped scope")
                .len(),
            ids.len() + 1
        );
    }

    let mut txn = vault.store.env.write_txn().expect("write txn");
    assert_eq!(
        read_watermark_in_txn(&vault, &txn, MESO).expect("live reset"),
        reset
    );
    assert_eq!(
        collect_dirty_turn_ids_in_txn(&vault, &txn, MESO, 0, 0).expect("zero fence"),
        ids[..DEFAULT_MESO_ROUND_TURN_CAP]
    );
    advance_watermark_in_txn(&vault, &mut txn, MESO, 0).expect("settle capped zero round");
    txn.commit().expect("commit settlement");
    let settled = read_watermark(&vault, MESO).expect("settled");
    assert!(!settled.before_first);
    assert_eq!(settled.last_learned_at, 0);
    assert_eq!(
        settled.last_turn_id,
        Some(ids[DEFAULT_MESO_ROUND_TURN_CAP - 1])
    );
    let mut remaining = ids[DEFAULT_MESO_ROUND_TURN_CAP..].to_vec();
    remaining.push(later);
    assert_eq!(
        dirty_ids(&vault, MESO),
        remaining,
        "no replay or stranded zero turns"
    );

    let mut txn = vault.store.env.write_txn().expect("next write txn");
    advance_watermark_in_txn(&vault, &mut txn, MESO, 0).expect("settle zero remainder");
    txn.commit().expect("commit remainder");
    assert_eq!(dirty_ids(&vault, MESO), vec![later]);
    let mut txn = vault.store.env.write_txn().expect("later write txn");
    advance_watermark_in_txn(&vault, &mut txn, MESO, 1).expect("settle later turn");
    assert!(
        advance_watermark_in_txn(&vault, &mut txn, MESO, 0).is_err(),
        "normal rewind refused"
    );
    txn.commit().expect("commit later settlement");
    assert!(dirty_ids(&vault, MESO).is_empty());
}

#[test]
fn prefilter_rescan_empty_zero_round_settles_to_complete_second() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::device());
    reopen_prefilter_rescan(&vault, MESO, 0).expect("full rescan");
    assert!(read_watermark(&vault, MESO).expect("reset").before_first);
    let mut txn = vault.store.env.write_txn().expect("write txn");
    assert!(
        collect_dirty_turn_ids_in_txn(&vault, &txn, MESO, 0, 0)
            .expect("empty fence")
            .is_empty()
    );
    advance_watermark_in_txn(&vault, &mut txn, MESO, 0).expect("settle empty round");
    txn.commit().expect("commit settlement");
    assert_eq!(
        read_watermark(&vault, MESO).expect("complete second zero"),
        ConsolidationWatermark::bootstrap()
    );
}

#[test]
fn before_first_watermark_codec_rejects_noncanonical_positions() {
    let reset = ConsolidationWatermark {
        before_first: true,
        ..ConsolidationWatermark::bootstrap()
    };
    let encoded = encode_watermark(&reset).expect("encode before-first");
    assert_eq!(
        decode_watermark(&encoded).expect("decode before-first"),
        reset
    );
    assert_ne!(
        encoded,
        encode_watermark(&ConsolidationWatermark::bootstrap()).expect("bootstrap")
    );
    let id = EntityId::from_bytes([1; 16]).expect("id");
    for invalid in [
        ConsolidationWatermark {
            last_learned_at: 1,
            ..reset
        },
        ConsolidationWatermark {
            last_turn_id: Some(id),
            ..reset
        },
    ] {
        assert!(encode_watermark(&invalid).is_err());
    }
    for entries in [
        vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(WATERMARK_SCHEMA_VERSION),
            ),
            (Value::from(KEY_LAST_LEARNED_AT), Value::Nil),
            (
                Value::from(KEY_LAST_TURN_ID),
                Value::Binary(id.as_bytes().to_vec()),
            ),
        ],
        vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(WATERMARK_SCHEMA_VERSION_V1),
            ),
            (Value::from(KEY_LAST_LEARNED_AT), Value::Nil),
        ],
        vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(WATERMARK_SCHEMA_VERSION),
            ),
            (Value::from(KEY_LAST_LEARNED_AT), Value::Nil),
            (Value::from(KEY_LAST_LEARNED_AT), Value::from(0_u64)),
            (Value::from(KEY_LAST_TURN_ID), Value::Nil),
        ],
    ] {
        let raw = encode_value(&Value::Map(entries)).expect("encode invalid row");
        assert!(
            decode_watermark(&raw).is_err(),
            "noncanonical reset must be refused"
        );
    }
}
