use super::EDGE_KEY_LEN;
use super::EDGE_VALUE_STRUCTURAL_LEN;
use super::ENTITY_ID_LEN;
use super::EdgeKind;
use super::EntityId;
use super::Vad;
use super::encode_edge_value;
use super::parse_strict_edge_record;

#[test]
fn strict_edge_record_parser_normalizes_corruption_errors() {
    let source = EntityId::from_bytes([0x11; ENTITY_ID_LEN]).unwrap();
    let target = EntityId::from_bytes([0x22; ENTITY_ID_LEN]).unwrap();
    let mut key = [0_u8; EDGE_KEY_LEN];
    key[..ENTITY_ID_LEN].copy_from_slice(source.as_bytes());
    key[ENTITY_ID_LEN] = EdgeKind::Supports as u8;
    key[ENTITY_ID_LEN + 1..].copy_from_slice(target.as_bytes());

    let truncated_value = [0_u8; EDGE_VALUE_STRUCTURAL_LEN - 1];
    let err = parse_strict_edge_record(&key, &truncated_value)
        .expect_err("truncated edge value must fail closed");
    assert!(matches!(err, crate::error::Error::CorruptedIndex(_)));

    key[ENTITY_ID_LEN + 1..].fill(0xFF);
    let value = encode_edge_value(EdgeKind::Supports, 0.5, 1, Vad::NEUTRAL, None).unwrap();
    let err =
        parse_strict_edge_record(&key, &value).expect_err("reserved target id must fail closed");
    assert!(matches!(err, crate::error::Error::CorruptedIndex(_)));
}

/// Canon's structural edge kinds: oneiron-docs
/// `site/src/data/oneiron-contracts.ts`, `edgeValueLayouts[structural].kinds`
/// (the ARCH-0034 structural 12 B row), as of docs commit 0f8e58e0a1d4
/// (2026-09-26), which extended the row from 11 names to all 20 the engine
/// classifies.
const CANON_STRUCTURAL_KINDS: &str = "authored_by · scoped_to · part_of · supersedes · belongs_to · claim_of · child_of · assigned_to · derived_from · same_as · merged_into · split_into · blocked_by · blocks · fulfills · discharged_by · parent · spawned_by · addressed_to · replies_to";

