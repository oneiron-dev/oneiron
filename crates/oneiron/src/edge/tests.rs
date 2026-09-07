use super::EDGE_KEY_LEN;
use super::EDGE_VALUE_STRUCTURAL_LEN;
use super::ENTITY_ID_LEN;
use super::EdgeKind;
use super::EntityId;
use super::Vad;
use super::encode_edge_value;
use super::parse_strict_edge_record;

#[test]
fn strict_edge_record_parser_decodes_key_and_value() {
    let source = EntityId::from_bytes([0x11; ENTITY_ID_LEN]).unwrap();
    let target = EntityId::from_bytes([0x22; ENTITY_ID_LEN]).unwrap();
    let kind = EdgeKind::Supports;
    let mut key = [0_u8; EDGE_KEY_LEN];
    key[..ENTITY_ID_LEN].copy_from_slice(source.as_bytes());
    key[ENTITY_ID_LEN] = kind as u8;
    key[ENTITY_ID_LEN + 1..].copy_from_slice(target.as_bytes());
    let value = encode_edge_value(kind, 0.75, 42, Vad::NEUTRAL, None).unwrap();

    let record = parse_strict_edge_record(&key, &value).unwrap();
    assert_eq!(record.source, source);
    assert_eq!(record.kind, kind);
    assert_eq!(record.target, target);
    assert_eq!(record.decoded.weight, 0.75);
    assert_eq!(record.decoded.created_at, 42);

    let info = record.into_edge_info();
    assert_eq!(info.kind, kind);
    assert_eq!(info.target, target);
    assert_eq!(info.target_short_id, None);
    assert_eq!(info.weight, 0.75);
    assert_eq!(info.created_at, 42);
}

/// ONE-1414 done-means 10 + the no-pooling contract, at the byte level.
///
/// One test because these are one decision: `same_as` is byte 20, carries
/// the 12-byte structural layout, has NO stored-weight prior, and is never
/// traversed. A future edit that gave it a λ or a default weight would have
/// to delete a line here to pass.
#[test]
fn same_as_is_byte_20_structural_unweighted_and_never_traversed() {
    assert_eq!(EdgeKind::SameAs as u8, 20);
    assert_eq!(EdgeKind::try_from_u8(20), Some(EdgeKind::SameAs));
    assert_eq!(EdgeKind::SameAs.default_weight(), None);
    assert_eq!(crate::ppr::lambda_for_kind(EdgeKind::SameAs), None);
    assert_eq!(
        super::edge_value_layout_for_kind(EdgeKind::SameAs, false),
        super::EdgeValueLayout::Structural
    );

    // Byte 20 is the ONLY byte this ticket allocates: 21/22 keep their
    // reserved identity-topology meaning untouched.
    assert_eq!(EdgeKind::try_from_u8(21), Some(EdgeKind::MergedInto));
    assert_eq!(EdgeKind::try_from_u8(22), Some(EdgeKind::SplitInto));
}

/// CMT-4 (ONE-1541) at the byte level: bytes 25/26 are the brief
/// fulfillment pair, both structural, both unweighted, both untraversed,
/// and both reserved against a raw public write in either direction.
#[test]
fn fulfillment_pair_is_structural_unweighted_and_reserved() {
    assert_eq!(EdgeKind::Fulfills as u8, 25);
    assert_eq!(EdgeKind::DischargedBy as u8, 26);
    assert_eq!(EdgeKind::try_from_u8(25), Some(EdgeKind::Fulfills));
    assert_eq!(EdgeKind::try_from_u8(26), Some(EdgeKind::DischargedBy));
    // The append is append-ONLY: byte 20 keeps `same_as` and the
    // identity-redirect pair keeps 21/22.
    assert_eq!(EdgeKind::try_from_u8(20), Some(EdgeKind::SameAs));
    assert_eq!(EdgeKind::try_from_u8(21), Some(EdgeKind::MergedInto));
    assert_eq!(EdgeKind::try_from_u8(22), Some(EdgeKind::SplitInto));
    // The frontier moved by exactly two.
    assert!(EdgeKind::try_from_u8(27).is_none());

    for kind in [EdgeKind::Fulfills, EdgeKind::DischargedBy] {
        assert_eq!(kind.default_weight(), None);
        assert_eq!(crate::ppr::lambda_for_kind(kind), None);
        assert_eq!(
            super::edge_value_layout_for_kind(kind, false),
            super::EdgeValueLayout::Structural
        );
        assert!(matches!(
            super::validate_public_edge_kind(kind),
            Err(crate::error::Error::ReservedEdgeKind(
                "fulfills" | "discharged_by"
            ))
        ));
        assert!(matches!(
            super::validate_public_edge_creation_kind(kind),
            Err(crate::error::Error::ReservedEdgeKind(
                "fulfills" | "discharged_by"
            ))
        ));

        // The door's explicit 1.0 round-trips as a 12-byte structural row.
        let value = encode_edge_value(kind, 1.0, 1_772_000_400, Vad::NEUTRAL, None)
            .expect("fulfillment edges encode at the door's explicit weight");
        assert_eq!(value.len(), EDGE_VALUE_STRUCTURAL_LEN);
        let decoded = super::decode_edge_value_for_kind(kind, &value)
            .expect("structural fulfillment value decodes for its kind");
        assert_eq!(decoded.weight.to_bits(), 1.0_f32.to_bits());
        assert_eq!(decoded.created_at, 1_772_000_400);
        assert_eq!(decoded.vad, None);
        assert_eq!(decoded.provenance, None);
    }
}

/// The owning write door stores an EXPLICIT `0.0`, and the row decodes back
/// as a 12-byte structural value carrying exactly that weight.
#[test]
fn same_as_encodes_explicit_zero_weight_as_a_structural_row() {
    let value = encode_edge_value(EdgeKind::SameAs, 0.0, 1_772_000_300, Vad::NEUTRAL, None)
        .expect("same_as encodes at explicit zero weight");
    assert_eq!(value.len(), EDGE_VALUE_STRUCTURAL_LEN);

    let decoded = super::decode_edge_value_for_kind(EdgeKind::SameAs, &value)
        .expect("structural same_as value decodes for its kind");
    assert_eq!(decoded.weight.to_bits(), 0.0_f32.to_bits());
    assert_eq!(decoded.created_at, 1_772_000_300);
    assert_eq!(decoded.vad, None);
    assert_eq!(decoded.provenance, None);
}

/// A raw byte-20 edge key parses back to `SameAs` with its endpoints
/// intact — the decode half of the wire contract.
#[test]
fn same_as_edge_record_decodes_from_raw_bytes() {
    let source = EntityId::from_bytes([0x31; ENTITY_ID_LEN]).unwrap();
    let target = EntityId::from_bytes([0x32; ENTITY_ID_LEN]).unwrap();
    let mut key = [0_u8; EDGE_KEY_LEN];
    key[..ENTITY_ID_LEN].copy_from_slice(source.as_bytes());
    key[ENTITY_ID_LEN] = 20;
    key[ENTITY_ID_LEN + 1..].copy_from_slice(target.as_bytes());
    let value = encode_edge_value(EdgeKind::SameAs, 0.0, 7, Vad::NEUTRAL, None).unwrap();

    let record = parse_strict_edge_record(&key, &value).expect("byte-20 edge record parses");
    assert_eq!(record.kind, EdgeKind::SameAs);
    assert_eq!(record.source, source);
    assert_eq!(record.target, target);
}

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
    assert!(matches!(
        err,
        crate::error::Error::CorruptedIndex("edge record")
    ));

    key[ENTITY_ID_LEN + 1..].fill(0xFF);
    let value = encode_edge_value(EdgeKind::Supports, 0.5, 1, Vad::NEUTRAL, None).unwrap();
    let err = parse_strict_edge_record(&key, &value)
        .expect_err("reserved target id must fail closed");
    assert!(matches!(
        err,
        crate::error::Error::CorruptedIndex("edge record")
    ));
}
