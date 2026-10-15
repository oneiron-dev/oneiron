//! Entity/edge identity contracts: edge kinds, value layouts, weights, type prefixes.

use super::*;

#[test]
fn edge_value_layout_round_trips_all_contract_edge_kinds() -> Result<()> {
    for (i, (kind, layout)) in CONTRACT_EDGE_VALUE_LAYOUTS.iter().copied().enumerate() {
        let weight = 0.25 + (i as f32 * 0.02);
        let created_at = 1_772_000_000 + i as u64;
        let vad = contract_vad(i);
        let encode_vad = match layout {
            ContractEdgeLayout::Structural => Vad::NEUTRAL,
            ContractEdgeLayout::SemanticBare => vad,
        };

        let value = encode_edge_value(kind, weight, created_at, encode_vad, None)?;
        assert_eq!(
            value.len(),
            layout.bytes(),
            "wrong value length for {kind:?}"
        );
        assert_common_edge_value_fields(&value, weight, created_at);

        let decoded = decode_edge_value_for_kind(kind, &value)?;
        assert_f32_exact(decoded.weight, weight);
        assert_eq!(decoded.created_at, created_at);
        assert_eq!(decoded.provenance, None);

        match layout {
            ContractEdgeLayout::Structural => {
                assert_eq!(decoded.vad, None, "structural {kind:?} must not carry VAD");
            }
            ContractEdgeLayout::SemanticBare => {
                assert_vad_bytes(&value, vad);
                let decoded_vad = decoded.vad.expect("semantic-bare edge must carry VAD");
                assert_vad_exact(decoded_vad, vad);
            }
        }
    }

    Ok(())
}

#[test]
fn semantic_provenance_round_trips_vad_and_hot_flags() -> Result<()> {
    let flags = EdgeProvenanceFlags {
        confirmation_status: EdgeConfirmationStatus::Confirmed,
        actor_class: EdgeActorClass::Agent,
    };

    for (i, (kind, layout)) in CONTRACT_EDGE_VALUE_LAYOUTS.iter().copied().enumerate() {
        if layout != ContractEdgeLayout::SemanticBare {
            continue;
        }

        let weight = 0.5 + (i as f32 * 0.015625);
        let created_at = 1_773_000_000 + i as u64;
        let vad = contract_vad(i);

        let value = encode_edge_value(kind, weight, created_at, vad, Some(flags))?;
        assert_eq!(
            value.len(),
            EDGE_VALUE_SEMANTIC_PROVENANCED_LEN,
            "provenanced {kind:?} must write {EDGE_VALUE_SEMANTIC_PROVENANCED_LEN} B"
        );
        assert_common_edge_value_fields(&value, weight, created_at);
        assert_vad_bytes(&value, vad);
        assert_eq!(value[24], EdgeConfirmationStatus::Confirmed as u8);
        assert_eq!(value[25], EdgeActorClass::Agent as u8);

        let decoded = decode_edge_value_for_kind(kind, &value)?;
        assert_f32_exact(decoded.weight, weight);
        assert_eq!(decoded.created_at, created_at);
        assert_vad_exact(decoded.vad.expect("provenanced edge must carry VAD"), vad);
        assert_eq!(decoded.provenance, Some(flags));
    }

    Ok(())
}

#[test]
fn decode_edge_value_rejects_non_contract_lengths() {
    for len in [0_usize, 13, 25, 27] {
        let value = vec![0_u8; len];
        let err = decode_edge_value(&value).expect_err("expected invalid edge value length");
        assert!(
            matches!(err, Error::CorruptedIndex("edge value")),
            "length {len} returned wrong error: {err:?}"
        );
    }
}

#[test]
fn decode_edge_value_for_kind_rejects_kind_layout_mismatches() {
    let vad = Vad {
        valence: 0.25,
        arousal: 0.5,
        dominance: 0.75,
    };
    let cases = [
        (
            "structural kind with semantic-bare value",
            EdgeKind::ChildOf,
            contract_semantic_bare_value(0.8, 1_772_000_100, vad),
        ),
        (
            "structural kind with semantic-provenanced value",
            EdgeKind::AssignedTo,
            contract_semantic_provenanced_value(0.7, 1_772_000_101, vad),
        ),
        (
            "semantic kind with structural value",
            EdgeKind::Mentions,
            contract_structural_value(0.6, 1_772_000_102),
        ),
    ];

    for (name, kind, value) in cases {
        let err = decode_edge_value_for_kind(kind, &value).expect_err(name);
        assert!(
            matches!(err, Error::CorruptedIndex("edge value")),
            "{name}: wrong error: {err:?}"
        );
    }
}

/// ONE-1115 AC4 — edge weights are pinned to the contract range \[0, 1\]
/// (contracts.ts `edgeKinds`) at write time: the value encoder and the batch
/// apply path both reject out-of-range and non-finite weights with the typed
/// `InvalidEdgeWeight`, and the boundary values 0.0 / 1.0 are accepted.
#[test]
fn edge_weight_outside_unit_range_rejected_at_write() -> Result<()> {
    fn assert_invalid_weight(err: Error, rejected: f32) {
        let Error::InvalidEdgeWeight { value } = err else {
            panic!("expected InvalidEdgeWeight for {rejected}, got {err:?}");
        };
        if rejected.is_nan() {
            assert!(value.is_nan(), "error payload must echo NaN, got {value}");
        } else {
            assert_eq!(
                value.to_bits(),
                rejected.to_bits(),
                "error payload must echo the rejected weight"
            );
        }
    }

    let (_dir, vault) = open_test_vault();

    for bad in [-0.1_f32, 1.1, f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        // Value encoder (types::encode_edge_value).
        let encode_err = encode_edge_value(EdgeKind::Mentions, bad, 0, Vad::NEUTRAL, None)
            .expect_err("encoder must reject out-of-range weight");
        assert_invalid_weight(encode_err, bad);

        // Batch apply path (put_edge → apply_edge_with_created_at).
        let apply_err = vault
            .put_edge(&EntityId::now(), EdgeKind::Mentions, &EntityId::now(), bad)
            .expect_err("apply path must reject out-of-range weight");
        assert_invalid_weight(apply_err, bad);
    }

    // Closed-interval boundaries are valid weights on both paths.
    for good in [0.0_f32, 1.0] {
        encode_edge_value(EdgeKind::Mentions, good, 0, Vad::NEUTRAL, None)
            .expect("boundary weight must encode");

        let src = EntityId::now();
        let tgt = EntityId::now();
        vault.put_edge(&src, EdgeKind::Mentions, &tgt, good)?;
        let out = vault.edges_out(&src)?;
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].weight.to_bits(),
            good.to_bits(),
            "boundary weight must round-trip the write gate"
        );
    }
    Ok(())
}

/// ONE-1152 (a) oracle self-test: a leaked FORWARD short-id row — keyed
/// `(short_id bytes ‖ content_hash u8)` with the entity id in the VALUE
/// (pinned DB manifest direction, ARCH-0019) — must trip
/// [`assert_no_entity_state`]. Pre-fix, the oracle probed `short_ids` BY
/// ENTITY KEY (a guaranteed miss against the forward layout) and never
/// scanned forward values, so this exact plant escaped silently.
#[test]
#[should_panic(expected = "short_ids row references rejected entity")]
fn assert_no_entity_state_catches_leaked_forward_short_id_row() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let id = EntityId::now();

    // Forward row: key = ASCII short id ‖ content-hash byte, value = id.
    let mut forward_key = b"cl1".to_vec();
    forward_key.push(0x42);
    let mut wtxn = vault.store.env.write_txn().unwrap();
    vault
        .store
        .short_ids
        .put(&mut wtxn, &forward_key, id.as_bytes())
        .unwrap();
    wtxn.commit().unwrap();

    assert_no_entity_state(&vault, &id).unwrap();
}

#[test]
fn conversation_edges_are_structural_door_only_and_non_traversed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    for (byte, kind) in [
        (27, EdgeKind::Parent),
        (28, EdgeKind::SpawnedBy),
        (29, EdgeKind::AddressedTo),
        (30, EdgeKind::RepliesTo),
    ] {
        assert_eq!(EdgeKind::try_from_u8(byte), Some(kind));
        assert_eq!(kind as u8, byte);
        assert_eq!(kind.default_weight(), None);
        assert_eq!(ppr::lambda_for_kind(kind), None);
        let encoded = encode_edge_value(kind, 1.0, 7, Vad::NEUTRAL, None)?;
        assert_eq!(encoded.len(), 12);
        assert_eq!(
            decode_edge_value_for_kind(kind, &encoded)?.layout,
            EdgeValueLayout::Structural
        );
        assert!(matches!(
            encode_edge_value(
                kind,
                1.0,
                7,
                Vad {
                    valence: 0.5,
                    arousal: 0.0,
                    dominance: 0.0
                },
                None
            ),
            Err(Error::InvariantViolation(_))
        ));
        assert!(matches!(
            encode_edge_value(
                kind,
                1.0,
                7,
                Vad::NEUTRAL,
                Some(EdgeProvenanceFlags {
                    confirmation_status: EdgeConfirmationStatus::Confirmed,
                    actor_class: EdgeActorClass::Human
                })
            ),
            Err(Error::InvariantViolation(_))
        ));
        assert_eq!(
            vault
                .put_edge(&EntityId::now(), kind, &EntityId::now(), 1.0)
                .unwrap_err()
                .kind(),
            crate::ErrorKind::ReservedEdgeKind
        );
        assert!(matches!(
            edge::validate_public_edge_kind(kind),
            Err(Error::Registry(
                crate::error::RegistryError::ReservedEdgeKind("conversation_dag")
            ))
        ));
    }
    for (byte, kind) in PINNED_EDGE_KIND_DISCRIMINANTS {
        assert_eq!(EdgeKind::try_from_u8(byte), Some(kind));
    }
    assert_eq!(EdgeKind::try_from_u8(21), Some(EdgeKind::MergedInto));
    assert_eq!(EdgeKind::try_from_u8(22), Some(EdgeKind::SplitInto));
    Ok(())
}
