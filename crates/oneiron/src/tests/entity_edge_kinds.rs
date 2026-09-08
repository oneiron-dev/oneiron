//! Entity/edge identity contracts: edge kinds, value layouts, weights, type prefixes.

use super::*;

#[test]
fn entity_id_now_is_monotonic_lexicographically() {
    let mut prev = EntityId::now();
    let mut saw_increase = false;
    for _ in 0..128 {
        let next = EntityId::now();
        assert!(prev <= next, "EntityId::now() regressed: prev > next");
        saw_increase |= prev < next;
        prev = next;
    }
    assert!(
        saw_increase,
        "expected EntityId::now() to advance at least once"
    );
}

#[test]
fn edge_kind_discriminants_match_arch_0034_contract() {
    for (disc, kind) in PINNED_EDGE_KIND_DISCRIMINANTS {
        assert_eq!(kind as u8, disc, "{kind:?} discriminant drifted");
    }
}

#[test]
fn edge_kind_u8_round_trip_accepts_pinned_range() {
    for (disc, expected) in PINNED_EDGE_KIND_DISCRIMINANTS {
        let kind = EdgeKind::try_from_u8(disc).expect("valid discriminant");
        assert_eq!(kind, expected);
        assert_eq!(kind as u8, disc);
    }
    // The frontier: 27 and up stay unallocated (ONE-1541 took 25/26).
    assert!(EdgeKind::try_from_u8(27).is_none());
}

/// ONE-1541 done-means: appending `fulfills`/`discharged_by` must leave every
/// frozen landed byte 0–22 exactly where it was — including the byte-20
/// `same_as` slot — while minting 25/26. Bytes 23/24 are deliberately not
/// asserted here: this lane neither mints them nor depends on their state.
#[test]
fn edge_kind_append_preserves_legacy_bytes() {
    for (disc, expected) in PINNED_EDGE_KIND_DISCRIMINANTS {
        if disc > 22 {
            continue;
        }
        assert_eq!(
            EdgeKind::try_from_u8(disc),
            Some(expected),
            "legacy edge byte {disc} drifted"
        );
    }
    assert_eq!(EdgeKind::try_from_u8(20), Some(EdgeKind::SameAs));

    assert_eq!(EdgeKind::try_from_u8(25), Some(EdgeKind::Fulfills));
    assert_eq!(EdgeKind::try_from_u8(26), Some(EdgeKind::DischargedBy));
    assert_eq!(EdgeKind::Fulfills as u8, 25);
    assert_eq!(EdgeKind::DischargedBy as u8, 26);

    for kind in [EdgeKind::Fulfills, EdgeKind::DischargedBy] {
        assert_eq!(kind.default_weight(), None, "{kind:?} carries no prior");
        assert_eq!(
            ppr::lambda_for_kind(kind),
            None,
            "{kind:?} is not traversed"
        );
        assert_eq!(
            edge::edge_value_layout_for_kind(kind, false),
            EdgeValueLayout::Structural
        );
    }
}

/// ONE-1924 — minting `blocked_by` at u8 23 must leave the edge byte frontier
/// intact: the ARCH-0055 redirect pair keeps bytes 21/22, and byte 20 belongs
/// to ONE-1414's `same_as` (minted there; parked for it before that).
#[test]
fn blocked_by_mint_preserves_edge_byte_frontier() {
    assert_eq!(EdgeKind::BlockedBy as u8, 23);
    assert_eq!(EdgeKind::try_from_u8(23), Some(EdgeKind::BlockedBy));

    assert_eq!(
        EdgeKind::try_from_u8(20),
        Some(EdgeKind::SameAs),
        "byte 20 is ONE-1414's same_as slot"
    );
    assert_eq!(EdgeKind::try_from_u8(21), Some(EdgeKind::MergedInto));
    assert_eq!(EdgeKind::try_from_u8(22), Some(EdgeKind::SplitInto));
    assert_eq!(EdgeKind::MergedInto as u8, 21);
    assert_eq!(EdgeKind::SplitInto as u8, 22);
}

/// ONE-1924 — `blocked_by` is the contracts.ts u8-23 row: structural 12 B,
/// `pprWeight: null`, `lambda: null`. It carries no VAD and no provenance hot
/// flags, exactly like the `child_of` non-traversal precedent, so no PPR mass
/// can reach a dependency target through it.
#[test]
fn blocked_by_matches_structural_non_traversed_contract_row() -> Result<()> {
    assert_eq!(EdgeKind::BlockedBy.default_weight(), None);
    assert_eq!(ppr::lambda_for_kind(EdgeKind::BlockedBy), None);
    assert_eq!(
        edge::edge_value_layout_for_kind(EdgeKind::BlockedBy, false),
        EdgeValueLayout::Structural
    );

    let value = encode_edge_value(EdgeKind::BlockedBy, 1.0, 1_772_000_200, Vad::NEUTRAL, None)?;
    assert_eq!(value.len(), EDGE_VALUE_STRUCTURAL_LEN);
    let decoded = decode_edge_value_for_kind(EdgeKind::BlockedBy, &value)?;
    assert_f32_exact(decoded.weight, 1.0);
    assert_eq!(decoded.created_at, 1_772_000_200);
    assert_eq!(decoded.vad, None);
    assert_eq!(decoded.provenance, None);

    let vad_err = encode_edge_value(
        EdgeKind::BlockedBy,
        1.0,
        1_772_000_201,
        Vad {
            valence: 0.25,
            arousal: 0.0,
            dominance: 0.0,
        },
        None,
    )
    .expect_err("structural blocked_by must reject non-neutral VAD");
    assert_matches!(
        vad_err,
        Error::InvariantViolation("structural edges do not carry VAD")
    );

    let provenance_err = encode_edge_value(
        EdgeKind::BlockedBy,
        1.0,
        1_772_000_202,
        Vad::NEUTRAL,
        Some(EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Confirmed,
            actor_class: EdgeActorClass::Agent,
        }),
    )
    .expect_err("structural blocked_by must reject provenance hot flags");
    assert_matches!(
        provenance_err,
        Error::InvariantViolation("structural edges do not carry provenance hot flags")
    );

    Ok(())
}

#[test]
fn edge_value_layout_round_trips_all_contract_edge_kinds() -> Result<()> {
    for (i, (kind, layout)) in CONTRACT_EDGE_VALUE_LAYOUTS.iter().copied().enumerate() {
        let weight = 0.25 + (i as f32 * 0.03125);
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

#[test]
fn encode_edge_value_rejects_structural_non_neutral_vad() {
    let err = encode_edge_value(
        EdgeKind::BelongsTo,
        0.5,
        1_772_000_103,
        Vad {
            valence: 0.25,
            arousal: 0.0,
            dominance: 0.0,
        },
        None,
    )
    .expect_err("structural edge must reject non-neutral VAD");

    assert!(
        matches!(
            err,
            Error::InvariantViolation("structural edges do not carry VAD")
        ),
        "wrong error: {err:?}"
    );
}

#[test]
fn all_entity_type_prefixes() {
    use crate::registry::{
        ENTITY_TYPE_REGISTRY, EntityClassification, TypeByteZone, is_structural_kind,
        short_id_prefix, zone_of,
    };

    // ARCH-0002 / oneiron-contracts.ts §1 pinned storage ABI: per registry
    // row (kind id, type byte, short-id prefix, classification, band).
    // CLAIM=semantic ("deliberately NOT a StructuralKind"); TURN..NOTIFICATION
    // plus AGENT_DEF (byte 17) = core (band 1–63); COMPANION_REGISTER =
    // companion pack (band
    // 64–79); TASK_LIST/TASK/MACHINE/CODE_ARTIFACT/CODE_SYMBOL/
    // BLOB_ARTIFACT = productivity pack
    // (band 80–99); REDACTION_AUDIT/MODEL/POLICY_MANIFEST/
    // AUTHORITY_LOG/FEDERATION_GRANT/ACCESS_GRANT/PSYCH_PROFILE/
    // CHANNEL_IDENTITY/COUNTERPARTY_CONTACT/OUTBOUND_GRANT = maintenance
    // (band 120+).
    type RegistryRow = (
        &'static str,
        u8,
        Option<&'static str>,
        EntityClassification,
        TypeByteZone,
    );
    let expected: &[RegistryRow] = &[
        (
            "CLAIM",
            0,
            Some("cl"),
            EntityClassification::Semantic,
            TypeByteZone::Semantic,
        ),
        (
            "TURN",
            1,
            Some("tn"),
            EntityClassification::Core,
            TypeByteZone::Core,
        ),
        (
            "SESSION",
            2,
            Some("ss"),
            EntityClassification::Core,
            TypeByteZone::Core,
        ),
        (
            "MESSAGE",
            3,
            Some("ms"),
            EntityClassification::Core,
            TypeByteZone::Core,
        ),
        (
            "PERSON",
            4,
            Some("pr"),
            EntityClassification::Core,
            TypeByteZone::Core,
        ),
        (
            "RELATIONSHIP",
            5,
            Some("rl"),
            EntityClassification::Core,
            TypeByteZone::Core,
        ),
        (
            "EVENT",
            6,
            Some("ev"),
            EntityClassification::Core,
            TypeByteZone::Core,
        ),
        (
            "SKILL",
            7,
            Some("sk"),
            EntityClassification::Core,
            TypeByteZone::Core,
        ),
        (
            "SUMMARY",
            8,
            Some("sm"),
            EntityClassification::Core,
            TypeByteZone::Core,
        ),
        (
            "PLACE",
            9,
            Some("pl"),
            EntityClassification::Core,
            TypeByteZone::Core,
        ),
        (
            "ASSET_TEXT",
            10,
            Some("tx"),
            EntityClassification::Core,
            TypeByteZone::Core,
        ),
        (
            "CONVERSATION",
            11,
            Some("cv"),
            EntityClassification::Core,
            TypeByteZone::Core,
        ),
        (
            "ORG",
            12,
            Some("og"),
            EntityClassification::Core,
            TypeByteZone::Core,
        ),
        (
            "FACET",
            13,
            Some("fc"),
            EntityClassification::Core,
            TypeByteZone::Core,
        ),
        (
            "WORLD",
            14,
            Some("wd"),
            EntityClassification::Core,
            TypeByteZone::Core,
        ),
        (
            "ASSET",
            15,
            Some("as"),
            EntityClassification::Core,
            TypeByteZone::Core,
        ),
        (
            "NOTIFICATION",
            16,
            Some("nt"),
            EntityClassification::Core,
            TypeByteZone::Core,
        ),
        (
            "AGENT_DEF",
            17,
            Some("ag"),
            EntityClassification::Core,
            TypeByteZone::Core,
        ),
        (
            "COMPANION_REGISTER",
            78,
            Some("cr"),
            EntityClassification::Pack,
            TypeByteZone::System,
        ),
        // Maintenance-classified engine kind inside the system zone:
        // classification == Maintenance (the door gate) while publicly
        // writable COMPANION_REGISTER shares the zone — classification, not
        // zone position, decides. Per byte-space v3 canon row.
        (
            "IDENTITY_TOPOLOGY_EVENT",
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            None,
            EntityClassification::Maintenance,
            TypeByteZone::System,
        ),
        (
            "TASK_LIST",
            100,
            Some("tl"),
            EntityClassification::Pack,
            TypeByteZone::CompiledProduct,
        ),
        (
            "TASK",
            101,
            Some("tk"),
            EntityClassification::Pack,
            TypeByteZone::CompiledProduct,
        ),
        (
            "MACHINE",
            102,
            Some("mc"),
            EntityClassification::Pack,
            TypeByteZone::CompiledProduct,
        ),
        (
            "CODE_ARTIFACT",
            103,
            Some("cd"),
            EntityClassification::Pack,
            TypeByteZone::CompiledProduct,
        ),
        (
            "CODE_SYMBOL",
            104,
            Some("cs"),
            EntityClassification::Pack,
            TypeByteZone::CompiledProduct,
        ),
        (
            "BLOB_ARTIFACT",
            105,
            Some("ba"),
            EntityClassification::Pack,
            TypeByteZone::CompiledProduct,
        ),
        // ONE-1377 landed NOTE at 86; byte-space v3 canon assigns 106 and
        // ONE-1754 executed the persisted re-key. This table spells the NEW
        // byte because the re-key is done.
        (
            "NOTE",
            106,
            Some("no"),
            EntityClassification::Pack,
            TypeByteZone::CompiledProduct,
        ),
        (
            "SECRET_CUSTODY",
            77,
            None,
            EntityClassification::Maintenance,
            TypeByteZone::System,
        ),
        (
            "REDACTION_AUDIT",
            64,
            None,
            EntityClassification::Maintenance,
            TypeByteZone::System,
        ),
        // ONE-1138 ratified: MODEL = engine-authored maintenance kind, type
        // byte 65 under byte-space v3, short-ID prefix `mo` RESERVED — MACHINE
        // reuse rejected (kind = shape, DEC-0005 §7).
        (
            "MODEL",
            65,
            Some("mo"),
            EntityClassification::Maintenance,
            TypeByteZone::System,
        ),
        (
            "AUTHORITY_LOG",
            66,
            None,
            EntityClassification::Maintenance,
            TypeByteZone::System,
        ),
        (
            "POLICY_MANIFEST",
            67,
            None,
            EntityClassification::Maintenance,
            TypeByteZone::System,
        ),
        (
            "FEDERATION_GRANT",
            68,
            None,
            EntityClassification::Maintenance,
            TypeByteZone::System,
        ),
        (
            "DIAGNOSTIC",
            69,
            None,
            EntityClassification::Maintenance,
            TypeByteZone::System,
        ),
        (
            "ACCESS_GRANT",
            73,
            None,
            EntityClassification::Maintenance,
            TypeByteZone::System,
        ),
        (
            "PSYCH_PROFILE",
            ENTITY_TYPE_PSYCH_PROFILE,
            None,
            EntityClassification::Maintenance,
            TypeByteZone::System,
        ),
        (
            "CHANNEL_IDENTITY",
            ENTITY_TYPE_CHANNEL_IDENTITY,
            None,
            EntityClassification::Maintenance,
            TypeByteZone::System,
        ),
        (
            "COUNTERPARTY_CONTACT",
            ENTITY_TYPE_COUNTERPARTY_CONTACT,
            None,
            EntityClassification::Maintenance,
            TypeByteZone::System,
        ),
        (
            "OUTBOUND_GRANT",
            ENTITY_TYPE_OUTBOUND_GRANT,
            None,
            EntityClassification::Maintenance,
            TypeByteZone::System,
        ),
        (
            "PERSONA_SNAPSHOT_EXPORT",
            ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
            None,
            EntityClassification::Maintenance,
            TypeByteZone::System,
        ),
        (
            "CONNECTOR_KEY",
            crate::registry::ENTITY_TYPE_CONNECTOR_KEY,
            Some("ck"),
            EntityClassification::Maintenance,
            TypeByteZone::System,
        ),
        (
            "COMM_RECORD",
            crate::registry::ENTITY_TYPE_COMM_RECORD,
            None,
            EntityClassification::Maintenance,
            TypeByteZone::System,
        ),
        (
            "SKILL_CONTENT_ANCHOR",
            crate::registry::ENTITY_TYPE_SKILL_CONTENT_ANCHOR,
            None,
            EntityClassification::Maintenance,
            TypeByteZone::System,
        ),
    ];

    let actual: Vec<RegistryRow> = ENTITY_TYPE_REGISTRY
        .iter()
        .map(|entry| {
            (
                entry.kind,
                entry.type_byte,
                entry.short_id_prefix,
                entry.classification,
                entry.zone,
            )
        })
        .collect();
    assert_eq!(actual.as_slice(), expected);

    for (name, byte, prefix, classification, band) in expected {
        match prefix {
            Some(prefix) => {
                let got = short_id_prefix(*byte).unwrap_or_else(|err| {
                    panic!("case {name}: expected prefix {prefix:?}, got err {err:?}")
                });
                assert_eq!(
                    got, *prefix,
                    "case {name}: expected prefix {prefix:?}, got {got:?}"
                );
            }
            None => assert!(
                short_id_prefix(*byte).is_err(),
                "case {name}: expected no short-id prefix"
            ),
        }

        // Registry band metadata must agree with the total band function.
        assert_eq!(
            zone_of(*byte),
            *band,
            "case {name}: zone_of({byte}) disagrees with registry band"
        );

        // StructuralKind = registered core|pack rows ONLY. CLAIM (semantic)
        // and REDACTION_AUDIT (maintenance) are NOT StructuralKinds.
        let expect_structural = matches!(
            classification,
            EntityClassification::Core | EntityClassification::Pack
        );
        assert_eq!(
            is_structural_kind(*byte),
            expect_structural,
            "case {name}: is_structural_kind({byte})"
        );
    }

    assert!(short_id_prefix(99).is_err());
    assert!(short_id_prefix(255).is_err());

    // ONE-1930: every row now also declares the spellings it ANSWERS TO but no
    // longer mints. Empty everywhere on this base — the four board-facing moves
    // (`cl→c`, `pr→p`, `sk→s`, `wd→w`) wait on canon, which
    // `tests/byte_space_v3_conformance.rs` holds this registry equal to. This
    // assertion is the tripwire: the day a legacy prefix appears without canon
    // moving with it, conformance and this test disagree loudly.
    for entry in ENTITY_TYPE_REGISTRY {
        assert!(
            entry.legacy_short_id_prefixes.is_empty(),
            "{} declares legacy prefixes {:?}; canon must declare the move first",
            entry.kind,
            entry.legacy_short_id_prefixes
        );
        assert!(
            entry.short_id_prefix.is_some() || entry.legacy_short_id_prefixes.is_empty(),
            "{} retires a prefix without having a canonical one",
            entry.kind
        );
    }
}

#[test]
fn edge_kinds_child_of_and_assigned_to() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let child = EntityId::now();
    let parent = EntityId::now();
    let machine = EntityId::now();

    put_tree_nodes(vault.batch(), &[child, parent]).commit()?;
    vault.put_edge(&child, EdgeKind::ChildOf, &parent, 1.0)?;
    vault.put_edge(&child, EdgeKind::AssignedTo, &machine, 0.8)?;

    let out = vault.edges_out(&child)?;
    assert_eq!(out.len(), 2);
    assert!(
        out.iter()
            .any(|e| e.kind == EdgeKind::ChildOf && e.target == parent)
    );
    assert!(
        out.iter()
            .any(|e| e.kind == EdgeKind::AssignedTo && e.target == machine)
    );

    // Contract pprWeight is null for both kinds (contracts.ts edgeKinds u8=6/7):
    // no stored-weight prior exists, so callers pick the weight explicitly.
    assert_eq!(EdgeKind::ChildOf.default_weight(), None);
    assert_eq!(EdgeKind::AssignedTo.default_weight(), None);
    Ok(())
}

/// ONE-1115 AC2 — `EdgeKind::default_weight` must equal the contract's
/// LITERAL `edgeKinds.pprWeight` column (oneiron-docs
/// `site/src/data/oneiron-contracts.ts`). `child_of`, `assigned_to`, and
/// `blocked_by` are the only `pprWeight: null` rows; any single-row drift
/// fails this test.
#[test]
fn default_weight_matches_contract_ppr_weight_literals() {
    let expected: [(EdgeKind, Option<f32>); 21] = [
        (EdgeKind::AuthoredBy, Some(0.9)),
        (EdgeKind::ScopedTo, Some(0.7)),
        (EdgeKind::PartOf, Some(0.8)),
        (EdgeKind::Supersedes, Some(0.3)),
        (EdgeKind::BelongsTo, Some(1.0)),
        (EdgeKind::ClaimOf, Some(1.0)),
        (EdgeKind::ChildOf, None),
        (EdgeKind::AssignedTo, None),
        (EdgeKind::DerivedFrom, Some(0.2)),
        (EdgeKind::Mentions, Some(0.6)),
        (EdgeKind::About, Some(0.5)),
        (EdgeKind::Supports, Some(1.0)),
        (EdgeKind::Opposes, Some(0.0)),
        (EdgeKind::ParticipatesIn, Some(1.0)),
        (EdgeKind::Attached, Some(0.8)),
        (EdgeKind::EmployedBy, Some(0.8)),
        (EdgeKind::HasFacet, Some(0.7)),
        (EdgeKind::FacetOf, Some(0.7)),
        (EdgeKind::InWorld, Some(0.7)),
        (EdgeKind::SetIn, Some(0.7)),
        (EdgeKind::BlockedBy, None),
    ];
    for (kind, weight) in expected {
        assert_eq!(
            kind.default_weight(),
            weight,
            "stored-weight prior mismatch for {kind:?}"
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
