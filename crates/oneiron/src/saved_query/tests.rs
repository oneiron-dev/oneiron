use serde_json::json;

use super::*;
use crate::entity_id::EntityId;

fn id(seed: u8) -> EntityId {
    crate::test_util::entity(seed)
}

fn sample_definition() -> SavedQueryDefinition {
    SavedQueryDefinition {
        schema_version: SAVED_QUERY_SCHEMA_VERSION,
        owner_actor: id(0x21),
        scope: QueryScope::default(),
        definition_version: 3,
        filter: FilterAst::Claim {
            predicate: "crm.fit".to_owned(),
            cmp: ClaimComparison::Exists,
            value: Value::Null,
        },
        matcher: MatcherSpec::Hard {
            expression: FilterAst::All { terms: Vec::new() },
        },
        eval: EvalPolicy {
            mode: EvalMode::Manual,
            max_entities_per_wake: 8,
            max_judges_per_wake: 2,
        },
        lifecycle: SavedQueryLifecycle::Active,
    }
}

fn sample_memo_row() -> VerdictMemoRow {
    VerdictMemoRow {
        key: VerdictMemoKey {
            query_ref: id(0x22),
            entity_ref: id(0x23),
            evidence_hash: [7u8; EVIDENCE_HASH_LEN],
        },
        definition_version: 3,
        verdict: MatchVerdict::Match,
        why: "because".to_owned(),
        envelope: SavedQueryDerivationEnvelope {
            content_hash: hex_lower(&[7u8; EVIDENCE_HASH_LEN]),
            model_id: "hard".to_owned(),
            version: EVALUATOR_VERSION.to_owned(),
            params_hash: hex_lower(&[9u8; EVIDENCE_HASH_LEN]),
        },
        evaluated_at: 1_700,
    }
}

/// The memo key is the three identity components concatenated, in a fixed
/// order, under a versioned prefix. Nothing else may enter it — a key that also
/// hashed the verdict would never hit.
#[test]
fn memo_key_is_prefix_plus_three_fixed_width_components() {
    let key = VerdictMemoKey {
        query_ref: id(0x24),
        entity_ref: id(0x25),
        evidence_hash: [0x5A; EVIDENCE_HASH_LEN],
    };
    let encoded = MEMOS.key_bytes(&key);
    let prefix = b"saved_query.memo.v1:";
    assert!(encoded.starts_with(prefix));
    assert_eq!(encoded.len(), prefix.len() + 16 + 16 + EVIDENCE_HASH_LEN);
    assert_eq!(
        &encoded[prefix.len()..prefix.len() + 16],
        id(0x24).as_bytes()
    );
    assert_eq!(
        &encoded[prefix.len() + 16..prefix.len() + 32],
        id(0x25).as_bytes()
    );
    assert_eq!(&encoded[prefix.len() + 32..], &[0x5A; EVIDENCE_HASH_LEN]);
}

/// Event keys sort by epoch under a `(query, entity)` prefix scan, so history
/// reads back oldest-first without a sort step that could disagree with disk.
#[test]
fn event_keys_sort_by_epoch_within_the_pair_prefix() {
    let (query, entity) = (id(0x28), id(0x29));
    let mut prefix = MEMBERSHIP_EVENTS.decl().prefix.to_vec();
    prefix.extend_from_slice(&event_pair_prefix(&query, &entity));
    let mut keys = [
        MEMBERSHIP_EVENTS.key_bytes(&(query, entity, 10)),
        MEMBERSHIP_EVENTS.key_bytes(&(query, entity, 2)),
        MEMBERSHIP_EVENTS.key_bytes(&(query, entity, 300)),
    ];
    assert!(keys.iter().all(|key| key.starts_with(&prefix)));
    keys.sort();
    assert_eq!(keys[0], MEMBERSHIP_EVENTS.key_bytes(&(query, entity, 2)));
    assert_eq!(keys[1], MEMBERSHIP_EVENTS.key_bytes(&(query, entity, 10)));
    assert_eq!(keys[2], MEMBERSHIP_EVENTS.key_bytes(&(query, entity, 300)));
}

/// A row that is not JSON, is missing a field, or names a verdict outside the
/// closed set is CorruptedIndex — never a silent miss and never a default.
#[test]
fn malformed_memo_rows_are_rejected() {
    let encoded = encode_memo_row(&sample_memo_row()).expect("encode");
    let mut truncated = encoded.clone();
    truncated.truncate(encoded.len() / 2);

    let mut parsed: Value = serde_json::from_slice(&encoded).expect("row is json");
    parsed["verdict"] = json!("maybe");
    let unknown_verdict = serde_json::to_vec(&parsed).expect("re-encode");

    let mut parsed: Value = serde_json::from_slice(&encoded).expect("row is json");
    parsed["evidence_hash"] = json!("00ff");
    let short_hash = serde_json::to_vec(&parsed).expect("re-encode");

    let mut parsed: Value = serde_json::from_slice(&encoded).expect("row is json");
    parsed.as_object_mut().expect("object").remove("why");
    let missing_field = serde_json::to_vec(&parsed).expect("re-encode");

    for (label, bytes) in [
        ("truncated", truncated),
        ("unknown verdict", unknown_verdict),
        ("short hash", short_hash),
        ("missing field", missing_field),
    ] {
        assert!(
            matches!(decode_memo_row(&bytes), Err(Error::CorruptedIndex(_))),
            "{label} memo row must be rejected"
        );
    }
}

/// Canonical JSON sorts object keys recursively; the crate builds `serde_json`
/// with `preserve_order`, so two equal values with different insertion orders
/// would otherwise hash differently.
#[test]
fn canonical_json_is_insertion_order_independent() {
    let first = json!({"b": 1, "a": {"d": 2, "c": 3}});
    let second = json!({"a": {"c": 3, "d": 2}, "b": 1});
    assert_ne!(
        serde_json::to_vec(&first).expect("raw"),
        serde_json::to_vec(&second).expect("raw"),
        "the fixture must actually differ before canonicalization"
    );
    let definition = sample_definition();
    let evidence = |value| RelevantEvidence {
        entity_ref: id(1),
        claim_values: vec![("predicate".to_string(), value)],
        edge_targets: Vec::new(),
        semantic_inputs: Vec::new(),
        scope_membership: QueryScope {
            worlds: Vec::new(),
            facets: Vec::new(),
        },
    };
    assert_eq!(
        compute_evidence_hash(&definition, &evidence(first)).expect("evidence hash"),
        compute_evidence_hash(&definition, &evidence(second)).expect("evidence hash"),
    );
}

/// The watermark row is `epoch || content digest`; any other length is disk
/// corruption, not a shorter epoch.
#[test]
fn watermark_rows_round_trip_and_reject_wrong_lengths() {
    let content = [3u8; EVIDENCE_HASH_LEN];
    let encoded = encode_watermark(42, &content);
    assert_eq!(decode_watermark(&encoded).expect("decode"), (42, content));
    assert!(matches!(
        decode_watermark(&encoded[..encoded.len() - 1]),
        Err(Error::CorruptedIndex(_))
    ));
}

/// Irrelevant evidence must not move the hash, and relevant evidence must.
#[test]
fn evidence_hash_covers_relevant_evidence_and_scope() {
    let definition = sample_definition();
    let base = RelevantEvidence {
        entity_ref: id(0x2C),
        claim_values: vec![("crm.fit".to_owned(), json!("fit"))],
        edge_targets: Vec::new(),
        semantic_inputs: Vec::new(),
        scope_membership: QueryScope::default(),
    };
    let hash = compute_evidence_hash(&definition, &base).expect("hash");

    let mut moved = base.clone();
    moved.claim_values = vec![("crm.fit".to_owned(), json!("not_fit"))];
    assert_ne!(
        hash,
        compute_evidence_hash(&definition, &moved).expect("hash")
    );

    let mut bumped = definition.clone();
    bumped.definition_version += 1;
    assert_ne!(hash, compute_evidence_hash(&bumped, &base).expect("hash"));

    let mut rescoped = definition.clone();
    rescoped.scope = QueryScope {
        worlds: vec![id(0x2D)],
        facets: Vec::new(),
    };
    assert_ne!(hash, compute_evidence_hash(&rescoped, &base).expect("hash"));

    // Scope MEMBERSHIP is evidence too: moving into or out of a world has
    // to invalidate the memo, and nothing else carries that movement.
    let mut moved_world = base.clone();
    moved_world.scope_membership = QueryScope {
        worlds: vec![id(0x2D)],
        facets: Vec::new(),
    };
    assert_ne!(
        hash,
        compute_evidence_hash(&definition, &moved_world).expect("hash")
    );

    assert_eq!(
        hash,
        compute_evidence_hash(&definition, &base).expect("hash")
    );
}

/// The MessagePack projection must be injective: a byte string and the
/// literal text of its hex spelling cannot land on the same JSON, and a map
/// key that looks like a wrapper tag cannot impersonate one.
#[test]
fn rmpv_projection_is_injective_across_types() {
    assert_ne!(
        rmpv_to_json(&rmpv::Value::Binary(vec![0x61])),
        rmpv_to_json(&rmpv::Value::from("61"))
    );
    assert_ne!(
        rmpv_to_json(&rmpv::Value::Ext(1, vec![0x61])),
        rmpv_to_json(&rmpv::Value::Binary(vec![0x61]))
    );
    let impersonator = rmpv::Value::Map(vec![(rmpv::Value::from("$bin"), rmpv::Value::from("61"))]);
    assert_ne!(
        rmpv_to_json(&impersonator),
        rmpv_to_json(&rmpv::Value::Binary(vec![0x61]))
    );
    // Non-string map keys are preserved rather than erased.
    let numeric_keys = rmpv::Value::Map(vec![(rmpv::Value::from(1), rmpv::Value::from("a"))]);
    assert_ne!(
        rmpv_to_json(&numeric_keys),
        rmpv_to_json(&rmpv::Value::Map(Vec::new()))
    );
}

/// Length prefixes exist so `("ab", "c")` and `("a", "bc")` cannot collide.
#[test]
fn evidence_hash_length_prefixes_prevent_field_smearing() {
    let definition = sample_definition();
    let left = RelevantEvidence {
        entity_ref: id(0x2E),
        claim_values: vec![("ab".to_owned(), json!("c"))],
        edge_targets: Vec::new(),
        semantic_inputs: Vec::new(),
        scope_membership: QueryScope::default(),
    };
    let right = RelevantEvidence {
        claim_values: vec![("a".to_owned(), json!("bc"))],
        ..left.clone()
    };
    assert_ne!(
        compute_evidence_hash(&definition, &left).expect("hash"),
        compute_evidence_hash(&definition, &right).expect("hash")
    );
}

#[test]
fn memory_watch_is_durable_owner_bound_and_reversible() {
    use crate::campaign::register_crm_pack;
    use crate::registry::TypeByteFamily;
    use crate::{TimeRange, VaultConfig};
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = crate::Vault::open_unseeded_for_test(dir.path(), VaultConfig::device())
        .expect("open vault");
    register_crm_pack(&vault, 107, 108, TypeByteFamily::Productivity).expect("pack");
    let owner = id(0xB1);
    let other = id(0xB2);
    let anchor = id(0xB3);
    let subject = id(0xB4);
    vault
        .put_entity(
            &owner,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )
        .expect("owner");
    vault
        .put_entity(
            &subject,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"subject",
        )
        .expect("subject");
    let body = ClaimBody::new(
        "profile.city",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("Osaka"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    vault
        .put_claim(&anchor, &body, TimeRange { start: 1, end: 1 }, 1)
        .expect("claim");
    let watch = memory_watch::set_memory_watch(&vault, owner, anchor, true, 10)
        .expect("enable")
        .expect("watch");
    assert_eq!(
        memory_watch::set_memory_watch(&vault, owner, anchor, true, 11).expect("idempotent"),
        Some(watch.clone())
    );
    assert_eq!(
        memory_watch::memory_watches(&vault, owner).expect("list"),
        vec![watch.clone()]
    );
    assert!(
        memory_watch::memory_watches(&vault, other)
            .expect("other list")
            .is_empty()
    );
    assert!(
        memory_watch::memory_watch(&vault, other, anchor)
            .expect("other read")
            .is_none()
    );
    drop(vault);
    let reopened =
        crate::Vault::open_unseeded_for_test(dir.path(), VaultConfig::device()).expect("reopen");
    assert_eq!(
        memory_watch::memory_watch(&reopened, owner, anchor).expect("persisted"),
        Some(watch.clone())
    );
    assert_eq!(
        memory_watch::set_memory_watch(&reopened, owner, anchor, false, 12).expect("disable"),
        None
    );
    assert!(
        memory_watch::memory_watches(&reopened, owner)
            .expect("disabled list")
            .is_empty()
    );
    assert_eq!(
        memory_watch::set_memory_watch(&reopened, owner, anchor, true, 13).expect("reenable"),
        Some(watch)
    );
}
