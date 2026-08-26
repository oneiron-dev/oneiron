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
    let encoded = keys::memo(&key);
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

/// Swapping the query and entity refs must produce a different key: a single
/// concatenation with fixed widths is only unambiguous if the order is honored.
#[test]
fn memo_key_distinguishes_swapped_refs() {
    let forward = keys::memo(&VerdictMemoKey {
        query_ref: id(0x26),
        entity_ref: id(0x27),
        evidence_hash: [1u8; EVIDENCE_HASH_LEN],
    });
    let swapped = keys::memo(&VerdictMemoKey {
        query_ref: id(0x27),
        entity_ref: id(0x26),
        evidence_hash: [1u8; EVIDENCE_HASH_LEN],
    });
    assert_ne!(forward, swapped);
}

/// Event keys sort by epoch under a `(query, entity)` prefix scan, so history
/// reads back oldest-first without a sort step that could disagree with disk.
#[test]
fn event_keys_sort_by_epoch_within_the_pair_prefix() {
    let (query, entity) = (id(0x28), id(0x29));
    let prefix = keys::event_prefix(&query, &entity);
    let mut keys = [
        keys::event(&query, &entity, 10),
        keys::event(&query, &entity, 2),
        keys::event(&query, &entity, 300),
    ];
    assert!(keys.iter().all(|key| key.starts_with(&prefix)));
    keys.sort();
    assert_eq!(keys[0], keys::event(&query, &entity, 2));
    assert_eq!(keys[1], keys::event(&query, &entity, 10));
    assert_eq!(keys[2], keys::event(&query, &entity, 300));
}

#[test]
fn memo_row_round_trips_through_its_codec() {
    let row = sample_memo_row();
    let encoded = encode_memo_row(&row).expect("encode");
    assert_eq!(decode_memo_row(&encoded).expect("decode"), row);
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

#[test]
fn definition_round_trips_through_its_codec() {
    let definition = sample_definition();
    let json = definition_to_json(&definition).expect("encode");
    assert_eq!(definition_from_json(&json).expect("decode"), definition);
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
    assert_eq!(
        canonical_json_bytes(&first).expect("canonical"),
        canonical_json_bytes(&second).expect("canonical")
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

/// An exact-match vector pair reaches the full micros scale, so a query with a
/// 1_000_000 floor can still match its own exemplar.
#[test]
fn cosine_similarity_saturates_on_identical_vectors() {
    assert_eq!(
        cosine_similarity_micros(&[1.0, 2.0], &[1.0, 2.0]),
        1_000_000
    );
    assert_eq!(cosine_similarity_micros(&[1.0, 0.0], &[0.0, 1.0]), 0);
    // Anti-correlated clamps to zero rather than recentering onto a positive
    // range that a zero floor would admit.
    assert_eq!(cosine_similarity_micros(&[1.0, 0.0], &[-1.0, 0.0]), 0);
    assert_eq!(cosine_similarity_micros(&[1.0], &[1.0, 2.0]), 0);
}

/// The fingerprint's only job is to move when either vector moves.
#[test]
fn vector_pair_fingerprint_tracks_both_sides() {
    let base = vector_pair_fingerprint(&Some(vec![1.0, 2.0]), &Some(vec![3.0, 4.0]));
    assert_ne!(
        base,
        vector_pair_fingerprint(&Some(vec![1.0, 2.5]), &Some(vec![3.0, 4.0]))
    );
    assert_ne!(
        base,
        vector_pair_fingerprint(&Some(vec![1.0, 2.0]), &Some(vec![3.0, 4.5]))
    );
    assert_ne!(base, vector_pair_fingerprint(&None, &Some(vec![3.0, 4.0])));
}

/// Empty axes mean "unrestricted"; two disjoint restricted axes CLOSE, which is
/// the fail-closed signal, not an unrestricted empty result.
#[test]
fn scope_intersection_separates_unrestricted_from_closed() {
    let unrestricted = QueryScope::default();
    let alpha = QueryScope {
        worlds: vec![id(0x2A)],
        facets: vec!["work".to_owned()],
    };
    let beta = QueryScope {
        worlds: vec![id(0x2B)],
        facets: vec!["work".to_owned()],
    };

    assert_eq!(alpha.intersect(&unrestricted), Some(alpha.clone()));
    assert_eq!(unrestricted.intersect(&alpha), Some(alpha.clone()));
    assert_eq!(alpha.intersect(&alpha), Some(alpha.clone()));
    assert_eq!(alpha.intersect(&beta), None);
    assert!(alpha.is_closed_against(&beta));
    assert!(!alpha.is_closed_against(&unrestricted));
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

/// A restricted axis needs a WITNESS on that axis. An entity with no world
/// membership is outside a world-scoped query, not universally inside it.
#[test]
fn scope_admits_only_entities_holding_the_restricted_axis() {
    let (alpha, beta, facet) = (id(0x2F), id(0x30), id(0x31).to_hex());
    let world_scoped = QueryScope {
        worlds: vec![alpha],
        facets: Vec::new(),
    };
    assert!(world_scoped.admits(&QueryScope {
        worlds: vec![alpha],
        facets: Vec::new(),
    }));
    assert!(!world_scoped.admits(&QueryScope::default()));
    assert!(!world_scoped.admits(&QueryScope {
        worlds: vec![beta],
        facets: Vec::new(),
    }));

    // An unrestricted scope admits everything, including a bare entity.
    assert!(QueryScope::default().admits(&QueryScope::default()));

    // Both axes must be witnessed when both are restricted.
    let both = QueryScope {
        worlds: vec![alpha],
        facets: vec![facet.clone()],
    };
    assert!(!both.admits(&QueryScope {
        worlds: vec![alpha],
        facets: Vec::new(),
    }));
    assert!(both.admits(&QueryScope {
        worlds: vec![alpha],
        facets: vec![facet],
    }));
}

/// Claim evidence is admitted by WORLD: base reality reads everywhere, a
/// claim scoped to an out-of-reach world reads nowhere.
#[test]
fn claim_world_scope_admission_mirrors_the_gate_rule() {
    let scoped_to = |world: Option<EntityId>| {
        let mut body = ClaimBody::new(
            "crm.fit",
            ClaimSubject::Entity(id(0x32)),
            rmpv::Value::from("fit"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        body.world = world;
        body
    };
    let scope = QueryScope {
        worlds: vec![id(0x33)],
        facets: Vec::new(),
    };
    assert!(claim_in_scope(&scoped_to(None), &scope));
    assert!(claim_in_scope(&scoped_to(Some(id(0x33))), &scope));
    assert!(!claim_in_scope(&scoped_to(Some(id(0x34))), &scope));
    // An unrestricted world axis admits every claim world.
    assert!(claim_in_scope(
        &scoped_to(Some(id(0x34))),
        &QueryScope::default()
    ));
}

/// Active alone is not effective. Approval, staleness, and the valid-time
/// window all gate whether a claim is standing truth at the requested time.
#[test]
fn only_effective_claims_count_as_evidence() {
    let base = || {
        ClaimBody::new(
            "crm.fit",
            ClaimSubject::Entity(id(0x35)),
            rmpv::Value::from("fit"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
    };
    assert!(claim_effective_at(&base(), 1_000));

    let mut proposed = base();
    proposed.approval = ClaimApprovalStatus::Proposed;
    assert!(!claim_effective_at(&proposed, 1_000));

    let mut stale = base();
    stale.stale = true;
    assert!(!claim_effective_at(&stale, 1_000));

    let mut superseded = base();
    superseded.lifecycle = ClaimLifecycleStatus::Superseded;
    assert!(!claim_effective_at(&superseded, 1_000));

    let mut not_yet = base();
    not_yet.valid_from = Some(2_000);
    assert!(!claim_effective_at(&not_yet, 1_000));
    assert!(claim_effective_at(&not_yet, 2_000));

    let mut expired = base();
    expired.valid_to = Some(500);
    assert!(!claim_effective_at(&expired, 1_000));
    assert!(claim_effective_at(&expired, 500));
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

/// Two live values for one predicate must both reach the judge; a
/// predicate-keyed object would show it only the last one while the hash
/// covered both.
#[test]
fn judge_evidence_preserves_every_live_claim_value() {
    let evidence = RelevantEvidence {
        entity_ref: id(0x36),
        claim_values: vec![
            ("crm.fit".to_owned(), json!("fit")),
            ("crm.fit".to_owned(), json!("not_fit")),
        ],
        edge_targets: Vec::new(),
        semantic_inputs: Vec::new(),
        scope_membership: QueryScope::default(),
    };
    let projected = evidence_to_json(&evidence);
    let claims = projected["claims"].as_array().expect("claims are pairs");
    assert_eq!(claims.len(), 2);
    assert_eq!(claims[0], json!(["crm.fit", "fit"]));
    assert_eq!(claims[1], json!(["crm.fit", "not_fit"]));
}

/// Stage 2 scores the vectors the fingerprint was taken from. The function
/// takes NO vault, so a re-read cannot creep back in: a verdict derived
/// from vectors the evidence hash does not name is a memo that lies.
#[test]
fn semantic_decision_scores_the_fingerprinted_vectors() {
    let exemplar_ref = id(0x37);
    let collected = |subject: Option<Vec<f32>>, exemplar: Option<Vec<f32>>| CollectedEvidence {
        evidence: RelevantEvidence {
            entity_ref: id(0x38),
            claim_values: Vec::new(),
            edge_targets: Vec::new(),
            semantic_inputs: vec![(exemplar_ref, vector_pair_fingerprint(&subject, &exemplar))],
            scope_membership: QueryScope::default(),
        },
        subject_vector: subject,
        exemplar_vectors: vec![(exemplar_ref, exemplar)],
    };

    let identical = collected(Some(vec![1.0, 2.0]), Some(vec![1.0, 2.0]));
    assert_eq!(
        semantic_decision(&identical, exemplar_ref, MICROS_PER_UNIT).verdict,
        MatchVerdict::Match
    );

    let orthogonal = collected(Some(vec![1.0, 0.0]), Some(vec![0.0, 1.0]));
    assert_eq!(
        semantic_decision(&orthogonal, exemplar_ref, 1).verdict,
        MatchVerdict::NoMatch
    );

    // An unknowable similarity never admits membership.
    let missing = collected(None, Some(vec![1.0, 2.0]));
    assert_eq!(
        semantic_decision(&missing, exemplar_ref, 0).verdict,
        MatchVerdict::NoMatch
    );
}

/// A zero bound is a budget lie, not an unbounded budget.
#[test]
fn zero_wake_bounds_are_rejected_at_the_write_door() {
    let mut definition = sample_definition();
    definition.eval.max_judges_per_wake = 0;
    assert!(matches!(
        validate_definition(&definition),
        Err(Error::InvalidConfig(_))
    ));

    let mut definition = sample_definition();
    definition.eval.max_entities_per_wake = 0;
    assert!(matches!(
        validate_definition(&definition),
        Err(Error::InvalidConfig(_))
    ));

    assert!(validate_definition(&sample_definition()).is_ok());
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

/// A judge answer must be a closed-set verdict in a JSON object. Prose, a
/// missing reason, and an unknown verdict token are all upstream failures.
#[test]
fn judge_responses_must_be_closed_set_json() {
    assert_eq!(
        decode_judge_decision(r#"{"verdict":"match","why":"fits the rubric"}"#).expect("decode"),
        MatchDecision {
            verdict: MatchVerdict::Match,
            why: "fits the rubric".to_owned(),
        }
    );
    for bad in [
        "yes, definitely a match",
        r#"{"verdict":"probably","why":"x"}"#,
        r#"{"verdict":"match"}"#,
        r#"{"why":"x"}"#,
    ] {
        assert!(
            matches!(
                decode_judge_decision(bad),
                Err(Error::UpstreamToolFailure { .. })
            ),
            "{bad:?} must not decode to a verdict"
        );
    }
}

/// The watermark decides the outcome; payload equality alone never does.
#[test]
fn watermark_verdict_rejects_stale_epochs_without_calling_them_applied() {
    let content = [1u8; EVIDENCE_HASH_LEN];
    let other = [2u8; EVIDENCE_HASH_LEN];

    assert_eq!(watermark_verdict(None, 1, &content), None);
    assert_eq!(
        watermark_verdict(Some((1, Some(content))), 2, &content),
        None
    );
    assert_eq!(
        watermark_verdict(Some((1, Some(content))), 1, &content),
        Some(MembershipCommitOutcome::AlreadyApplied)
    );
    // Same epoch, different content: a conflict, not a retry.
    assert_eq!(
        watermark_verdict(Some((1, Some(content))), 1, &other),
        Some(MembershipCommitOutcome::RejectedStaleEpoch { current_epoch: 1 })
    );
    // The replayed-Entered-after-re-entry case.
    assert_eq!(
        watermark_verdict(Some((3, Some(other))), 1, &content),
        Some(MembershipCommitOutcome::RejectedStaleEpoch { current_epoch: 3 })
    );
    // A watermark recovered from the replicated claim chain carries no
    // content digest, so a same-epoch replay it cannot prove is stale —
    // never "already applied".
    assert_eq!(
        watermark_verdict(Some((2, None)), 2, &content),
        Some(MembershipCommitOutcome::RejectedStaleEpoch { current_epoch: 2 })
    );
    assert_eq!(watermark_verdict(Some((2, None)), 3, &content), None);
}
