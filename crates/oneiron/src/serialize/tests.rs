use std::collections::HashMap;

use crate::context_pack::ContextEntity;
use crate::context_pack::ContextPack;
use crate::context_pack::EmptyContext;
use crate::context_pack::EmptyReason;
use crate::context_pack::FieldProfile;
use crate::context_pack::PackFormat;
use crate::context_pack::PackStats;
use crate::context_pack::TokenAllocation;
use crate::entity_id::EntityId;
use crate::pipeline::Signal;

use super::*;
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;

fn sample_pack() -> ContextPack {
    let mut claim_fields = HashMap::new();
    claim_fields.insert("pred".to_owned(), Value::String("goal.learning".to_owned()));
    claim_fields.insert(
        "val".to_owned(),
        Value::String("Learn Japanese by June".to_owned()),
    );
    claim_fields.insert(
        "evid".to_owned(),
        Value::Array(vec![
            Value::String("tn17:a1".to_owned()),
            Value::String("tn23:c4".to_owned()),
        ]),
    );

    let mut turn_fields = HashMap::new();
    turn_fields.insert(
        "txt".to_owned(),
        Value::String("I really want to learn Japanese".to_owned()),
    );
    turn_fields.insert("spkr".to_owned(), Value::String("user".to_owned()));
    turn_fields.insert(
        "at".to_owned(),
        Value::Number(Number::from(
            crate::unix_seconds_now().saturating_sub(3 * 86_400),
        )),
    );

    ContextPack {
        results: vec![
            ContextEntity {
                id: EntityId::from_bytes_unchecked([1; 16]),
                short_id: "cl88".to_owned(),
                content_hash: 0xf2,
                entity_type: 0,
                score: 0.42,
                fields: Some(claim_fields),
                edges: None,
                vector: None,
            },
            ContextEntity {
                id: EntityId::from_bytes_unchecked([2; 16]),
                short_id: "tn17".to_owned(),
                content_hash: 0xa1,
                entity_type: 1,
                score: 0.39,
                fields: Some(turn_fields),
                edges: None,
                vector: None,
            },
        ],
        neighbors: vec![ContextEntity {
            id: EntityId::from_bytes_unchecked([3; 16]),
            short_id: "pr05".to_owned(),
            content_hash: 0xb3,
            entity_type: 4,
            score: 0.0,
            fields: Some(HashMap::from([(
                "name".to_owned(),
                Value::String("Alice".to_owned()),
            )])),
            edges: None,
            vector: None,
        }],
        stats: PackStats {
            candidates_considered: 45,
            signals_used: vec![Signal::Vector, Signal::Text, Signal::Temporal],
            query_time_us: 2_100,
            entities_hydrated: 2,
            neighbors_hydrated: 1,
            cosine_ghosts_dampened: 0,
            claims_suppressed: 0,
            tokens: crate::context_pack::PackTokenStats::default(),
            items_truncated: crate::context_pack::PackItemAccounting::item_budget(),
            items_dropped: crate::context_pack::PackItemAccounting::token_budget(),
        },
        empty: None,
    }
}

fn config(format: PackFormat) -> SerializeConfig {
    SerializeConfig {
        format,
        profile: FieldProfile::Standard,
        budget: 4000,
        allocation: TokenAllocation::default(),
        include_stats: false,
        merge_neighbors: true,
        max_field_chars: 500,
        max_item_tokens: 0,
    }
}

fn savings_config(format: PackFormat, profile: FieldProfile) -> SerializeConfig {
    SerializeConfig {
        format,
        profile,
        budget: 0,
        allocation: TokenAllocation::default(),
        include_stats: false,
        merge_neighbors: true,
        max_field_chars: 500,
        max_item_tokens: 0,
    }
}

fn prepared_entity_for_test(id_len: usize, fields: Vec<(String, Value)>) -> PreparedEntity {
    PreparedEntity {
        entity_type: 0,
        score: 0.0,
        source: PreparedEntitySource::Result,
        source_id: [0x01; 16],
        id: "x".repeat(id_len),
        fields,
    }
}

fn token_dense_text(prefix: &str, count: usize) -> String {
    (0..count)
        .map(|index| format!("{prefix}_{index:03}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn nested_child_value(depth: usize, leaf: Value) -> Value {
    let mut value = leaf;
    for _ in 0..depth {
        let mut object = Map::new();
        object.insert("child".to_owned(), value);
        value = Value::Object(object);
    }
    value
}

fn nested_child_object(depth: usize) -> Value {
    nested_child_value(depth, Value::String("leaf".to_owned()))
}

fn child_value_at_depth(value: &Value, depth: usize) -> Option<&Value> {
    let mut current = value;
    for _ in 0..depth {
        current = current.as_object()?.get("child")?;
    }
    Some(current)
}

fn claim_entity(seed: u8, predicate: &str, value: &str, score: f32) -> ContextEntity {
    claim_entity_with_value(seed, predicate, Value::String(value.to_owned()), score)
}

fn claim_entity_with_value(seed: u8, predicate: &str, value: Value, score: f32) -> ContextEntity {
    ContextEntity {
        id: EntityId::from_bytes_unchecked([seed; 16]),
        short_id: format!("cl{seed:02}"),
        content_hash: seed,
        entity_type: ENTITY_TYPE_CLAIM,
        score,
        fields: Some(HashMap::from([
            ("pred".to_owned(), Value::String(predicate.to_owned())),
            ("val".to_owned(), value),
        ])),
        edges: None,
        vector: None,
    }
}

fn pack_with_results(results: Vec<ContextEntity>) -> ContextPack {
    ContextPack {
        results,
        neighbors: Vec::new(),
        stats: empty_stats(),
        empty: None,
    }
}

fn token_savings_regression_pack() -> ContextPack {
    let mut pack = ContextPack {
        results: Vec::new(),
        neighbors: Vec::new(),
        stats: PackStats {
            candidates_considered: 28,
            signals_used: vec![Signal::Vector, Signal::Text, Signal::Temporal],
            query_time_us: 3_800,
            entities_hydrated: 28,
            neighbors_hydrated: 0,
            cosine_ghosts_dampened: 0,
            claims_suppressed: 0,
            tokens: crate::context_pack::PackTokenStats::default(),
            items_truncated: crate::context_pack::PackItemAccounting::item_budget(),
            items_dropped: crate::context_pack::PackItemAccounting::token_budget(),
        },
        empty: None,
    };

    let now = crate::unix_seconds_now();

    for i in 0..10_u8 {
        pack.results.push(ContextEntity {
                id: EntityId::from_bytes_unchecked([20 + i; 16]),
                short_id: format!("cl{i:02}"),
                content_hash: 0x40 + i,
                entity_type: 0,
                score: 0.92 - f32::from(i) * 0.02,
                fields: Some(HashMap::from([
                    ("pred".to_owned(), Value::String(format!("priority.claim.{i}"))),
                    (
                        "val".to_owned(),
                        Value::String(format!(
                            "Claim {i} captures the current architecture decision, expected impact, and rollout constraint for the active workstream."
                        )),
                    ),
                    (
                        "conf".to_owned(),
                        Value::Number(Number::from_f64(0.71 + f64::from(i) * 0.01).expect("finite confidence")),
                    ),
                    (
                        "sal".to_owned(),
                        Value::Number(Number::from_f64(0.88 - f64::from(i) * 0.01).expect("finite salience")),
                    ),
                    (
                        "evid".to_owned(),
                        Value::Array(vec![
                            Value::String(format!("tn{i:02}:aa")),
                            Value::String(format!("sm{:02}:bb", i % 3)),
                        ]),
                    ),
                    (
                        "from".to_owned(),
                        Value::Number(Number::from(
                            now.saturating_sub(((u64::from(i) + 1) * 86_400) + 3_600),
                        )),
                    ),
                    (
                        "to".to_owned(),
                        Value::Number(Number::from(
                            now.saturating_add(((u64::from(i) + 2) * 86_400) + 3_600),
                        )),
                    ),
                    (
                        "src".to_owned(),
                        Value::String(format!(
                            "research-log://autopilot/claims/{i}/evidence-chain/response-format-savings-regression"
                        )),
                    ),
                    ("world".to_owned(), Value::String("oneiron.autopilot".to_owned())),
                    (
                        "subj".to_owned(),
                        Value::String(format!("response-format-savings-target-{i}")),
                    ),
                    (
                        "scope".to_owned(),
                        Value::String(format!(
                            "Scope note {i}: preserve compact serializer output while carrying enough metadata for audits, provenance review, and future regression diagnosis."
                        )),
                    ),
                ])),
                edges: None,
                vector: None,
            });
    }

    for i in 0..15_u8 {
        pack.results.push(ContextEntity {
                id: EntityId::from_bytes_unchecked([0x90 + i; 16]),
                short_id: format!("tn{i:02}"),
                content_hash: 0x70 + i,
                entity_type: 1,
                score: 0.74 - f32::from(i) * 0.01,
                fields: Some(HashMap::from([
                    (
                        "txt".to_owned(),
                        Value::String(format!(
                            "Turn {i}: reviewer asks whether compact outputs still carry the critical claim, turn, and summary context without excess envelope bytes."
                        )),
                    ),
                    (
                        "spkr".to_owned(),
                        Value::String(if i % 2 == 0 { "user" } else { "assistant" }.to_owned()),
                    ),
                    (
                        "at".to_owned(),
                        Value::Number(Number::from(now.saturating_sub((u64::from(i) + 1) * 3_600))),
                    ),
                    (
                        "sess".to_owned(),
                        Value::String(format!(
                            "architecture-review-session-response-format-token-budget-{i:02}"
                        )),
                    ),
                ])),
                edges: None,
                vector: None,
            });
    }

    for i in 0..3_u8 {
        pack.results.push(ContextEntity {
                id: EntityId::from_bytes_unchecked([100 + i; 16]),
                short_id: format!("sm{i:02}"),
                content_hash: 0xa0 + i,
                entity_type: 8,
                score: 0.65 - f32::from(i) * 0.03,
                fields: Some(HashMap::from([
                    (
                        "txt".to_owned(),
                        Value::String(format!(
                            "Summary {i}: the pack gathers recent implementation details, reviewer concerns, acceptance criteria, and follow-up constraints for token-efficient response formats."
                        )),
                    ),
                    ("lvl".to_owned(), Value::String("session".to_owned())),
                    (
                        "at".to_owned(),
                        Value::Number(Number::from(now.saturating_sub((u64::from(i) + 1) * 7_200))),
                    ),
                    (
                        "src".to_owned(),
                        Value::String(format!(
                            "summary-source://oneiron/autopilot/response-format-regression/{i}/expanded-provenance"
                        )),
                    ),
                ])),
                edges: None,
                vector: None,
            });
    }

    pack
}

fn serialized_len(pack: &ContextPack, format: PackFormat, profile: FieldProfile) -> usize {
    serialize_pack(pack, &savings_config(format, profile)).len()
}

fn savings_ratio(json_full_len: usize, compact_len: usize) -> f64 {
    assert!(
        json_full_len > 0,
        "json_full_len must be > 0 for savings ratio computation"
    );
    1.0 - (compact_len as f64 / json_full_len as f64)
}

#[test]
fn json_round_trip() {
    let pack = sample_pack();
    let bytes = serialize_pack(&pack, &config(PackFormat::Json));
    let parsed: Value = serde_json::from_slice(&bytes).expect("json parse");
    assert!(parsed.get("claims").is_some());
    assert!(parsed.get("turns").is_some());
}

#[test]
fn toon_contains_group_header() {
    let pack = sample_pack();
    let bytes = serialize_pack(&pack, &config(PackFormat::Toon));
    let text = String::from_utf8(bytes).expect("utf8");
    assert!(text.contains("claims"));
}

#[test]
fn toon_native_encoder_serializes_nested_and_tabular_sections() {
    let groups = vec![
        (
            GroupKey::Kind(ENTITY_TYPE_CLAIM),
            vec![PreparedEntity {
                entity_type: ENTITY_TYPE_CLAIM,
                score: 0.0,
                source: PreparedEntitySource::Result,
                source_id: [0x02; 16],
                id: "cl88:f2".to_owned(),
                fields: vec![
                    ("pred".to_owned(), Value::String("goal.learning".to_owned())),
                    ("val".to_owned(), Value::String("Learn Japanese".to_owned())),
                    (
                        "evid".to_owned(),
                        Value::Array(vec![
                            Value::String("tn17:a1".to_owned()),
                            Value::String("tn23:c4".to_owned()),
                        ]),
                    ),
                ],
            }],
        ),
        (
            GroupKey::Kind(ENTITY_TYPE_TURN),
            vec![
                PreparedEntity {
                    entity_type: ENTITY_TYPE_TURN,
                    score: 0.0,
                    source: PreparedEntitySource::Result,
                    source_id: [0x03; 16],
                    id: "tn17:a1".to_owned(),
                    fields: vec![
                        ("spkr".to_owned(), Value::String("user".to_owned())),
                        ("txt".to_owned(), Value::String("hello, world".to_owned())),
                    ],
                },
                PreparedEntity {
                    entity_type: ENTITY_TYPE_TURN,
                    score: 0.0,
                    source: PreparedEntitySource::Result,
                    source_id: [0x04; 16],
                    id: "tn23:c4".to_owned(),
                    fields: vec![
                        ("spkr".to_owned(), Value::String("assistant".to_owned())),
                        ("txt".to_owned(), Value::String("false".to_owned())),
                    ],
                },
            ],
        ),
    ];

    let text = encode_toon_section(&groups);

    assert_eq!(
        text,
        "claims[1]:\n  - id: \"cl88:f2\"\n    pred: goal.learning\n    val: Learn Japanese\n    evid[2]: \"tn17:a1\",\"tn23:c4\"\nturns[2]{id,spkr,txt}:\n  \"tn17:a1\",user,\"hello, world\"\n  \"tn23:c4\",assistant,\"false\""
    );
}

#[test]
fn toon_native_encoder_uses_list_form_for_arrays_of_empty_objects() {
    let groups = vec![(
        GroupKey::Kind(ENTITY_TYPE_EVENT),
        vec![PreparedEntity {
            entity_type: ENTITY_TYPE_EVENT,
            score: 0.0,
            source: PreparedEntitySource::Result,
            source_id: [0x05; 16],
            id: "ev01:01".to_owned(),
            fields: vec![(
                "meta".to_owned(),
                Value::Array(vec![Value::Object(Map::new()), Value::Object(Map::new())]),
            )],
        }],
    )];

    let text = encode_toon_section(&groups);

    assert_eq!(
        text,
        "events[1]:\n  - id: \"ev01:01\"\n    meta[2]:\n      -\n      -"
    );
}

#[test]
fn toon_native_encoder_replaces_values_beyond_max_depth_with_null() {
    let groups = vec![(
        GroupKey::Kind(ENTITY_TYPE_EVENT),
        vec![PreparedEntity {
            entity_type: ENTITY_TYPE_EVENT,
            score: 0.0,
            source: PreparedEntitySource::Result,
            source_id: [0x06; 16],
            id: "ev01:01".to_owned(),
            fields: vec![("meta".to_owned(), nested_child_object(TOON_MAX_DEPTH + 8))],
        }],
    )];

    let text = encode_toon_section(&groups);

    assert!(
        text.contains("child: null"),
        "depth-limited TOON should emit null sentinel: {text}"
    );
    assert!(
        !text.contains("leaf"),
        "depth-limited TOON should not serialize the too-deep leaf: {text}"
    );
}

#[test]
fn toon_bounded_truncate_strings_stops_at_depth_cap() {
    let leaf = "deep field value that should remain untouched".repeat(8);
    let mut value = nested_child_value(TOON_MAX_DEPTH + 8, Value::String(leaf.clone()));

    truncate_strings_with_depth_limit(&mut value, 4, Some(TOON_MAX_DEPTH));

    assert_eq!(
        child_value_at_depth(&value, TOON_MAX_DEPTH + 8).and_then(Value::as_str),
        Some(leaf.as_str()),
        "truncation must not walk past the TOON value-depth cap"
    );
}

#[test]
fn toon_bounded_estimate_value_chars_stops_at_depth_cap() {
    let value = nested_child_value(
        TOON_MAX_DEPTH + 8,
        Value::String("deep field value that should not be counted".repeat(256)),
    );
    let expected = (0..TOON_MAX_DEPTH).fold(4, |chars, _| {
        2 + estimate_json_string_chars("child") + 1 + chars
    });

    assert_eq!(
        estimate_value_chars_with_depth_limit(&value, Some(TOON_MAX_DEPTH)),
        expected,
        "bounded estimation should price the capped subtree as null"
    );
    assert!(
        estimate_value_chars(&value) > expected,
        "unbounded estimation should still account for the deep leaf"
    );
}

#[test]
fn toon_preparation_caps_deep_values_before_item_budget_estimation() {
    let value = nested_child_value(
        TOON_MAX_DEPTH + 16,
        Value::String("deep field value that would exceed the item budget".repeat(256)),
    );
    let pack = pack_with_results(vec![claim_entity_with_value(1, "note.deep", value, 1.0)]);

    let mut cfg = config(PackFormat::Toon);
    cfg.max_field_chars = 0;
    cfg.max_item_tokens = 512;
    cfg.budget = 0;

    let prepared = prepare_pack(&pack, &cfg, false);
    let claims = prepared
        .results
        .iter()
        .find_map(|(key, rows)| (*key == GroupKey::Kind(ENTITY_TYPE_CLAIM)).then_some(rows))
        .expect("claim group");
    let prepared_value = claims[0]
        .fields
        .iter()
        .find_map(|(key, value)| (key == "val").then_some(value))
        .expect("prepared value");

    assert_eq!(
        child_value_at_depth(prepared_value, TOON_MAX_DEPTH),
        Some(&Value::Null),
        "TOON preparation should prune at the writer depth cap before encoding"
    );
    assert_eq!(prepared.stats.items_truncated.count, 0);
    assert_eq!(prepared.stats.items_dropped.count, 0);
}

#[test]
fn markdown_has_table_layout() {
    let pack = sample_pack();
    let bytes = serialize_pack(&pack, &config(PackFormat::Markdown));
    let text = String::from_utf8(bytes).expect("utf8");
    assert!(text.contains("## Claims"));
    assert!(text.contains("|----|"));
}

#[test]
fn plaintext_has_compact_rows() {
    let pack = sample_pack();
    let bytes = serialize_pack(&pack, &config(PackFormat::Plaintext));
    let text = String::from_utf8(bytes).expect("utf8");
    assert!(text.contains("CLAIMS"));
    assert!(text.contains("cl88:f2|"));
}

#[test]
fn yaml_has_claims_key() {
    let pack = sample_pack();
    let bytes = serialize_pack(&pack, &config(PackFormat::Yaml));
    let text = String::from_utf8(bytes).expect("utf8");
    assert!(text.contains("claims:"));
    assert!(text.contains("- id:"));
}

#[test]
fn serialized_fixture_output_respects_real_token_budget() {
    let pack = token_savings_regression_pack();
    for format in [
        PackFormat::Json,
        PackFormat::Yaml,
        PackFormat::Toon,
        PackFormat::Markdown,
        PackFormat::Plaintext,
    ] {
        for budget in [64_usize, 128, 256] {
            let mut cfg = config(format);
            cfg.budget = budget;

            let bytes = serialize_pack(&pack, &cfg);
            let text = String::from_utf8(bytes).expect("utf8");
            let tokens = DEFAULT_CONTEXT_PACK_TOKENIZER.count(&text);
            assert!(
                tokens <= budget,
                "{format:?} emitted {tokens} tokens above budget {budget}:\n{text}"
            );
        }
    }
}

#[test]
fn serialized_pack_stats_stamp_tokenizer_and_row_tokens() {
    let pack = sample_pack();
    let mut cfg = config(PackFormat::Plaintext);
    cfg.budget = 256;

    let (bytes, telemetry) = serialize_pack_with_telemetry(&pack, &cfg);
    let text = String::from_utf8(bytes).expect("utf8");

    assert_eq!(
        telemetry.stats.tokens.tokenizer_id,
        DEFAULT_CONTEXT_PACK_TOKENIZER.id()
    );
    assert_eq!(
        telemetry.stats.tokens.total_tokens,
        DEFAULT_CONTEXT_PACK_TOKENIZER.count(&text)
    );
    assert!(!telemetry.stats.tokens.sections.is_empty());
    assert!(!telemetry.stats.tokens.items.is_empty());
    assert!(
        telemetry
            .stats
            .tokens
            .items
            .iter()
            .all(|item| item.tokens > 0)
    );
}

#[test]
fn split_mode_uses_shared_budget_pool() {
    let mut pack = ContextPack {
        results: Vec::new(),
        neighbors: Vec::new(),
        stats: empty_stats(),
        empty: None,
    };

    for i in 0..6_u8 {
        pack.results.push(ContextEntity {
            id: EntityId::from_bytes_unchecked([10 + i; 16]),
            short_id: format!("r{i}"),
            content_hash: i,
            entity_type: 0,
            score: 1.0,
            fields: Some(HashMap::from([
                ("pred".to_owned(), Value::String("p".to_owned())),
                ("val".to_owned(), Value::String("v".repeat(12))),
            ])),
            edges: None,
            vector: None,
        });
        pack.neighbors.push(ContextEntity {
            id: EntityId::from_bytes_unchecked([30 + i; 16]),
            short_id: format!("n{i}"),
            content_hash: i,
            entity_type: 4,
            score: 0.0,
            fields: Some(HashMap::from([(
                "name".to_owned(),
                Value::String("neighbor".to_owned()),
            )])),
            edges: None,
            vector: None,
        });
    }

    let mut cfg = config(PackFormat::Toon);
    cfg.merge_neighbors = false;
    cfg.budget = 120;

    let prepared = prepare_pack(&pack, &cfg, false);
    let total_tokens = estimate_groups_tokens_with_depth_limit(
        &prepared.results,
        DEFAULT_CONTEXT_PACK_TOKENIZER,
        None,
    )
    .saturating_add(estimate_groups_tokens_with_depth_limit(
        &prepared.neighbors,
        DEFAULT_CONTEXT_PACK_TOKENIZER,
        None,
    ));

    assert!(
        total_tokens <= cfg.budget,
        "shared split-mode budget should cap total tokens: {total_tokens}"
    );
    assert!(!prepared.results.is_empty());
    assert!(!prepared.neighbors.is_empty());
}

#[test]
fn split_rebudgeting_reuses_consumed_slack_without_overshooting_total_cap() {
    let allocation = TokenAllocation::default();
    let results_source = vec![(
        GroupKey::Kind(0),
        vec![
            prepared_entity_for_test(18, Vec::new()),
            prepared_entity_for_test(1, Vec::new()),
        ],
    )];
    let neighbors_source = vec![(
        GroupKey::Kind(4),
        vec![
            prepared_entity_for_test(18, Vec::new()),
            prepared_entity_for_test(1, Vec::new()),
        ],
    )];

    let token_budget = 20;
    let (results, neighbors) = budget_split_sections(
        &results_source,
        &neighbors_source,
        &allocation,
        token_budget,
    );
    let total_tokens =
        estimate_groups_tokens_with_depth_limit(&results, DEFAULT_CONTEXT_PACK_TOKENIZER, None)
            .saturating_add(estimate_groups_tokens_with_depth_limit(
                &neighbors,
                DEFAULT_CONTEXT_PACK_TOKENIZER,
                None,
            ));

    assert_eq!(results[0].1.len(), 1);
    assert_eq!(neighbors[0].1.len(), 1);
    assert!(
        total_tokens <= token_budget,
        "rebudgeted sections should stay within the shared cap: {total_tokens}"
    );
}

#[test]
fn field_profile_changes_output() {
    let pack = sample_pack();

    let mut minimal = config(PackFormat::Json);
    minimal.profile = FieldProfile::Minimal;
    let minimal_json: Value = serde_json::from_slice(&serialize_pack(&pack, &minimal)).unwrap();

    let mut full = config(PackFormat::Json);
    full.profile = FieldProfile::Full;
    let full_json: Value = serde_json::from_slice(&serialize_pack(&pack, &full)).unwrap();

    let minimal_claim = &minimal_json["claims"][0];
    let full_claim = &full_json["claims"][0];
    assert!(minimal_claim.get("conf").is_none());
    assert!(full_claim.get("pred").is_some());
}

#[test]
fn max_field_chars_truncates_nested_json_strings() {
    let pack = ContextPack {
        results: vec![ContextEntity {
            id: EntityId::from_bytes_unchecked([42; 16]),
            short_id: "js01".to_owned(),
            content_hash: 0x42,
            // Any kind without a labelled section lands in GroupKey::Other;
            // 255 is no longer usable as a stand-in for "some other kind".
            entity_type: ENTITY_TYPE_CODE_ARTIFACT,
            score: 0.7,
            fields: Some(HashMap::from([(
                "payload".to_owned(),
                serde_json::json!({
                    "object": {
                        "label": "abcdef",
                        "short": "ok",
                    },
                    "array": [
                        "ghijklmnop",
                        {
                            "label": "mnopqr",
                        },
                    ],
                }),
            )])),
            edges: None,
            vector: None,
        }],
        neighbors: vec![],
        stats: empty_stats(),
        empty: None,
    };

    let mut cfg = config(PackFormat::Json);
    cfg.max_field_chars = 4;

    let parsed: Value = serde_json::from_slice(&serialize_pack(&pack, &cfg)).expect("json parse");
    let payload = &parsed["other"][0]["payload"];

    for (value, expected) in [
        (&payload["object"]["label"], "abc…"),
        (&payload["array"][0], "ghi…"),
        (&payload["array"][1]["label"], "mno…"),
    ] {
        let text = value.as_str().expect("nested string");
        assert_eq!(text, expected);
        assert_eq!(text.chars().count(), 4);
        assert!(text.ends_with('…'));
    }

    assert_eq!(payload["object"]["short"], "ok");
}

#[test]
fn serialization_token_savings_regressions() {
    // (case_name, format, profile, min_savings_vs_json_full)
    // Each row asserts the compact (format, profile) pair saves at least
    // `min_savings` fraction of bytes vs the json/Full baseline.
    let cases: &[(&str, PackFormat, FieldProfile, f64)] = &[
        ("toon_minimal", PackFormat::Toon, FieldProfile::Minimal, 0.6),
        (
            "toon_standard",
            PackFormat::Toon,
            FieldProfile::Standard,
            0.45,
        ),
        (
            "plaintext_standard",
            PackFormat::Plaintext,
            FieldProfile::Standard,
            0.55,
        ),
    ];

    let pack = token_savings_regression_pack();
    let json_full_len = serialized_len(&pack, PackFormat::Json, FieldProfile::Full);

    for (name, format, profile, threshold) in cases {
        let compact_len = serialized_len(&pack, *format, *profile);
        let savings = savings_ratio(json_full_len, compact_len);
        assert!(
            savings >= *threshold,
            "case {name}: savings {savings:.3} below {threshold:.2}; json_full_len={json_full_len}, compact_len={compact_len}"
        );
    }
}

#[test]
fn short_id_serialization_uses_at_most_two_tokens_per_reference() {
    let pack = ContextPack {
        results: vec![ContextEntity {
            id: EntityId::from_bytes_unchecked([42; 16]),
            short_id: "cl42".to_owned(),
            content_hash: 0x2a,
            entity_type: 0,
            score: 0.5,
            fields: Some(HashMap::from([
                (
                    "pred".to_owned(),
                    Value::String("goal.compact-id".to_owned()),
                ),
                (
                    "val".to_owned(),
                    Value::String("Keep compact claim references cheap.".to_owned()),
                ),
            ])),
            edges: None,
            vector: None,
        }],
        neighbors: vec![],
        stats: empty_stats(),
        empty: None,
    };

    let bytes = serialize_pack(
        &pack,
        &savings_config(PackFormat::Plaintext, FieldProfile::Minimal),
    );
    let text = String::from_utf8(bytes).expect("utf8");
    let rendered_ref = text
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == ':'))
        .find(|part| part.starts_with("cl42"))
        .expect("cl42 reference in serialized output");
    let short_id = rendered_ref.split(':').next().expect("short id segment");
    let rendered_ref_tokens = DEFAULT_CONTEXT_PACK_TOKENIZER.count(rendered_ref);

    assert!(
        short_id.is_ascii() && short_id.len() <= 6,
        "short id reference should fit <= 6 ASCII bytes: short_id={short_id:?}, bytes={}",
        short_id.len()
    );
    assert!(
        rendered_ref.is_ascii() && rendered_ref_tokens <= 6,
        "rendered short id reference should stay compact under o200k_base: rendered_ref={rendered_ref:?}, bytes={}, tokens={rendered_ref_tokens}",
        rendered_ref.len()
    );
    assert!(
        text.contains("cl42:2a"),
        "serialized output should include rendered short id with hash: {text}"
    );
}

#[test]
fn token_budget_truncates_groups() {
    let mut pack = sample_pack();
    for i in 0..40_u8 {
        pack.results.push(ContextEntity {
            id: EntityId::from_bytes_unchecked([50 + i; 16]),
            short_id: format!("cl{i}"),
            content_hash: i,
            entity_type: 0,
            score: 0.3,
            fields: Some(HashMap::from([
                ("pred".to_owned(), Value::String("p".to_owned())),
                ("val".to_owned(), Value::String("v".repeat(64))),
            ])),
            edges: None,
            vector: None,
        });
    }

    let total_claims = pack.results.iter().filter(|e| e.entity_type == 0).count();

    let mut cfg = config(PackFormat::Toon);
    cfg.budget = 100;
    let prepared = prepare_pack(&pack, &cfg, false);
    let claims_len = prepared
        .results
        .iter()
        .find_map(|(key, rows)| (*key == GroupKey::Kind(0)).then_some(rows.len()))
        .unwrap_or(0);
    assert!(claims_len < total_claims);
}

#[test]
fn max_item_tokens_truncates_string_with_exact_suffix() {
    let long_value = "x".repeat(1200);
    let pack = pack_with_results(vec![claim_entity(1, "note.long", &long_value, 1.0)]);

    let mut cfg = config(PackFormat::Json);
    cfg.include_stats = true;
    cfg.max_field_chars = 0;
    cfg.max_item_tokens = 32;

    let parsed: Value = serde_json::from_slice(&serialize_pack(&pack, &cfg)).expect("json parse");
    let rendered = parsed["claims"][0]["val"]
        .as_str()
        .expect("truncated string value");
    let suffix = "...(truncated, 1200 chars total)";

    assert!(rendered.ends_with(suffix), "rendered={rendered}");
    assert_ne!(rendered, long_value);
    assert_eq!(parsed["stats"]["truncated"]["count"], 1);
    assert_eq!(parsed["stats"]["truncated"]["reason"], "item_budget");
}

#[test]
fn max_item_tokens_preserves_claim_predicate_when_value_is_shorter() {
    let predicate = format!("note.{}", "predicate".repeat(15));
    let value = token_dense_text("v", 120);
    let pack = pack_with_results(vec![claim_entity(1, &predicate, &value, 1.0)]);

    let mut cfg = config(PackFormat::Json);
    cfg.max_field_chars = 0;
    cfg.max_item_tokens = 64;

    let parsed: Value = serde_json::from_slice(&serialize_pack(&pack, &cfg)).expect("json parse");
    let rendered_value = parsed["claims"][0]["val"]
        .as_str()
        .expect("truncated string value");

    assert_eq!(
        parsed["claims"][0]["pred"].as_str(),
        Some(predicate.as_str())
    );
    assert!(rendered_value.ends_with(&format!(
        "...(truncated, {} chars total)",
        value.chars().count()
    )));
    assert_ne!(rendered_value, value);
}

#[test]
fn max_item_tokens_preserves_claim_predicate_for_non_string_value() {
    let predicate = format!("note.{}", "predicate".repeat(15));
    let mut object = Map::new();
    object.insert("summary".to_owned(), Value::String("s".repeat(300)));
    object.insert("confidence".to_owned(), Value::Number(Number::from(7)));
    let original_value = Value::Object(object);
    let original_value_chars = estimate_value_chars(&original_value);
    let pack = pack_with_results(vec![claim_entity_with_value(
        1,
        &predicate,
        original_value,
        1.0,
    )]);

    let mut cfg = config(PackFormat::Json);
    cfg.max_field_chars = 0;
    cfg.max_item_tokens = 64;

    let parsed: Value = serde_json::from_slice(&serialize_pack(&pack, &cfg)).expect("json parse");
    let rendered_value = parsed["claims"][0]["val"]
        .as_str()
        .expect("truncated non-string value");

    assert_eq!(
        parsed["claims"][0]["pred"].as_str(),
        Some(predicate.as_str())
    );
    assert_eq!(
        rendered_value,
        format!("...(truncated, {original_value_chars} chars total)")
    );
}

#[test]
fn max_item_tokens_strips_claim_to_safe_minimal_row_when_value_truncation_is_not_enough() {
    let predicate = "note.metadata_heavy";
    let mut entity = PreparedEntity {
        entity_type: ENTITY_TYPE_CLAIM,
        score: 1.0,
        source: PreparedEntitySource::Result,
        source_id: [0x07; 16],
        id: "cl01:01".to_owned(),
        fields: vec![
            ("pred".to_owned(), Value::String(predicate.to_owned())),
            ("val".to_owned(), Value::String("v".repeat(120))),
            ("src".to_owned(), Value::String("s".repeat(300))),
            ("scope".to_owned(), Value::String("c".repeat(300))),
        ],
    };
    let mut stats = empty_stats();

    assert!(apply_item_budget(&mut entity, 32, &mut stats));

    assert!(
        estimate_entity_tokens_with_depth_limit(&entity, DEFAULT_CONTEXT_PACK_TOKENIZER, None)
            <= 32
    );
    assert_eq!(
        entity
            .fields
            .iter()
            .find_map(|(key, value)| (key == "pred").then_some(value.as_str()).flatten()),
        Some(predicate)
    );
    assert!(entity.fields.iter().any(|(key, _)| key == "val"));
    assert!(!entity.fields.iter().any(|(key, _)| key == "src"));
    assert!(!entity.fields.iter().any(|(key, _)| key == "scope"));
    assert_eq!(stats.items_truncated.count, 1);
    assert_eq!(stats.items_dropped.count, 0);
}

#[test]
fn max_item_tokens_strips_claim_metadata_without_truncating_short_value() {
    let predicate = "note.metadata_heavy";
    let mut entity = PreparedEntity {
        entity_type: ENTITY_TYPE_CLAIM,
        score: 1.0,
        source: PreparedEntitySource::Result,
        source_id: [0x08; 16],
        id: "cl01:01".to_owned(),
        fields: vec![
            ("pred".to_owned(), Value::String(predicate.to_owned())),
            ("val".to_owned(), Value::String("ok".to_owned())),
            ("src".to_owned(), Value::String("s".repeat(300))),
            ("scope".to_owned(), Value::String("c".repeat(300))),
        ],
    };
    let mut stats = empty_stats();

    assert!(apply_item_budget(&mut entity, 32, &mut stats));

    assert!(
        estimate_entity_tokens_with_depth_limit(&entity, DEFAULT_CONTEXT_PACK_TOKENIZER, None)
            <= 32
    );
    assert_eq!(
        entity
            .fields
            .iter()
            .find_map(|(key, value)| (key == "pred").then_some(value.as_str()).flatten()),
        Some(predicate)
    );
    assert_eq!(
        entity
            .fields
            .iter()
            .find_map(|(key, value)| (key == "val").then_some(value.as_str()).flatten()),
        Some("ok")
    );
    assert!(!entity.fields.iter().any(|(key, _)| key == "src"));
    assert!(!entity.fields.iter().any(|(key, _)| key == "scope"));
    assert_eq!(stats.items_truncated.count, 1);
    assert_eq!(stats.items_dropped.count, 0);
}

#[test]
fn max_item_tokens_trims_multiple_non_claim_strings_until_under_cap() {
    let mut entity = PreparedEntity {
        entity_type: ENTITY_TYPE_TURN,
        score: 1.0,
        source: PreparedEntitySource::Result,
        source_id: [0x09; 16],
        id: "tn01:01".to_owned(),
        fields: vec![
            ("txt".to_owned(), Value::String("a".repeat(160))),
            ("note".to_owned(), Value::String("b".repeat(160))),
        ],
    };
    let mut stats = empty_stats();

    assert!(apply_item_budget(&mut entity, 40, &mut stats));

    assert!(
        estimate_entity_tokens_with_depth_limit(&entity, DEFAULT_CONTEXT_PACK_TOKENIZER, None)
            <= 40
    );
    assert_eq!(stats.items_truncated.count, 1);
    assert_eq!(stats.items_dropped.count, 0);
    for (_, value) in &entity.fields {
        let rendered = value.as_str().expect("string field");
        assert!(rendered.ends_with("...(truncated, 160 chars total)"));
    }
}

#[test]
fn max_item_tokens_replaces_non_claim_without_safe_strings_with_minimal_row() {
    let mut entity = PreparedEntity {
        entity_type: ENTITY_TYPE_EVENT,
        score: 1.0,
        source: PreparedEntitySource::Result,
        source_id: [0x0A; 16],
        id: "ev01:01".to_owned(),
        fields: vec![
            (
                "meta".to_owned(),
                Value::Array((0..200).map(|i| Value::Number(Number::from(i))).collect()),
            ),
            ("weight".to_owned(), Value::Number(Number::from(42))),
        ],
    };
    let mut stats = empty_stats();

    assert!(apply_item_budget(&mut entity, 8, &mut stats));

    assert!(entity.fields.is_empty());
    assert!(
        estimate_entity_tokens_with_depth_limit(&entity, DEFAULT_CONTEXT_PACK_TOKENIZER, None) <= 8
    );
    assert_eq!(stats.items_truncated.count, 1);
    assert_eq!(stats.items_dropped.count, 0);
}

#[test]
fn max_item_tokens_drops_rows_when_tiny_budget_cannot_fit_suffix_or_minimal_row() {
    let pack = pack_with_results(vec![claim_entity(1, "note.tiny", &"x".repeat(200), 1.0)]);

    let mut cfg = config(PackFormat::Json);
    cfg.max_field_chars = 0;
    cfg.max_item_tokens = 1;
    cfg.budget = 0;

    let prepared = prepare_pack(&pack, &cfg, true);

    assert!(prepared.results.is_empty());
    assert_eq!(prepared.stats.items_truncated.count, 0);
    assert_eq!(prepared.stats.items_dropped.count, 1);
    assert_eq!(prepared.stats.items_dropped.reason.as_str(), "item_budget");
}

#[test]
fn item_and_token_budget_reasons_are_discriminated() {
    let over_item = token_dense_text("over", 120);
    let budget_drop = "fits item cap but not total budget";
    let pack = pack_with_results(vec![
        claim_entity(1, "note.over_item", &over_item, 1.0),
        claim_entity(2, "note.budget_drop", budget_drop, 0.5),
    ]);

    let mut cfg = config(PackFormat::Toon);
    cfg.max_field_chars = 0;
    cfg.max_item_tokens = 64;
    cfg.budget = 80;

    let prepared = prepare_pack(&pack, &cfg, false);
    let kept_rows: usize = prepared.results.iter().map(|(_, rows)| rows.len()).sum();

    assert_eq!(kept_rows, 1);
    assert_eq!(prepared.stats.items_truncated.count, 1);
    assert_eq!(
        prepared.stats.items_truncated.reason.as_str(),
        "item_budget"
    );
    assert_eq!(prepared.stats.items_dropped.count, 1);
    assert_eq!(prepared.stats.items_dropped.reason.as_str(), "token_budget");
}

#[test]
fn critical_predicate_claims_bypass_item_cap_when_serialized_budget_is_disabled() {
    let critical_value = "c".repeat(1200);
    let pack = pack_with_results(vec![claim_entity(
        1,
        "preference.food",
        &critical_value,
        1.0,
    )]);

    let mut cfg = config(PackFormat::Toon);
    cfg.max_field_chars = 0;
    cfg.max_item_tokens = 8;
    cfg.budget = 0;

    let prepared = prepare_pack(&pack, &cfg, false);
    let kept = prepared
        .results
        .iter()
        .find_map(|(key, rows)| (*key == GroupKey::Kind(ENTITY_TYPE_CLAIM)).then_some(rows))
        .expect("critical claim group");
    let rendered_value = kept[0]
        .fields
        .iter()
        .find_map(|(key, value)| (key == "val").then_some(value.as_str()).flatten())
        .expect("critical value");

    assert_eq!(rendered_value, critical_value);
    assert_eq!(prepared.stats.items_truncated.count, 0);
    assert_eq!(prepared.stats.items_dropped.count, 0);
}

#[test]
fn hard_serialized_budget_can_drop_critical_predicate_claims() {
    let critical_value = "c".repeat(1200);
    let pack = pack_with_results(vec![claim_entity(
        1,
        "preference.food",
        &critical_value,
        1.0,
    )]);

    let mut cfg = config(PackFormat::Toon);
    cfg.max_field_chars = 0;
    cfg.max_item_tokens = 8;
    cfg.budget = 8;

    let prepared = prepare_pack(&pack, &cfg, false);
    let kept_rows: usize = prepared.results.iter().map(|(_, rows)| rows.len()).sum();

    assert_eq!(kept_rows, 0);
    assert_eq!(prepared.stats.items_truncated.count, 0);
    assert_eq!(prepared.stats.items_dropped.count, 1);
    assert_eq!(prepared.stats.items_dropped.reason.as_str(), "token_budget");
    assert!(prepared.stats.tokens.total_tokens <= cfg.budget);
}

#[test]
fn max_item_tokens_zero_preserves_oversized_output_and_zero_counts() {
    let long_value = "z".repeat(1200);
    let pack = pack_with_results(vec![claim_entity(1, "note.disabled", &long_value, 1.0)]);

    let mut cfg = config(PackFormat::Json);
    cfg.max_field_chars = 0;

    let bytes = serialize_pack(&pack, &cfg);
    let parsed: Value = serde_json::from_slice(&bytes).expect("json parse");
    let prepared = prepare_pack(&pack, &cfg, true);

    assert_eq!(
        parsed["claims"][0]["val"].as_str(),
        Some(long_value.as_str())
    );
    assert!(
        !String::from_utf8(bytes)
            .expect("utf8")
            .contains("...(truncated,")
    );
    assert_eq!(prepared.stats.items_truncated.count, 0);
    assert_eq!(prepared.stats.items_dropped.count, 0);
}

#[test]
fn over_cap_items_increment_truncated_once_each() {
    let pack = pack_with_results(vec![
        claim_entity(1, "note.first", &token_dense_text("first", 90), 1.0),
        claim_entity(2, "note.second", &token_dense_text("second", 90), 0.9),
    ]);

    let mut cfg = config(PackFormat::Json);
    cfg.max_field_chars = 0;
    cfg.max_item_tokens = 64;

    let prepared = prepare_pack(&pack, &cfg, true);

    assert_eq!(prepared.stats.items_truncated.count, 2);
    assert_eq!(
        prepared.stats.items_truncated.reason.as_str(),
        "item_budget"
    );
    assert_eq!(prepared.stats.items_dropped.count, 0);
}

#[test]
fn token_budget_zero_disables_budget_enforcement() {
    let mut pack = sample_pack();
    for i in 0..12_u8 {
        pack.results.push(ContextEntity {
            id: EntityId::from_bytes_unchecked([50 + i; 16]),
            short_id: format!("cl{i}"),
            content_hash: i,
            entity_type: 0,
            score: 0.3,
            fields: Some(HashMap::from([
                ("pred".to_owned(), Value::String("p".to_owned())),
                ("val".to_owned(), Value::String("v".repeat(64))),
            ])),
            edges: None,
            vector: None,
        });
    }

    let total_results = pack.results.len();
    let total_neighbors = pack.neighbors.len();

    let mut cfg = config(PackFormat::Toon);
    cfg.budget = 0;
    cfg.merge_neighbors = false;

    let prepared = prepare_pack(&pack, &cfg, false);
    let kept_results: usize = prepared.results.iter().map(|(_, rows)| rows.len()).sum();
    let kept_neighbors: usize = prepared.neighbors.iter().map(|(_, rows)| rows.len()).sum();

    assert_eq!(kept_results, total_results);
    assert_eq!(kept_neighbors, total_neighbors);
}

#[test]
fn json_budget_below_mandatory_envelope_emits_minimal_over_budget_payload() {
    let pack = pack_with_results(vec![claim_entity(1, "note.tiny", "tiny budget row", 1.0)]);

    let mut cfg = config(PackFormat::Json);
    cfg.merge_neighbors = false;
    cfg.budget = 1;

    let (bytes, telemetry) = serialize_pack_with_telemetry(&pack, &cfg);
    let text = String::from_utf8(bytes).expect("utf8");
    let parsed: Value = serde_json::from_str(&text).expect("json parse");

    assert_eq!(parsed["results"], serde_json::json!({}));
    assert_eq!(parsed["neighbors"], serde_json::json!({}));
    assert!(telemetry.stats.tokens.total_tokens > cfg.budget);
    assert_eq!(telemetry.stats.items_dropped.count, 1);
    assert_eq!(
        telemetry.stats.items_dropped.reason.as_str(),
        "token_budget"
    );
}

#[test]
fn max_field_chars_zero_disables_and_one_emits_ellipsis() {
    let overlong = "overlong claim value".to_owned();
    let pack = ContextPack {
        results: vec![ContextEntity {
            id: EntityId::from_bytes_unchecked([42; 16]),
            short_id: "cl42".to_owned(),
            content_hash: 0x42,
            entity_type: 0,
            score: 0.5,
            fields: Some(HashMap::from([
                ("pred".to_owned(), Value::String("goal.note".to_owned())),
                ("val".to_owned(), Value::String(overlong.clone())),
            ])),
            edges: None,
            vector: None,
        }],
        neighbors: vec![],
        stats: empty_stats(),
        empty: None,
    };

    let mut unlimited = config(PackFormat::Json);
    unlimited.merge_neighbors = true;
    unlimited.max_field_chars = 0;
    let parsed: Value = serde_json::from_slice(&serialize_pack(&pack, &unlimited)).expect("json");
    assert_eq!(parsed["claims"][0]["val"].as_str(), Some(overlong.as_str()));

    let mut single_char = config(PackFormat::Json);
    single_char.merge_neighbors = true;
    single_char.max_field_chars = 1;
    let parsed: Value = serde_json::from_slice(&serialize_pack(&pack, &single_char)).expect("json");
    assert_eq!(parsed["claims"][0]["val"].as_str(), Some("…"));
}

#[test]
fn zero_section_budget_drops_all_rows() {
    let allocation = TokenAllocation::default();
    let source = vec![(
        GroupKey::Kind(0),
        vec![prepared_entity_for_test(18, Vec::new())],
    )];

    let (groups, used) = budget_groups(&source, &allocation, 0);

    assert!(groups.is_empty());
    assert_eq!(used, 0);
}

#[test]
fn empty_groups_are_omitted() {
    let mut pack = sample_pack();
    pack.results.retain(|entity| entity.entity_type != 0);

    let text = String::from_utf8(serialize_pack(&pack, &config(PackFormat::Markdown))).unwrap();
    assert!(!text.contains("## Claims"));
}

#[test]
fn relative_timestamps_render_for_llm_formats() {
    let pack = sample_pack();
    let text = String::from_utf8(serialize_pack(&pack, &config(PackFormat::Plaintext))).unwrap();
    assert!(text.contains("-3d") || text.contains("-2d") || text.contains("-4d"));
}

#[test]
fn short_id_hash_format_is_applied() {
    let pack = sample_pack();
    let text = String::from_utf8(serialize_pack(&pack, &config(PackFormat::Plaintext))).unwrap();
    assert!(text.contains("cl88:f2"));
}

#[test]
fn grouping_priority_orders_claims_before_turns() {
    let pack = sample_pack();
    let text = String::from_utf8(serialize_pack(&pack, &config(PackFormat::Plaintext))).unwrap();
    let claims_pos = text.find("CLAIMS").unwrap_or(usize::MAX);
    let turns_pos = text.find("TURNS").unwrap_or(usize::MAX);
    assert!(claims_pos < turns_pos);
}

#[test]
fn plaintext_escapes_pipes() {
    let mut pack = sample_pack();
    if let Some(fields) = pack.results[0].fields.as_mut() {
        fields.insert("val".to_owned(), Value::String("hello|world".to_owned()));
    }

    let text = String::from_utf8(serialize_pack(&pack, &config(PackFormat::Plaintext))).unwrap();
    assert!(text.contains("hello\\|world"));
}

#[test]
fn multiple_other_types_share_normalized_budget() {
    let mut pack = sample_pack();
    pack.results.clear();
    pack.neighbors.clear();

    let row_text = "v".repeat(45);

    for i in 0..8_u8 {
        pack.results.push(ContextEntity {
            id: EntityId::from_bytes_unchecked([10 + i; 16]),
            short_id: format!("cl{i}"),
            content_hash: i,
            entity_type: 0,
            score: 1.0,
            fields: Some(HashMap::from([
                ("pred".to_owned(), Value::String("p".to_owned())),
                ("val".to_owned(), Value::String(row_text.clone())),
            ])),
            edges: None,
            vector: None,
        });

        pack.results.push(ContextEntity {
            id: EntityId::from_bytes_unchecked([40 + i; 16]),
            short_id: format!("tn{i}"),
            content_hash: i,
            entity_type: 1,
            score: 1.0,
            fields: Some(HashMap::from([(
                "txt".to_owned(),
                Value::String(row_text.clone()),
            )])),
            edges: None,
            vector: None,
        });

        pack.results.push(ContextEntity {
            id: EntityId::from_bytes_unchecked([80 + i; 16]),
            short_id: format!("sm{i}"),
            content_hash: i,
            entity_type: 8,
            score: 1.0,
            fields: Some(HashMap::from([(
                "txt".to_owned(),
                Value::String(row_text.clone()),
            )])),
            edges: None,
            vector: None,
        });

        pack.results.push(ContextEntity {
            id: EntityId::from_bytes_unchecked([120 + i; 16]),
            short_id: format!("pr{i}"),
            content_hash: i,
            entity_type: 4,
            score: 1.0,
            fields: Some(HashMap::from([(
                "name".to_owned(),
                Value::String(row_text.clone()),
            )])),
            edges: None,
            vector: None,
        });

        pack.results.push(ContextEntity {
            id: EntityId::from_bytes_unchecked([160 + i; 16]),
            short_id: format!("ev{i}"),
            content_hash: i,
            entity_type: 6,
            score: 1.0,
            fields: Some(HashMap::from([(
                "name".to_owned(),
                Value::String(row_text.clone()),
            )])),
            edges: None,
            vector: None,
        });
    }

    let mut cfg = config(PackFormat::Toon);
    cfg.budget = 200;
    let prepared = prepare_pack(&pack, &cfg, false);

    let persons_count = prepared
        .results
        .iter()
        .find_map(|(key, rows)| (*key == GroupKey::Kind(4)).then_some(rows.len()))
        .unwrap_or(0);
    let events_count = prepared
        .results
        .iter()
        .find_map(|(key, rows)| (*key == GroupKey::Kind(6)).then_some(rows.len()))
        .unwrap_or(0);

    assert_eq!(
        persons_count, 1,
        "persons should be constrained by normalized 'other' share"
    );
    assert_eq!(
        events_count, 1,
        "events should be constrained by normalized 'other' share"
    );
}

#[test]
fn unknown_entity_types_share_single_other_group() {
    let pack = ContextPack {
        results: vec![
            ContextEntity {
                id: EntityId::from_bytes_unchecked([18; 16]),
                short_id: "u18".to_owned(),
                content_hash: 0x18,
                entity_type: 18,
                score: 0.9,
                fields: Some(HashMap::from([(
                    "name".to_owned(),
                    Value::String("eighteen".to_owned()),
                )])),
                edges: None,
                vector: None,
            },
            ContextEntity {
                id: EntityId::from_bytes_unchecked([20; 16]),
                short_id: "u20".to_owned(),
                content_hash: 0x20,
                entity_type: 20,
                score: 0.8,
                fields: Some(HashMap::from([(
                    "name".to_owned(),
                    Value::String("twenty".to_owned()),
                )])),
                edges: None,
                vector: None,
            },
        ],
        neighbors: vec![],
        stats: empty_stats(),
        empty: None,
    };

    let parsed: Value =
        serde_json::from_slice(&serialize_pack(&pack, &config(PackFormat::Json))).expect("json");
    let other = parsed
        .get("other")
        .and_then(Value::as_array)
        .expect("other group");
    assert_eq!(other.len(), 2);
    assert_eq!(other[0]["name"], "eighteen");
    assert_eq!(other[1]["name"], "twenty");
}

#[test]
fn yaml_stats_are_emitted_as_comments() {
    let mut cfg = config(PackFormat::Yaml);
    cfg.include_stats = true;

    let text = String::from_utf8(serialize_pack(&sample_pack(), &cfg)).expect("utf8");
    assert!(text.contains("# query:"));
    assert!(!text.contains("\n---\nquery:"));
}

#[test]
fn yaml_quotes_unsafe_field_keys() {
    let pack = ContextPack {
        results: vec![ContextEntity {
            id: EntityId::from_bytes_unchecked([0x92; 16]),
            short_id: "mc01".to_owned(),
            content_hash: 0x01,
            entity_type: ENTITY_TYPE_MACHINE,
            score: 0.5,
            fields: Some(HashMap::from([
                ("x:y".to_owned(), Value::String("value".to_owned())),
                ("true".to_owned(), Value::String("reserved".to_owned())),
            ])),
            edges: None,
            vector: None,
        }],
        neighbors: vec![],
        stats: empty_stats(),
        empty: None,
    };

    let text = String::from_utf8(serialize_pack(&pack, &config(PackFormat::Yaml))).expect("utf8");
    assert!(text.contains("\"x:y\": value"));
    assert!(text.contains("\"true\": reserved"));
}

#[test]
fn yaml_quotes_scalar_control_characters() {
    let pack = ContextPack {
            results: vec![ContextEntity {
                id: EntityId::from_bytes_unchecked([0x93; 16]),
                short_id: "mc02".to_owned(),
                content_hash: 0x02,
                entity_type: ENTITY_TYPE_MACHINE,
                score: 0.5,
                fields: Some(HashMap::from([(
                    "text".to_owned(),
                    Value::String(
                        "nul\0bel\x07backspace\x08vertical\x0Bform\x0Cesc\x1Bunit\x1Fdel\x7Fnextline\u{0085}"
                            .to_owned(),
                    ),
                )])),
                edges: None,
                vector: None,
            }],
            neighbors: vec![],
            stats: empty_stats(),
            empty: None,
        };

    let text = String::from_utf8(serialize_pack(&pack, &config(PackFormat::Yaml))).expect("utf8");
    assert!(
            text.contains(
                "text: \"nul\\0bel\\abackspace\\bvertical\\vform\\fesc\\eunit\\x1Fdel\\x7Fnextline\\x85\""
            ),
            "{text}"
        );
}

#[test]
fn estimate_value_chars_matches_compact_json() {
    let values = vec![
        Value::Null,
        Value::Bool(true),
        Value::String("hello\nworld".to_owned()),
        serde_json::json!(["alpha", 3, false]),
        serde_json::json!({"a": "b", "nested": {"x": [1, 2, {"k": "v"}]}}),
    ];

    for value in values {
        assert_eq!(
            estimate_value_chars(&value),
            serde_json::to_string(&value).expect("json").len()
        );
    }
}

#[test]
fn estimate_json_string_chars_matches_serde_json_escape_rules() {
    let values = [
        "",
        "plain",
        "line\nbreak",
        "\u{1F}",
        "\u{7F}",
        "\u{85}",
        "\"\\",
    ];

    for value in values {
        assert_eq!(
            estimate_json_string_chars(value),
            serde_json::to_string(value).expect("json").len(),
            "mismatch for {value:?}"
        );
    }
}

#[test]
fn estimate_entity_chars_accounts_for_escaped_field_names() {
    let plain = prepared_entity_for_test(
        16,
        vec![("ab".to_owned(), Value::String("value".to_owned()))],
    );
    let escaped = prepared_entity_for_test(
        16,
        vec![("a\"".to_owned(), Value::String("value".to_owned()))],
    );

    let plain_json =
        serde_json::to_string(&json_rows(std::slice::from_ref(&plain), false)[0]).expect("json");
    let escaped_json =
        serde_json::to_string(&json_rows(std::slice::from_ref(&escaped), false)[0]).expect("json");

    assert_eq!(
        estimate_entity_chars(&escaped).saturating_sub(estimate_entity_chars(&plain)),
        escaped_json.len().saturating_sub(plain_json.len())
    );
}

#[test]
fn surplus_budget_redistributes_to_hungry_types() {
    // 1 tiny turn + 40 fat claims with a tight budget.
    // The turn barely uses its allocation, so surplus should flow to claims.
    // Verify claims gets more entities than its raw fraction would allow.
    let mut pack = sample_pack();
    pack.results.clear();
    pack.neighbors.clear();

    // Single turn — very small, won't fill its allocation.
    pack.results.push(ContextEntity {
        id: EntityId::from_bytes_unchecked([99; 16]),
        short_id: "tn01".to_owned(),
        content_hash: 0x01,
        entity_type: 1,
        score: 0.5,
        fields: Some(HashMap::from([(
            "txt".to_owned(),
            Value::String("hi".to_owned()),
        )])),
        edges: None,
        vector: None,
    });

    // 40 claims — will exceed claims budget at low token limits.
    for i in 0..40_u8 {
        pack.results.push(ContextEntity {
            id: EntityId::from_bytes_unchecked([50 + i; 16]),
            short_id: format!("cl{i}"),
            content_hash: i,
            entity_type: 0,
            score: 0.3,
            fields: Some(HashMap::from([
                ("pred".to_owned(), Value::String("p".to_owned())),
                ("val".to_owned(), Value::String("v".repeat(40))),
            ])),
            edges: None,
            vector: None,
        });
    }

    let mut cfg = config(PackFormat::Toon);
    cfg.budget = 200;
    let prepared = prepare_pack(&pack, &cfg, false);

    let claims_count = prepared
        .results
        .iter()
        .find_map(|(key, rows)| (*key == GroupKey::Kind(0)).then_some(rows.len()))
        .unwrap_or(0);

    let raw_claim_token_budget = (cfg.budget as f32 * 0.45) as usize;
    let avg_claim_tokens = estimate_entity_tokens_with_depth_limit(
        &prepared_entity_for_test(
            5,
            vec![
                ("pred".to_owned(), Value::String("p".to_owned())),
                ("val".to_owned(), Value::String("v".repeat(40))),
            ],
        ),
        DEFAULT_CONTEXT_PACK_TOKENIZER,
        None,
    );
    let raw_baseline = raw_claim_token_budget / avg_claim_tokens.max(1);

    assert!(
        claims_count > raw_baseline,
        "redistribution should give claims more than raw {raw_baseline}: got {claims_count}"
    );
    // Turn should still be present (it fits easily).
    let turns_count = prepared
        .results
        .iter()
        .find_map(|(key, rows)| (*key == GroupKey::Kind(1)).then_some(rows.len()))
        .unwrap_or(0);
    assert!(turns_count > 0);
}

// ── TaskList and Task productivity-band tests ──────────────────

fn empty_stats() -> PackStats {
    PackStats {
        candidates_considered: 0,
        signals_used: vec![],
        query_time_us: 0,
        entities_hydrated: 0,
        neighbors_hydrated: 0,
        cosine_ghosts_dampened: 0,
        claims_suppressed: 0,
        tokens: crate::context_pack::PackTokenStats::default(),
        items_truncated: crate::context_pack::PackItemAccounting::item_budget(),
        items_dropped: crate::context_pack::PackItemAccounting::token_budget(),
    }
}

fn empty_pack_with_reason(reason: EmptyReason) -> ContextPack {
    ContextPack {
        results: vec![],
        neighbors: vec![],
        stats: empty_stats(),
        empty: Some(EmptyContext {
            reason,
            total_in_scope: 7,
            hint: "test hint".to_owned(),
        }),
    }
}

#[test]
fn empty_reason_json_wire_literals_are_stable() {
    for (reason, expected) in [
        (EmptyReason::FilterMatchedNone, "filter_matched_none"),
        (EmptyReason::NoData, "no_data"),
        (EmptyReason::AllActivated, "all_activated"),
        (EmptyReason::BelowThreshold, "below_threshold"),
    ] {
        let pack = empty_pack_with_reason(reason);
        let parsed: Value =
            serde_json::from_slice(&serialize_pack(&pack, &config(PackFormat::Json)))
                .expect("json");
        assert_eq!(parsed["empty"]["reason"], expected);
        assert_eq!(parsed["empty"]["totalInScope"], 7);
        assert_eq!(parsed["empty"]["hint"], "test hint");
        let decoded: EmptyReason =
            serde_json::from_value(parsed["empty"]["reason"].clone()).expect("empty reason");
        assert_eq!(decoded, reason);
    }
}

#[test]
fn non_empty_json_omits_empty_key() {
    let parsed: Value =
        serde_json::from_slice(&serialize_pack(&sample_pack(), &config(PackFormat::Json)))
            .expect("json");
    assert!(
        parsed.get("empty").is_none(),
        "non-empty pack must omit the empty key"
    );
}

#[test]
fn productivity_field_profiles() {
    // (case_name, entity_type, short_id, content_hash, group_key,
    //  raw_fields, present_in_standard_json, absent_from_standard_json,
    //  expected_standard_order, extra_assertions)
    //
    // `extra_assertions` runs after the common JSON/Standard checks; use it for
    // per-variant tails (plaintext rendering, full-profile membership checks,
    // Minimal-profile ordering). It receives `(pack, fields_for_profile_fn)` so
    // it can build additional configs as needed.
    struct Case<'a> {
        name: &'a str,
        entity_type: u8,
        short_id: &'a str,
        content_hash: u8,
        group_key: &'a str,
        build_fields: fn() -> HashMap<String, Value>,
        present_in_standard: &'a [&'a str],
        absent_from_standard: &'a [&'a str],
        expected_standard_order: &'a [&'a str],
        extra: fn(&ContextPack),
    }

    fn task_list_fields() -> HashMap<String, Value> {
        let mut fields = HashMap::new();
        fields.insert("name".to_owned(), Value::String("Sprint 42".to_owned()));
        fields.insert(
            "description".to_owned(),
            Value::String("Q2 deliverables".to_owned()),
        );
        fields.insert("goal".to_owned(), Value::String("Ship the MVP".to_owned()));
        fields.insert("icon".to_owned(), Value::String("rocket".to_owned()));
        fields.insert("status".to_owned(), Value::String("active".to_owned()));
        // Extras only in Full / fallback.
        fields.insert("color".to_owned(), Value::String("#ff0000".to_owned()));
        fields.insert(
            "repoUrl".to_owned(),
            Value::String("https://github.com/example".to_owned()),
        );
        fields
    }

    fn task_fields() -> HashMap<String, Value> {
        let mut fields = HashMap::new();
        fields.insert("role".to_owned(), Value::String("habit".to_owned()));
        fields.insert("title".to_owned(), Value::String("Morning run".to_owned()));
        fields.insert("status".to_owned(), Value::String("active".to_owned()));
        fields.insert(
            "dueDate".to_owned(),
            Value::Number(Number::from(
                crate::unix_seconds_now().saturating_add(2 * 86_400),
            )),
        );
        fields.insert("priority".to_owned(), Value::Number(Number::from(2_u64)));
        fields.insert("frequency".to_owned(), Value::String("daily".to_owned()));
        // Extras only in Full.
        fields.insert(
            "frequencyDetail".to_owned(),
            Value::String("weekdays".to_owned()),
        );
        fields.insert(
            "currentStreak".to_owned(),
            Value::Number(Number::from(5_u64)),
        );
        fields
    }

    fn task_list_extra(pack: &ContextPack) {
        // Re-assert specific value equality for Standard fields (was in the
        // original test_task_list_field_profiles via assert_eq!).
        let cfg_json = SerializeConfig {
            format: PackFormat::Json,
            profile: FieldProfile::Standard,
            budget: 4000,
            allocation: TokenAllocation::default(),
            include_stats: false,
            merge_neighbors: true,
            max_field_chars: 500,
            max_item_tokens: 0,
        };
        let parsed: Value =
            serde_json::from_slice(&serialize_pack(pack, &cfg_json)).expect("json parse");
        let first = &parsed["task_lists"][0];
        assert_eq!(first["name"], "Sprint 42");
        assert_eq!(first["goal"], "Ship the MVP");
        assert_eq!(first["status"], "active");

        // Plaintext Standard: assert group-name uppercasing + short_id:hash + text payload.
        let cfg_plain = SerializeConfig {
            format: PackFormat::Plaintext,
            profile: FieldProfile::Standard,
            budget: 4000,
            allocation: TokenAllocation::default(),
            include_stats: false,
            merge_neighbors: true,
            max_field_chars: 500,
            max_item_tokens: 0,
        };
        let text = String::from_utf8(serialize_pack(pack, &cfg_plain)).expect("utf8");
        assert!(
            text.contains("TASK_LISTS"),
            "group name should be TASK_LISTS"
        );
        assert!(text.contains("tl01:aa"), "short_id:hash should appear");
        assert!(text.contains("Sprint 42"));
        assert!(text.contains("Ship the MVP"));
    }

    fn task_extra(pack: &ContextPack) {
        // Re-assert specific string value equality for title/role/status
        // (was in the original test_task_field_profiles via assert_eq!).
        let cfg_json = SerializeConfig {
            format: PackFormat::Json,
            profile: FieldProfile::Standard,
            budget: 4000,
            allocation: TokenAllocation::default(),
            include_stats: false,
            merge_neighbors: true,
            max_field_chars: 500,
            max_item_tokens: 0,
        };
        let parsed: Value =
            serde_json::from_slice(&serialize_pack(pack, &cfg_json)).expect("json parse");
        let first = &parsed["tasks"][0];
        assert_eq!(first["title"], "Morning run");
        assert_eq!(first["role"], "habit");
        assert_eq!(first["status"], "active");

        // Minimal ordering for TASK.
        let minimal = fields_for_profile(ENTITY_TYPE_TASK, FieldProfile::Minimal);
        assert_eq!(minimal, &["title", "role"]);

        // Full membership for TASK.
        let full = fields_for_profile(ENTITY_TYPE_TASK, FieldProfile::Full);
        assert!(full.contains(&"frequency"));
        assert!(full.contains(&"frequencyDetail"));
        assert!(full.contains(&"currentStreak"));
        assert!(full.contains(&"longestStreak"));
        assert!(full.contains(&"parentId"));
        assert!(full.contains(&"listId"));
        assert!(full.contains(&"position"));
    }

    let cases: &[Case] = &[
        Case {
            name: "task_list",
            entity_type: ENTITY_TYPE_TASK_LIST,
            short_id: "tl01",
            content_hash: 0xaa,
            group_key: "task_lists",
            build_fields: task_list_fields,
            present_in_standard: &["name", "goal", "status"],
            absent_from_standard: &["description", "icon"],
            expected_standard_order: &["name", "goal", "status"],
            extra: task_list_extra,
        },
        Case {
            name: "task",
            entity_type: ENTITY_TYPE_TASK,
            short_id: "tk01",
            content_hash: 0xbb,
            group_key: "tasks",
            build_fields: task_fields,
            present_in_standard: &["title", "role", "status", "priority", "dueDate"],
            absent_from_standard: &["frequency", "frequencyDetail", "currentStreak"],
            expected_standard_order: &["title", "role", "status", "priority", "dueDate"],
            extra: task_extra,
        },
    ];

    for case in cases {
        let entity = ContextEntity {
            id: EntityId::from_bytes_unchecked([case.entity_type; 16]),
            short_id: case.short_id.to_owned(),
            content_hash: case.content_hash,
            entity_type: case.entity_type,
            score: 0.8,
            fields: Some((case.build_fields)()),
            edges: None,
            vector: None,
        };
        let pack = ContextPack {
            results: vec![entity],
            neighbors: vec![],
            stats: empty_stats(),
            empty: None,
        };

        // JSON / Standard profile inclusion + exclusion.
        let cfg_json = SerializeConfig {
            format: PackFormat::Json,
            profile: FieldProfile::Standard,
            budget: 4000,
            allocation: TokenAllocation::default(),
            include_stats: false,
            merge_neighbors: true,
            max_field_chars: 500,
            max_item_tokens: 0,
        };
        let bytes = serialize_pack(&pack, &cfg_json);
        let parsed: Value = serde_json::from_slice(&bytes).expect("json parse");
        let group = parsed
            .get(case.group_key)
            .unwrap_or_else(|| panic!("case {}: missing group key {}", case.name, case.group_key));
        let first = &group[0];
        for field in case.present_in_standard {
            assert!(
                first.get(field).is_some(),
                "case {}: field {field:?} should be present in Standard JSON",
                case.name
            );
        }
        for field in case.absent_from_standard {
            assert!(
                first.get(field).is_none(),
                "case {}: field {field:?} should be absent from Standard JSON",
                case.name
            );
        }

        // Standard profile ordering matches the documented schema.
        let standard = fields_for_profile(case.entity_type, FieldProfile::Standard);
        assert_eq!(
            standard, case.expected_standard_order,
            "case {}: Standard profile ordering mismatch",
            case.name
        );

        (case.extra)(&pack);
    }
}

#[test]
fn skill_full_profile_exposes_reliability_metadata() {
    let full = fields_for_profile(ENTITY_TYPE_SKILL, FieldProfile::Full);
    assert_eq!(full, crate::skill::SKILL_RECORD_BODY_KEYS);
    for key in ["generated", "humanAuthored", "dependencies", "provenance"] {
        assert!(full.contains(&key), "full SKILL profile must include {key}");
    }
}

#[test]
fn agent_def_profiles_keep_prompt_out_of_lean_packs() {
    assert_eq!(
        fields_for_profile(ENTITY_TYPE_AGENT_DEF, FieldProfile::Minimal),
        &["agentId"]
    );
    let full = fields_for_profile(ENTITY_TYPE_AGENT_DEF, FieldProfile::Full);
    assert_eq!(full, crate::agent_def::AGENT_DEF_BODY_KEYS);
    // The bounded 16 KiB custom prompt is a Full-only field: an empty
    // allow-list would otherwise leak every hydrated key into lean packs.
    for profile in [FieldProfile::Minimal, FieldProfile::Standard] {
        assert!(
            !fields_for_profile(ENTITY_TYPE_AGENT_DEF, profile).contains(&"instructions"),
            "instructions must be excluded from the {profile:?} profile"
        );
    }
}

#[test]
fn companion_register_records_serialize_as_first_class_export_group() {
    let persona_ref = EntityId::from_bytes_unchecked([0x31; 16]).to_hex();
    let person_ref = EntityId::from_bytes_unchecked([0x32; 16]).to_hex();
    let source_ref = EntityId::from_bytes_unchecked([0x33; 16]).to_hex();
    let target_ref = EntityId::from_bytes_unchecked([0x34; 16]).to_hex();
    let actor_ref = EntityId::from_bytes_unchecked([0x35; 16]).to_hex();

    let persona_fields = HashMap::from([
        (
            "schema_version".to_owned(),
            serde_json::json!(crate::companion::COMPANION_RECORD_SCHEMA_VERSION),
        ),
        ("kind".to_owned(), Value::String("persona".to_owned())),
        ("scope".to_owned(), serde_json::json!({ "kind": "neutral" })),
        (
            "subject".to_owned(),
            serde_json::json!({
                "kind": "persona",
                "persona_ref": persona_ref,
            }),
        ),
        ("lifecycle".to_owned(), Value::String("active".to_owned())),
        ("export".to_owned(), Value::String("portable".to_owned())),
        (
            "lifecycle_events".to_owned(),
            serde_json::json!([{ "kind": "created", "at": 123_u64 }]),
        ),
        (
            "provenance".to_owned(),
            serde_json::json!({
                "actor_ref": actor_ref,
                "actor_class": 1,
                "source": "user_stated",
                "approval": "approved",
            }),
        ),
        (
            "value".to_owned(),
            serde_json::json!({ "note": "not part of portable companion projection" }),
        ),
    ]);
    let relationship_fields = HashMap::from([
        (
            "schema_version".to_owned(),
            serde_json::json!(crate::companion::COMPANION_RECORD_SCHEMA_VERSION),
        ),
        ("kind".to_owned(), Value::String("relationship".to_owned())),
        (
            "scope".to_owned(),
            serde_json::json!({ "kind": "personal", "person_ref": person_ref }),
        ),
        (
            "subject".to_owned(),
            serde_json::json!({
                "kind": "relationship",
                "relationship_ref": {
                    "source_ref": source_ref,
                    "target_ref": target_ref,
                },
            }),
        ),
        ("lifecycle".to_owned(), Value::String("active".to_owned())),
        ("export".to_owned(), Value::String("portable".to_owned())),
        (
            "provenance".to_owned(),
            serde_json::json!({
                "actor_ref": EntityId::from_bytes_unchecked([0x36; 16]).to_hex(),
                "actor_class": 1,
                "source": "user_stated",
                "approval": "approved",
            }),
        ),
    ]);
    let pack = ContextPack {
        results: vec![
            ContextEntity {
                id: EntityId::from_bytes_unchecked([0x64; 16]),
                short_id: "cr01".to_owned(),
                content_hash: 0xa1,
                entity_type: ENTITY_TYPE_COMPANION_REGISTER,
                score: 0.9,
                fields: Some(persona_fields),
                edges: None,
                vector: None,
            },
            ContextEntity {
                id: EntityId::from_bytes_unchecked([0x65; 16]),
                short_id: "cr02".to_owned(),
                content_hash: 0xa2,
                entity_type: ENTITY_TYPE_COMPANION_REGISTER,
                score: 0.8,
                fields: Some(relationship_fields),
                edges: None,
                vector: None,
            },
        ],
        neighbors: vec![],
        stats: empty_stats(),
        empty: None,
    };
    let config = |format, profile| SerializeConfig {
        format,
        profile,
        budget: 4000,
        allocation: TokenAllocation::default(),
        include_stats: false,
        merge_neighbors: true,
        max_field_chars: 500,
        max_item_tokens: 0,
    };

    let cfg_json = config(PackFormat::Json, FieldProfile::Standard);
    let parsed: Value =
        serde_json::from_slice(&serialize_pack(&pack, &cfg_json)).expect("json parse");
    assert!(parsed.get("other").is_none());
    let records = parsed["companion_records"]
        .as_array()
        .expect("companion records group");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["kind"], "persona");
    assert_eq!(
        records[0]["scope"],
        serde_json::json!({ "kind": "neutral" })
    );
    assert_eq!(records[1]["kind"], "relationship");
    assert_eq!(
        records[1]["scope"]["kind"],
        Value::String("personal".to_owned())
    );
    assert_eq!(
        records[1]["subject"]["kind"],
        Value::String("relationship".to_owned())
    );
    assert!(records[0].get("provenance").is_none());
    assert!(records[0].get("lifecycle_events").is_none());
    assert!(records[0].get("schema_version").is_none());
    assert!(records[0].get("value").is_none());
    assert_eq!(
        fields_for_profile(ENTITY_TYPE_COMPANION_REGISTER, FieldProfile::Standard),
        &["kind", "scope", "subject", "lifecycle", "export"]
    );

    let cfg_full = config(PackFormat::Json, FieldProfile::Full);
    let full: Value =
        serde_json::from_slice(&serialize_pack(&pack, &cfg_full)).expect("json parse");
    assert_eq!(
        full["companion_records"][0]["schema_version"],
        serde_json::json!(crate::companion::COMPANION_RECORD_SCHEMA_VERSION)
    );
    assert!(full["companion_records"][0].get("provenance").is_some());
    assert_eq!(
        full["companion_records"][0]["lifecycle_events"],
        serde_json::json!([{ "kind": "created", "at": 123_u64 }])
    );
    assert!(full["companion_records"][0].get("value").is_none());
    assert_eq!(
        fields_for_profile(ENTITY_TYPE_COMPANION_REGISTER, FieldProfile::Full),
        &[
            "schema_version",
            "kind",
            "scope",
            "subject",
            "lifecycle",
            "export",
            "lifecycle_events",
            "provenance"
        ]
    );

    let cfg_plain = config(PackFormat::Plaintext, FieldProfile::Standard);
    let text = String::from_utf8(serialize_pack(&pack, &cfg_plain)).expect("utf8");
    assert!(text.contains("COMPANION_RECORDS"));
    assert!(text.contains("relationship"));
}

#[test]
fn companion_register_records_budget_with_fixed_state_allocation() {
    assert!(GROUP_ORDER.contains(&ENTITY_TYPE_COMPANION_REGISTER));

    let source_id = [0x64; 16];
    let groups = group_entities(vec![PreparedEntity {
        entity_type: ENTITY_TYPE_COMPANION_REGISTER,
        score: 0.9,
        source: PreparedEntitySource::Result,
        source_id,
        id: "cr01".to_owned(),
        fields: vec![
            ("kind".to_owned(), Value::String("persona".to_owned())),
            ("scope".to_owned(), serde_json::json!({ "kind": "neutral" })),
            (
                "subject".to_owned(),
                serde_json::json!({
                    "kind": "persona",
                    "persona_ref": EntityId::from_bytes_unchecked([0x31; 16]).to_hex(),
                }),
            ),
        ],
    }]);
    let needed =
        estimate_groups_tokens_with_depth_limit(&groups, DEFAULT_CONTEXT_PACK_TOKENIZER, None);
    let zero_other_allocation = TokenAllocation {
        claims: 1.0,
        turns: 0.0,
        summaries: 0.0,
        other: 0.0,
    };

    assert_eq!(
        type_fraction(
            GroupKey::Kind(ENTITY_TYPE_COMPANION_REGISTER),
            &zero_other_allocation
        ),
        zero_other_allocation.claims
    );

    let (budgeted, used) = budget_groups(&groups, &zero_other_allocation, needed);
    let records = budgeted
        .iter()
        .find_map(|(key, rows)| {
            (*key == GroupKey::Kind(ENTITY_TYPE_COMPANION_REGISTER)).then_some(rows)
        })
        .expect("companion register group should keep state allocation budget");

    assert_eq!(used, needed);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].source_id, source_id);
}

#[test]
fn federation_grant_member_ref_hex_projection_is_preserved() {
    let member_ref = EntityId::from_bytes_unchecked([0x62; 16]).to_hex();
    let fields = HashMap::from([
        (
            "scope".to_owned(),
            serde_json::json!({"kind": "vault", "vault_id": 7}),
        ),
        ("member_ref".to_owned(), Value::String(member_ref.clone())),
        ("role".to_owned(), Value::String("admin".to_owned())),
        ("preset".to_owned(), Value::String("admin".to_owned())),
    ]);
    let pack = ContextPack {
        results: vec![ContextEntity {
            id: EntityId::from_bytes_unchecked([ENTITY_TYPE_FEDERATION_GRANT; 16]),
            short_id: String::new(),
            content_hash: 0,
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            score: 1.0,
            fields: Some(fields),
            edges: None,
            vector: None,
        }],
        neighbors: vec![],
        stats: empty_stats(),
        empty: None,
    };
    for profile in [FieldProfile::Standard, FieldProfile::Full] {
        let cfg_json = SerializeConfig {
            format: PackFormat::Json,
            profile,
            budget: 4000,
            allocation: TokenAllocation::default(),
            include_stats: false,
            merge_neighbors: true,
            max_field_chars: 500,
            max_item_tokens: 0,
        };

        let parsed: Value =
            serde_json::from_slice(&serialize_pack(&pack, &cfg_json)).expect("json parse");
        let first = &parsed["federation_grants"][0];

        assert_eq!(first["member_ref"], member_ref);
    }
}

#[test]
fn test_due_date_timestamp_rendering() {
    // dueDate set to 2 days in the future — should render as "+2d" in plaintext.
    let now = crate::unix_seconds_now();
    let due = now + 2 * 86_400;

    let mut fields = HashMap::new();
    fields.insert("title".to_owned(), Value::String("Deploy v2".to_owned()));
    fields.insert("role".to_owned(), Value::String("task".to_owned()));
    fields.insert("status".to_owned(), Value::String("pending".to_owned()));
    fields.insert("dueDate".to_owned(), Value::Number(Number::from(due)));

    let entity = ContextEntity {
        id: EntityId::from_bytes_unchecked([0x91; 16]),
        short_id: "tk02".to_owned(),
        content_hash: 0xcc,
        entity_type: ENTITY_TYPE_TASK,
        score: 0.9,
        fields: Some(fields),
        edges: None,
        vector: None,
    };

    let pack = ContextPack {
        results: vec![entity],
        neighbors: vec![],
        stats: empty_stats(),
        empty: None,
    };

    // Plaintext format renders timestamps relatively.
    let cfg = SerializeConfig {
        format: PackFormat::Plaintext,
        profile: FieldProfile::Standard,
        budget: 4000,
        allocation: TokenAllocation::default(),
        include_stats: false,
        merge_neighbors: true,
        max_field_chars: 500,
        max_item_tokens: 0,
    };

    let text = String::from_utf8(serialize_pack(&pack, &cfg)).expect("utf8");

    // dueDate should be rendered as a relative timestamp, not the raw epoch integer.
    assert!(
        text.contains("+2d") || text.contains("+1d") || text.contains("+3d"),
        "dueDate should be a relative timestamp like +2d, got: {text}"
    );
    // The raw epoch number should NOT appear in the output.
    assert!(
        !text.contains(&due.to_string()),
        "raw epoch value should not appear in plaintext"
    );

    // Verify dueDate is recognized as a timestamp field.
    assert!(
        is_timestamp_field("dueDate"),
        "dueDate must be in is_timestamp_field"
    );

    // JSON format should keep the raw numeric timestamp (no relative rendering).
    let cfg_json = SerializeConfig {
        format: PackFormat::Json,
        profile: FieldProfile::Standard,
        budget: 4000,
        allocation: TokenAllocation::default(),
        include_stats: false,
        merge_neighbors: true,
        max_field_chars: 500,
        max_item_tokens: 0,
    };

    let json_bytes = serialize_pack(&pack, &cfg_json);
    let parsed: Value = serde_json::from_slice(&json_bytes).expect("json parse");
    let task = &parsed["tasks"][0];
    assert_eq!(
        task["dueDate"].as_u64().unwrap(),
        due,
        "JSON format should preserve raw numeric timestamp"
    );
}

#[test]
fn test_group_labels_sparse_ids() {
    let asset = group_labels(GroupKey::Kind(ENTITY_TYPE_ASSET));
    assert_eq!(asset.key, "assets");
    assert_eq!(asset.name, "ASSETS");
    assert_eq!(asset.title, "Assets");

    let notification = group_labels(GroupKey::Kind(ENTITY_TYPE_NOTIFICATION));
    assert_eq!(notification.key, "notifications");
    assert_eq!(notification.name, "NOTIFICATIONS");
    assert_eq!(notification.title, "Notifications");

    let tl = group_labels(GroupKey::Kind(ENTITY_TYPE_TASK_LIST));
    assert_eq!(tl.key, "task_lists");
    assert_eq!(tl.name, "TASK_LISTS");
    assert_eq!(tl.title, "Task Lists");

    let tk = group_labels(GroupKey::Kind(ENTITY_TYPE_TASK));
    assert_eq!(tk.key, "tasks");
    assert_eq!(tk.name, "TASKS");
    assert_eq!(tk.title, "Tasks");

    let mc = group_labels(GroupKey::Kind(ENTITY_TYPE_MACHINE));
    assert_eq!(mc.key, "machines");
    assert_eq!(mc.name, "MACHINES");
    assert_eq!(mc.title, "Machines");

    let grant = group_labels(GroupKey::Kind(ENTITY_TYPE_FEDERATION_GRANT));
    assert_eq!(grant.key, "federation_grants");
    assert_eq!(grant.name, "FEDERATION_GRANTS");
    assert_eq!(grant.title, "Federation Grants");
    assert_eq!(
        fields_for_profile(ENTITY_TYPE_FEDERATION_GRANT, FieldProfile::Minimal),
        crate::federation::FEDERATION_GRANT_FIELDS_MINIMAL
    );

    let access_grant = group_labels(GroupKey::Kind(ENTITY_TYPE_ACCESS_GRANT));
    assert_eq!(access_grant.key, "access_grants");
    assert_eq!(access_grant.name, "ACCESS_GRANTS");
    assert_eq!(access_grant.title, "Access Grants");
    assert_eq!(
        fields_for_profile(ENTITY_TYPE_ACCESS_GRANT, FieldProfile::Minimal),
        crate::access_grant::ACCESS_GRANT_FIELDS_MINIMAL
    );

    let counterparty_contact = group_labels(GroupKey::Kind(ENTITY_TYPE_COUNTERPARTY_CONTACT));
    assert_eq!(counterparty_contact.key, "counterparty_contacts");
    assert_eq!(counterparty_contact.name, "COUNTERPARTY_CONTACTS");
    assert_eq!(counterparty_contact.title, "Counterparty Contacts");
    assert_eq!(
        fields_for_profile(ENTITY_TYPE_COUNTERPARTY_CONTACT, FieldProfile::Minimal),
        crate::counterparty_contact::COUNTERPARTY_CONTACT_FIELDS_MINIMAL
    );

    let outbound_grant = group_labels(GroupKey::Kind(ENTITY_TYPE_OUTBOUND_GRANT));
    assert_eq!(outbound_grant.key, "outbound_grants");
    assert_eq!(outbound_grant.name, "OUTBOUND_GRANTS");
    assert_eq!(outbound_grant.title, "Outbound Grants");
    assert_eq!(
        fields_for_profile(ENTITY_TYPE_OUTBOUND_GRANT, FieldProfile::Minimal),
        crate::outbound_grant::OUTBOUND_GRANT_FIELDS_MINIMAL
    );

    let companion = group_labels(GroupKey::Kind(ENTITY_TYPE_COMPANION_REGISTER));
    assert_eq!(companion.key, "companion_records");
    assert_eq!(companion.name, "COMPANION_RECORDS");
    assert_eq!(companion.title, "Companion Records");
    assert_eq!(
        fields_for_profile(ENTITY_TYPE_COMPANION_REGISTER, FieldProfile::Minimal),
        &["kind", "scope", "subject"]
    );

    let psych_profile = group_labels(GroupKey::Kind(ENTITY_TYPE_PSYCH_PROFILE));
    assert_eq!(psych_profile.key, "psych_profiles");
    assert_eq!(psych_profile.name, "PSYCH_PROFILES");
    assert_eq!(psych_profile.title, "Psych Profiles");
    assert_eq!(
        fields_for_profile(ENTITY_TYPE_PSYCH_PROFILE, FieldProfile::Minimal),
        crate::psych_profile::PSYCH_PROFILE_FIELDS_MINIMAL
    );

    // Types outside the known set fall back to OTHER_GROUP_LABELS, whether
    // they arrive as an unlabelled kind or as the dedicated Other bucket.
    // Byte-space v3 removed the u8::MAX stand-in that used to be spelled here.
    for unknown in [
        group_labels(GroupKey::Other),
        group_labels(GroupKey::Kind(ENTITY_TYPE_CODE_ARTIFACT)),
    ] {
        assert_eq!(unknown.key, "other");
        assert_eq!(unknown.name, "OTHER");
        assert_eq!(unknown.title, "Other");
    }
}

/// ONE-1377: a take is retrieved as a NOTE, never reprinted as a CLAIM, and
/// the Minimal profile carries the attribution pair WITHOUT the unbounded
/// prose body. The field sets are pinned literally — a widened profile has to
/// change this test, not slip past it.
#[test]
fn note_group_is_separate_from_claims_with_pinned_profile_fields() {
    let note = group_labels(GroupKey::Kind(ENTITY_TYPE_NOTE));
    assert_eq!(note.key, "notes");
    assert_eq!(note.name, "NOTES");
    assert_eq!(note.title, "Notes");

    assert_eq!(
        fields_for_profile(ENTITY_TYPE_NOTE, FieldProfile::Minimal),
        &["kind", "author_ref"]
    );
    assert_eq!(
        fields_for_profile(ENTITY_TYPE_NOTE, FieldProfile::Standard),
        &["kind", "author_ref", "markdown"]
    );
    assert_eq!(
        fields_for_profile(ENTITY_TYPE_NOTE, FieldProfile::Full),
        &["kind", "author_ref", "markdown"]
    );

    let author = EntityId::from_bytes_unchecked([0x7a; 16]);
    let note_row = ContextEntity {
        id: EntityId::from_bytes_unchecked([0x9e; 16]),
        short_id: "no01".to_owned(),
        content_hash: 0x11,
        entity_type: ENTITY_TYPE_NOTE,
        score: 0.9,
        fields: Some(HashMap::from([
            (
                "kind".to_owned(),
                Value::String(crate::note::NoteKind::OpinionTake.as_str().to_owned()),
            ),
            ("author_ref".to_owned(), Value::String(author.to_hex())),
            (
                "markdown".to_owned(),
                Value::String("The source predates the merger.".to_owned()),
            ),
        ])),
        edges: None,
        vector: None,
    };

    let mut pack = sample_pack();
    pack.results.push(note_row);

    for (profile, expects_markdown) in [
        (FieldProfile::Minimal, false),
        (FieldProfile::Standard, true),
        (FieldProfile::Full, true),
    ] {
        let mut cfg = config(PackFormat::Json);
        cfg.profile = profile;
        let rendered = serialize_pack(&pack, &cfg);
        let json: Value = serde_json::from_slice(&rendered).expect("json pack");

        let notes = json["notes"].as_array().expect("notes group");
        assert_eq!(notes.len(), 1, "{profile:?}");
        let row = notes[0].as_object().expect("note row");
        assert_eq!(row["kind"], Value::String("opinion/take".to_owned()));
        assert_eq!(row["author_ref"], Value::String(author.to_hex()));
        assert_eq!(
            row.contains_key("markdown"),
            expects_markdown,
            "{profile:?} markdown exposure"
        );

        // The take never leaks into the neutral-claim group.
        let claims = json["claims"].as_array().expect("claims group");
        assert!(
            claims
                .iter()
                .all(|claim| claim.get("kind").and_then(Value::as_str) != Some("opinion/take")),
            "{profile:?}: take must not be projected into CLAIMS"
        );
    }
}
