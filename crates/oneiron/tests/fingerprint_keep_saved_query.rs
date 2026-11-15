//! K-proof (pins) for PLAN-UC-04 stage 1.1: the saved-query digests keep their bytes.
//!
//! Stage 1.1 moves three stored SHA-256 digests onto the fingerprint crate's K door and
//! deletes the big-endian `hash_bytes`/`hash_len` pair; it also points the store's
//! sorted-JSON copy at the kept encoder (`oneiron_model::llm::canonical_json_bytes`):
//! - the evidence hash (`compute_evidence_hash`), the memo key;
//! - a membership plan's content digest (`plan_content_digest`, through a door), which
//!   the membership watermark keeps;
//! - the vector pair fingerprint (`vector_pair_fingerprint`), evidence inside the hash;
//! - `canonical_json_bytes`, whose bytes are hashed into the evidence hash and stored
//!   as saved-query rows.
//!
//! `PINS` holds what main printed for every fixture (a scratch branch at main with this
//! file and the door); the head must give the same hex.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test fingerprint_keep_saved_query`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::campaign::claims::{CampaignMemberChannel, CampaignMemberState};
use oneiron::saved_query::{
    ClaimComparison, EVIDENCE_HASH_LEN, EvalMode, EvalPolicy, FilterAst, MatcherSpec,
    MembershipCause, MembershipEvent, MembershipTransition, MembershipWritePlan, QueryScope,
    RelevantEvidence, SavedQueryDefinition, SavedQueryLifecycle, compute_evidence_hash,
    derived_member_value,
};
use oneiron::test_doors::fingerprint_keep_saved_query::plan_content_digest;
use oneiron::{EdgeActorClass, EntityId};
use oneiron_store::query_memo_codec::{
    canonical_json_bytes, rmpv_to_json, vector_pair_fingerprint,
};
use serde_json::{Value, json};

/// What main printed, by fixture name. Empty until main's run is read.
const PINS: &[(&str, &str)] = &[];

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("an unreserved id")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn definition(
    schema_version: u32,
    definition_version: u64,
    owner: u8,
    scope: QueryScope,
) -> SavedQueryDefinition {
    SavedQueryDefinition {
        schema_version,
        owner_actor: id(owner),
        owner_actor_class: EdgeActorClass::Human,
        scope,
        definition_version,
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

fn evidence(entity: u8) -> RelevantEvidence {
    RelevantEvidence {
        entity_ref: id(entity),
        claim_values: Vec::new(),
        claim_value_fingerprints: Vec::new(),
        edge_targets: Vec::new(),
        semantic_inputs: Vec::new(),
        scope_membership: QueryScope::default(),
    }
}

/// A JSON value whose maps are written out of key order (`serde_json` keeps
/// insertion order in this workspace), with unicode keys, `u64::MAX` and nesting.
fn unsorted_value() -> Value {
    json!({
        "zeta": [3, {"y": null, "x": true}],
        "\u{65e5}\u{672c}": "\u{1f600}",
        "alpha": {"max": u64::MAX, "min": i64::MIN, "float": 0.1, "negative_zero": -0.0},
        "": "",
        "escape": "quote \" backslash \\ nul \u{0} tab \t",
    })
}

fn evidence_rows() -> Vec<(&'static str, SavedQueryDefinition, RelevantEvidence)> {
    let worlds = QueryScope {
        worlds: vec![id(0x31), id(0x32)],
        facets: vec![String::new(), "work".to_owned(), "\u{e9}t\u{e9}".to_owned()],
    };
    let mut full = evidence(0x2e);
    full.claim_values = vec![
        ("crm.fit".to_owned(), unsorted_value()),
        (String::new(), Value::Null),
        ("crm.list".to_owned(), json!([])),
        ("crm.map".to_owned(), json!({})),
    ];
    full.claim_value_fingerprints = vec![
        ("crm.fit".to_owned(), vec![0x91, 0x00, 0xff]),
        (String::new(), Vec::new()),
    ];
    full.edge_targets = vec![("works_at".to_owned(), id(0x51)), (String::new(), id(0x52))];
    full.semantic_inputs = vec![
        (
            id(0x61),
            vector_pair_fingerprint(&Some(vec![1.0, -0.0]), &Some(vec![0.5])),
        ),
        (id(0x62), String::new()),
    ];
    full.scope_membership = worlds.clone();
    let mut nan_projected = evidence(0x2f);
    nan_projected.claim_values = vec![(
        "crm.score".to_owned(),
        rmpv_to_json(&rmpv::Value::F64(f64::NAN)),
    )];
    vec![
        (
            "evidence_empty",
            definition(0, 0, 0x21, QueryScope::default()),
            evidence(0x22),
        ),
        (
            "evidence_max_versions",
            definition(u32::MAX, u64::MAX, 0x21, QueryScope::default()),
            evidence(0x22),
        ),
        ("evidence_full", definition(1, 3, 0x23, worlds), full),
        (
            "evidence_nan_claim_value",
            definition(1, 3, 0x23, QueryScope::default()),
            nan_projected,
        ),
    ]
}

fn event(epoch: u64, transition: MembershipTransition, cause: MembershipCause) -> MembershipEvent {
    MembershipEvent {
        query_ref: id(0x71),
        campaign_ref: id(0x72),
        entity_ref: id(0x73),
        epoch,
        valid_at: 1_700_000_000,
        detected_at: 1_700_000_005,
        transition,
        cause,
        evidence_hash: [0x5a; EVIDENCE_HASH_LEN],
    }
}

fn channel() -> CampaignMemberChannel {
    CampaignMemberChannel {
        channel: "email".to_owned(),
        basis_evidence: id(0x81),
        sender_ref: id(0x82),
    }
}

fn plan_rows() -> Vec<(&'static str, MembershipWritePlan)> {
    let entered = event(
        1,
        MembershipTransition::Entered,
        MembershipCause::DataChange,
    );
    let exited = event(
        u64::MAX,
        MembershipTransition::Exited,
        MembershipCause::ScopeChange,
    );
    let paused = event(
        7,
        MembershipTransition::Entered,
        MembershipCause::DefinitionChange,
    );
    vec![
        (
            "plan_entered_no_channels",
            MembershipWritePlan {
                value: derived_member_value(&entered, CampaignMemberState::Enrolled, Vec::new()),
                event: entered,
            },
        ),
        (
            "plan_exited_max_epoch",
            MembershipWritePlan {
                value: derived_member_value(&exited, CampaignMemberState::Exited, vec![channel()]),
                event: exited,
            },
        ),
        (
            "plan_paused_until_max",
            MembershipWritePlan {
                value: derived_member_value(
                    &paused,
                    CampaignMemberState::Paused {
                        until: Some(u64::MAX),
                        new_trigger: None,
                    },
                    vec![channel()],
                ),
                event: paused,
            },
        ),
    ]
}

type Vectors = (Option<Vec<f32>>, Option<Vec<f32>>);

fn vector_rows() -> Vec<(&'static str, Vectors)> {
    vec![
        ("vectors_none_none", (None, None)),
        ("vectors_empty_none", (Some(Vec::new()), None)),
        ("vectors_none_empty", (None, Some(Vec::new()))),
        (
            "vectors_edge_values",
            (
                Some(vec![1.0, -0.0, f32::NAN, f32::INFINITY, f32::MIN_POSITIVE]),
                Some(vec![f32::MAX, f32::NEG_INFINITY]),
            ),
        ),
    ]
}

fn json_rows() -> Vec<(&'static str, Value)> {
    vec![
        ("json_unsorted_nested", unsorted_value()),
        ("json_null", Value::Null),
        ("json_empty_object", json!({})),
        ("json_empty_list", json!([])),
        ("json_empty_string", json!("")),
        (
            "json_nan_projected",
            rmpv_to_json(&rmpv::Value::F32(f32::NAN)),
        ),
        (
            "json_list_of_unsorted_maps",
            json!([{"b": 1, "a": [{"d": 4, "c": 3}]}, {"\u{1f600}": 1, "A": 2}]),
        ),
    ]
}

/// Every fixture's digest as lowercase hex, in a fixed order.
fn digests() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, definition, evidence) in evidence_rows() {
        let digest = compute_evidence_hash(&definition, &evidence).expect("evidence hash");
        out.push((name.to_owned(), hex(&digest)));
    }
    for (name, plan) in plan_rows() {
        let digest = plan_content_digest(&plan).expect("plan digest");
        out.push((name.to_owned(), hex(&digest)));
    }
    for (name, (subject, exemplar)) in vector_rows() {
        out.push((
            name.to_owned(),
            vector_pair_fingerprint(&subject, &exemplar),
        ));
    }
    for (name, value) in json_rows() {
        let bytes = canonical_json_bytes(&value).expect("canonical json");
        out.push((name.to_owned(), hex(&bytes)));
    }
    out
}

#[test]
fn the_saved_query_digests_keep_main_bytes() {
    let digests = digests();
    for (name, hex) in &digests {
        println!("PIN {name} {hex}");
    }
    let names: BTreeSet<&str> = digests.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names.len(), digests.len(), "fixture names are distinct");
    if PINS.is_empty() {
        // Print mode, at main and at the first head run.
        return;
    }
    let got: Vec<(&str, &str)> = digests
        .iter()
        .map(|(name, hex)| (name.as_str(), hex.as_str()))
        .collect();
    assert_eq!(got, PINS);
}

/// QUERY-MEMO-NAN-NULL stays until stage 9: a NaN claim value projects to null, so its
/// evidence hash equals a null value's. Kept on purpose, because the hash is stored.
#[test]
fn a_nan_claim_value_and_a_null_one_still_collide() {
    let definition = definition(1, 3, 0x23, QueryScope::default());
    let mut nan = evidence(0x2f);
    nan.claim_values = vec![(
        "crm.score".to_owned(),
        rmpv_to_json(&rmpv::Value::F64(f64::NAN)),
    )];
    let mut null = evidence(0x2f);
    null.claim_values = vec![("crm.score".to_owned(), Value::Null)];
    assert_eq!(
        compute_evidence_hash(&definition, &nan).expect("hash"),
        compute_evidence_hash(&definition, &null).expect("hash")
    );
}
