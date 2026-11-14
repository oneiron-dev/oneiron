//! Native selection parity for extraction grouping and scoring.
//!
//! Loads the dreamer fixture and compares native ordering, holds and
//! scores against the crate mirror, without any new engine door.

use std::collections::BTreeMap;

use oneiron::EntityId;
use oneiron::dreamer_consolidation::selection::{
    SelectionCandidate, SelectionConfig, SelectionHold as NativeHold, StrengthSignals,
    select_candidates, strength_score,
};
use oneiron_dreamer::extraction_observations::{CandidateObservation, Observations};
use oneiron_dreamer::extraction_selection::{
    CandidateGroup, CandidateGroups, ExtractionSelectionConfig, SelectionHold as DreamerHold,
    select as dreamer_select,
};
use serde_json::{Value, json};

const FIXTURE_JSON: &str =
    include_str!("../../oneiron-dreamer/tests/fixtures/extraction_selection.json");
const ATTEMPT_HEX: &str = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";
const SCOPE_FACET: &str = "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0";
const SCOPE_PROJECT: &str = "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1";
const REPLAY_FACET: &str = "f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2";

fn load_fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("the fixture parses")
}

fn native_config(selection: &Value) -> SelectionConfig {
    serde_json::from_value(selection.clone()).expect("native config decodes")
}

fn dreamer_config(selection: &Value, policy_pin: &str) -> ExtractionSelectionConfig {
    ExtractionSelectionConfig::from_selection(selection.clone(), policy_pin)
        .expect("crate config decodes")
}

fn dreamer_candidate(scalar: &Value, index: usize) -> CandidateObservation {
    let mirror = json!({
        "index": index,
        "claim": scalar["claim"],
        "identity_token": scalar["identity"],
        "topic_token": scalar["topic"],
        "value_token": scalar["value"],
        "slice_token": scalar["slice"],
        "predicate": scalar["predicate"],
        "corrects": scalar["corrects"],
        "meet": "generated",
        "observed": false,
        "evidence_count": scalar["evidence_count"],
        "first_seen_ms": scalar["first_seen_ms"],
        "latest_ms": scalar["latest_ms"],
        "diversity": scalar["diversity"],
        "fan_in": scalar["fan_in"],
        "new_refs": scalar["new_refs"],
        "has_vector": false,
        "named_facet": null,
        "scope_facet": SCOPE_FACET,
        "scope_project": SCOPE_PROJECT,
        "replay_facet": REPLAY_FACET,
    });
    serde_json::from_value(mirror).expect("the scalar expands")
}

fn native_candidate(scalar: &Value, now_ms: u64, config: &SelectionConfig) -> SelectionCandidate {
    let hex = scalar["claim"].as_str().expect("claim decodes");
    let claim_id = EntityId::from_hex(hex).expect("claim is an id");
    let predicate = scalar["predicate"].as_str().expect("predicate decodes");
    let count = scalar["evidence_count"].as_u64().expect("count decodes") as usize;
    let latest = scalar["latest_ms"].as_u64().expect("latest decodes");
    let diversity = scalar["diversity"].as_u64().expect("diversity decodes") as usize;
    let signals =
        StrengthSignals::from_evidence(predicate, count, latest, diversity, now_ms, config);
    SelectionCandidate {
        claim_id,
        first_seen_ms: scalar["first_seen_ms"]
            .as_u64()
            .expect("first seen decodes"),
        evidence_count: count,
        fan_in: scalar["fan_in"].as_u64().expect("fan in decodes"),
        new_refs: scalar["new_refs"].as_u64().expect("new refs decode"),
        signals,
    }
}

fn singleton_groups(len: usize) -> CandidateGroups {
    let mut groups = Vec::new();
    for index in 0..len {
        groups.push(CandidateGroup {
            representative_index: index,
            member_indexes: vec![index],
            corrects: None,
        });
    }
    CandidateGroups {
        groups,
        pending_bindings: Vec::new(),
    }
}

fn dreamer_observations(
    candidates: &Value,
    policy_pin: &str,
    facts_pin: &str,
    now_ms: u64,
) -> Observations {
    let rows = candidates.as_array().expect("the case lists candidates");
    let mut mirrors = Vec::new();
    for (index, scalar) in rows.iter().enumerate() {
        mirrors.push(dreamer_candidate(scalar, index));
    }
    Observations {
        attempt: ATTEMPT_HEX.to_owned(),
        now_ms,
        policy_pin: policy_pin.to_owned(),
        facts_pin: facts_pin.to_owned(),
        candidates: mirrors,
        priors: Vec::new(),
        replay: Vec::new(),
        scores: Vec::new(),
    }
}

fn check_parity_for_case(
    case: &Value,
    selection: &Value,
    policy_pin: &str,
    facts_pin: &str,
    now_ms: u64,
) {
    let name = case["name"].as_str().expect("the case is named");
    let rows = case["candidates"]
        .as_array()
        .expect("the case lists candidates");
    let native_cfg = native_config(selection);
    let dreamer_cfg = dreamer_config(selection, policy_pin);
    let mut native_inputs = Vec::new();
    let mut to_index: BTreeMap<EntityId, usize> = BTreeMap::new();
    for (index, scalar) in rows.iter().enumerate() {
        let input = native_candidate(scalar, now_ms, &native_cfg);
        to_index.insert(input.claim_id, index);
        native_inputs.push(input);
    }
    let groups = singleton_groups(rows.len());
    let observations = dreamer_observations(&case["candidates"], policy_pin, facts_pin, now_ms);
    let native_plan =
        select_candidates(&native_inputs, now_ms, &native_cfg).expect("native selects");
    let dreamer_plan =
        dreamer_select(&groups, &observations, now_ms, &dreamer_cfg).expect("crate selects");
    let mut native_ready = Vec::new();
    for id in &native_plan.ready {
        native_ready.push(*to_index.get(id).expect("native id maps"));
    }
    assert_eq!(dreamer_plan.ready, native_ready, "ready for {name}");
    let mut native_held = Vec::new();
    for (id, hold) in &native_plan.held {
        let index = *to_index.get(id).expect("native held maps");
        let reason = match hold {
            NativeHold::Soak => DreamerHold::Soak,
            NativeHold::EvidenceCount => DreamerHold::EvidenceCount,
        };
        native_held.push((index, reason));
    }
    assert_eq!(
        dreamer_plan.held, native_held,
        "held order and kinds for {name}"
    );
    for scored in &dreamer_plan.groups {
        let rep = scored.representative_index;
        let native_score = strength_score(native_inputs[rep].signals, &native_cfg)
            .expect("native scores the same signals");
        assert_eq!(
            scored.score.to_bits(),
            native_score.to_bits(),
            "score bits for {name} {rep}"
        );
    }
}

#[test]
fn extraction_selection_matches_native_order_holds_and_scores() {
    let fixture = load_fixture();
    let selection = fixture["selection"].clone();
    let policy_pin = fixture["policy_pin"]
        .as_str()
        .expect("the fixture pins policy");
    let facts_pin = fixture["facts_pin"]
        .as_str()
        .expect("the fixture pins facts");
    let now_ms = fixture["now_ms"].as_u64().expect("the fixture carries now");
    let cases = fixture["selection_cases"]
        .as_array()
        .expect("the fixture lists cases");
    for case in cases {
        check_parity_for_case(case, &selection, policy_pin, facts_pin, now_ms);
    }
}

#[test]
fn f6_shared_arithmetic_proxies_through_extraction_score() {
    // F6 exposes no score publicly: the shared extraction score here is a
    // proxy for the F6 shared arithmetic, not a claim that any archive ran.
    let fixture = load_fixture();
    let selection = fixture["selection"].clone();
    let policy_pin = fixture["policy_pin"]
        .as_str()
        .expect("the fixture pins policy");
    let facts_pin = fixture["facts_pin"]
        .as_str()
        .expect("the fixture pins facts");
    let now_ms = fixture["now_ms"].as_u64().expect("the fixture carries now");
    let proxy = &fixture["f6_proxy"];
    let predicate = proxy["predicate"]
        .as_str()
        .expect("proxy predicate decodes");
    let source_count = proxy["source_count"].as_u64().expect("proxy count decodes");
    let latest = proxy["latest_learned_at_ms"]
        .as_u64()
        .expect("proxy latest decodes");
    let diversity = proxy["distinct_diversity"]
        .as_u64()
        .expect("proxy diversity decodes");
    let native_cfg = native_config(&selection);
    let dreamer_cfg = dreamer_config(&selection, policy_pin);
    let scalar = json!({
        "claim": "b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7",
        "predicate": predicate,
        "identity": "id-0",
        "topic": "topic-0",
        "value": "value-0",
        "slice": "slice-0",
        "corrects": null,
        "evidence_count": source_count,
        "first_seen_ms": now_ms.saturating_sub(120_000),
        "latest_ms": latest,
        "diversity": diversity,
        "fan_in": 0,
        "new_refs": 0,
    });
    let groups = singleton_groups(1);
    let observations = Observations {
        attempt: ATTEMPT_HEX.to_owned(),
        now_ms,
        policy_pin: policy_pin.to_owned(),
        facts_pin: facts_pin.to_owned(),
        candidates: vec![dreamer_candidate(&scalar, 0)],
        priors: Vec::new(),
        replay: Vec::new(),
        scores: Vec::new(),
    };
    let plan = dreamer_select(&groups, &observations, now_ms, &dreamer_cfg).expect("proxy selects");
    let signals = StrengthSignals::from_evidence(
        predicate,
        source_count as usize,
        latest,
        diversity as usize,
        now_ms,
        &native_cfg,
    );
    let native_score = strength_score(signals, &native_cfg).expect("native scores proxy");
    assert_eq!(plan.groups.len(), 1, "one proxy group");
    assert_eq!(
        plan.groups[0].score.to_bits(),
        native_score.to_bits(),
        "proxy score bits"
    );
    assert_eq!(plan.ready, vec![0], "the proxy candidate is ready");
}
