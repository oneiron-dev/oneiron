//! Checks ordinary routing and observed-beside policy through the public crate API.

use oneiron_dreamer::extraction_observations::{
    CandidateObservation, Observations, PriorObservation, ReplayObservation,
};
use oneiron_dreamer::extraction_routing::{Correction, Error, route};
use oneiron_dreamer::extraction_selection::{
    ExtractionSelectionConfig, ExtractionSelectionPlan, ScoredCandidateGroup,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const FIXTURE_JSON: &str = include_str!("fixtures/extraction_routing.json");

/// Expands one fixture row over its shared native observation defaults.
fn expanded<T: DeserializeOwned>(base: &Value, row: &Value) -> T {
    let mut value = base.clone();
    value
        .as_object_mut()
        .expect("default object")
        .extend(row.as_object().expect("row object").clone());
    serde_json::from_value(value).expect("fixture row decodes")
}

/// Builds a union observation and selection plan with original request indexes.
fn inputs(
    fixture: &Value,
    case: &Value,
) -> (
    ExtractionSelectionPlan,
    Observations,
    ExtractionSelectionConfig,
) {
    let candidates: Vec<CandidateObservation> = case["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .enumerate()
        .map(|(position, row)| {
            let mut base = fixture["candidate"].clone();
            base["index"] = json!(position);
            base["claim"] = json!(format!("{:032x}", position + 1));
            expanded(&base, row)
        })
        .collect();
    let groups: Vec<ScoredCandidateGroup> = match case.get("groups") {
        Some(groups) => serde_json::from_value(groups.clone()).expect("groups"),
        None => candidates
            .iter()
            .map(|candidate| ScoredCandidateGroup {
                representative_index: candidate.index,
                member_indexes: vec![candidate.index],
                corrects: None,
                score: 0.5,
            })
            .collect(),
    };
    let ready = case.get("ready").map_or_else(
        || candidates.iter().map(|candidate| candidate.index).collect(),
        |ready| serde_json::from_value(ready.clone()).expect("ready"),
    );
    let prior_rows = case.get("priors").cloned().unwrap_or_else(|| json!([]));
    let replay_rows = case.get("replay").cloned().unwrap_or_else(|| json!([]));
    let priors: Vec<PriorObservation> = prior_rows
        .as_array()
        .expect("priors")
        .iter()
        .map(|row| expanded(&fixture["prior"], row))
        .collect();
    let replay: Vec<ReplayObservation> = replay_rows
        .as_array()
        .expect("replay")
        .iter()
        .map(|row| expanded(&fixture["replay"], row))
        .collect();
    let policy_pin = fixture["policy_pin"].as_str().expect("policy pin");
    let facts_pin = fixture["facts_pin"].as_str().expect("facts pin");
    let now_ms = fixture["now_ms"].as_u64().expect("clock");
    let observations = Observations {
        attempt: "a5".repeat(16),
        now_ms,
        policy_pin: policy_pin.to_owned(),
        facts_pin: facts_pin.to_owned(),
        candidates,
        priors,
        replay,
        scores: serde_json::from_value(case.get("scores").cloned().unwrap_or_else(|| json!([])))
            .expect("scores"),
    };
    let selection = ExtractionSelectionPlan {
        ready,
        groups,
        held: serde_json::from_value(case.get("held").cloned().unwrap_or_else(|| json!([])))
            .expect("held"),
        pending_bindings: serde_json::from_value(
            case.get("pending").cloned().unwrap_or_else(|| json!([])),
        )
        .expect("pending"),
        retry_at_ms: now_ms + 1,
        policy_pin: policy_pin.to_owned(),
        facts_pin: case
            .get("selection_facts_pin")
            .and_then(Value::as_str)
            .unwrap_or(facts_pin)
            .to_owned(),
    };
    let mut config = fixture["selection"].clone();
    if let Some(threshold) = case.get("threshold") {
        config["cosine_threshold"] = threshold.clone();
    }
    let config_pin = case
        .get("config_pin")
        .and_then(Value::as_str)
        .unwrap_or(policy_pin);
    let config = ExtractionSelectionConfig::from_selection(config, config_pin).expect("config");
    (selection, observations, config)
}

/// Checks every route, group mapping, set, context and correction in one fixture row.
fn assert_case(fixture: &Value, case: &Value) {
    let name = case["name"].as_str().expect("case name");
    let (selection, observations, config) = inputs(fixture, case);
    let answer = route(&selection, &observations, &config);
    if let Some(error) = case["error"].as_str() {
        let error = match (error, answer) {
            ("config", Err(Error::InvalidConfig))
            | ("policy", Err(Error::PolicyPin { .. }))
            | ("observations", Err(Error::InvalidObservations(_))) => return,
            (_, answer) => format!("{answer:?}"),
        };
        panic!("{name}: expected routing refusal, got {error}");
    }
    let plan = answer.unwrap_or_else(|error| panic!("{name}: {error}"));
    assert_eq!(plan.policy_pin, observations.policy_pin, "{name}");
    assert_eq!(plan.facts_pin, observations.facts_pin, "{name}");
    let expected_routes = case["routes"].as_array().expect("expected routes");
    assert_eq!(plan.routes.len(), selection.ready.len(), "{name}");
    assert_eq!(plan.routes.len(), expected_routes.len(), "{name}");
    let empty = json!([]);
    for (position, (routed, expected)) in plan.routes.iter().zip(expected_routes).enumerate() {
        assert_eq!(
            serde_json::to_value(&routed.choice).expect("choice"),
            *expected,
            "{name}"
        );
        assert_eq!(
            routed.representative_index, selection.ready[position],
            "{name}"
        );
        let group = selection
            .groups
            .iter()
            .find(|group| group.representative_index == routed.representative_index)
            .expect("group");
        assert_eq!(routed.member_indexes, group.member_indexes, "{name}");
        assert_eq!(
            json!(routed.dropped_stated_heads),
            *case["dropped_heads"].get(position).unwrap_or(&empty),
            "{name}"
        );
        assert_eq!(
            json!(routed.dropped_correction),
            case["dropped_corrections"]
                .get(position)
                .cloned()
                .unwrap_or(Value::Null),
            "{name}"
        );
    }
    let expected_sets = case.get("sets").unwrap_or(&empty).as_array().expect("sets");
    assert_eq!(plan.judge_sets.len(), expected_sets.len(), "{name}");
    for (set, expected) in plan.judge_sets.iter().zip(expected_sets) {
        assert_eq!(
            json!(set.candidate_indexes),
            expected["candidate_indexes"],
            "{name}"
        );
        assert_eq!(json!(set.prior_heads), expected["prior_heads"], "{name}");
        assert_eq!(
            json!(set.identity_token),
            expected["identity_token"],
            "{name}"
        );
        let heads = expected["prior_heads"].as_array().expect("heads");
        let unique = if heads.len() == 1 {
            heads[0].clone()
        } else {
            Value::Null
        };
        assert_eq!(json!(set.prior_head), unique, "{name}");
    }
    let corrections: Vec<Correction> = serde_json::from_value(
        case.get("corrections")
            .cloned()
            .unwrap_or_else(|| json!([])),
    )
    .expect("corrections");
    assert_eq!(plan.corrections, corrections, "{name}");
}

#[test]
fn ordinary_routing_matches_native_policy_fixtures() {
    let fixture: Value = serde_json::from_str(FIXTURE_JSON).expect("fixture");
    for case in fixture["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .filter(|case| case["policy"] == "native")
    {
        assert_case(&fixture, case);
    }
}

#[test]
fn observed_routing_excludes_only_matching_stated_heads() {
    let fixture: Value = serde_json::from_str(FIXTURE_JSON).expect("fixture");
    for case in fixture["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .filter(|case| case["policy"] == "observed_beside")
    {
        assert_case(&fixture, case);
    }
}
