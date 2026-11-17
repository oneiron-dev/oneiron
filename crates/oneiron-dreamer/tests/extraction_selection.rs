//! Extraction grouping, union and selection over the shared fixture.
//!
//! The fixture holds one explicit selection policy, one clock and scalar
//! candidate rows. Helpers expand scalars into full observation mirrors
//! through the public `serde_json` shape, so production stays unchanged.

use oneiron_dreamer::extraction_observations::{CandidateObservation, Observations};
use oneiron_dreamer::extraction_selection::{
    CandidateGroup, CandidateGroups, Error, ExtractionSelectionConfig, SelectionHold,
    group_candidates, select, union_operands,
};
use serde_json::{Value, json};

const FIXTURE_JSON: &str = include_str!("fixtures/extraction_selection.json");
const ATTEMPT_HEX: &str = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";
const SCOPE_FACET: &str = "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0";
const SCOPE_PROJECT: &str = "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1";
const REPLAY_FACET: &str = "f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2";

fn load_fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("the fixture parses")
}

fn candidate_from_scalar(scalar: &Value, index: usize) -> CandidateObservation {
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
    serde_json::from_value(mirror).expect("the scalar expands to a mirror")
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

fn observations_for_case(
    candidates: &Value,
    policy_pin: &str,
    facts_pin: &str,
    now_ms: u64,
) -> Observations {
    let rows = candidates.as_array().expect("the case lists candidates");
    let mut mirrors = Vec::new();
    for (index, scalar) in rows.iter().enumerate() {
        mirrors.push(candidate_from_scalar(scalar, index));
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

fn expected_held(expected: &Value) -> Vec<(usize, SelectionHold)> {
    let rows = expected["held"].as_array().expect("the case expects held");
    let mut held = Vec::new();
    for row in rows {
        let pair = row.as_array().expect("a held pair");
        let index = pair[0].as_u64().expect("a held index") as usize;
        let kind = pair[1].as_str().expect("a held kind");
        let hold = match kind {
            "soak" => SelectionHold::Soak,
            "evidence_count" => SelectionHold::EvidenceCount,
            _ => panic!("unknown hold {kind}"),
        };
        held.push((index, hold));
    }
    held
}

fn check_selection_case(
    case: &Value,
    selection: &Value,
    policy_pin: &str,
    facts_pin: &str,
    now_ms: u64,
) {
    let name = case["name"].as_str().expect("the case is named");
    let config = ExtractionSelectionConfig::from_selection(selection.clone(), policy_pin)
        .expect("the case config decodes");
    let candidates = &case["candidates"];
    let count = candidates
        .as_array()
        .expect("the case lists candidates")
        .len();
    let groups = singleton_groups(count);
    let observations = observations_for_case(candidates, policy_pin, facts_pin, now_ms);
    let plan = select(&groups, &observations, now_ms, &config).expect("the case selects");
    let expected = &case["expected"];
    let ready: Vec<usize> =
        serde_json::from_value(expected["ready"].clone()).expect("ready decodes");
    let held = expected_held(expected);
    let retry = expected["retry_at_ms"].as_u64().expect("retry decodes");
    assert_eq!(plan.ready, ready, "ready for {name}");
    assert_eq!(plan.held, held, "held for {name}");
    assert_eq!(plan.retry_at_ms, retry, "retry for {name}");
    assert_eq!(plan.groups.len(), count, "one score per group for {name}");
    assert!(plan.pending_bindings.is_empty(), "no pending for {name}");
    assert_eq!(plan.policy_pin, policy_pin, "policy pin for {name}");
    assert_eq!(plan.facts_pin, facts_pin, "facts pin for {name}");
    for scored in &plan.groups {
        assert!(scored.score.is_finite(), "finite score for {name}");
    }
}

#[test]
fn selection_cases_match_fixture_ready_held_and_retry() {
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
    assert_eq!(cases.len(), 5, "five selection cases");
    for case in cases {
        check_selection_case(case, &selection, policy_pin, facts_pin, now_ms);
    }
}

fn grouping_rows(grouping: &Value) -> Vec<Option<CandidateObservation>> {
    let rows = grouping["observations"]
        .as_array()
        .expect("grouping lists rows");
    let mut out = Vec::new();
    for (position, entry) in rows.iter().enumerate() {
        if entry.is_null() {
            out.push(None);
        } else {
            out.push(Some(candidate_from_scalar(entry, position)));
        }
    }
    out
}

#[test]
fn grouping_merges_equal_tokens_and_keeps_pending() {
    let fixture = load_fixture();
    let grouping = &fixture["grouping"];
    let rows = grouping_rows(grouping);
    let groups = group_candidates(&rows);
    let expected: Vec<CandidateGroup> =
        serde_json::from_value(grouping["expected_groups"].clone()).expect("groups decode");
    let pending: Vec<usize> =
        serde_json::from_value(grouping["expected_pending"].clone()).expect("pending decodes");
    assert_eq!(
        groups.groups, expected,
        "equal native keys merge whatever the members correct"
    );
    assert_eq!(
        groups.pending_bindings, pending,
        "the None row stays pending"
    );
    assert_eq!(
        groups.groups[0].member_indexes,
        vec![0, 1, 3],
        "slice and corrects differ yet merge"
    );
    assert_eq!(
        groups.groups[0].corrects, None,
        "members that disagree on the corrected claim drop the correction"
    );
}

#[test]
fn group_keeps_a_correction_only_when_every_member_names_it() {
    let fixture = load_fixture();
    let grouping = &fixture["grouping"];
    let scalars = grouping["observations"]
        .as_array()
        .expect("grouping lists rows");
    let operands: Vec<Value> =
        serde_json::from_value(grouping["operands"].clone()).expect("operands decode");
    let corrected = operands[3]["corrects"].as_str().expect("row 3 corrects");
    let same = group_candidates(&[
        Some(candidate_from_scalar(&scalars[3], 0)),
        Some(candidate_from_scalar(&scalars[3], 1)),
    ]);
    assert_eq!(same.groups.len(), 1, "equal keys fold");
    assert_eq!(same.groups[0].corrects.as_deref(), Some(corrected));
    let mixed = group_candidates(&[
        Some(candidate_from_scalar(&scalars[3], 0)),
        Some(candidate_from_scalar(&scalars[0], 1)),
    ]);
    assert_eq!(
        mixed.groups.len(),
        1,
        "a correction does not split the fold"
    );
    assert_eq!(mixed.groups[0].member_indexes, vec![0, 1]);
    assert_eq!(mixed.groups[0].corrects, None, "the correction is dropped");
    let unions = union_operands(&[operands[3].clone(), operands[0].clone()], &mixed);
    assert_eq!(
        unions[0]["corrects"], operands[3]["corrects"],
        "the union keeps the representative's own identity"
    );
}

#[test]
fn union_dedupes_evidence_and_keeps_representative_shape() {
    let fixture = load_fixture();
    let grouping = &fixture["grouping"];
    let operands: Vec<Value> =
        serde_json::from_value(grouping["operands"].clone()).expect("operands decode");
    let rows = grouping_rows(grouping);
    let groups = group_candidates(&rows);
    let unions = union_operands(&operands, &groups);
    let expected: Vec<Vec<Value>> =
        serde_json::from_value(grouping["expected_union"].clone()).expect("union decodes");
    assert_eq!(unions.len(), expected.len(), "one union per bound group");
    assert_eq!(unions[0]["corrects"], operands[0]["corrects"]);
    for (union, wanted) in unions.iter().zip(expected.iter()) {
        let evidence = union["evidence"]
            .as_array()
            .expect("union carries evidence");
        assert_eq!(evidence, wanted, "exact JSON union in member order");
    }
    assert_eq!(
        unions[0]["rel"], operands[0]["rel"],
        "representative rel kept"
    );
    assert_eq!(
        unions[0]["topic"], operands[0]["topic"],
        "representative topic kept"
    );
    assert_eq!(
        unions[1]["evidence"]
            .as_array()
            .expect("second union")
            .len(),
        1
    );
}

#[test]
fn required_policy_fields_and_policy_pin_are_enforced() {
    let fixture = load_fixture();
    let pin = fixture["policy_pin"]
        .as_str()
        .expect("the fixture pins policy");
    let facts = fixture["facts_pin"]
        .as_str()
        .expect("the fixture pins facts");
    let now_ms = fixture["now_ms"].as_u64().expect("the fixture carries now");
    let selection = fixture["selection"].clone();
    let config = ExtractionSelectionConfig::from_selection(selection.clone(), pin)
        .expect("the config binds its outer pin");
    let mut missing = selection;
    missing
        .as_object_mut()
        .expect("the selection is an object")
        .remove("frequency_scale");
    assert!(ExtractionSelectionConfig::from_selection(missing, pin).is_err());
    let rows = &fixture["selection_cases"][2]["candidates"];
    let mut observations = observations_for_case(rows, pin, facts, now_ms);
    observations.policy_pin = "cc".repeat(32);
    let count = observations.candidates.len();
    assert!(matches!(
        select(&singleton_groups(count), &observations, now_ms, &config),
        Err(Error::PolicyPin { .. })
    ));
}
