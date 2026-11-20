//! A metric axis's tolerance (census L9-07; RESEARCH-0651's acceptance
//! rule, item 5; Engine ruling 2026-11-13 22:39 = A). Without one, every
//! change counts: latency jitter of 0.4 ms beside a better primary metric
//! escalates the comparison, and a floor 0.0005 lower rejects it. A change
//! no larger than its axis's tolerance is now a tie on that axis; a config
//! that names no tolerance decides, and serializes, exactly as before.
//!
//! Every config is built from JSON, as a campaign row arrives.
//!
//! Run with: `cargo test --locked -p oneiron --all-features --test metric_axis_tolerance`.

use oneiron::autoreason_campaign::general::{CampaignConfig, Measurement, Verdict};
use serde_json::{Value, json};

const SET_ID: &str = "retrieval-scorecard";
const SET_REVISION: &str = "r1";
const HELD_OUT_REVISION: &str = "held-out-1";

/// A dominance campaign over a primary quality axis, a latency cost and an
/// abstention floor, with the given `tolerance` per axis (`None` names none).
fn config(tolerances: [Option<f64>; 3]) -> CampaignConfig {
    let axes: Vec<Value> = [
        ("ndcg", "higher", "primary"),
        ("p95_ms", "lower", "cost"),
        ("abstain_f1", "higher", "floor"),
    ]
    .into_iter()
    .zip(tolerances)
    .map(|((name, direction, role), tolerance)| {
        let mut axis = json!({ "name": name, "direction": direction, "role": role });
        if let Some(tolerance) = tolerance {
            axis["tolerance"] = json!(tolerance);
        }
        axis
    })
    .collect();
    serde_json::from_value(json!({
        "campaign_id": "metric-axis-tolerance",
        "search_axes": [{ "name": "fanout", "values": ["4", "8"] }],
        "metric_set": { "set_id": SET_ID, "revision": SET_REVISION, "axes": axes },
        "splits": {
            "search": { "dataset_id": "retrieval-pack", "revision": "search-1" },
            "held_out": { "dataset_id": "retrieval-pack", "revision": HELD_OUT_REVISION },
            "sealed": { "dataset_id": "retrieval-pack", "revision": "sealed-1" },
        },
        "budget": { "budget_id": "lease-1", "max_units": 10, "exploration_units": 2 },
        "decide": { "kind": "dominance" },
    }))
    .expect("the campaign config parses")
}

/// The tolerances the tests rule with: none on the primary, 1 ms on the
/// latency cost, 0.001 on the floor.
const TOLERANT: [Option<f64>; 3] = [Some(0.0), Some(1.0), Some(0.001)];
/// No axis names a tolerance.
const UNNAMED: [Option<f64>; 3] = [None, None, None];

/// One arm's held-out scores: (ndcg, p95_ms, abstain_f1).
fn measured(ndcg: f64, p95_ms: f64, abstain_f1: f64) -> Measurement {
    serde_json::from_value(json!({
        "dataset": { "dataset_id": "retrieval-pack", "revision": HELD_OUT_REVISION },
        "metric_set_id": SET_ID,
        "metric_set_revision": SET_REVISION,
        "scores": { "ndcg": ndcg, "p95_ms": p95_ms, "abstain_f1": abstain_f1 },
    }))
    .expect("the measurement parses")
}

fn verdict(config: &CampaignConfig, incumbent: &Measurement, candidate: &Measurement) -> Verdict {
    config
        .decide_held_out(incumbent, candidate)
        .expect("the held-out comparison decides")
        .verdict()
}

#[test]
fn a_cost_axis_within_its_tolerance_does_not_turn_a_win_into_a_tradeoff() {
    let config = config(TOLERANT);
    config.validate().expect("the config validates");
    // Better on the primary, 0.4 ms slower, the floor unchanged.
    let incumbent = measured(0.50, 100.0, 0.90);
    let candidate = measured(0.55, 100.4, 0.90);
    assert_eq!(verdict(&config, &incumbent, &candidate), Verdict::Promote);
}

#[test]
fn a_floor_drop_within_its_tolerance_does_not_reject() {
    let config = config(TOLERANT);
    // Better on the primary, the floor 0.0005 lower.
    let incumbent = measured(0.50, 100.0, 0.9000);
    let candidate = measured(0.55, 100.0, 0.8995);
    assert_eq!(verdict(&config, &incumbent, &candidate), Verdict::Promote);
}

#[test]
fn a_change_past_its_tolerance_still_counts_and_a_negative_tolerance_is_refused() {
    let config = config(TOLERANT);
    let incumbent = measured(0.50, 100.0, 0.90);
    // 2 ms slower against 1 ms of tolerance: a tradeoff.
    assert_eq!(
        verdict(&config, &incumbent, &measured(0.55, 102.0, 0.90)),
        Verdict::EscalateTradeoff
    );
    // The floor 0.01 lower against 0.001: rejected, even with a better primary.
    assert_eq!(
        verdict(&config, &incumbent, &measured(0.55, 100.0, 0.89)),
        Verdict::Reject
    );
    // A primary gain within its own tolerance is no gain: a tie rejects.
    let primary_tolerant = self::config([Some(0.1), Some(1.0), Some(0.001)]);
    assert_eq!(
        verdict(&primary_tolerant, &incumbent, &measured(0.55, 100.0, 0.90)),
        Verdict::Reject
    );
    // A tolerance must be finite and non-negative.
    let negative = self::config([Some(0.0), Some(-1.0), Some(0.001)]);
    assert!(negative.validate().is_err());
    assert!(negative.decide_held_out(&incumbent, &incumbent).is_err());
}

/// The control, green before and after: a config that names no tolerance
/// counts every change, and serializes with no tolerance field.
#[test]
fn a_config_that_names_no_tolerance_decides_and_serializes_as_before() {
    let config = config(UNNAMED);
    config.validate().expect("the config validates");
    let incumbent = measured(0.50, 100.0, 0.9000);
    assert_eq!(
        verdict(&config, &incumbent, &measured(0.55, 100.4, 0.9000)),
        Verdict::EscalateTradeoff
    );
    assert_eq!(
        verdict(&config, &incumbent, &measured(0.55, 100.0, 0.8995)),
        Verdict::Reject
    );
    assert_eq!(
        verdict(&config, &incumbent, &measured(0.55, 100.0, 0.9000)),
        Verdict::Promote
    );
    assert_eq!(
        verdict(&config, &incumbent, &incumbent),
        Verdict::Reject,
        "a tie rejects"
    );
    let serialized = serde_json::to_value(&config).expect("the config serializes");
    for axis in serialized["metric_set"]["axes"]
        .as_array()
        .expect("axes is a list")
    {
        assert!(axis.get("tolerance").is_none(), "{axis}");
    }
}
