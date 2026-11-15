//! Pure policy checks for conflict items and merged-value requests.
//!
//! Hand-built sets as `extraction_decisions.rs` builds its own; no vault.
//! The step is a value passed to `set_plan`.

use oneiron_dreamer::conflict_decisions::{ConflictDecision, PinnedClaim, Resolution};
use oneiron_dreamer::conflict_resolution::{
    MemberFacts, OpenCause, Plan, ResolvedOutcome, SetPlan, member_facts, set_plan, step_request,
};
use oneiron_dreamer::extraction_decisions::{Outcome, SetOperands, SetOutcome, SkipRule};
use oneiron_dreamer::extraction_observations::SourceVersion;
use oneiron_dreamer::extraction_reply::{
    BoundExtractionCandidate, BoundExtractionReply, BoundExtractionSubject,
};
use oneiron_dreamer::extraction_routing::ExtractionRoutePlan;
use oneiron_dreamer::extraction_selection::{ExtractionSelectionPlan, ScoredCandidateGroup};
use serde_json::{Value, json};

/// Holds Owen's listed subject id, as 32 lowercase hex digits.
const OWEN_HEX: &str = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";
/// Holds the cited turn id, as 32 lowercase hex digits.
const TURN_HEX: &str = "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";
/// Holds one prior head, as 32 lowercase hex digits.
const HEAD_HEX: &str = "d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3";
/// Holds another prior head, as 32 lowercase hex digits.
const OTHER_HEAD_HEX: &str = "e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4";

/// Returns one union operand over Owen citing the turn.
fn operand(value: &str) -> Value {
    json!({
        "subject": OWEN_HEX,
        "predicate": "likes",
        "value": value,
        "evidence": [{"turn": TURN_HEX}],
    })
}

/// Returns one pinned head with a dummy served version.
fn pin(head: &str) -> PinnedClaim {
    PinnedClaim {
        claim: head.to_owned(),
        version: SourceVersion {
            entity: head.to_owned(),
            entity_type: 4,
            learned_at: 0,
            revision: "blake3:0000000000000000000000000000000000000000000000000000000000000000"
                .to_owned(),
            projection: None,
        },
    }
}

/// Builds one operand set from its parts.
fn operands(
    candidates: Vec<Value>,
    priors: Vec<PinnedClaim>,
    set_members: Vec<usize>,
    representatives: Vec<usize>,
    spans: bool,
) -> SetOperands {
    SetOperands {
        candidates,
        priors,
        set_members,
        representatives,
        spans_predicates: spans,
    }
}

/// Builds one skipped outcome.
fn skipped(head: &str, rule: SkipRule) -> SetOutcome {
    SetOutcome::Skipped {
        prior_head: head.to_owned(),
        rule,
    }
}

/// Builds one decided outcome with no decision entries.
fn decided(resolution: Resolution, identity: Option<usize>) -> SetOutcome {
    SetOutcome::Decided(ConflictDecision {
        resolution,
        identity,
        decisions: Vec::new(),
    })
}

/// Builds one member's facts.
fn facts(confidence: f64, hints: &[&str]) -> MemberFacts {
    MemberFacts {
        confidence,
        prospective_queries: hints.iter().copied().map(str::to_owned).collect(),
    }
}

/// Returns one reply candidate with its confidence and hints.
fn reply_candidate(index: usize, confidence: f64, hints: &[&str]) -> BoundExtractionCandidate {
    BoundExtractionCandidate {
        index,
        subject: BoundExtractionSubject::Listed(OWEN_HEX.to_owned()),
        predicate: "likes".to_owned(),
        value: Value::String("tea".to_owned()),
        confidence,
        prospective_queries: hints.iter().copied().map(str::to_owned).collect(),
        rel: None,
        topic_key: None,
        evidence: Vec::new(),
    }
}

/// A skipped set plans a skip item with no kept, no value and no request.
#[test]
fn skipped_sets_plan_skip_items() {
    for rule in [SkipRule::FastPath, SkipRule::BoundCorrection] {
        let candidate = operand("tea");
        let priors = vec![pin(HEAD_HEX)];
        let set = operands(
            vec![candidate.clone()],
            priors.clone(),
            vec![0],
            vec![0],
            false,
        );
        let outcome = skipped(HEAD_HEX, rule);
        assert_eq!(step_request(&set, &outcome, 0).expect("no request"), None);
        let found = [facts(0.9, &["owen tea"])];
        let plan = set_plan(&set, &outcome, &found, None, 0).expect("skip plans");
        let SetPlan::Resolved { outcome, item } = &plan else {
            panic!("a skipped set resolves");
        };
        assert_eq!(*outcome, ResolvedOutcome::Skip);
        let heads = serde_json::to_value(&priors).expect("heads encode");
        assert_eq!(
            *item,
            json!({
                "kind": "conflict_resolution",
                "spec": {
                    "local": "conflict-set-0",
                    "members": [{
                        "candidate": candidate,
                        "confidence": 0.9,
                        "prospective_queries": ["owen tea"],
                    }],
                    "heads": heads,
                    "set_members": [0],
                    "outcome": "skip",
                },
            })
        );
        assert!(item["spec"].get("kept").is_none());
        assert!(item["spec"].get("value").is_none());
    }
}

/// A merge with a kept member asks once and lands the kept value unchanged.
#[test]
fn merge_with_kept_member_asks_once_and_lands_unchanged() {
    let green = operand("green tea");
    let black = operand("black coffee");
    let priors = vec![pin(HEAD_HEX)];
    let set = operands(
        vec![green.clone(), black.clone()],
        priors.clone(),
        vec![0, 1],
        vec![3, 7],
        false,
    );
    let outcome = decided(Resolution::Merge, Some(7));
    let request = step_request(&set, &outcome, 0)
        .expect("request builds")
        .expect("a kept merge asks");
    let heads = serde_json::to_value(&priors).expect("heads encode");
    assert_eq!(
        request,
        json!({
            "resolution": "merge",
            "kept": 1,
            "candidates": [green.clone(), black.clone()],
            "priors": heads.clone(),
            "set_members": [0, 1],
        })
    );
    let value = json!({"blend": ["green tea", "black coffee"], "ratio": 2});
    let found = [facts(0.9, &[]), facts(0.7, &["yuki tea"])];
    let plan = set_plan(&set, &outcome, &found, Some(&value), 0).expect("merge plans");
    let SetPlan::Resolved { outcome, item } = &plan else {
        panic!("a valued merge resolves");
    };
    assert_eq!(*outcome, ResolvedOutcome::Merge);
    assert_eq!(
        *item,
        json!({
            "kind": "conflict_resolution",
            "spec": {
                "local": "conflict-set-0",
                "members": [
                    {"candidate": green, "confidence": 0.9, "prospective_queries": []},
                    {"candidate": black, "confidence": 0.7, "prospective_queries": ["yuki tea"]},
                ],
                "heads": heads,
                "set_members": [0, 1],
                "outcome": "merge",
                "kept": 1,
                "value": value,
            },
        })
    );
}

/// A supersede asks as supersede and lands as a merge.
#[test]
fn supersede_asks_supersede_and_lands_merge() {
    let candidate = operand("black coffee");
    let priors = vec![pin(HEAD_HEX)];
    let set = operands(vec![candidate], priors, vec![0], vec![2], false);
    let outcome = decided(Resolution::Supersede, Some(2));
    let request = step_request(&set, &outcome, 0)
        .expect("request builds")
        .expect("a supersede asks");
    assert_eq!(request["resolution"], json!("supersede"));
    assert_eq!(request["kept"], json!(0));
    let value = json!("black coffee");
    let found = [facts(0.9, &[])];
    let plan = set_plan(&set, &outcome, &found, Some(&value), 0).expect("supersede plans");
    let SetPlan::Resolved { outcome, item } = &plan else {
        panic!("a valued supersede resolves");
    };
    assert_eq!(*outcome, ResolvedOutcome::Merge);
    assert_eq!(item["spec"]["outcome"], json!("merge"));
    assert_eq!(item["spec"]["kept"], json!(0));
    assert_eq!(item["spec"]["value"], value);
}

/// A null merged value opens a marker for no value.
#[test]
fn null_value_opens_no_merged_value() {
    let set = operands(
        vec![operand("green tea"), operand("black coffee")],
        Vec::new(),
        vec![0, 1],
        vec![0, 1],
        false,
    );
    let outcome = decided(Resolution::Merge, Some(0));
    assert!(
        step_request(&set, &outcome, 0)
            .expect("request builds")
            .is_some()
    );
    let found = [facts(0.9, &[]), facts(0.7, &[])];
    let plan = set_plan(&set, &outcome, &found, None, 1).expect("null plans");
    let SetPlan::Opened { cause, item } = &plan else {
        panic!("a null value opens");
    };
    assert_eq!(*cause, OpenCause::NoMergedValue);
    assert_eq!(item["kind"], json!("conflict"));
    assert_eq!(item["spec"]["local"], json!("conflict-set-1"));
    assert_eq!(
        item["spec"]["members"].as_array().expect("members").len(),
        2
    );
}

/// A merge naming none across predicates opens without asking; inside one it asks and merges.
#[test]
fn unnamed_merge_spans_or_asks() {
    let green = operand("green tea");
    let black = operand("black coffee");
    let across = operands(
        vec![green.clone(), black.clone()],
        Vec::new(),
        vec![0, 1],
        vec![0, 1],
        true,
    );
    let outcome = decided(Resolution::Merge, None);
    assert_eq!(
        step_request(&across, &outcome, 0).expect("no request"),
        None
    );
    let found = [facts(0.9, &[]), facts(0.7, &[])];
    let plan = set_plan(&across, &outcome, &found, None, 0).expect("across plans");
    let SetPlan::Opened { cause, item } = &plan else {
        panic!("an across merge opens");
    };
    assert_eq!(*cause, OpenCause::CrossPredicateMergeUnnamed);
    assert_eq!(item["kind"], json!("conflict"));

    let single = operands(
        vec![green, black],
        Vec::new(),
        vec![0, 1],
        vec![0, 1],
        false,
    );
    let request = step_request(&single, &outcome, 0)
        .expect("request builds")
        .expect("a single-predicate merge asks");
    assert!(request.get("kept").is_none());
    assert_eq!(request["resolution"], json!("merge"));
    let value = json!("house blend");
    let plan = set_plan(&single, &outcome, &found, Some(&value), 0).expect("single plans");
    let SetPlan::Resolved { outcome, item } = &plan else {
        panic!("a valued single merge resolves");
    };
    assert_eq!(*outcome, ResolvedOutcome::Merge);
    assert!(item["spec"].get("kept").is_none());
    assert_eq!(item["spec"]["value"], value);
}

/// An accumulate plans its item and asks no step.
#[test]
fn accumulate_plans_without_a_step() {
    let green = operand("green tea");
    let black = operand("black coffee");
    let priors = vec![pin(HEAD_HEX), pin(OTHER_HEAD_HEX)];
    let set = operands(
        vec![green.clone(), black.clone()],
        priors.clone(),
        vec![0, 1],
        vec![0, 1],
        false,
    );
    let outcome = decided(Resolution::Accumulate, None);
    assert_eq!(step_request(&set, &outcome, 0).expect("no request"), None);
    let found = [facts(0.9, &["owen tea"]), facts(0.7, &[])];
    let plan = set_plan(&set, &outcome, &found, None, 2).expect("accumulate plans");
    let SetPlan::Resolved { outcome, item } = &plan else {
        panic!("an accumulate resolves");
    };
    assert_eq!(*outcome, ResolvedOutcome::Accumulate);
    let heads = serde_json::to_value(&priors).expect("heads encode");
    assert_eq!(
        *item,
        json!({
            "kind": "conflict_resolution",
            "spec": {
                "local": "conflict-set-2",
                "members": [
                    {"candidate": green, "confidence": 0.9, "prospective_queries": ["owen tea"]},
                    {"candidate": black, "confidence": 0.7, "prospective_queries": []},
                ],
                "heads": heads,
                "set_members": [0, 1],
                "outcome": "accumulate",
            },
        })
    );
}

/// Escalations and missing answers open with their causes.
#[test]
fn escalations_open_with_their_causes() {
    for (resolution, cause) in [
        (Resolution::Escalate, OpenCause::Escalated),
        (Resolution::NoStandingAnswer, OpenCause::NoStandingAnswer),
    ] {
        let candidate = operand("tea");
        let set = operands(vec![candidate.clone()], Vec::new(), vec![0], vec![0], false);
        let outcome = decided(resolution, None);
        assert_eq!(step_request(&set, &outcome, 0).expect("no request"), None);
        let found = [facts(0.9, &[])];
        let plan = set_plan(&set, &outcome, &found, None, 0).expect("escalation plans");
        let SetPlan::Opened { cause: found, item } = &plan else {
            panic!("an escalation opens");
        };
        assert_eq!(*found, cause);
        assert_eq!(item["kind"], json!("conflict"));
        assert_eq!(
            item["spec"]["members"],
            json!([{"candidate": candidate, "confidence": 0.9, "prospective_queries": []}]),
        );
    }
}

/// A kept operand outside the set is an error that asks no step.
#[test]
fn kept_outside_the_set_is_an_error() {
    let green = operand("green tea");
    let black = operand("black coffee");
    let set = operands(
        vec![green.clone(), black.clone()],
        Vec::new(),
        vec![0, 1],
        vec![0, 1],
        false,
    );
    let outside = decided(Resolution::Merge, Some(5));
    assert!(step_request(&set, &outside, 0).is_err());
    let found = [facts(0.9, &[]), facts(0.7, &[])];
    assert!(set_plan(&set, &outside, &found, Some(&json!("x")), 0).is_err());

    let third = operand("oolong");
    let subset = operands(
        vec![green, black, third],
        Vec::new(),
        vec![0, 1],
        vec![10, 11, 12],
        false,
    );
    let unlisted = decided(Resolution::Merge, Some(12));
    assert!(step_request(&subset, &unlisted, 0).is_err());
    let three = [facts(0.9, &[]), facts(0.7, &[]), facts(0.5, &[])];
    assert!(set_plan(&subset, &unlisted, &three, Some(&json!("x")), 0).is_err());
}

/// Builds one selection group from its representative and members.
fn scored_group(representative: usize, members: &[usize]) -> ScoredCandidateGroup {
    ScoredCandidateGroup {
        representative_index: representative,
        member_indexes: members.to_vec(),
        corrects: None,
        score: 0.5,
    }
}

/// Builds one outcome shell holding the reply mapping, groups and operand sets.
fn outcome_shell(
    candidate_indexes: Vec<usize>,
    groups: Vec<ScoredCandidateGroup>,
    sets: Vec<SetOperands>,
) -> Outcome {
    Outcome {
        operands: Vec::new(),
        candidate_indexes,
        corrections: Vec::new(),
        selection: ExtractionSelectionPlan {
            ready: Vec::new(),
            held: Vec::new(),
            groups,
            pending_bindings: Vec::new(),
            retry_at_ms: 1,
            policy_pin: "policy".to_owned(),
            facts_pin: "facts".to_owned(),
        },
        route: ExtractionRoutePlan {
            routes: Vec::new(),
            judge_sets: Vec::new(),
            corrections: Vec::new(),
            policy_pin: "policy".to_owned(),
            facts_pin: "facts".to_owned(),
        },
        sets: Vec::new(),
        set_operands: sets,
    }
}

/// Two sets keep order, members and G2 facts.
#[test]
fn two_sets_keep_order_members_and_g2_facts() {
    let reply = BoundExtractionReply {
        candidates: vec![
            reply_candidate(0, 0.9, &["  owen tea  ", "owen tea", "", "coffee"]),
            reply_candidate(1, 0.7, &["yuki tea"]),
            reply_candidate(2, 0.5, &[]),
            reply_candidate(3, 0.8, &["owen coffee"]),
            reply_candidate(4, 0.1, &["coffee", "  tea  "]),
        ],
        persons: Vec::new(),
        skipped: Vec::new(),
    };
    let first = operands(
        vec![operand("a"), operand("b"), operand("c")],
        Vec::new(),
        vec![0, 2],
        vec![0, 1, 2],
        false,
    );
    let second = operands(vec![operand("d")], Vec::new(), vec![0], vec![3], false);
    let outcome = outcome_shell(
        vec![0, 1, 2, 3, 4],
        vec![
            scored_group(0, &[0, 4]),
            scored_group(1, &[1]),
            scored_group(2, &[2]),
            scored_group(3, &[3]),
        ],
        vec![first.clone(), second.clone()],
    );
    let facts = member_facts(&reply, &outcome, 0).expect("facts build");
    assert_eq!(facts.len(), 3);
    assert_eq!(facts[0].confidence, 0.9);
    assert_eq!(
        facts[0].prospective_queries,
        vec!["owen tea".to_owned(), "coffee".to_owned(), "tea".to_owned()],
    );
    assert_eq!(facts[1].prospective_queries, vec!["yuki tea".to_owned()]);
    assert!(facts[2].prospective_queries.is_empty());

    let decided_first = decided(Resolution::Accumulate, None);
    let decided_second = decided(Resolution::Escalate, None);
    let second_facts = member_facts(&reply, &outcome, 1).expect("second facts build");
    let first_plan = set_plan(&first, &decided_first, &facts, None, 0).expect("first plans");
    let second_plan =
        set_plan(&second, &decided_second, &second_facts, None, 1).expect("second plans");
    assert_eq!(first_plan.item()["spec"]["local"], json!("conflict-set-0"));
    assert_eq!(second_plan.item()["spec"]["local"], json!("conflict-set-1"));
    assert_eq!(
        first_plan.item()["spec"]["members"]
            .as_array()
            .expect("members")
            .len(),
        3
    );
    assert_eq!(first_plan.item()["spec"]["set_members"], json!([0, 2]));
    let plan = Plan {
        sets: vec![first_plan.clone(), second_plan.clone()],
    };
    assert_eq!(
        plan.items(),
        vec![first_plan.item().clone(), second_plan.item().clone()]
    );
}
