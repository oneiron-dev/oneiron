//! Pure checks for the extraction job through its public helpers.
//!
//! Covers step windows, slice layouts, reply joining, person binding,
//! person batches, component building and the failed-set marker rule. No
//! client calls. Inline JSON fixtures follow the style of the other dreamer
//! tests.

use oneiron_dreamer::conflict_decisions::{ConflictDecision, Resolution};
use oneiron_dreamer::conflict_resolution::{
    self, Error as PlanError, Plan, ResolvedOutcome, SetPlan,
};
use oneiron_dreamer::extraction::Error as JobError;
use oneiron_dreamer::extraction::components;
use oneiron_dreamer::extraction::inputs::Turn;
use oneiron_dreamer::extraction::join::{self, PersonKey};
use oneiron_dreamer::extraction::persons;
use oneiron_dreamer::extraction::steps::{self, ExtractionStepLayout, ExtractionStepSlice};
use oneiron_dreamer::extraction::{ItemResult, PersonResult};
use oneiron_dreamer::extraction_decisions::{Outcome, SetOperands, SetOutcome};
use oneiron_dreamer::extraction_reply::BoundExtractionReply;
use oneiron_dreamer::extraction_reply::BoundExtractionSubject;
use oneiron_dreamer::extraction_routing::{
    AlreadyRepresentedReason, CandidateRoute, ExtractionRoutePlan, JudgeSet, Route,
};
use oneiron_dreamer::extraction_selection::{ExtractionSelectionPlan, ScoredCandidateGroup};
use serde_json::{Value, json};

/// Holds Owen's listed subject id, as 32 lowercase hex digits.
const OWEN_HEX: &str = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";
/// Holds Yuki's listed subject id, as 32 lowercase hex digits.
const YUKI_HEX: &str = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
/// Holds Owen's minted person row id, as 32 lowercase hex digits.
const PERSON_OWEN_HEX: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
/// Holds the first served turn, as 32 lowercase hex digits.
const TURN_A: &str = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
/// Holds the second served turn, as 32 lowercase hex digits.
const TURN_B: &str = "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";
/// Holds the third served turn, as 32 lowercase hex digits.
const TURN_C: &str = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
/// Holds the fourth served turn, as 32 lowercase hex digits.
const TURN_D: &str = "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";
/// Holds the fifth served turn, as 32 lowercase hex digits.
const TURN_E: &str = "c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5";
/// Holds one prior head, as 32 lowercase hex digits.
const HEAD_HEX: &str = "d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3";
/// Holds another prior head, as 32 lowercase hex digits.
const OTHER_HEAD_HEX: &str = "e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4";
/// Holds a dummy turn revision, as `blake3` plus 64 zeros.
const REVISION: &str = "blake3:0000000000000000000000000000000000000000000000000000000000000000";

/// Decodes one bound reply from its inline JSON fixture.
fn decode_reply(value: Value) -> BoundExtractionReply {
    serde_json::from_value(value).expect("the reply fixture decodes")
}

/// Builds one served turn with its exact served version.
fn served_turn(turn: &str, version: Value) -> Turn {
    Turn {
        turn: turn.to_owned(),
        version,
    }
}

/// Builds one layout row from its positions and page count.
fn layout_row(evidence: Vec<usize>, pages: usize) -> ExtractionStepSlice {
    ExtractionStepSlice { evidence, pages }
}

/// Asserts one layout refusal is a step decode error without reading its prose.
fn assert_layout_error(result: Result<Vec<Value>, JobError>) {
    match result {
        Err(JobError::Decode { verb, .. }) => {
            assert_eq!(verb, "ai.steps.submit");
        }
        other => panic!("expected layout decode refusal, got {other:?}"),
    }
}

/// Builds one scored selection group with no correction.
fn scored_group(representative: usize, members: &[usize]) -> ScoredCandidateGroup {
    ScoredCandidateGroup {
        representative_index: representative,
        member_indexes: members.to_vec(),
        corrects: None,
        score: 0.5,
    }
}

/// Builds one selection shell holding the given groups.
fn selection_shell(groups: Vec<ScoredCandidateGroup>) -> ExtractionSelectionPlan {
    ExtractionSelectionPlan {
        ready: groups
            .iter()
            .map(|group| group.representative_index)
            .collect(),
        held: Vec::new(),
        groups,
        pending_bindings: Vec::new(),
        retry_at_ms: 1,
        policy_pin: "policy".to_owned(),
        facts_pin: "facts".to_owned(),
    }
}

/// Builds one route shell holding the given routes and sets.
fn route_shell(routes: Vec<CandidateRoute>, judge_sets: Vec<JudgeSet>) -> ExtractionRoutePlan {
    ExtractionRoutePlan {
        routes,
        judge_sets,
        corrections: Vec::new(),
        policy_pin: "policy".to_owned(),
        facts_pin: "facts".to_owned(),
    }
}

/// Builds one route for its representative with no dropped heads.
fn candidate_route(representative: usize, members: Vec<usize>, choice: Route) -> CandidateRoute {
    CandidateRoute {
        representative_index: representative,
        member_indexes: members,
        dropped_stated_heads: Vec::new(),
        dropped_correction: None,
        choice,
    }
}

/// Builds one outcome shell as the conflict tests do, with operands and plans.
fn outcome_shell(
    operands: Vec<Value>,
    candidate_indexes: Vec<usize>,
    selection: ExtractionSelectionPlan,
    route: ExtractionRoutePlan,
) -> Outcome {
    Outcome {
        operands,
        candidate_indexes,
        corrections: Vec::new(),
        selection,
        route,
        sets: Vec::new(),
        set_operands: Vec::new(),
    }
}

/// Builds one person view with its landed rows and reason tokens.
fn person_view(local: &str, landed: bool, rows: Vec<String>, reasons: Vec<String>) -> ItemResult {
    ItemResult {
        local: local.to_owned(),
        kind: "person".to_owned(),
        landed,
        rows,
        approval: None,
        reasons,
        batch: "batch-0".to_owned(),
    }
}

/// Step windows at 16 cover 0, 1, 16, 17 and 40 with every position once.
#[test]
fn step_windows_cover_every_position_once() {
    assert!(steps::step_windows(0, 16).is_empty());
    let one_turn = steps::step_windows(1, 16);
    assert_eq!(one_turn.len(), 1);
    assert_eq!(one_turn[0], 0..1);
    let full_window = steps::step_windows(16, 16);
    assert_eq!(full_window.len(), 1);
    assert_eq!(full_window[0], 0..16);
    assert_eq!(steps::step_windows(17, 16), vec![0..16, 16..17]);
    assert_eq!(steps::step_windows(40, 16), vec![0..16, 16..32, 32..40]);
    for count in [0, 1, 16, 17, 40] {
        let windows = steps::step_windows(count, 16);
        let mut seen = vec![false; count];
        for window in &windows {
            for position in window.clone() {
                assert!(position < count, "position {position} is inside {count}");
                assert!(
                    !seen[position],
                    "position {position} appears once for {count}"
                );
                seen[position] = true;
            }
        }
        assert!(
            seen.iter().all(|seen| *seen),
            "every position appears for {count}"
        );
        for (at, window) in windows.iter().enumerate() {
            if at == 0 {
                assert_eq!(window.start, 0, "first window starts at zero");
            } else {
                assert_eq!(
                    window.start,
                    windows[at - 1].end,
                    "windows stay consecutive"
                );
            }
        }
        if count == 0 {
            assert!(windows.is_empty());
        } else {
            assert_eq!(windows.last().expect("a window").end, count);
        }
    }
}

/// Two layout rows over five entries build exact requests with pages 1 and 2.
#[test]
fn layout_requests_follow_rows_then_pages() {
    let window = [
        served_turn(TURN_A, json!({"rev": "a"})),
        served_turn(TURN_B, json!({"rev": "b"})),
        served_turn(TURN_C, json!({"rev": "c"})),
        served_turn(TURN_D, json!({"rev": "d"})),
        served_turn(TURN_E, json!({"rev": "e"})),
    ];
    let layout = ExtractionStepLayout::StepSlices {
        slices: vec![layout_row(vec![0, 1, 2], 1), layout_row(vec![3, 4], 2)],
    };
    let requests = steps::layout_requests(&window, &layout).expect("the layout builds");
    assert_eq!(requests.len(), 3);
    assert!(requests[0].get("page").is_none());
    assert_eq!(
        requests[0],
        json!({
            "evidence": [
                {"turn": TURN_A, "version": {"rev": "a"}},
                {"turn": TURN_B, "version": {"rev": "b"}},
                {"turn": TURN_C, "version": {"rev": "c"}},
            ],
        })
    );
    assert_eq!(requests[1]["page"], json!(0));
    assert_eq!(requests[2]["page"], json!(1));
    assert_eq!(
        requests[1],
        json!({
            "evidence": [
                {"turn": TURN_D, "version": {"rev": "d"}},
                {"turn": TURN_E, "version": {"rev": "e"}},
            ],
            "page": 0,
        })
    );
    assert_eq!(
        requests[2],
        json!({
            "evidence": [
                {"turn": TURN_D, "version": {"rev": "d"}},
                {"turn": TURN_E, "version": {"rev": "e"}},
            ],
            "page": 1,
        })
    );
}

/// Invalid rows refuse outside, uncovered and zero pages plus repeats and empties.
#[test]
fn layout_requests_reject_invalid_rows() {
    let window = [
        served_turn(TURN_A, json!(1)),
        served_turn(TURN_B, json!(2)),
        served_turn(TURN_C, json!(3)),
        served_turn(TURN_D, json!(4)),
        served_turn(TURN_E, json!(5)),
    ];
    let outside = ExtractionStepLayout::StepSlices {
        slices: vec![layout_row(vec![0, 1, 2, 3, 5], 1)],
    };
    assert_layout_error(steps::layout_requests(&window, &outside));
    let uncovered = ExtractionStepLayout::StepSlices {
        slices: vec![layout_row(vec![0, 1, 2, 3], 1)],
    };
    assert_layout_error(steps::layout_requests(&window, &uncovered));
    let zero_pages = ExtractionStepLayout::StepSlices {
        slices: vec![layout_row(vec![0, 1, 2, 3, 4], 0)],
    };
    assert_layout_error(steps::layout_requests(&window, &zero_pages));
    let repeated = ExtractionStepLayout::StepSlices {
        slices: vec![layout_row(vec![0, 1, 2], 1), layout_row(vec![2, 3, 4], 1)],
    };
    assert_layout_error(steps::layout_requests(&window, &repeated));
    let empty_rows = ExtractionStepLayout::StepSlices { slices: Vec::new() };
    assert_layout_error(steps::layout_requests(&window, &empty_rows));
    let empty_evidence = ExtractionStepLayout::StepSlices {
        slices: vec![layout_row(Vec::new(), 1)],
    };
    assert_layout_error(steps::layout_requests(&window, &empty_evidence));
    let unordered = ExtractionStepLayout::StepSlices {
        slices: vec![layout_row(vec![0, 2, 1, 3, 4], 1)],
    };
    assert_layout_error(steps::layout_requests(&window, &unordered));
}

/// Joining rebases candidate and skip indexes and preserves fields and order.
#[test]
fn join_rebases_candidates_and_skips() {
    let first = decode_reply(json!({
        "candidates": [
            {
                "index": 0,
                "subject": {"listed": OWEN_HEX},
                "predicate": "likes",
                "value": "tea",
                "confidence": 0.9,
                "prospective_queries": ["owen tea"],
                "evidence": [],
            },
            {
                "index": 2,
                "subject": {"listed": OWEN_HEX},
                "predicate": "dislikes",
                "value": "coffee",
                "confidence": 0.7,
                "prospective_queries": [],
                "rel": ["fond_of"],
                "topic_key": {"topic": "drinks"},
                "evidence": [
                    {
                        "turn": TURN_A,
                        "version": {
                            "entity": TURN_A,
                            "entity_type": 1,
                            "learned_at": 1_720_000_000_000_u64,
                            "revision": REVISION,
                        },
                        "span": {"start": 0, "end": 4},
                    },
                ],
            },
        ],
        "persons": [],
        "skipped": [{"index": 1, "reason": "quote_not_found"}],
    }));
    let second = decode_reply(json!({
        "candidates": [
            {
                "index": 0,
                "subject": {"listed": YUKI_HEX},
                "predicate": "likes",
                "value": "sake",
                "confidence": 0.6,
                "prospective_queries": ["yuki sake"],
                "evidence": [],
            },
        ],
        "persons": [],
        "skipped": [{"index": 1, "reason": "span_missing"}],
    }));
    let joined = join::join_replies(&[first.clone(), second.clone()]);
    assert!(joined.people.is_empty());
    assert!(joined.bindings.is_empty());
    let indexes: Vec<usize> = joined
        .reply
        .candidates
        .iter()
        .map(|candidate| candidate.index)
        .collect();
    assert_eq!(indexes, vec![0, 2, 3]);
    let values: Vec<Value> = joined
        .reply
        .candidates
        .iter()
        .map(|candidate| candidate.value.clone())
        .collect();
    assert_eq!(values, vec![json!("tea"), json!("coffee"), json!("sake")]);
    assert_eq!(joined.reply.candidates[0], first.candidates[0]);
    let mut rebased = first.candidates[1].clone();
    rebased.index = 2;
    assert_eq!(joined.reply.candidates[1], rebased);
    assert_eq!(joined.reply.candidates[1].rel, Some(json!(["fond_of"])));
    assert_eq!(
        joined.reply.candidates[1].topic_key,
        Some(json!({"topic": "drinks"}))
    );
    assert_eq!(
        joined.reply.candidates[1].evidence,
        first.candidates[1].evidence
    );
    let mut moved = second.candidates[0].clone();
    moved.index = 3;
    assert_eq!(joined.reply.candidates[2], moved);
    let skip_indexes: Vec<usize> = joined
        .reply
        .skipped
        .iter()
        .map(|skipped| skipped.index)
        .collect();
    assert_eq!(skip_indexes, vec![1, 4]);
    let reasons: Vec<String> = joined
        .reply
        .skipped
        .iter()
        .map(|skipped| skipped.reason.clone())
        .collect();
    assert_eq!(
        reasons,
        vec!["quote_not_found".to_owned(), "span_missing".to_owned()]
    );
    assert_eq!(joined.skipped.len(), 2);
    assert_eq!(joined.skipped[0].index, 1);
    assert_eq!(
        joined.skipped[0].reasons,
        vec!["quote_not_found".to_owned()]
    );
    assert_eq!(joined.skipped[1].index, 4);
    assert_eq!(joined.skipped[1].reasons, vec!["span_missing".to_owned()]);
    let origins: Vec<(usize, usize, usize)> = joined
        .origins
        .iter()
        .map(|origin| (origin.index, origin.reply, origin.original_index))
        .collect();
    assert_eq!(
        origins,
        vec![(0, 0, 0), (2, 0, 2), (1, 0, 1), (3, 1, 0), (4, 1, 1)]
    );
}

/// Distinct names with the same declared number keep distinct person keys.
#[test]
fn join_keeps_distinct_names_with_one_declared_number() {
    let first = decode_reply(json!({
        "candidates": [
            {
                "index": 0,
                "subject": {"declared": 1},
                "predicate": "likes",
                "value": "tea",
                "confidence": 0.9,
                "prospective_queries": [],
                "evidence": [],
            },
        ],
        "persons": [{"declared": 1, "name": "owen", "turns": [TURN_A]}],
        "skipped": [],
    }));
    let second = decode_reply(json!({
        "candidates": [
            {
                "index": 0,
                "subject": {"declared": 1},
                "predicate": "likes",
                "value": "sake",
                "confidence": 0.8,
                "prospective_queries": [],
                "evidence": [],
            },
        ],
        "persons": [{"declared": 1, "name": "yuki", "turns": [TURN_A]}],
        "skipped": [],
    }));
    let joined = join::join_replies(&[first, second]);
    assert_eq!(joined.people.len(), 2);
    assert_eq!(joined.people[0].name, "owen");
    assert_eq!(joined.people[0].turns, vec![TURN_A.to_owned()]);
    assert_eq!(joined.people[1].name, "yuki");
    assert_eq!(joined.people[1].turns, vec![TURN_A.to_owned()]);
    assert_eq!(joined.bindings.len(), 2);
    assert_eq!(joined.bindings[0].index, 0);
    assert_eq!(joined.bindings[0].key, 0);
    assert_eq!(joined.bindings[1].index, 1);
    assert_eq!(joined.bindings[1].key, 1);
    assert_eq!(joined.reply.candidates.len(), 2);
    assert_eq!(joined.reply.candidates[0].index, 0);
    assert_eq!(joined.reply.candidates[1].index, 1);
    assert!(matches!(
        joined.reply.candidates[0].subject,
        BoundExtractionSubject::Declared(1)
    ));
    assert!(matches!(
        joined.reply.candidates[1].subject,
        BoundExtractionSubject::Declared(1)
    ));
}

/// The same trimmed name and turn set dedupes across replies and numbers.
#[test]
fn join_shares_one_key_for_a_trimmed_name_and_turn_set() {
    let first = decode_reply(json!({
        "candidates": [
            {
                "index": 0,
                "subject": {"declared": 1},
                "predicate": "likes",
                "value": "tea",
                "confidence": 0.9,
                "prospective_queries": [],
                "evidence": [],
            },
        ],
        "persons": [{"declared": 1, "name": "  owen  ", "turns": [TURN_B, TURN_A, TURN_A]}],
        "skipped": [],
    }));
    let second = decode_reply(json!({
        "candidates": [
            {
                "index": 0,
                "subject": {"declared": 7},
                "predicate": "likes",
                "value": "tea",
                "confidence": 0.8,
                "prospective_queries": [],
                "evidence": [],
            },
        ],
        "persons": [{"declared": 7, "name": "owen", "turns": [TURN_A, TURN_B]}],
        "skipped": [],
    }));
    let joined = join::join_replies(&[first, second]);
    assert_eq!(joined.people.len(), 1);
    assert_eq!(joined.people[0].name, "owen");
    assert_eq!(
        joined.people[0].turns,
        vec![TURN_A.to_owned(), TURN_B.to_owned()]
    );
    assert_eq!(joined.bindings.len(), 2);
    assert_eq!(joined.bindings[0].key, 0);
    assert_eq!(joined.bindings[1].key, 0);
    assert_eq!(joined.reply.candidates.len(), 2);
}

/// A declared subject missing its own reply declaration is skipped.
#[test]
fn join_skips_a_candidate_whose_reply_declares_no_such_person() {
    let first = decode_reply(json!({
        "candidates": [
            {
                "index": 0,
                "subject": {"declared": 1},
                "predicate": "likes",
                "value": "tea",
                "confidence": 0.9,
                "prospective_queries": [],
                "evidence": [],
            },
        ],
        "persons": [{"declared": 1, "name": "owen", "turns": [TURN_A]}],
        "skipped": [],
    }));
    let second = decode_reply(json!({
        "candidates": [
            {
                "index": 0,
                "subject": {"declared": 1},
                "predicate": "likes",
                "value": "sake",
                "confidence": 0.8,
                "prospective_queries": [],
                "evidence": [],
            },
        ],
        "persons": [{"declared": 2, "name": "yuki", "turns": [TURN_A]}],
        "skipped": [],
    }));
    let joined = join::join_replies(&[first, second]);
    assert_eq!(joined.people.len(), 2);
    assert_eq!(joined.reply.candidates.len(), 1);
    assert_eq!(joined.reply.candidates[0].index, 0);
    assert_eq!(joined.bindings.len(), 1);
    assert_eq!(joined.bindings[0].index, 0);
    assert_eq!(joined.bindings[0].key, 0);
    assert_eq!(joined.reply.skipped.len(), 1);
    assert_eq!(joined.reply.skipped[0].index, 1);
    assert_eq!(
        joined.reply.skipped[0].reason,
        "declared subject has no person in its own reply"
    );
    assert_eq!(joined.skipped.len(), 1);
    assert_eq!(joined.skipped[0].index, 1);
    assert_eq!(
        joined.skipped[0].reasons,
        vec!["declared subject has no person in its own reply".to_owned()]
    );
    let origins: Vec<(usize, usize, usize)> = joined
        .origins
        .iter()
        .map(|origin| (origin.index, origin.reply, origin.original_index))
        .collect();
    assert_eq!(origins, vec![(0, 0, 0), (1, 1, 0)]);
}

/// Binding lands one hex id and preserves refused tokens with listed only.
#[test]
fn bind_takes_a_landed_id_and_keeps_refused_tokens() {
    let reply = decode_reply(json!({
        "candidates": [
            {
                "index": 0,
                "subject": {"listed": OWEN_HEX},
                "predicate": "likes",
                "value": "tea",
                "confidence": 0.9,
                "prospective_queries": ["owen tea"],
                "evidence": [],
            },
            {
                "index": 1,
                "subject": {"declared": 1},
                "predicate": "likes",
                "value": "sake",
                "confidence": 0.8,
                "prospective_queries": [],
                "evidence": [],
            },
            {
                "index": 2,
                "subject": {"declared": 2},
                "predicate": "dislikes",
                "value": "coffee",
                "confidence": 0.7,
                "prospective_queries": [],
                "evidence": [],
            },
        ],
        "persons": [
            {"declared": 1, "name": "owen", "turns": [TURN_A]},
            {"declared": 2, "name": "yuki", "turns": [TURN_B]},
        ],
        "skipped": [{"index": 3, "reason": "quote_not_found"}],
    }));
    let joined = join::join_replies(&[reply]);
    assert_eq!(joined.people.len(), 2);
    let people = [
        PersonResult {
            key: 0,
            id: Some(PERSON_OWEN_HEX.to_owned()),
            view: person_view(
                "person-0",
                true,
                vec![PERSON_OWEN_HEX.to_owned()],
                Vec::new(),
            ),
        },
        PersonResult {
            key: 1,
            id: None,
            view: person_view(
                "person-1",
                false,
                Vec::new(),
                vec!["person_id_taken".to_owned(), "other_token".to_owned()],
            ),
        },
    ];
    let bound = persons::bind(joined, &people).expect("binding succeeds");
    assert!(bound.reply.persons.is_empty());
    assert_eq!(bound.reply.candidates.len(), 2);
    assert_eq!(bound.reply.candidates[0].index, 0);
    assert_eq!(bound.reply.candidates[1].index, 1);
    assert_eq!(
        bound.reply.candidates[0].subject,
        BoundExtractionSubject::Listed(OWEN_HEX.to_owned())
    );
    assert_eq!(
        bound.reply.candidates[1].subject,
        BoundExtractionSubject::Listed(PERSON_OWEN_HEX.to_owned())
    );
    for candidate in &bound.reply.candidates {
        assert!(matches!(
            candidate.subject,
            BoundExtractionSubject::Listed(_)
        ));
    }
    assert_eq!(bound.reply.skipped.len(), 2);
    assert_eq!(bound.reply.skipped[0].index, 3);
    assert_eq!(bound.reply.skipped[0].reason, "quote_not_found");
    assert_eq!(bound.reply.skipped[1].index, 2);
    assert_eq!(
        bound.reply.skipped[1].reason,
        json!(["person_id_taken", "other_token"]).to_string()
    );
    assert_eq!(bound.skipped.len(), 2);
    assert_eq!(bound.skipped[0].index, 3);
    assert_eq!(bound.skipped[0].reasons, vec!["quote_not_found".to_owned()]);
    assert_eq!(bound.skipped[1].index, 2);
    assert_eq!(
        bound.skipped[1].reasons,
        vec!["person_id_taken".to_owned(), "other_token".to_owned()]
    );
}

/// A listed-only reply with empty persons stays listed and keeps no persons.
#[test]
fn bind_leaves_a_listed_only_reply_unchanged() {
    let reply = decode_reply(json!({
        "candidates": [
            {
                "index": 0,
                "subject": {"listed": OWEN_HEX},
                "predicate": "likes",
                "value": "tea",
                "confidence": 0.9,
                "prospective_queries": ["owen tea"],
                "evidence": [],
            },
        ],
        "persons": [],
        "skipped": [],
    }));
    let joined = join::join_replies(&[reply]);
    assert!(joined.people.is_empty());
    assert!(joined.bindings.is_empty());
    let bound = persons::bind(joined, &[]).expect("empty binding succeeds");
    assert!(bound.reply.persons.is_empty());
    assert!(bound.skipped.is_empty());
    assert_eq!(bound.reply.candidates.len(), 1);
    assert_eq!(
        bound.reply.candidates[0].subject,
        BoundExtractionSubject::Listed(OWEN_HEX.to_owned())
    );
}

/// The person batch carries exact items with deduped served sources in order.
#[test]
fn person_request_holds_exact_items_and_served_sources() {
    let turns = [
        served_turn(TURN_A, json!({"rev": "a"})),
        served_turn(TURN_B, json!({"rev": "b"})),
        served_turn(TURN_C, json!({"rev": "c"})),
    ];
    let people = [
        PersonKey {
            name: "owen".to_owned(),
            turns: vec![TURN_C.to_owned(), TURN_A.to_owned()],
        },
        PersonKey {
            name: "yuki".to_owned(),
            turns: vec![TURN_B.to_owned(), TURN_A.to_owned()],
        },
    ];
    let request = persons::person_request(&people, &turns).expect("the batch builds");
    assert_eq!(
        request,
        json!({
            "items": [
                {
                    "kind": "person",
                    "spec": {
                        "local": "person-0",
                        "name": "owen",
                        "evidence": [{"stored": TURN_C}, {"stored": TURN_A}],
                    },
                },
                {
                    "kind": "person",
                    "spec": {
                        "local": "person-1",
                        "name": "yuki",
                        "evidence": [{"stored": TURN_B}, {"stored": TURN_A}],
                    },
                },
            ],
            "sources": [{"rev": "a"}, {"rev": "b"}, {"rev": "c"}],
        })
    );
}

/// One ready group builds its exact candidate item with shared hints.
#[test]
fn components_build_the_exact_candidate_item() {
    let reply = decode_reply(json!({
        "candidates": [
            {
                "index": 0,
                "subject": {"listed": OWEN_HEX},
                "predicate": "likes",
                "value": "tea",
                "confidence": 0.9,
                "prospective_queries": ["  owen tea  ", "shared", ""],
                "evidence": [],
            },
            {
                "index": 1,
                "subject": {"listed": OWEN_HEX},
                "predicate": "likes",
                "value": "tea",
                "confidence": 0.5,
                "prospective_queries": ["shared", "yuki tea", " yuki tea "],
                "evidence": [],
            },
        ],
        "persons": [],
        "skipped": [],
    }));
    let operands = vec![
        json!({
            "subject": OWEN_HEX,
            "predicate": "likes",
            "value": "tea",
            "evidence": [{"turn": TURN_A}, {"turn": TURN_B}],
            "corrects": HEAD_HEX,
            "rel": ["fond_of"],
            "topic": {"topic": "drinks"},
        }),
        json!({
            "subject": OWEN_HEX,
            "predicate": "likes",
            "value": "tea",
            "evidence": [{"turn": TURN_B}, {"turn": TURN_C}],
            "corrects": OTHER_HEAD_HEX,
            "rel": ["other"],
            "topic": {"other": 1},
        }),
    ];
    let selection = selection_shell(vec![scored_group(0, &[0, 1])]);
    let route = route_shell(vec![candidate_route(0, vec![0, 1], Route::New)], Vec::new());
    let outcome = outcome_shell(operands, vec![0, 1], selection, route);
    let plan = Plan { sets: Vec::new() };
    let built = components::build(&reply, &outcome, &plan).expect("the item builds");
    assert_eq!(built.already_represented, 0);
    assert_eq!(built.items.len(), 1);
    assert_eq!(built.items[0].representative_index, 0);
    assert_eq!(built.items[0].set, None);
    assert_eq!(built.items[0].planned, None);
    assert_eq!(
        built.items[0].item,
        json!({
            "kind": "candidate",
            "spec": {
                "local": "candidate-0",
                "member": {
                    "candidate": {
                        "subject": OWEN_HEX,
                        "predicate": "likes",
                        "value": "tea",
                        "evidence": [{"turn": TURN_A}, {"turn": TURN_B}, {"turn": TURN_C}],
                        "corrects": HEAD_HEX,
                        "rel": ["fond_of"],
                        "topic": {"topic": "drinks"},
                    },
                    "confidence": 0.9,
                    "prospective_queries": ["owen tea", "shared", "yuki tea"],
                },
            },
        })
    );
}

/// A mixed route list keeps order, counts one and ignores the orphan set.
#[test]
fn components_follow_route_order_and_emit_a_set_once() {
    let reply = decode_reply(json!({
        "candidates": [
            {
                "index": 0,
                "subject": {"listed": OWEN_HEX},
                "predicate": "likes",
                "value": "v0",
                "confidence": 0.9,
                "prospective_queries": ["owen zero"],
                "evidence": [],
            },
            {
                "index": 1,
                "subject": {"listed": OWEN_HEX},
                "predicate": "likes",
                "value": "v1",
                "confidence": 0.8,
                "prospective_queries": ["owen one"],
                "evidence": [],
            },
            {
                "index": 2,
                "subject": {"listed": OWEN_HEX},
                "predicate": "likes",
                "value": "v2",
                "confidence": 0.7,
                "prospective_queries": ["owen two"],
                "evidence": [],
            },
            {
                "index": 3,
                "subject": {"listed": OWEN_HEX},
                "predicate": "likes",
                "value": "v3",
                "confidence": 0.6,
                "prospective_queries": ["owen three"],
                "evidence": [],
            },
            {
                "index": 4,
                "subject": {"listed": OWEN_HEX},
                "predicate": "likes",
                "value": "v4",
                "confidence": 0.5,
                "prospective_queries": ["yuki four"],
                "evidence": [],
            },
            {
                "index": 5,
                "subject": {"listed": OWEN_HEX},
                "predicate": "likes",
                "value": "v5",
                "confidence": 0.4,
                "prospective_queries": ["yuki five"],
                "evidence": [],
            },
        ],
        "persons": [],
        "skipped": [],
    }));
    let operands: Vec<Value> = (0..6)
        .map(|at| {
            json!({
                "subject": OWEN_HEX,
                "predicate": "likes",
                "value": format!("v{at}"),
                "evidence": [{"turn": TURN_A}],
            })
        })
        .collect();
    let selection = selection_shell(vec![
        scored_group(0, &[0]),
        scored_group(1, &[1]),
        scored_group(2, &[2]),
        scored_group(3, &[3]),
        scored_group(4, &[4]),
        scored_group(5, &[5]),
    ]);
    let routes = vec![
        candidate_route(0, vec![0], Route::New),
        candidate_route(
            1,
            vec![1],
            Route::Attach {
                head: HEAD_HEX.to_owned(),
            },
        ),
        candidate_route(2, vec![2], Route::Judge { set: 0 }),
        candidate_route(3, vec![3], Route::Judge { set: 0 }),
        candidate_route(
            4,
            vec![4],
            Route::ObservedBeside {
                stated_heads: vec![HEAD_HEX.to_owned()],
            },
        ),
        candidate_route(
            5,
            vec![5],
            Route::AlreadyRepresented {
                head: OTHER_HEAD_HEX.to_owned(),
                reason: AlreadyRepresentedReason::RestatesUnlisted,
            },
        ),
    ];
    let judge_sets = vec![JudgeSet {
        candidate_indexes: vec![2, 3],
        component_indexes: vec![2, 3],
        identity_token: "anchor".to_owned(),
        prior_heads: vec![HEAD_HEX.to_owned()],
        prior_head: Some(HEAD_HEX.to_owned()),
    }];
    let route = route_shell(routes, judge_sets);
    let outcome = outcome_shell(operands, vec![0, 1, 2, 3, 4, 5], selection, route);
    let first_item = json!({
        "kind": "conflict_resolution",
        "spec": {"local": "conflict-set-0"},
    });
    let orphan_item = json!({
        "kind": "conflict_resolution",
        "spec": {"local": "conflict-set-1"},
    });
    let plan = Plan {
        sets: vec![
            SetPlan::Resolved {
                outcome: ResolvedOutcome::Skip,
                item: first_item.clone(),
            },
            SetPlan::Resolved {
                outcome: ResolvedOutcome::Accumulate,
                item: orphan_item,
            },
        ],
    };
    let built = components::build(&reply, &outcome, &plan).expect("the list builds");
    assert_eq!(built.already_represented, 1);
    assert_eq!(built.items.len(), 4);
    let representatives: Vec<usize> = built
        .items
        .iter()
        .map(|item| item.representative_index)
        .collect();
    assert_eq!(representatives, vec![0, 1, 2, 4]);
    assert_eq!(built.items[0].set, None);
    assert_eq!(built.items[0].planned, None);
    assert_eq!(built.items[0].item["kind"], json!("candidate"));
    assert_eq!(built.items[0].item["spec"]["local"], json!("candidate-0"));
    assert_eq!(built.items[1].set, None);
    assert_eq!(built.items[1].planned, None);
    assert_eq!(built.items[1].item["kind"], json!("candidate"));
    assert_eq!(built.items[1].item["spec"]["local"], json!("candidate-1"));
    assert_eq!(built.items[2].set, Some(0));
    assert_eq!(built.items[2].planned, Some(plan.sets[0].clone()));
    assert_eq!(built.items[2].item, first_item);
    assert_eq!(built.items[3].set, None);
    assert_eq!(built.items[3].planned, None);
    assert_eq!(built.items[3].item["kind"], json!("candidate"));
    assert_eq!(built.items[3].item["spec"]["local"], json!("candidate-4"));
    for item in &built.items {
        assert_ne!(item.set, Some(1), "the orphan set stays unreferenced");
    }
}

/// Builds one merged-value step error for set 3 with the result the engine served.
fn step_error(status: &str, result: Value) -> PlanError {
    PlanError::Step {
        set: 3,
        status: status.to_owned(),
        message: String::new(),
        result,
    }
}

/// Builds one failed merged-value step error of the given class and spent usage.
fn failed_step(class: &str, spent_usage: Value) -> PlanError {
    step_error(
        "failed",
        json!({
            "status": "failed",
            "failure": {
                "class": class,
                "message": "owen's merged value did not arrive",
                "llm": null,
                "validation_attempts": null,
                "validation_errors": [],
                "spent_usage": spent_usage,
            },
        }),
    )
}

/// A failed step names its set only for the failures native parks a marker for.
#[test]
fn a_failed_step_names_its_set_only_where_native_parks_a_marker() {
    let spent = json!({"input": {"total": 100}, "output": {"total": 50}});
    for class in [
        "retryable",
        "fatal",
        "budget_denied",
        "fallback",
        "deadline_hard_cut",
        "engine",
    ] {
        assert_eq!(
            failed_step(class, Value::Null).failed_set_marker(),
            Some(3),
            "{class} parks the marker"
        );
        assert_eq!(
            failed_step(class, spent.clone()).failed_set_marker(),
            Some(3),
            "{class} with spent usage parks the marker"
        );
    }
    for class in ["finalize_refused", "schema_validation"] {
        assert_eq!(
            failed_step(class, Value::Null).failed_set_marker(),
            Some(3),
            "{class} with no spent usage parks the marker"
        );
        assert_eq!(
            failed_step(class, spent.clone()).failed_set_marker(),
            None,
            "{class} of spent work parks none"
        );
    }
    assert_eq!(
        failed_step("budget_refused", Value::Null).failed_set_marker(),
        None
    );
    assert_eq!(
        failed_step("a_class_yuki_invented", Value::Null).failed_set_marker(),
        None
    );
    for status in ["budget_denied", "parked", "erased", "finished", "missing"] {
        assert_eq!(
            step_error(status, json!({"status": status})).failed_set_marker(),
            None,
            "a {status} step parks none"
        );
    }
    assert_eq!(
        step_error("failed", json!({"status": "failed"})).failed_set_marker(),
        None
    );
    assert_eq!(step_error("failed", Value::Null).failed_set_marker(), None);
    let refused = PlanError::Client {
        set: 3,
        verb: "ai.steps.submit",
        code: "MODEL_UNAVAILABLE".to_owned(),
        message: String::new(),
    };
    assert_eq!(refused.failed_set_marker(), None);
    assert_eq!(
        PlanError::KeptOutsideSet { set: 3, kept: 9 }.failed_set_marker(),
        None
    );
}

/// The marker item of a failed set is the item an opened set plans.
#[test]
fn the_marker_item_is_the_item_an_opened_set_plans() {
    let reply = decode_reply(json!({
        "candidates": [
            {
                "index": 0,
                "subject": {"listed": OWEN_HEX},
                "predicate": "likes",
                "value": "tea",
                "confidence": 0.9,
                "prospective_queries": ["owen tea"],
                "evidence": [],
            },
            {
                "index": 1,
                "subject": {"listed": OWEN_HEX},
                "predicate": "likes",
                "value": "coffee",
                "confidence": 0.7,
                "prospective_queries": ["owen coffee"],
                "evidence": [],
            },
        ],
        "persons": [],
        "skipped": [],
    }));
    let candidates = vec![
        json!({
            "subject": OWEN_HEX,
            "predicate": "likes",
            "value": "tea",
            "evidence": [{"turn": TURN_A}],
        }),
        json!({
            "subject": OWEN_HEX,
            "predicate": "likes",
            "value": "coffee",
            "evidence": [{"turn": TURN_B}],
        }),
    ];
    let set = SetOperands {
        candidates: candidates.clone(),
        priors: Vec::new(),
        set_members: vec![0, 1],
        representatives: vec![0, 1],
        spans_predicates: false,
    };
    let selection = selection_shell(vec![scored_group(0, &[0]), scored_group(1, &[1])]);
    let mut outcome = outcome_shell(
        candidates,
        vec![0, 1],
        selection,
        route_shell(Vec::new(), Vec::new()),
    );
    outcome.set_operands = vec![set.clone()];
    let escalated = SetOutcome::Decided(ConflictDecision {
        resolution: Resolution::Escalate,
        identity: None,
        decisions: Vec::new(),
    });
    let facts = conflict_resolution::member_facts(&reply, &outcome, 0).expect("the facts build");
    let opened =
        conflict_resolution::set_plan(&set, &escalated, &facts, None, 0).expect("the set opens");
    let item =
        conflict_resolution::open_marker_item(&reply, &outcome, 0).expect("the marker builds");
    assert_eq!(&item, opened.item());
    assert_eq!(item["kind"], json!("conflict"));
    assert_eq!(item["spec"]["local"], json!("conflict-set-0"));
    assert_eq!(item["spec"]["set_members"], json!([0, 1]));
    assert_eq!(
        item["spec"]["members"][1]["prospective_queries"],
        json!(["owen coffee"])
    );
    assert!(conflict_resolution::open_marker_item(&reply, &outcome, 1).is_err());
}
