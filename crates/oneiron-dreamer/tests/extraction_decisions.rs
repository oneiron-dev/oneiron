//! Pure public-API checks for decision operands and D2 skip policy.
//!
//! Covers `extraction_reply::decision_operands` and
//! `extraction_decisions::{fast_path, bound_correction}`. Each case cites the
//! native line its expectation copies; HEAD 36f82fbd16dc was re-found.

use oneiron_dreamer::extraction_decisions::{bound_correction, fast_path};
use oneiron_dreamer::extraction_observations::Observations;
use oneiron_dreamer::extraction_reply::{BoundExtractionReply, decision_operands};
use oneiron_dreamer::extraction_routing::{Correction, JudgeSet};
use serde_json::{Value, json};

/// Holds Owen's listed subject id, as 32 lowercase hex digits.
const OWEN_HEX: &str = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";
/// Holds the cited turn id, as 32 lowercase hex digits.
const TURN_HEX: &str = "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";
/// Holds the cited turn revision, as `blake3:<hex>`.
const REVISION: &str = "blake3:d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3";
/// Holds the cited turn projection, as `blake3:<hex>`.
const PROJECTION: &str = "blake3:e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4";
/// Holds the retained identity token in the fixtures.
const ANCHOR_TOKEN: &str = "anchor-identity";
/// Holds the member token when it differs from the anchor.
const MEMBER_TOKEN: &str = "member-identity";

/// Names one claim as 32 lowercase hex digits.
fn claim(position: u32) -> String {
    format!("{position:032x}")
}

/// Returns listed owen at 0 with rel and topic, declared yuki at 1, and listed
/// owen at 2 without rel or topic.
fn bound_reply_value() -> Value {
    json!({
        "candidates": [
            {
                "index": 0,
                "subject": { "listed": OWEN_HEX },
                "predicate": "likes",
                "value": "tea",
                "confidence": 0.9,
                "prospective_queries": ["owen tea"],
                "rel": ["fond_of"],
                "topic_key": { "topic": "drinks" },
                "evidence": [
                    {
                        "turn": TURN_HEX,
                        "version": {
                            "entity": TURN_HEX,
                            "entity_type": 1,
                            "learned_at": 1_720_000_000_000_u64,
                            "revision": REVISION,
                            "projection": PROJECTION,
                        },
                        "span": { "start": 0, "end": 4 },
                    },
                ],
            },
            {
                "index": 1,
                "subject": { "declared": 1 },
                "predicate": "likes",
                "value": "tea",
                "confidence": 0.6,
                "prospective_queries": ["yuki tea"],
                "evidence": [],
            },
            {
                "index": 2,
                "subject": { "listed": OWEN_HEX },
                "predicate": "dislikes",
                "value": "coffee",
                "confidence": 0.7,
                "prospective_queries": [],
                "evidence": [],
            },
        ],
        "persons": [{ "declared": 1, "name": "yuki", "turns": [TURN_HEX] }],
        "skipped": [],
    })
}

/// Returns one candidate row with full native fields.
fn candidate_value(index: usize, identity: &str, single_valued: bool) -> Value {
    json!({
        "index": index,
        "claim": claim(u32::try_from(index + 1).expect("small index")),
        "identity_token": identity,
        "topic_token": "topic",
        "value_token": "value",
        "slice_token": "slice",
        "predicate": "record.field",
        "corrects": Value::Null,
        "meet": "generated",
        "observed": false,
        "evidence_count": 3,
        "first_seen_ms": 1_719_999_800_000_u64,
        "latest_ms": 1_719_999_999_000_u64,
        "diversity": 2,
        "fan_in": 0,
        "new_refs": 0,
        "has_vector": false,
        "named_facet": Value::Null,
        "scope_facet": "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0",
        "scope_project": "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
        "replay_facet": "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0",
        "correctable": [],
        "single_valued": single_valued,
    })
}

/// Returns one prior row with the two D2 lists set.
fn prior_value(head: &str, non_widening: &[usize], subject_predicate_equal: &[usize]) -> Value {
    json!({
        "claim": head,
        "version": {
            "entity": head,
            "entity_type": 4,
            "learned_at": 0,
            "revision": "blake3:0000000000000000000000000000000000000000000000000000000000000000",
            "projection": Value::Null,
        },
        "identity_token": "identity",
        "topic_token": "topic",
        "value_token": "value",
        "source": "generated",
        "standing": "prior",
        "writable": true,
        "scope_facet": "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0",
        "scope_project": "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
        "scope_equal_candidates": [],
        "non_widening_candidates": non_widening,
        "subject_predicate_equal_candidates": subject_predicate_equal,
    })
}

/// Gathers candidate and prior rows into served observations.
fn observations(candidates: Vec<Value>, priors: Vec<Value>) -> Observations {
    serde_json::from_value(json!({
        "attempt": "owen-attempt",
        "now_ms": 1_720_000_000_000_u64,
        "policy_pin": "policy-pin",
        "facts_pin": "facts-pin",
        "candidates": candidates,
        "listed": [],
        "priors": priors,
        "replay": [],
        "scores": [],
    }))
    .expect("observations decode")
}

/// Builds one judge set with its nomination component in hand.
fn judge_set(
    members: Vec<usize>,
    identity: &str,
    heads: Vec<String>,
    component: Vec<usize>,
) -> JudgeSet {
    JudgeSet {
        candidate_indexes: members,
        identity_token: identity.to_owned(),
        prior_head: (heads.len() == 1).then(|| heads[0].clone()),
        prior_heads: heads,
        component_indexes: component,
    }
}

/// Builds one surviving correction binding.
fn correction(representative_index: usize, head: String) -> Correction {
    Correction {
        representative_index,
        head,
    }
}

/// The adapter carries rel and topic and preserves the listed proposal.
#[test]
fn decision_operands_carries_rel_and_topic() {
    let reply: BoundExtractionReply =
        serde_json::from_value(bound_reply_value()).expect("reply decodes");
    let operands = decision_operands(&reply).expect("adapter builds");
    assert_eq!(operands.operands.len(), 2);
    let first = &operands.operands[0];
    // native: crates/oneiron/src/verbs/extraction_verdict.rs:107-112 rel is a string array, topic is JSON.
    assert_eq!(first["rel"], json!(["fond_of"]));
    assert_eq!(first["topic"], json!({ "topic": "drinks" }));
    assert_eq!(first["subject"], json!(OWEN_HEX));
    assert_eq!(first["predicate"], json!("likes"));
    assert_eq!(first["value"], json!("tea"));
    assert_eq!(first["evidence"][0]["turn"], json!(TURN_HEX));
    assert_eq!(first["evidence"][0]["span"]["start"], json!(0_u64));
    // native: crates/oneiron/src/dreamer_consolidation/executor/extraction.rs:351-356 rel enters the native identity.
    assert!(operands.operands[1].get("rel").is_none());
    assert!(operands.operands[1].get("topic").is_none());
}

/// Declared subjects stay off and each operand maps to its reply index.
#[test]
fn decision_operands_skips_declared_and_maps_reply_indexes() {
    let reply: BoundExtractionReply =
        serde_json::from_value(bound_reply_value()).expect("reply decodes");
    let operands = decision_operands(&reply).expect("adapter builds");
    // native: crates/oneiron/src/verbs/extraction_verdict.rs:100-102 a subject is listed hex only.
    assert_eq!(operands.operands.len(), 2);
    assert_eq!(operands.candidate_indexes, vec![0, 2]);
}

/// A relationship that is not a string array is a typed decode error.
#[test]
fn decision_operands_rejects_non_string_rel() {
    let mut value = bound_reply_value();
    value["candidates"][0]["rel"] = json!("fond_of");
    let reply: BoundExtractionReply = serde_json::from_value(value).expect("reply decodes");
    // native: crates/oneiron/src/verbs/extraction_verdict.rs:109 rel is Option<Vec<String>>.
    assert!(decision_operands(&reply).is_err());
}

/// Fast path skips one single-valued member its prior admits.
#[test]
fn fast_path_skips_single_member() {
    let head = claim(0x200);
    let rows = vec![candidate_value(0, ANCHOR_TOKEN, true)];
    let priors = vec![prior_value(&head, &[0], &[0])];
    let set = judge_set(vec![0], ANCHOR_TOKEN, vec![head], vec![0]);
    // native: crates/oneiron/src/dreamer_consolidation/judge_context.rs:15-25 one member, single-valued identity, no widening.
    assert!(fast_path(&set, &observations(rows, priors)).expect("reads"));
}

/// No members never take the fast path.
#[test]
fn fast_path_refuses_empty_members() {
    let head = claim(0x200);
    let rows = vec![candidate_value(0, ANCHOR_TOKEN, true)];
    let priors = vec![prior_value(&head, &[0], &[0])];
    let set = judge_set(Vec::new(), ANCHOR_TOKEN, vec![head], Vec::new());
    // native: crates/oneiron/src/dreamer_consolidation/judge_context.rs:15 members.len() == 1.
    assert!(!fast_path(&set, &observations(rows, priors)).expect("reads"));
}

/// Two members never take the fast path.
#[test]
fn fast_path_refuses_two_members() {
    let head = claim(0x200);
    let rows = vec![
        candidate_value(0, ANCHOR_TOKEN, true),
        candidate_value(1, ANCHOR_TOKEN, true),
    ];
    let priors = vec![prior_value(&head, &[0, 1], &[0, 1])];
    let set = judge_set(vec![0, 1], ANCHOR_TOKEN, vec![head], vec![0, 1]);
    // native: crates/oneiron/src/dreamer_consolidation/judge_context.rs:15 members.len() == 1.
    assert!(!fast_path(&set, &observations(rows, priors)).expect("reads"));
}

/// An anchor that is not single-valued never takes the fast path.
#[test]
fn fast_path_refuses_anchor_not_single_valued() {
    let head = claim(0x200);
    let rows = vec![candidate_value(0, ANCHOR_TOKEN, false)];
    let priors = vec![prior_value(&head, &[0], &[0])];
    let set = judge_set(vec![0], ANCHOR_TOKEN, vec![head], vec![0]);
    // native: crates/oneiron/src/dreamer_consolidation/judge_context.rs:16 reads conflict.identity; facts.rs:73 serves single_valued.
    assert!(!fast_path(&set, &observations(rows, priors)).expect("reads"));
}

/// No prior head means no fast path.
#[test]
fn fast_path_refuses_missing_prior_head() {
    let head = claim(0x200);
    let rows = vec![candidate_value(0, ANCHOR_TOKEN, true)];
    let priors = vec![prior_value(&head, &[0], &[0])];
    let set = judge_set(vec![0], ANCHOR_TOKEN, Vec::new(), vec![0]);
    // native: crates/oneiron/src/dreamer_consolidation/judge_context.rs:17 prior.is_some_and; conflicts.rs:63-66 reads prior_head.
    assert!(!fast_path(&set, &observations(rows, priors)).expect("reads"));
}

/// A member the widening check omits never takes the fast path.
#[test]
fn fast_path_refuses_widening_member() {
    let head = claim(0x200);
    let rows = vec![candidate_value(0, ANCHOR_TOKEN, true)];
    let priors = vec![prior_value(&head, &[], &[0])];
    let set = judge_set(vec![0], ANCHOR_TOKEN, vec![head], vec![0]);
    // native: crates/oneiron/src/dreamer_consolidation/judge_context.rs:18-24 no widening; facts.rs:155-164 serves non_widening.
    assert!(!fast_path(&set, &observations(rows, priors)).expect("reads"));
}

/// A retained single-valued anchor skips though the lone member is not single-valued.
#[test]
fn fast_path_keeps_retained_anchor_single_valued() {
    let head = claim(0x200);
    let rows = vec![
        candidate_value(0, ANCHOR_TOKEN, true),
        candidate_value(1, MEMBER_TOKEN, false),
    ];
    let priors = vec![prior_value(&head, &[1], &[0])];
    let set = judge_set(vec![1], ANCHOR_TOKEN, vec![head], vec![0, 1]);
    // native: crates/oneiron/src/dreamer_consolidation/routing.rs:183-190 retains the first identity; judge_context.rs:16 reads it.
    assert!(fast_path(&set, &observations(rows, priors)).expect("reads"));
}

/// A retained anchor that is not single-valued does not skip though the member is.
#[test]
fn fast_path_refuses_retained_anchor_not_single_valued() {
    let head = claim(0x200);
    let rows = vec![
        candidate_value(0, ANCHOR_TOKEN, false),
        candidate_value(1, MEMBER_TOKEN, true),
    ];
    let priors = vec![prior_value(&head, &[1], &[0])];
    let set = judge_set(vec![1], ANCHOR_TOKEN, vec![head], vec![0, 1]);
    // native: crates/oneiron/src/dreamer_consolidation/resources/prior.rs:190-200 exact removal keeps the anchor.
    assert!(!fast_path(&set, &observations(rows, priors)).expect("reads"));
}

/// A set identity the observations do not serve is a typed error.
#[test]
fn fast_path_missing_anchor_is_typed_error() {
    let head = claim(0x200);
    let rows = vec![candidate_value(0, MEMBER_TOKEN, true)];
    let priors = vec![prior_value(&head, &[0], &[0])];
    let set = judge_set(vec![0], ANCHOR_TOKEN, vec![head], vec![0]);
    // crate: crates/oneiron-dreamer/src/conflict_decisions/questions.rs:185-192 finds the first identity-token row.
    assert!(fast_path(&set, &observations(rows, priors)).is_err());
}

/// A named prior head the observations do not serve is a typed error.
#[test]
fn fast_path_missing_named_prior_is_typed_error() {
    let head = claim(0x200);
    let other = claim(0x201);
    let rows = vec![candidate_value(0, ANCHOR_TOKEN, true)];
    let priors = vec![prior_value(&other, &[0], &[0])];
    let set = judge_set(vec![0], ANCHOR_TOKEN, vec![head], vec![0]);
    // native: crates/oneiron/src/dreamer_consolidation/executor/conflicts.rs:63-66 looks the prior head up.
    assert!(fast_path(&set, &observations(rows, priors)).is_err());
}

/// A bound correction skips one member bound to its only head.
#[test]
fn bound_correction_skips_single_member() {
    let head = claim(0x200);
    let rows = vec![candidate_value(0, ANCHOR_TOKEN, true)];
    let priors = vec![prior_value(&head, &[0], &[0])];
    let set = judge_set(vec![0], ANCHOR_TOKEN, vec![head.clone()], vec![0]);
    let corrections = vec![correction(0, head)];
    // native: crates/oneiron/src/dreamer_consolidation/judge_context.rs:41-54 lone member, binding, only head, equal subject/predicate.
    assert!(bound_correction(&set, &observations(rows, priors), &corrections).expect("reads"));
}

/// No members never bind by correction.
#[test]
fn bound_correction_refuses_empty_members() {
    let head = claim(0x200);
    let rows = vec![candidate_value(0, ANCHOR_TOKEN, true)];
    let priors = vec![prior_value(&head, &[0], &[0])];
    let set = judge_set(Vec::new(), ANCHOR_TOKEN, vec![head.clone()], Vec::new());
    let corrections = vec![correction(0, head)];
    // native: crates/oneiron/src/dreamer_consolidation/judge_context.rs:41 let ([member], Some(prior)).
    assert!(!bound_correction(&set, &observations(rows, priors), &corrections).expect("reads"));
}

/// Two members never bind by correction.
#[test]
fn bound_correction_refuses_two_members() {
    let head = claim(0x200);
    let rows = vec![
        candidate_value(0, ANCHOR_TOKEN, true),
        candidate_value(1, ANCHOR_TOKEN, true),
    ];
    let priors = vec![prior_value(&head, &[0, 1], &[0, 1])];
    let set = judge_set(vec![0, 1], ANCHOR_TOKEN, vec![head.clone()], vec![0, 1]);
    let corrections = vec![correction(0, head)];
    // native: crates/oneiron/src/dreamer_consolidation/judge_context.rs:41 let ([member], Some(prior)).
    assert!(!bound_correction(&set, &observations(rows, priors), &corrections).expect("reads"));
}

/// No prior head means no bound correction.
#[test]
fn bound_correction_refuses_missing_prior_head() {
    let head = claim(0x200);
    let rows = vec![candidate_value(0, ANCHOR_TOKEN, true)];
    let priors = vec![prior_value(&head, &[0], &[0])];
    let set = judge_set(vec![0], ANCHOR_TOKEN, Vec::new(), vec![0]);
    let corrections = vec![correction(0, head)];
    // native: crates/oneiron/src/dreamer_consolidation/judge_context.rs:41 requires Some(prior).
    assert!(!bound_correction(&set, &observations(rows, priors), &corrections).expect("reads"));
}

/// No surviving correction means no bound correction.
#[test]
fn bound_correction_refuses_missing_correction() {
    let head = claim(0x200);
    let rows = vec![candidate_value(0, ANCHOR_TOKEN, true)];
    let priors = vec![prior_value(&head, &[0], &[0])];
    let set = judge_set(vec![0], ANCHOR_TOKEN, vec![head], vec![0]);
    // native: crates/oneiron/src/dreamer_consolidation/judge_context.rs:44 corrections.get(&member.claim_id).
    assert!(!bound_correction(&set, &observations(rows, priors), &[]).expect("reads"));
}

/// A correction naming another head does not bind this prior.
#[test]
fn bound_correction_refuses_correction_naming_other_head() {
    let head = claim(0x200);
    let rows = vec![candidate_value(0, ANCHOR_TOKEN, true)];
    let priors = vec![prior_value(&head, &[0], &[0])];
    let set = judge_set(vec![0], ANCHOR_TOKEN, vec![head], vec![0]);
    let corrections = vec![correction(0, claim(0x201))];
    // native: crates/oneiron/src/dreamer_consolidation/judge_context.rs:44 binding must equal prior.claim_id.
    assert!(!bound_correction(&set, &observations(rows, priors), &corrections).expect("reads"));
}

/// A second prior head means no bound correction.
#[test]
fn bound_correction_refuses_second_prior_head() {
    let head = claim(0x200);
    let other = claim(0x201);
    let rows = vec![candidate_value(0, ANCHOR_TOKEN, true)];
    let priors = vec![prior_value(&head, &[0], &[0])];
    let mut set = judge_set(vec![0], ANCHOR_TOKEN, vec![head.clone()], vec![0]);
    set.prior_heads = vec![head.clone(), other];
    let corrections = vec![correction(0, head)];
    // native: crates/oneiron/src/dreamer_consolidation/judge_context.rs:45 conflict.prior_heads == [prior.claim_id].
    assert!(!bound_correction(&set, &observations(rows, priors), &corrections).expect("reads"));
}

/// A prior whose subject or predicate differs does not bind.
#[test]
fn bound_correction_refuses_subject_predicate_unequal() {
    let head = claim(0x200);
    let rows = vec![candidate_value(0, ANCHOR_TOKEN, true)];
    let priors = vec![prior_value(&head, &[0], &[])];
    let set = judge_set(vec![0], ANCHOR_TOKEN, vec![head.clone()], vec![0]);
    let corrections = vec![correction(0, head)];
    // native: crates/oneiron/src/dreamer_consolidation/judge_context.rs:46-47 equal subject/predicate; facts.rs:136-143 serves the list.
    assert!(!bound_correction(&set, &observations(rows, priors), &corrections).expect("reads"));
}

/// An equality list naming the member without the anchor does not bind.
#[test]
fn bound_correction_refuses_equality_listing_member_without_anchor() {
    let head = claim(0x200);
    let rows = vec![
        candidate_value(0, ANCHOR_TOKEN, true),
        candidate_value(1, MEMBER_TOKEN, true),
    ];
    let priors = vec![prior_value(&head, &[1], &[1])];
    let set = judge_set(vec![1], ANCHOR_TOKEN, vec![head.clone()], vec![0, 1]);
    let corrections = vec![correction(1, head)];
    // native: crates/oneiron/src/dreamer_consolidation/judge_context.rs:46-47 compares conflict.identity (tokens.rs:29-37).
    assert!(!bound_correction(&set, &observations(rows, priors), &corrections).expect("reads"));
}

/// A member the widening check omits never binds by correction.
#[test]
fn bound_correction_refuses_widening_member() {
    let head = claim(0x200);
    let rows = vec![candidate_value(0, ANCHOR_TOKEN, true)];
    let priors = vec![prior_value(&head, &[], &[0])];
    let set = judge_set(vec![0], ANCHOR_TOKEN, vec![head.clone()], vec![0]);
    let corrections = vec![correction(0, head)];
    // native: crates/oneiron/src/dreamer_consolidation/judge_context.rs:48-54 source check; facts.rs:159-162 serves it.
    assert!(!bound_correction(&set, &observations(rows, priors), &corrections).expect("reads"));
}

/// A set identity the observations do not serve is a typed error.
#[test]
fn bound_correction_missing_anchor_is_typed_error() {
    let head = claim(0x200);
    let rows = vec![candidate_value(0, MEMBER_TOKEN, true)];
    let priors = vec![prior_value(&head, &[0], &[0])];
    let set = judge_set(vec![0], ANCHOR_TOKEN, vec![head.clone()], vec![0]);
    let corrections = vec![correction(0, head)];
    // crate: crates/oneiron-dreamer/src/conflict_decisions/questions.rs:185-192 finds the first identity-token row.
    assert!(bound_correction(&set, &observations(rows, priors), &corrections).is_err());
}

/// A named prior head the observations do not serve is a typed error.
#[test]
fn bound_correction_missing_named_prior_is_typed_error() {
    let head = claim(0x200);
    let other = claim(0x201);
    let rows = vec![candidate_value(0, ANCHOR_TOKEN, true)];
    let priors = vec![prior_value(&other, &[0], &[0])];
    let set = judge_set(vec![0], ANCHOR_TOKEN, vec![head.clone()], vec![0]);
    let corrections = vec![correction(0, head)];
    // native: crates/oneiron/src/dreamer_consolidation/executor/conflicts.rs:63-66 looks the prior head up.
    assert!(bound_correction(&set, &observations(rows, priors), &corrections).is_err());
}
