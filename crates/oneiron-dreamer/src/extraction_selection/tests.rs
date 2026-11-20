//! Tests the union rule that reads what the checking read says about corrections.

use super::*;
use crate::extraction_observations::{ListedObservation, PriorObservation, SourceVersion};
use serde_json::json;

/// Names the head the representatives here correct, as 32 lowercase hex digits.
fn head() -> String {
    "c1".repeat(16)
}

/// Pins the head as a cited claim.
fn pin() -> Value {
    json!({
        "claim": head(),
        "version": {
            "entity": head(),
            "entity_type": 0,
            "learned_at": 7,
            "revision": format!("blake3:{}", "ab".repeat(32)),
        },
    })
}

/// Builds one operand that proposes `predicate` and `value`, corrects the head when
/// `corrects`, and cites it when `cites`.
fn operand(predicate: &str, value: &str, corrects: bool, cites: bool) -> Value {
    let mut built = json!({
        "subject": "b1".repeat(16),
        "predicate": predicate,
        "value": value,
        "evidence": [],
    });
    if corrects {
        built["corrects"] = json!(head());
    }
    if cites {
        built["claim_evidence"] = json!([pin()]);
    }
    built
}

/// Groups the two operands of a request under the first.
fn pair() -> CandidateGroups {
    CandidateGroups {
        groups: vec![CandidateGroup {
            representative_index: 0,
            member_indexes: vec![0, 1],
            corrects: None,
        }],
        pending_bindings: Vec::new(),
    }
}

/// Builds the facts of a read that may ask position 0 about the head, may ask
/// position 1 about it when `member_asked`, and proves position 0 different from the
/// head when `differs`.
fn facts(member_asked: bool, differs: bool) -> CorrectionFacts {
    let member = if member_asked {
        vec![head()]
    } else {
        Vec::new()
    };
    CorrectionFacts {
        correctable: BTreeMap::from([(0, vec![head()]), (1, member)]),
        differs: if differs {
            BTreeSet::from([0])
        } else {
            BTreeSet::new()
        },
    }
}

/// Serves one version of the head.
fn version() -> SourceVersion {
    SourceVersion {
        entity: head(),
        entity_type: 0,
        learned_at: 7,
        revision: format!("blake3:{}", "ab".repeat(32)),
        projection: None,
    }
}

/// Builds one candidate row that corrects the head, assembled under `predicate`
/// with the value token `value_token`, and that the read may ask about the head.
fn row(index: usize, predicate: &str, value_token: &str) -> CandidateObservation {
    CandidateObservation {
        index,
        claim: "d4".repeat(16),
        identity_token: "identity".to_owned(),
        topic_token: "topic".to_owned(),
        value_token: value_token.to_owned(),
        slice_token: "slice".to_owned(),
        predicate: predicate.to_owned(),
        corrects: Some(head()),
        meet: "generated".to_owned(),
        observed: false,
        evidence_count: 1,
        first_seen_ms: 1,
        latest_ms: 1,
        diversity: 1,
        fan_in: 0,
        new_refs: 0,
        has_vector: false,
        named_facet: None,
        scope_facet: "f0".repeat(16),
        scope_project: "a0".repeat(16),
        replay_facet: "f0".repeat(16),
        correctable: vec![0],
        single_valued: false,
    }
}

/// A member that cites the head its representative corrects, with the
/// representative's predicate and value and no correction of its own, joins that
/// citation only when its read may ask it about the head.
#[test]
fn union_keeps_a_citation_of_the_corrected_head_from_a_member_asked_about_it() {
    let operands = vec![
        operand("likes", "coffee", true, false),
        operand("likes", "coffee", false, true),
    ];
    let joined = union_operands_with_facts(&operands, &pair(), &facts(true, false));
    assert_eq!(
        joined[0]["claim_evidence"],
        json!([pin()]),
        "a member the read may ask about the head joins its citation of it"
    );
    assert_eq!(
        joined[0]["corrects"],
        json!(head()),
        "the union keeps its representative's correction"
    );
    let left_out = union_operands_with_facts(&operands, &pair(), &facts(false, false));
    assert!(
        left_out[0].get("claim_evidence").is_none(),
        "a member the read does not ask about the head restates it: its citation stays out"
    );
    assert!(
        union_operands(&operands, &pair())[0]
            .get("claim_evidence")
            .is_none(),
        "with the operands alone a member with no correction proves nothing"
    );
}

/// A member that proposes another predicate proves nothing by itself, so its
/// citation of the corrected head stays out, unless the read proves the
/// representative different from that head: then every citation of it joins.
#[test]
fn union_keeps_every_citation_of_the_corrected_head_when_the_read_proves_it_differs() {
    let operands = vec![
        operand("preference.food", "coffee", true, false),
        operand("preference.drink", "coffee", true, true),
    ];
    let left_out = union_operands_with_facts(&operands, &pair(), &facts(true, false));
    assert!(
        left_out[0].get("claim_evidence").is_none(),
        "a member with another predicate proves nothing about the union"
    );
    let joined = union_operands_with_facts(&operands, &pair(), &facts(true, true));
    assert_eq!(
        joined[0]["claim_evidence"],
        json!([pin()]),
        "a representative the read proves different from the head takes every citation"
    );
}

/// A member the read does not ask about the head it cites restates that head, so
/// the head's predicate and value are the member's: a representative with another
/// value does not restate it, and the citation joins.
#[test]
fn union_keeps_a_citation_from_a_member_that_restates_the_head_with_another_value() {
    let operands = vec![
        operand("likes", "Coffee", true, false),
        operand("likes", "coffee", false, true),
    ];
    let joined = union_operands_with_facts(&operands, &pair(), &facts(false, false));
    assert_eq!(
        joined[0]["claim_evidence"],
        json!([pin()]),
        "the head carries the member's value, not the representative's"
    );
}

/// The read's facts: each row's correctable claims by request position, and each
/// correcting operand whose own predicate is not its row's, or whose value token is
/// not the head's while its value is one whose key is exact. A float's key is not: a
/// stored zero and a proposed negative zero are equal as JSON under two keys.
#[test]
fn correction_facts_read_the_pairs_and_the_operands_that_differ_from_their_head() {
    let mut operands = vec![
        operand("preference.food", "coffee", true, false),
        operand("preference.drink", "tea", true, false),
        operand("preference.food", "tea", true, false),
        operand("preference.food", "tea", true, false),
    ];
    operands[3]["value"] = json!(-0.0);
    let observations = Observations {
        attempt: "attempt".to_owned(),
        now_ms: 1,
        policy_pin: "policy".to_owned(),
        facts_pin: "facts".to_owned(),
        candidates: vec![
            row(0, "preference.food", "token-coffee"),
            row(1, "preference.food", "token-tea"),
            row(2, "preference.food", "token-tea"),
            row(3, "preference.food", "token-negative-zero"),
        ],
        listed: vec![ListedObservation {
            claim: head(),
            subject: "b1".repeat(16),
            version: version(),
        }],
        priors: vec![PriorObservation {
            claim: head(),
            version: version(),
            identity_token: "identity".to_owned(),
            topic_token: "topic".to_owned(),
            value_token: "token-tea".to_owned(),
            source: "user_stated".to_owned(),
            standing: "prior".to_owned(),
            writable: true,
            scope_facet: "f0".repeat(16),
            scope_project: "a0".repeat(16),
            scope_equal_candidates: Vec::new(),
            non_widening_candidates: Vec::new(),
            subject_predicate_equal_candidates: Vec::new(),
        }],
        replay: Vec::new(),
        scores: Vec::new(),
    };
    let read = CorrectionFacts::from_read(&operands, &observations);
    assert_eq!(
        read.correctable,
        BTreeMap::from([
            (0, vec![head()]),
            (1, vec![head()]),
            (2, vec![head()]),
            (3, vec![head()]),
        ]),
        "each row's correctable indexes read as the listed claims they name"
    );
    assert_eq!(
        read.differs,
        BTreeSet::from([0, 1]),
        "position 0 by its value token, position 1 by its predicate; positions 2 and 3 prove nothing"
    );
}

/// A union names the recorded step candidates of every member, each once in member
/// order, so the engine finds each joined quote in a record. A group whose members
/// name none carries no `from_steps` key.
#[test]
fn a_union_names_the_recorded_candidates_of_every_member() {
    let step = "5e".repeat(32);
    let mut first = operand("lives_in", "Kyoto", false, false);
    first["from_steps"] = json!([{ "step": step, "index": 0 }]);
    let mut second = operand("lives_in", "Kyoto", false, false);
    second["from_steps"] = json!([{ "step": step, "index": 3 }, { "step": step, "index": 0 }]);
    let unions = union_operands(&[first, second], &pair());
    assert_eq!(
        unions[0]["from_steps"],
        json!([{ "step": step, "index": 0 }, { "step": step, "index": 3 }]),
        "the representative's recorded candidate, then each further member's, each once"
    );
    let plain = union_operands(
        &[
            operand("lives_in", "Kyoto", false, false),
            operand("lives_in", "Kyoto", false, false),
        ],
        &pair(),
    );
    assert!(
        plain[0].get("from_steps").is_none(),
        "a union of operands that name no step names none"
    );
}

/// Builds one operand that proposes a home town with one quote of `turn`, and corrects
/// the head when `corrects`.
fn quoting(turn: &str, corrects: bool) -> Value {
    let mut built = operand("lives_in", "Kyoto", corrects, false);
    built["evidence"] = json!([{ "turn": turn.repeat(16) }]);
    built
}

/// A group that holds a member naming a recorded candidate beside a member naming none
/// is unioned with both quotes and no step name, whichever member represents it: no
/// recorded candidate carries the second member's quote.
#[test]
fn a_union_with_a_member_that_names_no_recorded_candidate_names_none() {
    let step = "5e".repeat(32);
    let mut recorded = quoting("a1", false);
    recorded["from_steps"] = json!([{ "step": step, "index": 0 }]);
    let standalone = quoting("a2", false);
    for operands in [
        [recorded.clone(), standalone.clone()],
        [standalone, recorded],
    ] {
        let unions = union_operands(&operands, &pair());
        assert!(
            unions[0].get("from_steps").is_none(),
            "the union names no recorded candidate: {}",
            unions[0]
        );
        assert_eq!(
            unions[0]["evidence"].as_array().map(Vec::len),
            Some(2),
            "the union carries both members' quotes"
        );
    }
}

/// A correcting union of such a group leaves out the representative's proposed
/// relationship, which the engine reads for no correction. A union that corrects
/// nothing keeps it, and so does a union whose every member names a recorded candidate.
#[test]
fn a_correcting_union_that_names_no_recorded_candidate_proposes_no_relationship() {
    let step = "5e".repeat(32);
    let relationship = json!(["e1".repeat(16)]);
    let named = |turn: &str, corrects: bool, index: usize| {
        let mut built = quoting(turn, corrects);
        built["from_steps"] = json!([{ "step": step, "index": index }]);
        built["rel"] = relationship.clone();
        built
    };
    let unions = union_operands(&[named("a1", true, 0), quoting("a2", true)], &pair());
    assert!(
        unions[0].get("rel").is_none(),
        "the correcting union proposes no relationship: {}",
        unions[0]
    );
    assert_eq!(
        unions[0]["corrects"],
        json!(head()),
        "the union keeps its representative's correction"
    );
    let unions = union_operands(&[named("a1", false, 0), quoting("a2", false)], &pair());
    assert_eq!(
        unions[0]["rel"], relationship,
        "a union that corrects nothing keeps its proposed relationship"
    );
    assert!(
        unions[0].get("from_steps").is_none(),
        "and it names no recorded candidate"
    );
    let unions = union_operands(&[named("a1", true, 0), named("a2", true, 1)], &pair());
    assert_eq!(
        unions[0]["rel"], relationship,
        "a union whose every member names a recorded candidate keeps it"
    );
    assert_eq!(
        unions[0]["from_steps"].as_array().map(Vec::len),
        Some(2),
        "and it names both recorded candidates"
    );
}
