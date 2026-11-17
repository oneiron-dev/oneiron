// [SKILL-JUDGMENT-SCORES-CUT-INSTRUCTIONS]: a judgment whose instructions were
// cut to fit the decision state bound refuses before the ladder is asked, so a
// prefix is never scored as the whole. A cut of the reserve sample alone, with
// the instructions whole, still scores.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use oneiron::EntityId;
use oneiron::error::Result;
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionDial,
    DecisionLadder, DecisionProvider, DecisionQuestion, DecisionRung, HumanDecisionQueue,
    HumanDecisionRequest, ProviderDecision, ProviderPin, TypedDecision,
};
use oneiron::model_decision::MAX_DECISION_STATE_BYTES;
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill_optimize::{
    HeldOutReplayCase, HeldOutReplayNotes, SkillOptimizeDecisions, SkillReplayResponses,
};
use oneiron::test_doors::skill_judgment_cut::score_case;
use serde_json::{Value, json};

struct NoPerson;
impl HumanDecisionQueue for NoPerson {
    fn queue(&self, _: HumanDecisionRequest) -> Result<()> {
        panic!("fixture must not ask a person");
    }
}

fn ladder(provider: &dyn DecisionProvider) -> DecisionLadder<'_> {
    DecisionLadder {
        rule: None,
        local: None,
        system_one: Some(provider),
        escalation: None,
        big: None,
        human: &NoPerson,
        human_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: "no-person".to_owned(),
            version: "1".to_owned(),
        },
        ask_to: None,
        paired: None,
        person: None,
        presence: None,
        correlation: None,
    }
}

fn dial() -> DecisionDial {
    DecisionDial {
        first: DecisionRung::SystemOne,
        ceiling: DecisionRung::Human,
        band: DecisionBand::default(),
    }
}

/// A judge that answers every score 0.9 at probability 0.9, and remembers
/// whether it was asked and how many decisions were recorded.
struct Stub {
    principal: EntityId,
    deadline: RetrievalDeadline,
    wording: BTreeMap<String, String>,
    asked: AtomicBool,
    recorded: AtomicU32,
}

impl Stub {
    fn new() -> Self {
        Self {
            principal: EntityId::now(),
            deadline: RetrievalDeadline::after(Duration::from_secs(3600)),
            wording: BTreeMap::from([("score".to_owned(), "Score the held-out replay".to_owned())]),
            asked: AtomicBool::new(false),
            recorded: AtomicU32::new(0),
        }
    }
}

impl DecisionProvider for Stub {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::SystemOne,
            model: "fixture-judge".to_owned(),
            version: "1".to_owned(),
        }
    }
    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        self.asked.store(true, Ordering::SeqCst);
        assert!(matches!(
            call.question.contract,
            AnswerContract::Score { .. }
        ));
        Ok(ProviderDecision {
            answer: DecisionAnswer::Score(0.9),
            probability: Some(0.9),
            paired: None,
            person: None,
            served: None,
            cost_per_thousand: None,
        })
    }
}

impl HeldOutReplayNotes for Stub {
    fn judge_revision(&self) -> &str {
        "fixture-judge@1"
    }
    fn decisions(&self) -> SkillOptimizeDecisions<'_> {
        SkillOptimizeDecisions {
            ladder: ladder(self),
            principal: self.principal,
            dial: dial(),
            bands: DecisionBandPolicy::default(),
            deadline: &self.deadline,
            wording: &self.wording,
        }
    }
    fn replay_state(&self, case: &HeldOutReplayCase<'_>) -> Result<Value> {
        Ok(json!({ "held_out_receipts": case.held_out_receipts }))
    }
    fn replay_responses(&self, _: &[String]) -> Result<SkillReplayResponses> {
        panic!("whole-reserve scores never read replay responses");
    }
    fn record_decision(&self, _: &DecisionQuestion, _: &TypedDecision, _: &Value) -> Result<()> {
        self.recorded.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// Instructions longer than the whole decision state bound, with one receipt:
/// the text alone overflows the bound, so fitting the state must cut the
/// instructions. The judgment refuses before the ladder is asked.
#[test]
fn cut_instructions_refuse_before_ask() {
    let stub = Stub::new();
    let judge: &dyn HeldOutReplayNotes = &stub;
    let instructions = "a".repeat(MAX_DECISION_STATE_BYTES + 4_464);
    assert!(instructions.len() > MAX_DECISION_STATE_BYTES);
    let held_out = vec!["fixture-receipt-1".to_owned()];
    let result = score_case(
        judge,
        EntityId::now(),
        "fixture.skill",
        "2",
        &instructions,
        &held_out,
    );
    assert!(
        result.is_err(),
        "a cut judgment must not score, got {result:?}"
    );
    assert!(
        !stub.asked.load(Ordering::SeqCst),
        "the refusal happens before the ladder is asked"
    );
    assert_eq!(
        stub.recorded.load(Ordering::SeqCst),
        0,
        "no decision is recorded for a refused judgment"
    );
}

/// Short instructions fit whole and score as today.
#[test]
fn whole_instructions_score() {
    let stub = Stub::new();
    let judge: &dyn HeldOutReplayNotes = &stub;
    let held_out = vec!["fixture-receipt-1".to_owned()];
    let score = score_case(
        judge,
        EntityId::now(),
        "fixture.skill",
        "2",
        "follow the steps",
        &held_out,
    )
    .expect("whole instructions score");
    assert_eq!(score, 0.9);
    assert!(stub.asked.load(Ordering::SeqCst));
    assert_eq!(stub.recorded.load(Ordering::SeqCst), 1);
}

/// A reserve too large to fit beside whole instructions cuts receipts, not
/// text: the judgment still scores.
#[test]
fn reserve_cut_still_scores() {
    let stub = Stub::new();
    let judge: &dyn HeldOutReplayNotes = &stub;
    let held_out: Vec<String> = (0..200)
        .map(|n| format!("receipt-{n:03}-{}", "b".repeat(500)))
        .collect();
    let score = score_case(
        judge,
        EntityId::now(),
        "fixture.skill",
        "2",
        "follow the steps",
        &held_out,
    )
    .expect("a reserve-only cut still scores");
    assert_eq!(score, 0.9);
    assert!(stub.asked.load(Ordering::SeqCst));
    assert_eq!(stub.recorded.load(Ordering::SeqCst), 1);
}
