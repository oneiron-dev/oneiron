//! [DECIDE-PATH-TWO-UNPINNED-SITES] (ARCH-0076 #decide-required: "Every
//! such call goes through decide()"): the judge label recheck's fits
//! judgment per pending pick is a typed question on the decision ladder,
//! never a verdict the host parses on its own.
//!
//! One pending pick goes to the host's Coach model, lent as the ladder's
//! one Big rung: one registered `skill_optimize.judge_label_fit` question,
//! keyed by the checker protocol and the rubric. Only a final yes or no
//! reads as a verdict, yes the pick still fits the rubric; an abstaining
//! pick is not decided. The host reads a decided yes as a fit and a
//! decided no as a conflict, settled exactly as before the move.
//!
//! The host's own provider (`oneiron-server` `RecheckJudge`, the Coach's
//! seat and wire) is not reachable from this crate; this test drives the
//! engine path every host provider is asked through.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test judge_label_recheck_decide`.

use std::sync::Mutex;
use std::time::Duration;

use oneiron::dreamer_runner::maintenance::judge_label_rechecks::{
    JudgeLabelFitCheck, JudgeLabelFitDecision, JudgeLabelFitDecisions,
};
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBandPolicy, DecisionCall, DecisionPack, DecisionProvider, DecisionRung,
    ProviderDecision, ProviderPin,
};
use oneiron::model_decision::AnswerContract;
use oneiron::model_decision::catalogue::JUDGE_LABEL_FIT;
use oneiron::{EntityId, Result};
use serde_json::{Value, json};

const PROTOCOL: [u8; 32] = [0x5e; 32];
const RUBRIC: [u8; 32] = [0x72; 32];
const WORDING: &str = "Does this earlier pick still fit the judge rubric now in force?";

/// The Coach's model as a host lends it, the ladder's one Big rung: yes
/// (the pick still fits), no, or an abstain, as it is told. It records the
/// question ids and the evidence of every pack it is asked.
struct CountingJudge {
    fits: Option<bool>,
    asked: Mutex<Vec<Vec<EntityId>>>,
    evidence: Mutex<Vec<Vec<EntityId>>>,
}

impl CountingJudge {
    fn new(fits: Option<bool>) -> Self {
        Self {
            fits,
            asked: Mutex::new(Vec::new()),
            evidence: Mutex::new(Vec::new()),
        }
    }

    fn asked(&self) -> Vec<Vec<EntityId>> {
        self.asked.lock().expect("asked lock").clone()
    }

    fn evidence(&self) -> Vec<Vec<EntityId>> {
        self.evidence.lock().expect("evidence lock").clone()
    }
}

impl DecisionProvider for CountingJudge {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Big,
            model: "coach-model".into(),
            version: "1".into(),
        }
    }

    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        let pack = DecisionPack {
            questions: std::slice::from_ref(&call.question),
            evidence: call.evidence,
            images: call.images,
            audio: call.audio,
            state: call.state,
            deadline: call.deadline,
            run: call.run,
            labels: call.labels,
        };
        Ok(self
            .decide_pack(&pack)?
            .pop()
            .expect("one answer per question"))
    }

    fn decide_pack(&self, pack: &DecisionPack<'_>) -> Result<Vec<ProviderDecision>> {
        self.asked
            .lock()
            .expect("asked lock")
            .push(pack.questions.iter().map(|question| question.id).collect());
        self.evidence
            .lock()
            .expect("evidence lock")
            .push(pack.evidence.to_vec());
        Ok(pack
            .questions
            .iter()
            .map(|_| {
                let (answer, probability) = match self.fits {
                    Some(true) => (DecisionAnswer::Noul(true), Some(0.95)),
                    Some(false) => (DecisionAnswer::Noul(false), Some(0.05)),
                    None => (DecisionAnswer::Abstain, None),
                };
                ProviderDecision {
                    answer,
                    probability,
                    paired: None,
                    person: None,
                    served: None,
                    cost_per_thousand: None,
                }
            })
            .collect())
    }
}

/// A recheck's state as a host builds it: the pick's question beside the
/// rubric, the case and the option the person picked.
fn recheck_state(check: &JudgeLabelFitCheck) -> Value {
    json!({
        "question": check.question().id.to_hex(),
        "rubric": "the edited judge rubric",
        "case": {
            "campaign": "calibration",
            "evidence": "one judged case",
            "options": ["the first answer", "the second answer"],
        },
        "picked": "the first answer",
    })
}

fn decide(
    check: &JudgeLabelFitCheck,
    principal: EntityId,
    evidence: &[EntityId],
    state: &Value,
    judge: &CountingJudge,
) -> JudgeLabelFitDecision {
    let bands = DecisionBandPolicy::default();
    check
        .decide(
            principal,
            evidence,
            state,
            &JudgeLabelFitDecisions {
                judge,
                bands: &bands,
                budget: Duration::from_secs(60),
            },
        )
        .expect("the ladder decides")
}

#[test]
fn judge_label_fits_is_decided_on_the_ladder_by_the_coach_provider() {
    let check =
        JudgeLabelFitCheck::new(&PROTOCOL, &RUBRIC, WORDING).expect("the registered question");

    // One registered question for the pick, keyed by the protocol and the
    // rubric.
    let expected = JUDGE_LABEL_FIT
        .question(
            &[&PROTOCOL, &RUBRIC],
            WORDING.to_owned(),
            AnswerContract::Noul,
        )
        .expect("the registered question");
    let question = check.question();
    assert_eq!(question.id, expected.id, "the registered family's question");
    assert_eq!(
        question.version, JUDGE_LABEL_FIT.version,
        "the registered family's version"
    );
    assert_eq!(
        question.contract,
        AnswerContract::Noul,
        "a yes/no question: {question:?}"
    );
    let other_rubric =
        JudgeLabelFitCheck::new(&PROTOCOL, &[0x73; 32], WORDING).expect("the registered question");
    assert_ne!(
        other_rubric.question().id,
        question.id,
        "a recheck against another rubric is another question"
    );

    // The label's own row and the rubric's skill revision, the rows a
    // host's recheck state is read from.
    let evidence = [EntityId::now(), EntityId::now()];
    let principal = EntityId::now();
    let judge = CountingJudge::new(Some(true));
    let decided = decide(&check, principal, &evidence, &recheck_state(&check), &judge);

    // The judge was asked through the ladder: the pick's question, in one
    // pack, on its rows.
    assert_eq!(
        judge.asked(),
        vec![vec![question.id]],
        "the Coach provider reads the pick's question in one pack"
    );
    assert_eq!(
        judge.evidence(),
        vec![evidence.to_vec()],
        "the rows the state was read from reach the provider"
    );
    let (fits, decision) = match decided {
        JudgeLabelFitDecision::Decided { fits, decision } => (fits, decision),
        other => panic!("the pick was answered yes: {other:?}"),
    };
    assert!(fits, "a decided yes reads as the pick still fitting");
    assert_eq!(decision.answer, DecisionAnswer::Noul(true));
    assert_eq!(decision.receipt.question, question.id);
    assert_eq!(decision.receipt.principal, principal);
    assert_eq!(
        decision.receipt.providers.last(),
        Some(&judge.pin()),
        "the Coach provider answered: {:?}",
        decision.receipt
    );
}

#[test]
fn a_decided_no_reads_as_the_pick_not_fitting() {
    let check =
        JudgeLabelFitCheck::new(&PROTOCOL, &RUBRIC, WORDING).expect("the registered question");
    let judge = CountingJudge::new(Some(false));
    let decided = decide(&check, EntityId::now(), &[], &recheck_state(&check), &judge);
    let (fits, decision) = match decided {
        JudgeLabelFitDecision::Decided { fits, decision } => (fits, decision),
        other => panic!("the pick was answered no: {other:?}"),
    };
    assert!(!fits, "a decided no reads as the pick not fitting");
    assert_eq!(decision.answer, DecisionAnswer::Noul(false));
    assert_eq!(
        judge.asked(),
        vec![vec![check.question().id]],
        "no stronger rung and no person is asked"
    );
}

#[test]
fn an_abstaining_pick_is_not_decided() {
    let check =
        JudgeLabelFitCheck::new(&PROTOCOL, &RUBRIC, WORDING).expect("the registered question");
    let judge = CountingJudge::new(None);
    let decided = decide(&check, EntityId::now(), &[], &recheck_state(&check), &judge);
    assert_eq!(decided, JudgeLabelFitDecision::Inconclusive);
    assert_eq!(
        judge.asked().len(),
        1,
        "no stronger rung and no person is asked"
    );
}
