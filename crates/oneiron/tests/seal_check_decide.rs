//! DECIDE-BYPASS-2 (ARCH-0076 #decide-required: "Every such call goes
//! through decide()"): the seal checker's flaw judgment per objective is a
//! typed question on the decision ladder, never a verdict the host parses
//! on its own.
//!
//! One check of two objectives goes to the host's independent judge, lent
//! as the ladder's one Big rung: one registered `dreamer.seal.objective_flaw`
//! question per objective, keyed by the checker's protocol, the check's kind
//! and the objective, asked in one pack. Only a final yes or no for every
//! objective reads as findings, yes a flaw present, each naming the result
//! the judge read; one abstaining objective leaves the whole check undecided,
//! and a repeated objective is never asked.
//!
//! The host's own provider (`oneiron-server` `SealJudge`, the Coach's seat
//! and wire) is not reachable from this crate; this test drives the engine
//! path every host provider is asked through.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test seal_check_decide`.

use std::sync::Mutex;
use std::time::Duration;

use oneiron::dreamer_runner::maintenance::seal_checks::{
    SealObjectiveCheck, SealObjectiveDecision, SealObjectiveDecisions,
};
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBandPolicy, DecisionCall, DecisionPack, DecisionProvider, DecisionRung,
    ProviderDecision, ProviderPin,
};
use oneiron::model_decision::AnswerContract;
use oneiron::model_decision::catalogue::SEAL_OBJECTIVE_FLAW;
use oneiron::self_heal::audit::{ObjectiveFinding, SealCheckKind};
use oneiron::{EntityId, Result};
use serde_json::{Value, json};

const PROTOCOL: [u8; 32] = [0x5e; 32];
const WORDING: &str =
    "Does a flaw keep this objective from being met, judged from the result alone?";
const RESULT_REF: &str = "output:result-under-check";
const COVERED: &str = "every endpoint has a test";
const DOCUMENTED: &str = "the change is documented";

/// The independent judge as a host lends it, the ladder's one Big rung: by
/// the objective the state shows beside each question's id, yes (a flaw)
/// for those in `flawed`, an abstain for those in `unsure`, no for the
/// rest. It records the question ids of every pack it is asked.
struct CountingJudge {
    flawed: &'static [&'static str],
    unsure: &'static [&'static str],
    asked: Mutex<Vec<Vec<EntityId>>>,
}

impl CountingJudge {
    fn new(flawed: &'static [&'static str], unsure: &'static [&'static str]) -> Self {
        Self {
            flawed,
            unsure,
            asked: Mutex::new(Vec::new()),
        }
    }

    fn asked(&self) -> Vec<Vec<EntityId>> {
        self.asked.lock().expect("asked lock").clone()
    }
}

impl DecisionProvider for CountingJudge {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Big,
            model: "independent-judge".into(),
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
        Ok(pack
            .questions
            .iter()
            .map(|question| {
                let objective = objective_beside(pack.state, question.id);
                let (answer, probability) = if self.unsure.contains(&objective.as_str()) {
                    (DecisionAnswer::Abstain, None)
                } else if self.flawed.contains(&objective.as_str()) {
                    (DecisionAnswer::Noul(true), Some(0.95))
                } else {
                    (DecisionAnswer::Noul(false), Some(0.05))
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

/// The objective `state` shows beside `question`'s id.
fn objective_beside(state: &Value, question: EntityId) -> String {
    state["objectives"]
        .as_array()
        .expect("objectives")
        .iter()
        .find(|entry| entry["question"] == question.to_hex())
        .and_then(|entry| entry["objective"].as_str())
        .expect("each asked question has its objective in the state")
        .to_owned()
}

/// A random audit's state as a host builds it: each objective beside its
/// question's id, and the result.
fn audit_state(check: &SealObjectiveCheck, objectives: &[&str]) -> Value {
    let objectives: Vec<Value> = objectives
        .iter()
        .zip(check.questions())
        .map(|(objective, question)| {
            json!({ "question": question.id.to_hex(), "objective": objective })
        })
        .collect();
    json!({ "check": "random_audit", "objectives": objectives, "result": "the attempt's answer" })
}

fn decide(
    check: &SealObjectiveCheck,
    principal: EntityId,
    state: &Value,
    judge: &CountingJudge,
) -> SealObjectiveDecision {
    let bands = DecisionBandPolicy::default();
    check
        .decide(
            principal,
            RESULT_REF,
            state,
            &SealObjectiveDecisions {
                judge,
                bands: &bands,
                budget: Duration::from_secs(60),
            },
        )
        .expect("the ladder decides")
}

#[test]
fn seal_objectives_are_decided_on_the_ladder_by_the_independent_judge() {
    let objectives = [COVERED, DOCUMENTED];
    let check =
        SealObjectiveCheck::new(SealCheckKind::RandomAudit, &objectives, &PROTOCOL, WORDING)
            .expect("questions")
            .expect("distinct objectives");

    // One registered question per objective, keyed by the protocol, the
    // check's kind and the objective.
    let covered = blake3::hash(COVERED.as_bytes());
    let expected = SEAL_OBJECTIVE_FLAW
        .question(
            &[&PROTOCOL, b"random_audit", covered.as_bytes()],
            WORDING.to_owned(),
            AnswerContract::Noul,
        )
        .expect("the registered question");
    let questions = check.questions();
    assert_eq!(questions.len(), 2, "one question per objective");
    assert_eq!(
        questions[0].id, expected.id,
        "the registered family's question"
    );
    assert!(
        questions
            .iter()
            .all(|question| question.version == SEAL_OBJECTIVE_FLAW.version
                && question.contract == AnswerContract::Noul),
        "yes/no questions of the registered family: {questions:?}"
    );
    assert_ne!(
        questions[0].id, questions[1].id,
        "each objective its own question"
    );
    let recheck = SealObjectiveCheck::new(
        SealCheckKind::ConfessionRecheck,
        &objectives,
        &PROTOCOL,
        WORDING,
    )
    .expect("questions")
    .expect("distinct objectives");
    assert_ne!(
        recheck.questions()[0].id,
        questions[0].id,
        "a recheck's question is not an audit's"
    );

    let principal = EntityId::now();
    let judge = CountingJudge::new(&[COVERED], &[]);
    let decided = decide(&check, principal, &audit_state(&check, &objectives), &judge);

    // The judge was asked through the ladder: both questions, in one pack.
    assert_eq!(
        judge.asked(),
        vec![vec![questions[0].id, questions[1].id]],
        "the independent judge reads both objectives' questions in one pack"
    );
    let (findings, decisions) = match decided {
        SealObjectiveDecision::Decided {
            findings,
            decisions,
        } => (findings, decisions),
        other => panic!("both objectives answered: {other:?}"),
    };
    assert_eq!(
        findings,
        vec![
            ObjectiveFinding {
                objective: COVERED.to_owned(),
                flaw_present: true,
                evidence_ref: RESULT_REF.to_owned(),
            },
            ObjectiveFinding {
                objective: DOCUMENTED.to_owned(),
                flaw_present: false,
                evidence_ref: RESULT_REF.to_owned(),
            },
        ],
        "yes is a flaw present, each finding names the result the judge read"
    );
    assert_eq!(decisions.len(), 2, "one typed decision per objective");
    for ((decision, question), flaw) in decisions.iter().zip(questions).zip([true, false]) {
        assert_eq!(decision.answer, DecisionAnswer::Noul(flaw));
        assert_eq!(decision.receipt.question, question.id);
        assert_eq!(decision.receipt.principal, principal);
        assert_eq!(
            decision.receipt.providers.last(),
            Some(&judge.pin()),
            "the independent judge answered: {:?}",
            decision.receipt
        );
    }
}

#[test]
fn an_abstaining_objective_leaves_the_whole_check_undecided() {
    let objectives = [COVERED, DOCUMENTED];
    let check =
        SealObjectiveCheck::new(SealCheckKind::RandomAudit, &objectives, &PROTOCOL, WORDING)
            .expect("questions")
            .expect("distinct objectives");
    let judge = CountingJudge::new(&[COVERED], &[DOCUMENTED]);
    let decided = decide(
        &check,
        EntityId::now(),
        &audit_state(&check, &objectives),
        &judge,
    );
    assert_eq!(decided, SealObjectiveDecision::Inconclusive);
    assert_eq!(
        judge.asked().len(),
        1,
        "no stronger rung and no person is asked"
    );
}

#[test]
fn a_repeated_objective_is_never_asked() {
    let check = SealObjectiveCheck::new(
        SealCheckKind::ConfessionRecheck,
        &[COVERED, COVERED],
        &PROTOCOL,
        WORDING,
    )
    .expect("questions");
    assert!(
        check.is_none(),
        "one question cannot stand for two findings"
    );
}
