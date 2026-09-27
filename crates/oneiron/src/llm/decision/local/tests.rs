use super::*;
use crate::llm::decision::{DecisionBand, DecisionClass};

struct FixedHead {
    scores: Vec<f64>,
}
impl LabelClassifier for FixedHead {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Local,
            model: "fixture/gliner".into(),
            version: "rev-1".into(),
        }
    }
    fn scores(&self, question: &str, unit: &str, labels: &[String]) -> Result<Vec<f64>> {
        assert_eq!(question, "Does this fit the intent?");
        assert_eq!(unit, "bounded fixture");
        assert_eq!(labels, &["yes", "no"]);
        Ok(self.scores.clone())
    }
}
fn question() -> DecisionQuestion {
    DecisionQuestion {
        id: EntityId::now(),
        version: 1,
        text: "Does this fit the intent?".into(),
        class: DecisionClass::Triage,
        contract: AnswerContract::Noul,
        accept_type: false,
    }
}
fn dial(first: DecisionRung, ceiling: DecisionRung) -> DecisionDial {
    DecisionDial {
        first,
        ceiling,
        band: DecisionBand::default(),
    }
}
fn input<'a>(
    question: &'a DecisionQuestion,
    unit: &'a str,
    resident: DecisionDial,
) -> DecisionInput<'a> {
    DecisionInput {
        question,
        principal: question.id,
        unit,
        evidence: &[],
        owner: dial(DecisionRung::Rule, DecisionRung::Local),
        resident,
    }
}

#[test]
fn fixed_labels_and_receipt() {
    let q = question();
    let seat = LocalDecisionSeat {
        head: Some(FixedHead {
            scores: vec![0.91, 0.09],
        }),
        rules: vec![],
    };
    let answer = seat
        .answer(input(
            &q,
            "bounded fixture",
            dial(DecisionRung::Local, DecisionRung::Local),
        ))
        .unwrap();
    assert_eq!(answer.answer, DecisionAnswer::Noul(true));
    assert_eq!(answer.probability, Some(0.91));
    assert_eq!(answer.receipt.question, q.id);
    assert_eq!(answer.receipt.question_version, 1);
    assert_eq!(
        answer.receipt.providers,
        vec![seat.head.as_ref().unwrap().pin()]
    );
    assert!(!answer.in_band);
}

#[test]
fn no_model_exact_rule_and_arithmetic_or_abstain() {
    let q = question();
    let rule = DecisionRule {
        question: q.clone(),
        unit: "bounded fixture".into(),
        expression: RuleExpression::Exact(DecisionAnswer::Noul(true)),
    };
    let seat: LocalDecisionSeat<FixedHead> = LocalDecisionSeat {
        head: None,
        rules: vec![rule],
    };
    let answer = seat
        .answer(input(
            &q,
            "bounded fixture",
            dial(DecisionRung::Rule, DecisionRung::Local),
        ))
        .unwrap();
    assert_eq!(answer.answer, DecisionAnswer::Noul(true));
    assert!(answer.receipt.providers.is_empty());
    let other = seat
        .answer(input(
            &q,
            "different unit",
            dial(DecisionRung::Rule, DecisionRung::Local),
        ))
        .unwrap();
    assert_eq!(other.answer, DecisionAnswer::Abstain);
    assert_eq!(other.human_ask, Some(HumanAskReason::ProviderUnavailable));
    let mut revised = q.clone();
    revised.version = 2;
    assert_eq!(
        seat.answer(input(
            &revised,
            "bounded fixture",
            dial(DecisionRung::Rule, DecisionRung::Local)
        ))
        .unwrap()
        .answer,
        DecisionAnswer::Abstain
    );
    let mut score_q = q;
    score_q.contract = AnswerContract::Score { min: 0.0, max: 1.0 };
    let math: LocalDecisionSeat<FixedHead> = LocalDecisionSeat {
        head: None,
        rules: vec![DecisionRule {
            question: score_q.clone(),
            unit: "one of four".into(),
            expression: RuleExpression::Ratio {
                numerator: 1.0,
                denominator: 4.0,
            },
        }],
    };
    let result = math
        .answer(input(
            &score_q,
            "one of four",
            dial(DecisionRung::Rule, DecisionRung::Local),
        ))
        .unwrap();
    assert_eq!(result.answer, DecisionAnswer::Score(0.25));
    assert_eq!(result.probability, None);
    assert_eq!(
        math.answer(input(
            &score_q,
            "other",
            dial(DecisionRung::Rule, DecisionRung::Local)
        ))
        .unwrap()
        .answer,
        DecisionAnswer::Abstain
    );
}

#[test]
fn malformed_model_or_math_never_invents_an_answer() {
    let q = question();
    let head = LocalDecisionSeat {
        head: Some(FixedHead {
            scores: vec![f64::NAN, 0.9],
        }),
        rules: vec![],
    };
    assert_eq!(
        head.answer(input(
            &q,
            "bounded fixture",
            dial(DecisionRung::Local, DecisionRung::Local)
        ))
        .unwrap()
        .answer,
        DecisionAnswer::Abstain
    );
    let mut score_q = q;
    score_q.contract = AnswerContract::Score { min: 0.0, max: 1.0 };
    let math: LocalDecisionSeat<FixedHead> = LocalDecisionSeat {
        head: None,
        rules: vec![DecisionRule {
            question: score_q.clone(),
            unit: "bounded fixture".into(),
            expression: RuleExpression::Ratio {
                numerator: 1.0,
                denominator: 0.0,
            },
        }],
    };
    assert!(
        math.answer(input(
            &score_q,
            "bounded fixture",
            dial(DecisionRung::Rule, DecisionRung::Local)
        ))
        .is_err()
    );
}

#[test]
fn band_endpoints_and_accept_type_negative_fail_closed() {
    let q = question();
    for p in [0.35, 0.5, 0.65] {
        let seat = LocalDecisionSeat {
            head: Some(FixedHead {
                scores: vec![p, 1.0 - p],
            }),
            rules: vec![],
        };
        let result = seat
            .answer(input(
                &q,
                "bounded fixture",
                dial(DecisionRung::Local, DecisionRung::Local),
            ))
            .unwrap();
        assert!(result.in_band);
        assert_eq!(result.answer, DecisionAnswer::Abstain);
        assert_eq!(result.human_ask, Some(HumanAskReason::Uncertain));
    }
    let mut accept = q;
    accept.accept_type = true;
    let seat = LocalDecisionSeat {
        head: Some(FixedHead {
            scores: vec![0.05, 0.95],
        }),
        rules: vec![],
    };
    let result = seat
        .answer(input(
            &accept,
            "bounded fixture",
            dial(DecisionRung::Local, DecisionRung::Local),
        ))
        .unwrap();
    assert_eq!(result.answer, DecisionAnswer::Abstain);
    assert_eq!(result.human_ask, Some(HumanAskReason::Uncertain));
}

#[test]
fn binary_head_must_agree_with_yes_probability_and_owner_band() {
    let q = question();
    let default_band = DecisionBand::default();
    let asymmetric_band = DecisionBand {
        low: 0.70,
        high: 0.80,
    };
    for (scores, band, expected) in [
        (vec![0.20, 0.10], default_band, DecisionAnswer::Abstain),
        (vec![0.80, 0.90], default_band, DecisionAnswer::Abstain),
        (vec![0.60, 0.40], asymmetric_band, DecisionAnswer::Abstain),
        (vec![0.20, 0.90], default_band, DecisionAnswer::Noul(false)),
        (vec![0.90, 0.20], default_band, DecisionAnswer::Noul(true)),
    ] {
        let expected_probability = scores[0];
        let seat = LocalDecisionSeat {
            head: Some(FixedHead { scores }),
            rules: vec![],
        };
        let mut request = input(
            &q,
            "bounded fixture",
            dial(DecisionRung::Local, DecisionRung::Local),
        );
        request.owner.band = band;
        request.resident.band = band;
        let result = seat.answer(request).unwrap();
        assert_eq!(result.answer, expected);
        assert_eq!(result.probability, Some(expected_probability));
        assert!(!result.in_band);
        assert_eq!(
            result.human_ask,
            matches!(expected, DecisionAnswer::Abstain).then_some(HumanAskReason::Uncertain)
        );
    }
}

struct TiedChoiceHead;
impl LabelClassifier for TiedChoiceHead {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Local,
            model: "fixture/gliner".into(),
            version: "rev-1".into(),
        }
    }
    fn scores(&self, question: &str, unit: &str, labels: &[String]) -> Result<Vec<f64>> {
        assert_eq!(question, "Does this fit the intent?");
        assert_eq!(unit, "bounded fixture");
        assert_eq!(labels, &["a", "b", "c", "d"]);
        Ok(vec![0.30, 0.30, 0.30, 0.10])
    }
}

#[test]
fn tied_choice_outside_band_is_uncertain_not_unavailable() {
    let mut q = question();
    q.contract = AnswerContract::Choice {
        options: ["a", "b", "c", "d"].map(str::to_owned).to_vec(),
    };
    let seat = LocalDecisionSeat {
        head: Some(TiedChoiceHead),
        rules: vec![],
    };
    let result = seat
        .answer(input(
            &q,
            "bounded fixture",
            dial(DecisionRung::Local, DecisionRung::Local),
        ))
        .unwrap();
    assert_eq!(result.answer, DecisionAnswer::Abstain);
    assert_eq!(result.probability, Some(0.30));
    assert!(!result.in_band);
    assert_eq!(result.human_ask, Some(HumanAskReason::Uncertain));
    assert_eq!(result.receipt.providers, vec![seat.head.unwrap().pin()]);
}

#[test]
fn resident_range_can_only_shrink() {
    let q = question();
    let seat: LocalDecisionSeat<FixedHead> = LocalDecisionSeat {
        head: None,
        rules: vec![],
    };
    for (owner, resident) in [
        (
            dial(DecisionRung::Local, DecisionRung::Local),
            dial(DecisionRung::Rule, DecisionRung::Local),
        ),
        (
            dial(DecisionRung::Rule, DecisionRung::Local),
            dial(DecisionRung::Rule, DecisionRung::Big),
        ),
        (
            dial(DecisionRung::Local, DecisionRung::Rule),
            dial(DecisionRung::Rule, DecisionRung::Rule),
        ),
    ] {
        let mut request = input(&q, "bounded fixture", resident);
        request.owner = owner;
        assert!(seat.answer(request).is_err());
    }
    let mut changed = dial(DecisionRung::Local, DecisionRung::Local);
    changed.band.high = 0.7;
    assert!(seat.answer(input(&q, "bounded fixture", changed)).is_err());
    let narrower = dial(DecisionRung::Rule, DecisionRung::Rule);
    assert!(seat.answer(input(&q, "bounded fixture", narrower)).is_ok());
}
