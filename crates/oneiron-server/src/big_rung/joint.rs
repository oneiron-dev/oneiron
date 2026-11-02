//! The Big rung's joint reading (FIX 1557). Over a route whose every offer
//! reports token log-probabilities, a yes/no or choice question is read
//! jointly with the host's paired question ("does this need more
//! thinking?"), as the house label read reads it (ARCH-0076: Q1 and Q2 stay
//! joint). The reply is one letter naming a joint label. The scores of its
//! first token's top alternatives, normalized over the joint labels, give
//! the answer's marginal and that answer's own paired P(yes). A route without
//! the capability keeps the written reply and records no joint reading.
use std::collections::BTreeMap;

use oneiron::LlmCapability;
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionCall, DecisionQuestion, PairedAnswer, ProviderDecision,
};
use oneiron::llm::joint_marginals;
use serde_json::{Value, json};

use super::{BigModel, ResolvedDecisionRoute};

/// The most alternatives one reply token's scores are asked for, the
/// OpenAI-compatible bound.
const TOP_LOGPROBS: usize = 20;
/// The letters joint labels are named by, one per alternative a reply token
/// reports, so every label's score can come back.
const LABEL_LETTERS: &str = "ABCDEFGHIJKLMNOPQRST";
/// The most options a joint read takes: two joint labels each. A wider
/// choice keeps the written reply.
const MAX_JOINT_OPTIONS: usize = TOP_LOGPROBS / 2;

/// One call's joint labels: for each of its options in order, the label for
/// (option, paired no), then (option, paired yes), as the house read orders
/// its rows.
pub(super) struct JointRead {
    paired: DecisionQuestion,
    options: Vec<String>,
}

impl BigModel {
    /// The joint read `call` takes on `route`: a yes/no, or a choice of at
    /// most [`MAX_JOINT_OPTIONS`], with the host's paired question bound and
    /// every offer of the route reporting token log-probabilities. `None`
    /// keeps the written reply.
    pub(super) fn joint_read(
        &self,
        call: &DecisionCall<'_>,
        route: &ResolvedDecisionRoute,
    ) -> Option<JointRead> {
        let paired = self.current_paired()?;
        let options = match &call.question.contract {
            AnswerContract::Noul => vec!["yes".to_owned(), "no".to_owned()],
            AnswerContract::Choice { options } if options.len() <= MAX_JOINT_OPTIONS => {
                options.clone()
            }
            _ => return None,
        };
        (paired.id != call.question.id
            && route
                .ladder
                .supports(&route.model, &LlmCapability::TokenLogprobs))
        .then_some(JointRead { paired, options })
    }
}

impl JointRead {
    fn letters(&self) -> impl Iterator<Item = char> + '_ {
        LABEL_LETTERS.chars().take(self.options.len() * 2)
    }

    /// The reply instructions in place of the written reply's: the paired
    /// question, and each joint label's letter with the two answers it names.
    pub(super) fn instructions(&self) -> String {
        let mut text = format!(
            "Also answer this second question: {}\nReply with exactly one letter and nothing \
             else: the one that names both of your answers.",
            self.paired.text
        );
        for (index, letter) in self.letters().enumerate() {
            let paired = if index % 2 == 0 { "no" } else { "yes" };
            text.push_str(&format!(
                "\n{letter}: {}, and {paired} to the second question",
                self.options[index / 2]
            ));
        }
        text
    }

    /// The request params that ask for the reply tokens' scores.
    pub(super) fn params() -> BTreeMap<String, Value> {
        BTreeMap::from([
            ("logprobs".to_owned(), json!(true)),
            ("top_logprobs".to_owned(), json!(TOP_LOGPROBS)),
        ])
    }

    /// The decision the reply's first token's scores give, over `contract`:
    /// the joint readout normalized over the labels it names, its marginals
    /// the answer and the paired P(yes). `None` when the reply reports no
    /// scores, or its first token's alternatives name no label.
    pub(super) fn decision(
        &self,
        contract: &AnswerContract,
        scores: Option<&Value>,
    ) -> Option<ProviderDecision> {
        let alternatives = scores?
            .get("content")?
            .as_array()?
            .first()?
            .get("top_logprobs")?
            .as_array()?;
        let letters: Vec<char> = self.letters().collect();
        let mut weights = vec![0.0_f64; letters.len()];
        for alternative in alternatives {
            let (Some(token), Some(logprob)) = (
                alternative.get("token").and_then(Value::as_str),
                alternative.get("logprob").and_then(Value::as_f64),
            ) else {
                continue;
            };
            let mut chars = token.trim().chars();
            let (Some(letter), None) = (chars.next(), chars.next()) else {
                continue;
            };
            // One label spelled two ways (`A`, ` a`) adds its weights.
            if let Some(index) = letters
                .iter()
                .position(|label| *label == letter.to_ascii_uppercase())
            {
                weights[index] += logprob.exp();
            }
        }
        let total: f64 = weights.iter().sum();
        if !(total.is_finite() && total > 0.0) {
            return None;
        }
        let readout: Vec<f64> = weights.iter().map(|weight| weight / total).collect();
        let (labels, paired) = joint_marginals(&readout);
        // The first label wins a tie, so a tied yes/no reads yes.
        let mut top = 0;
        for (index, p) in labels.iter().enumerate() {
            if *p > labels[top] {
                top = index;
            }
        }
        let (answer, probability) = match contract {
            // A yes/no's probability is P(yes), whichever way it reads.
            AnswerContract::Noul => (DecisionAnswer::Noul(top == 0), labels[0]),
            _ => (
                DecisionAnswer::Choice(self.options[top].clone()),
                labels[top],
            ),
        };
        Some(ProviderDecision {
            answer,
            probability: Some(probability.clamp(0.0, 1.0)),
            paired: Some(PairedAnswer {
                question: self.paired.id,
                question_version: self.paired.version,
                probability: paired.clamp(0.0, 1.0),
            }),
            person: None,
            served: None,
        })
    }
}
