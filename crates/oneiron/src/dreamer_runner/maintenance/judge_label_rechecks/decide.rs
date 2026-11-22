//! The judge label recheck's fits question on the decision ladder
//! (ARCH-0076 #decide-required): "Every such call goes through decide()".
//! One registered question per pending pick ([`JUDGE_LABEL_FIT`]), asked of
//! the host's Coach model as the ladder's one Big rung, with no stronger
//! rung and no person above it; only a final yes or no reads as a verdict,
//! yes the pick still fits. The host keeps the Coach's seat, its wording,
//! the state it shows and the wire it reads; the engine owns the question,
//! the ladder call and the mapping from the answer to whether the pick
//! fits.

use std::time::{Duration, Instant};

use serde_json::Value;

use crate::llm::decision::{DecisionProvider, HeldLadder, TypedDecision};
use crate::model_decision::catalogue::JUDGE_LABEL_FIT;
use crate::model_decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial,
    DecisionQuestion, DecisionRung, Reversibility,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Result};

/// What a host lends to decide one pick's fit.
pub struct JudgeLabelFitDecisions<'a> {
    /// The Coach's model, as the ladder's one Big rung: its seat, wire and
    /// meter stay the host's.
    pub judge: &'a dyn DecisionProvider,
    /// The bands an answer is read under.
    pub bands: &'a DecisionBandPolicy,
    /// How long the pick's question may take, on one clock.
    pub budget: Duration,
}

/// What the ladder made of one pick's fit.
#[derive(Debug, Clone, PartialEq)]
pub enum JudgeLabelFitDecision {
    /// A final yes or no on the pick: yes it still fits the rubric, beside
    /// the ladder's decision for it.
    Decided { fits: bool, decision: TypedDecision },
    /// The pick's question abstained or was cut: the pick is not decided.
    Inconclusive,
}

/// One pending pick as the ladder asks it: its one fits question.
#[derive(Debug, Clone)]
pub struct JudgeLabelFitCheck {
    question: DecisionQuestion,
}

impl JudgeLabelFitCheck {
    /// The fits question of a pick checked against the rubric of digest
    /// `rubric`, worded `wording` and keyed by the host checker's
    /// `protocol` digest and the rubric's.
    ///
    /// # Errors
    ///
    /// A question the catalogue refuses.
    pub fn new(protocol: &[u8; 32], rubric: &[u8; 32], wording: &str) -> Result<Self> {
        let question = JUDGE_LABEL_FIT.question(
            &[protocol, rubric],
            wording.to_owned(),
            AnswerContract::Noul,
        )?;
        Ok(Self { question })
    }

    /// The pick's question: the host shows the pick beside its id.
    #[must_use]
    pub fn question(&self) -> &DecisionQuestion {
        &self.question
    }

    /// The pick's question asked of `lend`'s judge over `state`, the state
    /// the host built from the pick and the rubric it is checked against,
    /// for `principal`, on the rows that state was read from (`evidence`).
    ///
    /// # Errors
    ///
    /// The ladder's or the judge's errors.
    pub fn decide(
        &self,
        principal: EntityId,
        evidence: &[EntityId],
        state: &Value,
        lend: &JudgeLabelFitDecisions<'_>,
    ) -> Result<JudgeLabelFitDecision> {
        let held = HeldLadder::unstaffed();
        let mut ladder = held.ladder();
        ladder.big = Some(lend.judge);
        let decisions = ladder.run_pack(
            &[&self.question],
            principal,
            evidence,
            state,
            dial(),
            lend.bands,
            Reversibility::ReversibleRead,
            &RetrievalDeadline::hard(Instant::now(), lend.budget),
        )?;
        let Some(decision) = decisions.into_iter().next() else {
            return Ok(JudgeLabelFitDecision::Inconclusive);
        };
        let DecisionAnswer::Noul(fits) = decision.answer else {
            return Ok(JudgeLabelFitDecision::Inconclusive);
        };
        Ok(JudgeLabelFitDecision::Decided { fits, decision })
    }
}

/// The dial a pick's question climbs: the Coach's model at the Big rung,
/// with no stronger rung and no person above it. The recheck is the
/// Coach's own read of the pick, never a person's; a pick it cannot settle
/// goes to its person's re-grade outside the ladder.
fn dial() -> DecisionDial {
    DecisionDial {
        first: DecisionRung::Big,
        ceiling: DecisionRung::Big,
        band: DecisionBand::default(),
    }
}
