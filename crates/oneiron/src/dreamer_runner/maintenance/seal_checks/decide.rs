//! The seal's objective questions on the decision ladder (ARCH-0076
//! #decide-required, DECIDE-BYPASS-2): "Every such call goes through
//! decide()". One registered question per objective of a check
//! ([`SEAL_OBJECTIVE_FLAW`]), asked of the host's independent judge as the
//! ladder's one Big rung, with no stronger rung and no person above it; only
//! a complete set of final yes/no answers reads as findings, yes a flaw
//! present. The host keeps the judge's seat, its wording, the state it shows
//! and the wire it reads; the engine owns the questions, the ladder call and
//! the mapping from answers to findings.

use std::time::{Duration, Instant};

use serde_json::Value;

use crate::llm::decision::{DecisionProvider, HeldLadder, TypedDecision};
use crate::model_decision::catalogue::SEAL_OBJECTIVE_FLAW;
use crate::model_decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial,
    DecisionQuestion, DecisionRung, Reversibility,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::self_heal::audit::{ObjectiveFinding, SealCheckKind};
use crate::{EntityId, Result};

/// What a host lends to decide one check's objectives.
pub struct SealObjectiveDecisions<'a> {
    /// The judge that did not produce the result, as the ladder's one Big
    /// rung: its seat, wire and meter stay the host's.
    pub judge: &'a dyn DecisionProvider,
    /// The bands an answer is read under.
    pub bands: &'a DecisionBandPolicy,
    /// How long the check's questions may take, on one clock.
    pub budget: Duration,
}

/// What the ladder made of one check's objectives.
#[derive(Debug, Clone, PartialEq)]
pub enum SealObjectiveDecision {
    /// A final yes or no for every objective: one finding per objective, in
    /// the check's order, each naming the result the judge read, beside the
    /// ladder's decision for it.
    Decided {
        findings: Vec<ObjectiveFinding>,
        decisions: Vec<TypedDecision>,
    },
    /// An objective's question abstained or was cut: no objective is
    /// decided, and the check stays pending.
    Inconclusive,
}

/// One check's objectives as the ladder asks them: one question each, in
/// the check's order.
#[derive(Debug, Clone)]
pub struct SealObjectiveCheck {
    objectives: Vec<String>,
    questions: Vec<DecisionQuestion>,
}

impl SealObjectiveCheck {
    /// The questions of a check of `kind` on `objectives`, worded
    /// `wording` and keyed by the host checker's `protocol` digest, the
    /// kind and each objective's digest. `None` when an objective repeats:
    /// one question cannot stand for two findings.
    ///
    /// # Errors
    ///
    /// A question the catalogue refuses.
    pub fn new(
        kind: SealCheckKind,
        objectives: &[&str],
        protocol: &[u8; 32],
        wording: &str,
    ) -> Result<Option<Self>> {
        let kind_tag: &[u8] = match kind {
            SealCheckKind::ConfessionRecheck => b"recheck",
            SealCheckKind::RandomAudit => b"random_audit",
        };
        let mut questions: Vec<DecisionQuestion> = Vec::with_capacity(objectives.len());
        for objective in objectives {
            let digest = blake3::hash(objective.as_bytes());
            let question = SEAL_OBJECTIVE_FLAW.question(
                &[protocol, kind_tag, digest.as_bytes()],
                wording.to_owned(),
                AnswerContract::Noul,
            )?;
            if questions.iter().any(|asked| asked.id == question.id) {
                return Ok(None);
            }
            questions.push(question);
        }
        Ok(Some(Self {
            objectives: objectives
                .iter()
                .map(|objective| (*objective).to_owned())
                .collect(),
            questions,
        }))
    }

    /// The questions, one per objective in the check's order: the host
    /// shows each objective beside its question's id.
    #[must_use]
    pub fn questions(&self) -> &[DecisionQuestion] {
        &self.questions
    }

    /// The check's questions asked of `lend`'s judge over `state`, the
    /// state the host built from the result and the objectives, for
    /// `principal`. Every question goes in one pack; the ladder splits it by
    /// the bands' questions per call. Each finding names `evidence_ref`, the
    /// result the judge read.
    ///
    /// # Errors
    ///
    /// The ladder's or the judge's errors.
    pub fn decide(
        &self,
        principal: EntityId,
        evidence_ref: &str,
        state: &Value,
        lend: &SealObjectiveDecisions<'_>,
    ) -> Result<SealObjectiveDecision> {
        let held = HeldLadder::unstaffed();
        let mut ladder = held.ladder();
        ladder.big = Some(lend.judge);
        let questions: Vec<&DecisionQuestion> = self.questions.iter().collect();
        let decisions = ladder.run_pack(
            &questions,
            principal,
            &[],
            state,
            dial(),
            lend.bands,
            Reversibility::ReversibleRead,
            &RetrievalDeadline::hard(Instant::now(), lend.budget),
        )?;
        if decisions.len() != self.objectives.len() {
            return Ok(SealObjectiveDecision::Inconclusive);
        }
        let mut findings = Vec::with_capacity(decisions.len());
        for (objective, decision) in self.objectives.iter().zip(&decisions) {
            let DecisionAnswer::Noul(flaw_present) = decision.answer else {
                return Ok(SealObjectiveDecision::Inconclusive);
            };
            findings.push(ObjectiveFinding {
                objective: objective.clone(),
                flaw_present,
                evidence_ref: evidence_ref.to_owned(),
            });
        }
        Ok(SealObjectiveDecision::Decided {
            findings,
            decisions,
        })
    }
}

/// The dial an objective's question climbs: the independent judge at the
/// Big rung, with no stronger rung and no person above it. A stronger seat
/// could be the executor's own model, and the seal's check is a model's
/// independent read, never a person's.
fn dial() -> DecisionDial {
    DecisionDial {
        first: DecisionRung::Big,
        ceiling: DecisionRung::Big,
        band: DecisionBand::default(),
    }
}
