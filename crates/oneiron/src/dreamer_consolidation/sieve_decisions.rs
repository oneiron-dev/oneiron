//! The sieve's typed questions (OF-498a). One owed rung asks four registered
//! families about its span in one pack: novelty (a noul), kind (a choice of
//! the sieve's span kinds), confidence (a score from 0 to 100, the integer
//! percent its band and interest score read) and, over the span's supplied
//! candidates, which one it names or none. Every candidate is offered: past
//! the option limit the candidates split into groups of their own, each asked
//! beside none, never a top few. The pack's wording is the host's; the rung's
//! authored instruction stays its request's own prompt.
//!
//! The answers read back as the span's reading. A question that went
//! unanswered, or a confidence that is not an integer percent, leaves the
//! reading unread, as a refused reply leaves it today: the rung asks again.

use super::call_labels::{CallLabelMap, LabelKind};
use super::executor::ConsolidationDecisions;
use super::provenance::KeptDecision;
use crate::dreamer_wake::{SieveRung, SpanKind};
use crate::llm::decision::catalogue::{SIEVE_CONFIDENCE, SIEVE_ENTITY, SIEVE_KIND, SIEVE_NOVELTY};
use crate::llm::decision::{AnswerContract, DecisionAnswer, DecisionQuestion};
use crate::{EntityId, Result};

/// The entity answer that names no candidate: a reading with no entity.
const NONE: &str = "none";
/// The most candidates one entity question offers beside [`NONE`]; the
/// contract allows 64 options.
const CANDIDATES_PER_QUESTION: usize = 63;
/// The top of the confidence scale: an integer percent.
const CONFIDENCE_MAX: f64 = 100.0;
/// Every span kind, in the order the kind question offers them.
const KINDS: [SpanKind; 2] = [SpanKind::Date, SpanKind::Name];

/// One rung's reading of its span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SieveReading {
    pub(super) kind: SpanKind,
    pub(super) novel: bool,
    pub(super) confidence: u8,
    pub(super) entity: Option<EntityId>,
}

/// One owed rung's pack over its span: novelty, kind and confidence, then
/// one entity question per candidate group, in that order.
pub(super) struct SieveTypingQuestion {
    questions: Vec<DecisionQuestion>,
}

impl SieveTypingQuestion {
    /// `rung`'s pack in `decisions`' wording, over `candidates` in order.
    /// Each candidate option shows as its entity label in `labels` (FIX
    /// 7506), the label the span view names it by; the options themselves
    /// stay the candidates' ids.
    pub(super) fn pack(
        rung: SieveRung,
        decisions: &ConsolidationDecisions,
        candidates: &[EntityId],
        labels: &mut CallLabelMap,
    ) -> Result<Self> {
        let key = rung_key(rung).as_bytes();
        let mut questions = vec![
            SIEVE_NOVELTY.question(
                &[key],
                decisions.sieve_novelty_wording.clone(),
                AnswerContract::Noul,
            )?,
            SIEVE_KIND.question(
                &[key],
                decisions.sieve_kind_wording.clone(),
                AnswerContract::Choice {
                    options: KINDS
                        .iter()
                        .map(|kind| kind_option(*kind).to_owned())
                        .collect(),
                },
            )?,
            SIEVE_CONFIDENCE.question(
                &[key],
                decisions.sieve_confidence_wording.clone(),
                AnswerContract::Score {
                    min: 0.0,
                    max: CONFIDENCE_MAX,
                },
            )?,
        ];
        for (group, ids) in candidates.chunks(CANDIDATES_PER_QUESTION).enumerate() {
            let group = group.to_string();
            let options: Vec<String> = std::iter::once(NONE.to_owned())
                .chain(ids.iter().map(EntityId::to_hex))
                .collect();
            let shown: Vec<String> = std::iter::once(NONE.to_owned())
                .chain(
                    ids.iter()
                        .map(|id| labels.assign(LabelKind::Entity, *id).to_string()),
                )
                .collect();
            let question = SIEVE_ENTITY.question(
                &[key, group.as_bytes()],
                decisions.sieve_entity_wording.clone(),
                AnswerContract::Choice { options },
            )?;
            labels.show_choices(question.id, shown);
            questions.push(question);
        }
        Ok(Self { questions })
    }

    /// The pack's questions, in order.
    pub(super) fn questions(&self) -> &[DecisionQuestion] {
        &self.questions
    }

    /// The reading the pack's `decided` decisions give, in pack order. Of
    /// the candidates the entity groups name, the one read most probable;
    /// none when every group answers none. None when a question went
    /// unanswered or the confidence is not an integer percent.
    pub(super) fn reading(&self, decided: &[KeptDecision]) -> Option<SieveReading> {
        if decided.len() != self.questions.len() {
            return None;
        }
        let [novelty, kind, confidence, entities @ ..] = decided else {
            return None;
        };
        let DecisionAnswer::Noul(novel) = novelty.answer()? else {
            return None;
        };
        let DecisionAnswer::Choice(kind) = kind.answer()? else {
            return None;
        };
        let kind = KINDS
            .into_iter()
            .find(|known| kind_option(*known) == kind.as_str())?;
        let DecisionAnswer::Score(confidence) = confidence.answer()? else {
            return None;
        };
        let confidence = percent(*confidence)?;
        let mut named: Option<(EntityId, f64)> = None;
        for decision in entities {
            let DecisionAnswer::Choice(option) = decision.answer()? else {
                return None;
            };
            if option == NONE {
                continue;
            }
            let id = EntityId::from_hex(option).ok()?;
            let probability = decision.probability()?;
            if named.is_none_or(|(_, best)| probability > best) {
                named = Some((id, probability));
            }
        }
        Some(SieveReading {
            kind,
            novel: *novel,
            confidence,
            entity: named.map(|(id, _)| id),
        })
    }
}

/// The key a rung's questions are asked under: each rung its own question.
fn rung_key(rung: SieveRung) -> &'static str {
    match rung {
        SieveRung::Novelty => "novelty",
        SieveRung::Typing => "typing",
    }
}

/// A span kind as the kind question offers it: its wire name.
fn kind_option(kind: SpanKind) -> &'static str {
    match kind {
        SpanKind::Date => "date",
        SpanKind::Name => "name",
    }
}

/// `score` as an integer percent, when it is one.
fn percent(score: f64) -> Option<u8> {
    (score.fract() == 0.0 && (0.0..=CONFIDENCE_MAX).contains(&score)).then_some(score as u8)
}
