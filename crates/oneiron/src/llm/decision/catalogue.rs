//! The engine's registered typed-question families, in one place. A family names what a
//! caller asks, at which version and class; the wording is the host's configuration, never
//! text here. A question's id derives from its family, the caller's key parts and the exact
//! wording, so changed wording is a new question with its own bands.

use super::{AnswerContract, DecisionClass, DecisionQuestion};
use crate::entity_id::derived_domains::DECISION_QUESTION;
use crate::{EntityId, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuestionFamily {
    pub name: &'static str,
    pub version: u32,
    pub class: DecisionClass,
}

impl QuestionFamily {
    /// This family's question with `text` and `contract`, keyed by `parts` (for example a
    /// tier and a detector family) after the family name.
    pub fn question(
        &self,
        parts: &[&[u8]],
        text: String,
        contract: AnswerContract,
    ) -> Result<DecisionQuestion> {
        let mut seed = Vec::with_capacity(parts.len() + 2);
        seed.push(self.name.as_bytes());
        seed.extend_from_slice(parts);
        seed.push(text.as_bytes());
        let question = DecisionQuestion {
            id: EntityId::derive(DECISION_QUESTION, &seed)?,
            version: self.version,
            text,
            class: self.class,
            contract,
            accept_type: false,
        };
        question.validate()?;
        Ok(question)
    }
}

/// Does this telemetry show the detector's anomaly? Keyed by tier and detector family.
pub const TELEMETRY_ANOMALY: QuestionFamily = QuestionFamily {
    name: "self_heal.telemetry_anomaly",
    version: 1,
    class: DecisionClass::Triage,
};

/// One critic lens's verdict, severity, hard check or scope. Keyed by field, artifact kind,
/// lens domain and lens id.
pub const CRITIC_REVIEW: QuestionFamily = QuestionFamily {
    name: "critic.review",
    version: 1,
    class: DecisionClass::Judgment,
};

/// Should this AUTO-mode fan-out start (allow, deny or escalate)? Keyed by the ask's trigger.
pub const FANOUT_ASK: QuestionFamily = QuestionFamily {
    name: "fanout.ask",
    version: 1,
    class: DecisionClass::Judgment,
};

/// How should this parked contradiction settle (keep one member, hold both, dismiss or
/// escalate)? Keyed by the contested predicates.
pub const CONFLICT_SETTLE: QuestionFamily = QuestionFamily {
    name: "dreamer.conflict_settle",
    version: 1,
    class: DecisionClass::Judgment,
};

/// Every registered family.
pub const FAMILIES: &[QuestionFamily] =
    &[TELEMETRY_ANOMALY, CRITIC_REVIEW, FANOUT_ASK, CONFLICT_SETTLE];
