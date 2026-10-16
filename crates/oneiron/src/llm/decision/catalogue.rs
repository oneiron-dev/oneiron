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

/// Which quoted team shape should this spawn run (pattern at a width)?
/// Keyed by task type. The options are the planner's own ranked shape
/// tokens, so an answer can only re-rank what the floor already quoted.
pub const PLANNER_SHAPE: QuestionFamily = QuestionFamily {
    name: "planner.shape",
    version: 1,
    class: DecisionClass::Judgment,
};

/// What conversational signal does a received reaction carry? Host wording;
/// the fixed labels are ack, agree, disagree, affect and none.
pub const REACTION_MEANING: QuestionFamily = QuestionFamily {
    name: "conversation.reaction.meaning",
    version: 1,
    class: DecisionClass::Judgment,
};

/// Replay scores, independent judge audits, blind preferences and skill tradeoffs.
pub const SKILL_OPTIMIZE_JUDGMENT: QuestionFamily = QuestionFamily {
    name: "skill_optimize.judgment",
    version: 1,
    class: DecisionClass::Judgment,
};

/// Which label one changed hunk of an attribution takes (one region for an outcome with no
/// edit). Keyed by lane and hunk position.
pub const ATTRIBUTION_HUNK: QuestionFamily = QuestionFamily {
    name: "skill_attribution.hunk",
    version: 1,
    class: DecisionClass::Judgment,
};

/// A campaign arm's taste over a blind input: a `[0, 1]` score and an audit-only usefulness
/// reading. Keyed by field.
pub const CAMPAIGN_TASTE: QuestionFamily = QuestionFamily {
    name: "autoreason_campaign.taste",
    version: 1,
    class: DecisionClass::Judgment,
};

/// Which eligible model a new seat pins, then which of that model's efforts it runs at.
/// Keyed by `model`, or by `effort` and the chosen model.
pub const SEAT_PICK: QuestionFamily = QuestionFamily {
    name: "llm.seat_pick",
    version: 1,
    class: DecisionClass::Judgment,
};

/// How well one model's description fits a routed task: a `[0, 1]` score, zero unfit.
/// Keyed by model.
pub const DESCRIPTION_FIT: QuestionFamily = QuestionFamily {
    name: "llm.description_fit",
    version: 1,
    class: DecisionClass::Judgment,
};

/// Does a claim-write candidate pass its auto check (allow or hold)?
pub const AUTO_CHECK: QuestionFamily = QuestionFamily {
    name: "llm.auto_check",
    version: 1,
    class: DecisionClass::Judgment,
};

/// The paired yes/no question every decision read asks beside the labels: does this need
/// more thinking? Keyed by its wording alone.
pub const THINK_MORE: QuestionFamily = QuestionFamily {
    name: "decision.think_more",
    version: 1,
    class: DecisionClass::Triage,
};

/// The host's person question, asked beside the call's questions when the dial reaches the
/// person: ask up to the next authorised role? Keyed by its wording alone.
pub const ASK_UP: QuestionFamily = QuestionFamily {
    name: "decision.ask_up",
    version: 1,
    class: DecisionClass::Triage,
};

/// How should this parked contradiction settle (keep one member, hold both, dismiss or
/// escalate)? Keyed by the contested predicates.
pub const CONFLICT_SETTLE: QuestionFamily = QuestionFamily {
    name: "dreamer.conflict_settle",
    version: 1,
    class: DecisionClass::Judgment,
};

/// Every registered family.
pub const FAMILIES: &[QuestionFamily] = &[
    TELEMETRY_ANOMALY,
    CRITIC_REVIEW,
    FANOUT_ASK,
    PLANNER_SHAPE,
    REACTION_MEANING,
    SKILL_OPTIMIZE_JUDGMENT,
    ATTRIBUTION_HUNK,
    CAMPAIGN_TASTE,
    SEAT_PICK,
    DESCRIPTION_FIT,
    AUTO_CHECK,
    THINK_MORE,
    ASK_UP,
    CONFLICT_SETTLE,
];
