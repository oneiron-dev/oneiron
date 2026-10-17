//! The engine's registered typed-question families, in one place. A family names what a
//! caller asks, at which version and class; the wording is the host's configuration, never
//! text here, save the one default [`TASK_REALIZE_INSTRUCTION`] a host may replace. A
//! question's id derives from its family, the caller's key parts and the exact wording, so
//! changed wording is a new question with its own bands.

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

/// Replay scores, independent judge audits, blind preferences, hidden-flaw findings per
/// objective (`honesty`) and skill tradeoffs.
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

/// A caller's own question through the host's ladder (`ai.verdict`): yes or
/// no, or one of its labels. The wording is the caller's; keyed by the
/// answer contract, so a changed label set is a new question.
pub const AI_VERDICT: QuestionFamily = QuestionFamily {
    name: "ai.verdict",
    version: 1,
    class: DecisionClass::Judgment,
};

/// A routine driver step through `ai.verdict` (OF-523, the CUA-S1 pattern): which of the
/// step's candidates the driver acts on (NONE, reobserve or ask up reserved), or where its
/// target is in a screenshot. Keyed by the answer contract, as [`AI_VERDICT`] is, so a
/// step's bands learn apart from plain verdicts.
pub const AI_VERDICT_ROUTINE: QuestionFamily = QuestionFamily {
    name: "ai.verdict.routine",
    version: 1,
    class: DecisionClass::Triage,
};

/// The paired yes/no question every decision read asks jointly with each question's labels:
/// does this need more thinking? Keyed by its wording alone.
pub const THINK_MORE: QuestionFamily = QuestionFamily {
    name: "decision.think_more",
    version: 1,
    class: DecisionClass::Triage,
};

/// The host's person question, asked beside the call's questions when the dial reaches the
/// person and read apart from them: ask up to the next authorised role? Keyed by its wording
/// alone.
pub const ASK_UP: QuestionFamily = QuestionFamily {
    name: "decision.ask_up",
    version: 1,
    class: DecisionClass::Triage,
};

/// The host's presence question, asked before a Box or Point question over the same
/// images and clock: is the target the `locate` state field words in the image at all?
/// Only a confident yes starts the coordinates. Keyed by its wording alone.
pub const IMAGE_PRESENCE: QuestionFamily = QuestionFamily {
    name: "decision.image_presence",
    version: 1,
    class: DecisionClass::Retrieval,
};

/// Does this candidate violate one owner-authored policy row? Keyed by the
/// document hash, row reference and action; wording comes from the row.
pub const POLICY_OWNER_ROW: QuestionFamily = QuestionFamily {
    name: "policy_model.owner_row",
    version: 1,
    class: DecisionClass::Judgment,
};

/// Does this candidate violate one attested hosted-legal policy row? Never
/// assembled on a local/BYO path. Keyed as the owner question is.
pub const POLICY_HOSTED_ROW: QuestionFamily = QuestionFamily {
    name: "policy_model.hosted_row",
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

/// Is everything okay past a wire, limit or scan threshold: a bot, or a valid burst
/// (OF-520)? Keyed by the crossing.
pub const WIRE_HEALTH: QuestionFamily = QuestionFamily {
    name: "server.wire_health",
    version: 1,
    class: DecisionClass::Triage,
};

/// Whether one held automated sign act lands (ARCH-0064 D6): allow or decline. Asked of
/// the vault owner role alone. Keyed by the document, the recipient and the hold.
pub const ESIGN_HELD_SIGNING: QuestionFamily = QuestionFamily {
    name: "esign.held_signing",
    version: 1,
    class: DecisionClass::Judgment,
};

/// Which capability setting one connector grant-slate row drafts (auto, always ask or
/// never allow; always allow too on an owner-asked re-draft). Keyed by door and tool.
pub const CONNECTOR_SLATE_DRAFT: QuestionFamily = QuestionFamily {
    name: "connector.grant_slate.draft",
    version: 1,
    class: DecisionClass::Judgment,
};

/// How a conflicting claim set the Dreamer extracted resolves (merge, supersede, accumulate
/// or escalate), and which listed candidate's identity a merge keeps. Keyed by `resolution`,
/// or by `identity` and the option group.
pub const CONFLICT_RESOLUTION: QuestionFamily = QuestionFamily {
    name: "dreamer.conflict_resolution",
    version: 1,
    class: DecisionClass::Judgment,
};

/// Which listed claim, if any, a candidate the Dreamer extracted corrects. Keyed by the
/// candidate's position and the option group.
pub const CORRECTION: QuestionFamily = QuestionFamily {
    name: "dreamer.correction",
    version: 1,
    class: DecisionClass::Judgment,
};

/// Does this candidate belong to the saved query its owner's rubric describes? Keyed by the
/// rubric's hash and version.
pub const SAVED_QUERY_MATCH: QuestionFamily = QuestionFamily {
    name: "saved_query.match",
    version: 1,
    class: DecisionClass::Judgment,
};

/// Does the owner policy's safeguard model find a violation (binary contract), or which
/// policy row the candidate violates, if any (category contracts)? Keyed by the document
/// hash, the contract and the option group.
pub const POLICY_OWNER_VIOLATION: QuestionFamily = QuestionFamily {
    name: "policy_model.owner_violation",
    version: 1,
    class: DecisionClass::Judgment,
};

/// The owner question for an attested hosted-legal policy. Keyed as the owner question is,
/// with the policy version.
pub const POLICY_HOSTED_VIOLATION: QuestionFamily = QuestionFamily {
    name: "policy_model.hosted_violation",
    version: 1,
    class: DecisionClass::Judgment,
};

/// Is this booking turn off topic for scheduling (the turn ends with a deflect)? Keyed by
/// the constraint schema version.
pub const BOOKING_OFF_TOPIC: QuestionFamily = QuestionFamily {
    name: "booking.off_topic",
    version: 1,
    class: DecisionClass::Triage,
};

/// Does this conversation turn sound like a project (yes or no)? Asked by the house mind on a
/// person's on-record turn; no key parts, so every conversation asks the one question.
pub const PROJECT_PROPOSAL: QuestionFamily = QuestionFamily {
    name: "conversation.project_proposal",
    version: 1,
    class: DecisionClass::Triage,
};

/// How well one arm of a session-branch claim edit fits the owner's held-out labels, from 0
/// to 1. Unkeyed: the wording is the key.
pub const CLAIM_REPLAY: QuestionFamily = QuestionFamily {
    name: "skill_hub.claim_replay",
    version: 1,
    class: DecisionClass::Judgment,
};

/// How does the Dreamer realize a TASK routed to it? One model step answers the TASK's spec
/// and brief, and the answer becomes the research NOTE the TASK's result names. The one
/// family that ships its wording, so a Dreamer-lane TASK realizes out of the box; the host's
/// own wording replaces it. Keyed by the TASK.
pub const TASK_REALIZE: QuestionFamily = QuestionFamily {
    name: "dreamer.task_realize",
    version: 1,
    class: DecisionClass::Judgment,
};

/// [`TASK_REALIZE`]'s shipped wording, the system message of its step.
pub const TASK_REALIZE_INSTRUCTION: &str = "You realize one task a person or agent routed to \
the background worker of their knowledge vault. The next message carries the task's spec as \
JSON and, when it has one, its brief: the objective, the intent, the constraints, the context \
handles, what done means and when to escalate. Do the task's work in writing and reply with \
the result itself, in Markdown, ready to be kept as a research note every reader of the vault \
may open. Meet each done-means criterion and keep to every constraint. Name context only by \
the handles you were given; never invent a fact, a source or a handle. When the task cannot \
be done from what you were given, say plainly what is missing instead of guessing.";

/// One task-highway surface question ([`crate::task_verb::TaskDecisions`]): take this
/// proposal, does Done mean met, ask up now? Keyed by which.
pub const TASK_SURFACE: QuestionFamily = QuestionFamily {
    name: "task_verb.surface",
    version: 1,
    class: DecisionClass::Judgment,
};

/// Which of these entities does one saved mention name, or is it someone new (OF-123)? Keyed
/// by the mention's entity kind.
pub const IDENTITY_SETTLE: QuestionFamily = QuestionFamily {
    name: "dreamer.identity_settle",
    version: 1,
    class: DecisionClass::Judgment,
};

/// Which fix does this agent need: a skill edit, a prompt and a fork-resume, an environment
/// fix, or a person (ARCH-0066 #healer, OF-418)? The Coach asks it of a failure-ladder case or
/// of a blocked report; the answer only shapes a proposed heal. Keyed by what was asked about.
pub const COACH_HEAL_ROUTE: QuestionFamily = QuestionFamily {
    name: "coach.heal_route",
    version: 1,
    class: DecisionClass::Judgment,
};

/// The Coach's code-fix checks (DEC-0005 FIX6, OF-380): which failure class a case is, whether
/// a replay fails the way the case did, whether a candidate fix's shadow replay no longer fails,
/// and whether an invented example is safe to leave the vault. Keyed by the check.
pub const CODE_FIX_JUDGMENT: QuestionFamily = QuestionFamily {
    name: "coach.code_fix_check",
    version: 1,
    class: DecisionClass::Judgment,
};

/// Should the vault pay for a room-paid launch whose payer PERSON has no billing account the
/// host can resolve (OF-531)? Yes bills the vault for the calls under that launch's root spend
/// scope; anything else keeps them held. Keyed by the payer and the root scope.
pub const PAYER_NEEDED: QuestionFamily = QuestionFamily {
    name: "spend.payer_needed",
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
    AI_VERDICT,
    AI_VERDICT_ROUTINE,
    THINK_MORE,
    ASK_UP,
    POLICY_OWNER_ROW,
    POLICY_HOSTED_ROW,
    CONFLICT_SETTLE,
    WIRE_HEALTH,
    ESIGN_HELD_SIGNING,
    CONNECTOR_SLATE_DRAFT,
    CONFLICT_RESOLUTION,
    CORRECTION,
    SAVED_QUERY_MATCH,
    POLICY_OWNER_VIOLATION,
    POLICY_HOSTED_VIOLATION,
    BOOKING_OFF_TOPIC,
    PROJECT_PROPOSAL,
    CLAIM_REPLAY,
    TASK_REALIZE,
    TASK_SURFACE,
    IDENTITY_SETTLE,
    COACH_HEAL_ROUTE,
    CODE_FIX_JUDGMENT,
    PAYER_NEEDED,
];
