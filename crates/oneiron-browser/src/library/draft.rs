//! A draft of a proposal from a run's own steps (CUA E7; DESIGN-2 §3 "The
//! agent"), at the Rule tier: no model, no driver, no custody bytes, no
//! admission. A session builds the steps from its history (each effect's
//! receipt and each step that stopped, `session::trail`); a demonstration
//! recorder builds the same steps from what it recorded.
//!
//! The draft takes one span of the steps (`draft_span_policy`, CALLS row):
//! by default the latest run of steps on the open page's origin, from the
//! navigation that opened it; else the bounds the caller names, `after_seq`
//! exclusive and `through_seq` inclusive, on the history's one sequence.
//! Nothing outside the span is pulled in, and no opening is made up: a span
//! with none, a step on another origin, a redirect to one, a tab no step of
//! the span brought to the front, a step with no page or tab, a step that
//! failed or stopped, one whose act proved it changed nothing, and an act no
//! step replays are each named as a gap, and a draft with any is not
//! complete.
//!
//! A program ends at the pre-press state (`draft_press_end_policy`, CALLS
//! row): the draft ends before the first step whose effect class is a send,
//! a payment, a publish, a destructive act or unknown, and names it. A
//! caller may take the draft past it (`past_press`); each press taken is
//! then listed.
//!
//! The proposal keeps literals as literals. Each non-empty text a type
//! typed and each option a select chose is a slot candidate, by its step
//! and the parameter it might take (`draft_slot_candidate_policy`, CALLS
//! row); the caller marks the slots. A secret is a typed slot at once, as
//! admission slots it (`secret_slot_policy`): its name among `params`, the
//! step or check naming `secret: "{{name}}"`, and `args` holding only this
//! run's handle. A secret a demonstration's page withheld (CUA E9a) is a
//! slot with no arg, named withheld, for the caller to bind. No held-out
//! value is made up: `replay_args` is empty, and the draft is never filed.

use super::ProposeInput;
use crate::{BatchStopCause, ExpectInput, OperandGap, ReplayAction, SecretKind};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod from_steps;

pub use from_steps::draft_from_steps;
pub(crate) use from_steps::draft_with_secrets;

/// Drafts a proposal from the attached run's own effects on its open page
/// (CUA E7): the span of its history to draft, the subgoal and the checks
/// the caller gives it. It names no receipt and no site: the session's own
/// history and page say them.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DraftInput {
    /// What the program is for, as a proposal names it.
    pub subgoal: String,
    /// What the page shows when the program worked, as a proposal's checks:
    /// a live handle goes back to its row's locator, a secret to a typed
    /// slot. The draft never reads them on the page.
    #[serde(default)]
    pub postcondition: Vec<ExpectInput>,
    /// The span starts after this entry of the session's history, by its
    /// `seq` (exclusive); by default where the latest run of entries on the
    /// open page's origin starts.
    #[serde(default)]
    pub after_seq: Option<u64>,
    /// The span ends with this entry (inclusive); by default with the
    /// latest entry on the open page's origin.
    #[serde(default)]
    pub through_seq: Option<u64>,
    /// Takes the draft past the steps it ends before by default (a send, a
    /// payment, a publish, a destructive or an unclassified control): each
    /// becomes an ordinary step, listed in `pressed_through`.
    #[serde(default)]
    pub past_press: bool,
    /// The task type the caller records for the span (FIX 10508). With it,
    /// a span whose checks are met on the page the call leaves is kept as
    /// the caller's solved-run evidence, grouped under its site, origin,
    /// type and subgoal; without it, nothing is kept.
    #[serde(default)]
    pub type_ref: Option<DraftTypeRef>,
}

/// A task type a caller records on its draft (FIX 10508): the type tree's
/// node and the tree version it was placed in, as a receipt's type names
/// them. It is the wire form; the engine reads it as its own task type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DraftTypeRef {
    pub node_id: String,
    pub tree_version: u64,
}

/// A draft: the proposal its span gives, the literals that might take
/// slots, and every gap that keeps it from replaying the span whole. It is
/// no admission grade: `propose` checks and replays it.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DraftOutput {
    /// The program's site, as the library keys it: its opening page's host
    /// and port, else the open page's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// The span's origin (scheme, host and port), parsed from its pages'
    /// URLs, never from the site.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// The span drafted: the entries after `after_seq` through
    /// `through_seq`; the two are equal when it holds none.
    pub after_seq: u64,
    pub through_seq: u64,
    pub proposal: ProposeInput,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slot_candidates: Vec<SlotCandidate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<DraftGap>,
    /// The press-class steps a `past_press` draft took as ordinary steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pressed_through: Vec<PressedThrough>,
    /// Whether the span holds steps and every one of them is in the
    /// proposal as it ran: no gap but the pre-press end.
    pub complete: bool,
}

/// A literal that might take a slot: a type's text or a select's option,
/// whole, by the proposal's step that holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SlotCandidate {
    /// The proposal's step, by index.
    pub step: usize,
    /// The history entry it came from.
    pub seq: u64,
    pub field: SlotField,
    pub literal: String,
    /// A name it might take, from its target's name: a-z, 0-9 and _, and
    /// no other candidate's or parameter's.
    pub suggested_param: String,
}

/// The step field a slot candidate stands in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SlotField {
    /// A type step's `text`.
    #[serde(rename = "text")]
    Text,
    /// A select step's `option`.
    #[serde(rename = "option")]
    Choice,
}

impl SlotField {
    const fn word(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Choice => "option",
        }
    }
}

/// A press-class step a `past_press` draft took.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PressedThrough {
    pub seq: u64,
    pub effect_class: String,
}

/// What keeps a draft from replaying its span whole, at the history entry
/// `seq` (a `verb`), or, with none, of the span or the caller's input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DraftGap {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verb: Option<String>,
    pub gap: DraftGapKind,
}

/// The gaps a draft names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "why", rename_all = "snake_case")]
pub enum DraftGapKind {
    /// The draft ends before this step, a press of `effect_class`; the
    /// program ends at the state before it.
    PrePress { effect_class: String },
    /// The draft ends before this click on a control no name classifies:
    /// it might send.
    UnknownPress,
    /// The entry holds no act a step replays: a click at a point, an
    /// engine switch, a stop with no effect, or an act whose operands were
    /// not kept.
    NoAction,
    /// A type's secret was not kept as a handle, for `cause`.
    SecretWithheld {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kind: Option<SecretKind>,
        cause: OperandGap,
    },
    /// The step failed or stopped, or a later stop marked its effect
    /// failed.
    Failed { cause: BatchStopCause },
    /// The act proved it changed nothing on the page.
    NoEffect,
    /// The span does not start with the navigation that opened its page.
    MissingOpening,
    /// The span holds no entry.
    EmptySpan,
    /// The open page has no http or https origin to find the default span
    /// by.
    NoLiveOrigin,
    /// The step acted on, led to, or was redirected to a page of `origin`,
    /// not the span's.
    ForeignOrigin {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        origin: Option<String>,
    },
    /// The step acted in another tab than the one the span's step before
    /// left in front.
    TabChange,
    /// The step is a Fill whose text only the host's writer writes
    /// (`generate`), which a replay with no model never asks (FIX 9269).
    GeneratedFill,
    /// A demonstration saw its page navigate with no act it recorded (a
    /// typed URL, a script's history move, a navigation outside the run's
    /// verbs), so a step may be missing (FIX 9413).
    UnrecordedNavigation,
    /// The step names no page or tab it began on.
    MissingContext,
    /// Postcondition check `check` names a live handle this session does
    /// not know; it is left out.
    CheckUnknownRef { check: usize },
    /// Postcondition check `check`'s secret was not kept as a handle, for
    /// `cause`; it is left out.
    CheckSecretWithheld { check: usize, cause: OperandGap },
    /// The draft has no postcondition: a proposal needs one or more checks.
    NoPostcondition,
    /// The draft has no subgoal.
    NoSubgoal,
}

/// One step a draft reads (CUA E7): an effect's receipt or a stop, as a
/// session's history holds it, or a step a demonstration recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftStep {
    pub seq: u64,
    pub verb: String,
    /// The tab it acted in, and the tab in front once it settled.
    pub tab: Option<String>,
    pub result_tab: Option<String>,
    /// The page it began on, and its origin.
    pub source_url: Option<String>,
    pub source_origin: Option<String>,
    /// The page it left, and its origin.
    pub result_url: String,
    pub result_origin: Option<String>,
    /// An `open`'s: the origin of the URL it asked for, before a redirect.
    pub requested_origin: Option<String>,
    /// The name of the row it acted on.
    pub target_name: Option<String>,
    pub effect_class: Option<String>,
    /// The act as a step replays it, or why there is none.
    pub action: Result<ReplayAction, DraftGapKind>,
    pub outcome: DraftOutcome,
}

/// How a draft step ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DraftOutcome {
    Ok,
    /// It failed or stopped; an effect it made stands.
    Failed {
        cause: BatchStopCause,
    },
    /// Its act proved it changed nothing.
    NoEffect,
    /// A stop noted after the effect `seq`, which it marks failed.
    Marked {
        seq: u64,
        cause: BatchStopCause,
    },
}

/// What a draft knows of the live session: its open page, and the kind of
/// each run-bound handle the postcondition names.
#[derive(Clone, Debug, Default)]
pub struct DraftPage {
    pub url: String,
    pub origin: Option<String>,
    pub secrets: BTreeMap<String, SecretKind>,
}

impl DraftStep {
    /// The origin of the page the step acted on: an `open`'s, the page it
    /// opened; any other's, the page it began on, else the one it left.
    fn acted_origin(&self) -> Option<&str> {
        match &self.action {
            Ok(ReplayAction::Open { .. }) => self.result_origin.as_deref(),
            _ => self
                .source_origin
                .as_deref()
                .or(self.result_origin.as_deref()),
        }
    }

    /// Whether the step is of a run on `origin`: one naming no origin
    /// breaks none, and is named a gap where it replays.
    fn on(&self, origin: &str) -> bool {
        self.acted_origin().is_none_or(|own| own == origin)
    }

    /// The origin of the page the step left.
    fn left_origin(&self) -> Option<&str> {
        self.result_origin
            .as_deref()
            .or(self.source_origin.as_deref())
    }
}
