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

use super::secret_slots::SlotBook;
use super::{ProposeInput, SecretParam, site_of};
use crate::{
    BatchStep, BatchStopCause, BrowserError, EFFECT_DESTRUCTIVE, EFFECT_PAY, EFFECT_PUBLISH,
    EFFECT_SEND, EFFECT_UNKNOWN, ExpectInput, OperandGap, ReplayAction, SecretKind, TypeOperand,
    is_live_handle,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The effect classes a draft ends before (`draft_press_end_policy`, CALLS
/// row; DESIGN-2 §3 "Programs end at the pre-press state"): a send, a
/// payment, a publish, a destructive act, and a control no name classifies,
/// which might be any of them. An account's sign-in stays an ordinary step,
/// under its own press at run time.
const DRAFT_PRESS_END: &[&str] = &[
    EFFECT_SEND,
    EFFECT_PAY,
    EFFECT_PUBLISH,
    EFFECT_DESTRUCTIVE,
    EFFECT_UNKNOWN,
];

/// The words of a target's name a slot candidate's suggested parameter
/// takes, at most (`draft_slot_candidate_policy`, CALLS row).
const SUGGESTED_PARAM_WORDS: usize = 4;

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

/// The span of the steps a draft takes: `start..end`, its bounds, and its
/// origin.
struct Span {
    start: usize,
    end: usize,
    after_seq: u64,
    through_seq: u64,
    origin: Option<String>,
}

/// The bounds a caller named, checked against the history's last entry.
fn bounds(input: &DraftInput, last: u64) -> Result<(), BrowserError> {
    let past = |bound: &str, seq: u64| {
        BrowserError::Input(format!(
            "{bound} {seq} names no entry of this session's history yet: its last is {last}"
        ))
    };
    if let Some(after) = input.after_seq
        && after > last
    {
        return Err(past("after_seq", after));
    }
    if let Some(through) = input.through_seq
        && through > last
    {
        return Err(past("through_seq", through));
    }
    if let (Some(after), Some(through)) = (input.after_seq, input.through_seq)
        && after > through
    {
        return Err(BrowserError::Input(format!(
            "after_seq {after} is past through_seq {through}: a span runs after the first through the second"
        )));
    }
    Ok(())
}

/// The span a draft takes (`draft_span_policy`, CALLS row): its end at
/// `through_seq`, else at the latest step on the open page's origin; its
/// start after `after_seq`, else where the run of steps on the end's
/// origin starts. Its origin is its opening's, else the end's.
fn span(input: &DraftInput, steps: &[DraftStep], page: &DraftPage) -> Result<Span, BrowserError> {
    let last = steps.last().map_or(0, |step| step.seq);
    bounds(input, last)?;
    let (end, origin) = match input.through_seq {
        Some(through) => {
            let end = steps.partition_point(|step| step.seq <= through);
            let origin = end
                .checked_sub(1)
                .and_then(|at| steps[at].left_origin())
                .map(str::to_owned);
            (end, origin)
        }
        None => {
            let origin = page.origin.clone();
            let latest = origin
                .as_deref()
                .and_then(|origin| steps.iter().rposition(|step| step.on(origin)));
            (latest.map_or(steps.len(), |at| at + 1), origin)
        }
    };
    let start = match (input.after_seq, origin.as_deref()) {
        (Some(after), _) => steps.partition_point(|step| step.seq <= after).min(end),
        (None, Some(origin)) => {
            let mut start = end;
            while start > 0 && steps[start - 1].on(origin) {
                start -= 1;
            }
            start
        }
        (None, None) => end,
    };
    let opened = steps[start..end]
        .first()
        .filter(|step| matches!(step.action, Ok(ReplayAction::Open { .. })))
        .and_then(|step| step.result_origin.clone());
    let seq_before = |at: usize| at.checked_sub(1).map_or(0, |at| steps[at].seq);
    Ok(Span {
        start,
        end,
        after_seq: input.after_seq.unwrap_or_else(|| seq_before(start)),
        through_seq: input.through_seq.unwrap_or_else(|| seq_before(end)),
        origin: opened.or(origin),
    })
}

/// A literal a step holds, kept for its suggested name.
struct Literal {
    candidate: SlotCandidate,
    name: Option<String>,
}

/// A draft as it is built, step by step.
struct Draft {
    origin: Option<String>,
    after_seq: u64,
    /// The span's opening `open`, by seq: its redirect starts the span at
    /// its result origin, its URL kept (FIX 9268).
    opening: Option<u64>,
    /// The tab the last step left in front.
    tab: Option<String>,
    params: Vec<String>,
    secret: Vec<SecretParam>,
    args: BTreeMap<String, String>,
    replay_args: BTreeMap<String, String>,
    steps: Vec<BatchStep>,
    literals: Vec<Literal>,
    gaps: Vec<DraftGap>,
    pressed: Vec<PressedThrough>,
}

impl Draft {
    fn gap(&mut self, step: &DraftStep, gap: DraftGapKind) {
        self.gaps.push(DraftGap {
            seq: Some(step.seq),
            verb: Some(step.verb.clone()),
            gap,
        });
    }

    fn input_gap(&mut self, gap: DraftGapKind) {
        self.gaps.push(DraftGap {
            seq: None,
            verb: None,
            gap,
        });
    }

    /// The typed slot a secret of `kind` held as `handle` takes, as
    /// admission takes it: `{{name}}`.
    fn slot(&mut self, kind: SecretKind, handle: &str) -> String {
        let mut book = SlotBook {
            params: &mut self.params,
            secret: &mut self.secret,
            args: &mut self.args,
            replay_args: &mut self.replay_args,
        };
        let name = book.mint(kind, handle.to_owned(), None);
        format!("{{{{{name}}}}}")
    }

    /// The typed slot a secret of `kind` no value binds takes: `{{name}}`,
    /// with no arg; the draft names it withheld, so it is not complete.
    fn unbound(&mut self, kind: SecretKind) -> String {
        let mut book = SlotBook {
            params: &mut self.params,
            secret: &mut self.secret,
            args: &mut self.args,
            replay_args: &mut self.replay_args,
        };
        let name = book.unbound(kind);
        format!("{{{{{name}}}}}")
    }

    /// One step of the span: false once the draft ends before it.
    fn step(&mut self, step: &DraftStep, past_press: bool) -> bool {
        if let Some(class) = step.effect_class.as_deref()
            && DRAFT_PRESS_END.contains(&class)
        {
            if !past_press {
                let gap = if class == EFFECT_UNKNOWN {
                    DraftGapKind::UnknownPress
                } else {
                    DraftGapKind::PrePress {
                        effect_class: class.to_owned(),
                    }
                };
                self.gap(step, gap);
                return false;
            }
            self.pressed.push(PressedThrough {
                seq: step.seq,
                effect_class: class.to_owned(),
            });
        }
        self.context(step);
        let stopped = match &step.outcome {
            DraftOutcome::Ok => false,
            DraftOutcome::NoEffect => {
                self.gap(step, DraftGapKind::NoEffect);
                false
            }
            DraftOutcome::Failed { cause } => {
                let cause = cause.clone();
                self.gap(step, DraftGapKind::Failed { cause });
                true
            }
            // The effect it marks failed, when the span holds it, names it.
            DraftOutcome::Marked { seq, cause } => {
                if *seq <= self.after_seq {
                    let cause = cause.clone();
                    self.gap(step, DraftGapKind::Failed { cause });
                }
                true
            }
        };
        match &step.action {
            Ok(action) => self.take(step, action),
            Err(DraftGapKind::NoAction) if stopped => {}
            Err(gap) => self.gap(step, gap.clone()),
        }
        true
    }

    /// The step's page and tab, against the span's origin and the tab the
    /// step before left in front.
    fn context(&mut self, step: &DraftStep) {
        if step.action.is_ok() {
            let opens = matches!(step.action, Ok(ReplayAction::Open { .. }));
            // An `open` begins anywhere; any other step on a page it names.
            let began = opens || step.source_origin.is_some();
            if step.tab.is_none() || step.result_tab.is_none() || !began {
                self.gap(step, DraftGapKind::MissingContext);
            }
            if let Some(origin) = self.origin.clone() {
                let opening = self.opening == Some(step.seq);
                let elsewhere = [
                    step.acted_origin(),
                    step.result_origin.as_deref(),
                    step.requested_origin
                        .as_deref()
                        .filter(|_| opens && !opening),
                ];
                if let Some(other) = elsewhere.into_iter().flatten().find(|own| *own != origin) {
                    let origin = Some(other.to_owned());
                    self.gap(step, DraftGapKind::ForeignOrigin { origin });
                }
            }
            let moved = matches!((&self.tab, &step.tab), (Some(left), Some(tab)) if left != tab);
            if moved {
                self.gap(step, DraftGapKind::TabChange);
            }
        }
        if let Some(tab) = step.result_tab.clone().or_else(|| step.tab.clone()) {
            self.tab = Some(tab);
        }
    }

    /// The step's act as the proposal's step, its literal a candidate and
    /// its secret a typed slot.
    fn take(&mut self, step: &DraftStep, action: &ReplayAction) {
        let at = self.steps.len();
        let batch = match action {
            ReplayAction::Open { url } => BatchStep::Open { url: url.clone() },
            ReplayAction::Click { locator } => BatchStep::Click {
                target: locator.clone(),
            },
            ReplayAction::Select { locator, option } => {
                self.literal(step, at, SlotField::Choice, option);
                BatchStep::Select {
                    target: locator.clone(),
                    option: option.clone(),
                }
            }
            ReplayAction::Fill { locator, field } => {
                // Generation is reached with no text, template or secret.
                let unwritten =
                    field.supplied.is_none() && field.template.is_none() && field.secret.is_none();
                if field.generate && unwritten {
                    self.gap(step, DraftGapKind::GeneratedFill);
                }
                BatchStep::Fill {
                    target: locator.clone(),
                    field: field.clone(),
                }
            }
            ReplayAction::Type {
                locator,
                operand,
                clear,
            } => {
                let (text, secret) = match operand {
                    TypeOperand::Literal { text } => {
                        self.literal(step, at, SlotField::Text, text);
                        (Some(text.clone()), None)
                    }
                    TypeOperand::Secret { kind, handle } => (None, Some(self.slot(*kind, handle))),
                    TypeOperand::Withheld { kind, cause } => {
                        let (kind, cause) = (*kind, *cause);
                        self.gap(step, DraftGapKind::SecretWithheld { kind, cause });
                        // A secret a page withheld (CUA E9a) keeps its step,
                        // its slot bound to no value; any other is left out.
                        match (kind, cause) {
                            (Some(kind), OperandGap::Unbound) => (None, Some(self.unbound(kind))),
                            _ => return,
                        }
                    }
                };
                BatchStep::Type {
                    target: locator.clone(),
                    text,
                    secret,
                    clear: *clear,
                }
            }
        };
        self.steps.push(batch);
    }

    /// A non-empty literal of the proposal's step `at`, whole, as a slot
    /// candidate; identical ones stay apart.
    fn literal(&mut self, step: &DraftStep, at: usize, field: SlotField, literal: &str) {
        if literal.is_empty() {
            return;
        }
        self.literals.push(Literal {
            candidate: SlotCandidate {
                step: at,
                seq: step.seq,
                field,
                literal: literal.to_owned(),
                suggested_param: String::new(),
            },
            name: step.target_name.clone(),
        });
    }

    /// The postcondition as the proposal keeps it: no live handle, each
    /// secret a typed slot; a check that cannot be kept so is left out.
    fn checks(&mut self, checks: &[ExpectInput], page: &DraftPage) -> Vec<ExpectInput> {
        if checks.is_empty() {
            self.input_gap(DraftGapKind::NoPostcondition);
        }
        let mut kept = Vec::with_capacity(checks.len());
        for (index, check) in checks.iter().enumerate() {
            if check.target.as_deref().is_some_and(is_live_handle) {
                self.input_gap(DraftGapKind::CheckUnknownRef { check: index });
                continue;
            }
            let mut check = check.clone();
            if let Some(handle) = check.secret.take() {
                let Some(kind) = page.secrets.get(&handle).copied() else {
                    let cause = OperandGap::UnknownKind;
                    self.input_gap(DraftGapKind::CheckSecretWithheld {
                        check: index,
                        cause,
                    });
                    continue;
                };
                check.secret = Some(self.slot(kind, &handle));
            }
            kept.push(check);
        }
        kept
    }

    /// Each candidate's suggested parameter (`draft_slot_candidate_policy`):
    /// its target's name's first words, lower-cased and joined by `_`,
    /// else its field's word, numbered past any name already taken.
    fn candidates(&mut self) -> Vec<SlotCandidate> {
        let mut taken = self.params.clone();
        let literals = std::mem::take(&mut self.literals);
        literals
            .into_iter()
            .map(|literal| {
                let Literal {
                    mut candidate,
                    name,
                } = literal;
                let base = suggested(name.as_deref(), candidate.field);
                let (mut name, mut nth) = (base.clone(), 1_u32);
                while taken.contains(&name) {
                    nth += 1;
                    name = format!("{base}_{nth}");
                }
                taken.push(name.clone());
                candidate.suggested_param = name;
                candidate
            })
            .collect()
    }
}

/// A parameter name from a target's `name`, for a candidate in `field`.
fn suggested(name: Option<&str>, field: SlotField) -> String {
    let words: Vec<String> = name
        .unwrap_or_default()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .take(SUGGESTED_PARAM_WORDS)
        .map(str::to_ascii_lowercase)
        .collect();
    let joined = words.join("_");
    let first = joined.chars().next();
    match first {
        Some(first) if first.is_ascii_lowercase() => joined,
        Some(_) => format!("{}_{joined}", field.word()),
        None => field.word().to_owned(),
    }
}

/// Drafts a proposal from `steps`, in their history's order, for the
/// session `page` names (CUA E7): its span, the proposal, its slot
/// candidates and its gaps. It reads nothing else.
///
/// # Errors
///
/// [`BrowserError::Input`] when a bound names no entry of the history yet,
/// or `after_seq` is past `through_seq`.
pub fn draft_from_steps(
    input: &DraftInput,
    steps: &[DraftStep],
    page: &DraftPage,
) -> Result<DraftOutput, BrowserError> {
    draft_with_secrets(input, steps, page).map(|(output, _)| output)
}

/// [`draft_from_steps`], with the typed secret slots its proposal names
/// (CUA E8a): a durable copy keeps their kinds once its args lose them.
pub(crate) fn draft_with_secrets(
    input: &DraftInput,
    steps: &[DraftStep],
    page: &DraftPage,
) -> Result<(DraftOutput, Vec<SecretParam>), BrowserError> {
    let span = span(input, steps, page)?;
    let mut draft = Draft {
        origin: span.origin.clone(),
        after_seq: span.after_seq,
        opening: None,
        tab: None,
        params: Vec::new(),
        secret: Vec::new(),
        args: BTreeMap::new(),
        replay_args: BTreeMap::new(),
        steps: Vec::new(),
        literals: Vec::new(),
        gaps: Vec::new(),
        pressed: Vec::new(),
    };
    if input.subgoal.trim().is_empty() {
        draft.input_gap(DraftGapKind::NoSubgoal);
    }
    let taken = &steps[span.start..span.end];
    if page.origin.is_none() && input.through_seq.is_none() {
        draft.input_gap(DraftGapKind::NoLiveOrigin);
    }
    match taken.first() {
        None => draft.input_gap(DraftGapKind::EmptySpan),
        Some(first) if !matches!(first.action, Ok(ReplayAction::Open { .. })) => {
            draft.gap(first, DraftGapKind::MissingOpening);
        }
        Some(first) => draft.opening = Some(first.seq),
    }
    for step in taken {
        if !draft.step(step, input.past_press) {
            break;
        }
    }
    let postcondition = draft.checks(&input.postcondition, page);
    let slot_candidates = draft.candidates();
    let site = match draft.steps.first() {
        Some(BatchStep::Open { url }) => site_of(url),
        _ => site_of(&page.url),
    };
    let complete = !taken.is_empty()
        && draft
            .gaps
            .iter()
            .all(|gap| matches!(gap.gap, DraftGapKind::PrePress { .. }));
    let output = DraftOutput {
        site,
        origin: span.origin,
        after_seq: span.after_seq,
        through_seq: span.through_seq,
        proposal: ProposeInput {
            subgoal: input.subgoal.clone(),
            params: draft.params,
            steps: draft.steps,
            postcondition,
            args: draft.args,
            replay_args: BTreeMap::new(),
            supersedes: None,
            seed: None,
        },
        slot_candidates,
        gaps: draft.gaps,
        pressed_through: draft.pressed,
        complete,
    };
    Ok((output, draft.secret))
}
