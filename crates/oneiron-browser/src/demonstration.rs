//! A demonstration (CUA E9; DESIGN-2 "The owner, by demonstration"): one
//! opted-in span of a browser session, recorded from its pages' own DOM
//! events as replay steps, and the draft E7's one helper makes of them
//! (`library::draft`). A session records nothing, and its pages carry no
//! listener, until a start opts it in.
//!
//! An act the run's own verb made keeps that verb's receipt: its exact
//! locator, its operand, its effect class. Any other act (a scripted input
//! sequence, a page's own control) takes the locator of the one row the
//! open page's outline shows for it, matched by role, name and order; an
//! act no row matches is a named gap, never a locator made up from the DOM.
//!
//! A secret never leaves its page (FIX 8028): the page's own twin of the
//! one classifier withholds the value before any event is sent, the host
//! checks again, and a secret edit is a type whose operand is withheld,
//! unbound, of its kind.
//!
//! The rules where canon is silent live here, one home each:
//! `demonstration_coalesce_policy` (edits, selects, clicks, submits and
//! navigations as steps) and `demonstration_gesture_policy` (which keys are
//! gestures no step replays).
#![cfg_attr(not(feature = "driver"), allow(dead_code))]

use crate::{
    BatchStopCause, DraftOutput, EFFECT_UNKNOWN, ExpectInput, OperandGap, ReplayAction, SecretKind,
    TypeOperand,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A demonstration's id within its session: `dm1`, `dm2`, ...
pub type DemonstrationId = String;

/// Who drove the span a demonstration recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DemonstrationSource {
    /// The run's own agent, or a scripted input sequence on its session.
    Agent,
    /// A person holding the browser (CUA E9b): an opted-in handover's take
    /// starts it, never this verb.
    Takeover,
}

/// Why a demonstration's span ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DemonstrationStopCause {
    /// Its stop ended it.
    Stopped,
    /// The agent handed the browser to a person, or a person took it: an
    /// agent's span never records a person's input.
    HandedOver,
    /// The person holding the browser handed it back.
    HandedBack,
    /// The run's sandbox was abandoned.
    Abandoned,
    /// The browser's guest stopped answering.
    GuestLost,
    /// The session moved to another engine: a span never runs on in a new
    /// guest.
    EngineSwitched,
    /// The session closed.
    SessionClosed,
}

/// Starts recording the attached run's browser (Chromium only).
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DemonstrationStartInput {
    /// What the demonstration shows, as the caller names it: descriptive
    /// only, never a subgoal or a check.
    #[serde(default)]
    pub label: Option<String>,
}

/// A recording that runs: this start's, or the one already running.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DemonstrationStarted {
    pub id: DemonstrationId,
    pub source: DemonstrationSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub started_at_ms: u64,
    /// The open page's web origin when it started; none on `about:blank`
    /// or any page with no http or https origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    pub url: String,
    /// A recording was running already: this is it, unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub already_running: bool,
}

/// Stops demonstration `id`, or takes one that already ended, and drafts
/// its steps with this subgoal and these checks.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DemonstrationStopInput {
    pub id: DemonstrationId,
    /// What the demonstrated program is for, as a proposal names it.
    #[serde(default)]
    pub subgoal: String,
    /// What the page shows when it worked, as a proposal's checks: a live
    /// handle goes back to its row's locator, a secret to a typed slot.
    #[serde(default)]
    pub postcondition: Vec<ExpectInput>,
}

/// A demonstration, ended: its steps, its gaps, and the draft E7's helper
/// made of them. Never filed: `library.propose` checks and replays a draft.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DemonstrationOutput {
    pub id: DemonstrationId,
    pub source: DemonstrationSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The web origin its first web page had; none when it had none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    pub steps: Vec<RecordedStep>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<RecordingGap>,
    pub started_at_ms: u64,
    pub stopped_at_ms: u64,
    pub stop_cause: DemonstrationStopCause,
    pub draft: DraftOutput,
}

/// One recorded step, in order: its act as a replay takes it, or none where
/// a gap of the same `seq` names why; where it began and what it left.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecordedStep {
    /// The step's place in this recording, from 1.
    pub seq: u64,
    /// `open`, `click`, `type`, `select`, or `gesture`.
    pub verb: String,
    /// The tab it acted in, and the tab in front once it settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tab: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_tab: Option<String>,
    /// The top page it began on, and the one it left.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_url: Option<String>,
    /// The name of the row it acted on, as the outline shows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_class: Option<String>,
    /// The run's own effect receipt this step is, by its seq.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ReplayAction>,
    /// A stop marked the run's own step failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<BatchStopCause>,
    /// The run's own step proved it changed nothing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_effect: bool,
}

/// What a recording could not keep as a replay step, at step `seq`, or, with
/// none, of the recording.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecordingGap {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tab: Option<String>,
    pub gap: RecordingGapKind,
}

/// The gaps a recording names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "why", rename_all = "snake_case")]
pub enum RecordingGapKind {
    /// The act's target has no replay locator, for `cause`.
    NoLocator { cause: LocatorGap },
    /// A gesture no replay step takes: a key outside typing (a shortcut,
    /// an arrow, Enter that submitted nothing), a drag, a file chooser.
    Gesture { gesture: String },
    /// The recorder could not listen in `target` (a tab or a frame): acts
    /// there are not recorded.
    Uncovered { target: String },
    /// The pages' events stopped reaching the host before the end: acts
    /// after the last step are not recorded.
    CaptureLost,
    /// A tab's page navigated with no act recorded since its last page (a
    /// typed URL, a script's history move, a navigation outside the run's
    /// verbs): a step may be missing (FIX 9413).
    UnrecordedNavigation,
    /// The capture never started, for `refusal` (a takeover's span on a
    /// Lightpanda guest, CUA E9b): no act of the span is recorded.
    NotStarted { refusal: String },
}

/// Why an act's target has no replay locator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LocatorGap {
    /// The page could not describe it: a canvas, a closed shadow root.
    NoTarget,
    /// Its document was gone before the host read its outline.
    DocumentGone,
    /// Its tab was not in front when the host read the outline.
    NotInFront,
    /// No row of the outline has its role and name.
    NoMatch,
    /// Several rows have its role and name, and its order among them did
    /// not settle which.
    Ambiguous,
    /// The outline could not be read.
    NoOutline,
}

/// A target the outline matched: its row's locator and name, and the effect
/// class its press takes.
pub(crate) struct Mapped {
    pub(crate) locator: String,
    pub(crate) name: String,
    pub(crate) effect_class: Option<String>,
}

/// A text edit's value after it: the whole text, or the kind of secret the
/// page withheld.
#[derive(Clone)]
pub(crate) enum Edited {
    Text(String),
    Secret(SecretKind),
}

/// A key going down, as the page saw it.
pub(crate) struct KeyFacts {
    pub(crate) key: String,
    /// `Control+`, `Alt+`, `Meta+` and `Shift+` as held, in that order.
    pub(crate) mods: String,
    /// The target takes typed text, is a select, activates on Enter or
    /// Space (a button, a link, a box), or sits in a form.
    pub(crate) editable: bool,
    pub(crate) select: bool,
    pub(crate) activates: bool,
    pub(crate) form: bool,
}

/// One thing the recorder saw, in its pages' order, in tab `tab` on top
/// page `url`.
pub(crate) struct Seen {
    pub(crate) tab: String,
    pub(crate) url: Option<String>,
    pub(crate) saw: Saw,
}

pub(crate) enum Saw {
    Click(Result<Mapped, LocatorGap>),
    /// An edit of the field `key` names within its document.
    Edit {
        key: String,
        target: Result<Mapped, LocatorGap>,
        value: Edited,
    },
    /// The edit of `key` closed: a change or a blur.
    Commit {
        key: String,
    },
    Select {
        target: Result<Mapped, LocatorGap>,
        option: String,
    },
    Key(KeyFacts),
    /// A form submitted, by its submitter, or with none.
    Submit(Option<Result<Mapped, LocatorGap>>),
    Gesture(String),
    /// A top-level document loaded, at the seen `url`.
    Document,
    /// What the capture lost: a page it could not listen in, an event it
    /// could not read.
    Gap(RecordingGapKind),
}

/// What a key is to a recording (`demonstration_gesture_policy`).
enum KeyRole {
    /// Typing, or a key whose outcome another event records.
    Ignored,
    /// Enter in a form field: a submit records it, else it is a gesture.
    Submits,
    Gesture(String),
}

/// Which keys are gestures no step replays (`demonstration_gesture_policy`,
/// CALLS row): in a text field, Enter outside a form, Escape and any Enter
/// with a modifier (the other keys' outcome is the field's text, which its
/// edit records); in a select none (its change records); on a button, link
/// or box, Enter and Space are its click; Tab and a bare Shift never; any
/// other key a page sees, with or without modifiers, is one.
fn demonstration_gesture_policy(key: &KeyFacts) -> KeyRole {
    let name = || KeyRole::Gesture(format!("key:{}{}", key.mods, key.key));
    let bare = key.mods.is_empty() || key.mods == "Shift+";
    match key.key.as_str() {
        "Tab" | "Shift" | "Control" | "Alt" | "Meta" | "CapsLock" => KeyRole::Ignored,
        _ if key.select => KeyRole::Ignored,
        "Enter" if key.editable && bare && key.form => KeyRole::Submits,
        "Enter" | "Escape" if key.editable => name(),
        _ if key.editable => KeyRole::Ignored,
        "Enter" | " " if key.activates && bare => KeyRole::Ignored,
        _ => name(),
    }
}

/// An edit not yet a step.
struct Pending {
    key: String,
    tab: String,
    url: Option<String>,
    target: Result<Mapped, LocatorGap>,
    value: Edited,
}

/// One recording as it runs, or as it ended and waits to be delivered.
pub(crate) struct Recording {
    pub(crate) id: DemonstrationId,
    pub(crate) source: DemonstrationSource,
    pub(crate) label: Option<String>,
    pub(crate) started_at_ms: u64,
    pub(crate) origin: Option<String>,
    pub(crate) url: String,
    pub(crate) steps: Vec<RecordedStep>,
    pub(crate) gaps: Vec<RecordingGap>,
    pending: Option<Pending>,
    /// An Enter in a form field of this tab, waiting for its submit.
    awaiting_submit: Option<(String, Option<String>)>,
    /// Each tab's top page, as last seen.
    pages: BTreeMap<String, String>,
    /// Whether an act was recorded since the last page loaded (FIX 9413);
    /// the page the recording began on counts as acted on.
    acted: bool,
    /// The tabs whose run's own act loaded a page whose document had sent
    /// nothing by that act's drain: the tab's next document is the act's
    /// own (FIX 10429).
    awaited: BTreeSet<String>,
}

impl Recording {
    pub(crate) fn new(
        id: DemonstrationId,
        source: DemonstrationSource,
        label: Option<String>,
        started_at_ms: u64,
        (origin, url): (Option<String>, String),
    ) -> Self {
        Self {
            id,
            source,
            label,
            started_at_ms,
            origin,
            url,
            steps: Vec::new(),
            gaps: Vec::new(),
            pending: None,
            awaiting_submit: None,
            pages: BTreeMap::new(),
            acted: true,
            awaited: BTreeSet::new(),
        }
    }

    /// The answer a start gives for this recording.
    pub(crate) fn started(&self, already_running: bool) -> DemonstrationStarted {
        DemonstrationStarted {
            id: self.id.clone(),
            source: self.source,
            label: self.label.clone(),
            started_at_ms: self.started_at_ms,
            origin: self.origin.clone(),
            url: self.url.clone(),
            already_running,
        }
    }

    /// Each tab's top page, as the recording last saw it.
    pub(crate) const fn pages(&self) -> &BTreeMap<String, String> {
        &self.pages
    }

    /// Names a gap of the recording, or of step `seq`.
    pub(crate) fn gap(&mut self, seq: Option<u64>, tab: Option<String>, gap: RecordingGapKind) {
        self.gaps.push(RecordingGap { seq, tab, gap });
    }

    /// Takes what the pages showed of acts no verb of the run made, in
    /// order (`demonstration_coalesce_policy`, CALLS row): consecutive edits
    /// of one field are one type of its final text, clearing it first,
    /// closed by its change or blur, another act, a navigation or the end;
    /// a select's change is one select of the option's label; a click is
    /// one click of the row it hit; Enter that submitted a form is a click
    /// of the form's submitter; a navigation is the context of the steps
    /// around it, never an `open` (only the run's own open is one).
    pub(crate) fn demonstration_coalesce_policy(&mut self, seen: Seen) {
        let Seen { tab, url, saw } = seen;
        if let Some(url) = &url {
            self.pages.insert(tab.clone(), url.clone());
        }
        if !matches!(saw, Saw::Document | Saw::Gap(_)) {
            self.acted = true;
            self.awaited.remove(&tab);
        }
        // A form field's change, and the submit, follow its Enter.
        if !matches!(saw, Saw::Submit(_) | Saw::Commit { .. }) {
            self.unsubmitted();
        }
        match saw {
            Saw::Edit { key, target, value } => self.edit(Pending {
                key,
                tab,
                url,
                target,
                value,
            }),
            Saw::Commit { key } => {
                if self.pending.as_ref().is_some_and(|edit| edit.key == key) {
                    self.flush();
                }
            }
            Saw::Click(target) => {
                self.flush();
                self.act(&tab, url, "click", target, |locator| ReplayAction::Click {
                    locator,
                });
            }
            Saw::Select { target, option } => {
                self.flush();
                self.act(&tab, url, "select", target, |locator| {
                    ReplayAction::Select { locator, option }
                });
            }
            Saw::Submit(submitter) => self.submit(&tab, url, submitter),
            Saw::Key(key) => self.key(tab, url, &key),
            Saw::Gesture(gesture) => {
                self.flush();
                self.gesture(&tab, url, gesture);
            }
            Saw::Document => {
                self.flush();
                // A page no recorded act led to (FIX 9413); the late
                // document of the run's own act is that act's (FIX 10429).
                if !self.awaited.remove(&tab) && !std::mem::take(&mut self.acted) {
                    let gap = RecordingGapKind::UnrecordedNavigation;
                    self.gap(None, Some(tab.clone()), gap);
                }
                if let Some(url) = url {
                    self.settle(&tab, &url);
                }
            }
            Saw::Gap(gap) => self.gap(None, Some(tab), gap),
        }
    }

    /// An edit: another field's open edit becomes its step first; the same
    /// field's keeps the page its first edit began on.
    fn edit(&mut self, mut edit: Pending) {
        if self
            .pending
            .as_ref()
            .is_some_and(|open| open.key != edit.key)
        {
            self.flush();
        }
        if let Some(open) = self.pending.take() {
            edit.url = open.url.or(edit.url);
        }
        self.pending = Some(edit);
    }

    /// A submit: after an Enter in one of its fields, a click of its
    /// submitter, or a gesture when it has none; after a click on its
    /// submitter, nothing more (the click is the step).
    fn submit(
        &mut self,
        tab: &str,
        url: Option<String>,
        submitter: Option<Result<Mapped, LocatorGap>>,
    ) {
        self.flush();
        if self.awaiting_submit.take().is_none() {
            return;
        }
        match submitter {
            Some(target) => self.act(tab, url, "click", target, |locator| ReplayAction::Click {
                locator,
            }),
            None => self.gesture(tab, url, "submit:no_button".to_owned()),
        }
    }

    /// A key, as the gesture policy reads it.
    fn key(&mut self, tab: String, url: Option<String>, key: &KeyFacts) {
        match demonstration_gesture_policy(key) {
            KeyRole::Ignored => {}
            KeyRole::Submits => {
                self.flush();
                self.awaiting_submit = Some((tab, url));
            }
            KeyRole::Gesture(gesture) => {
                self.flush();
                self.gesture(&tab, url, gesture);
            }
        }
    }

    /// A step the run's own verb made (its receipt's), with the final text
    /// the page showed for a type's field, if it showed one.
    pub(crate) fn own(&mut self, mut step: RecordedStep, edited: Option<Edited>) {
        self.unsubmitted();
        self.flush();
        self.acted = true;
        step.seq = self.next_seq();
        if let Some(action) = step.action.take() {
            step.action = Some(demonstration_own_act_policy(action, edited));
        }
        if let (Some(tab), Some(url)) = (&step.result_tab, &step.result_url) {
            self.pages.insert(tab.clone(), url.clone());
        }
        self.push(step);
    }

    /// The run's own act in tab `tab` loaded a page whose document had sent
    /// nothing by that act's drain (FIX 10429): the tab's next document is
    /// that act's own, and a script's redirect after it still follows an
    /// act.
    pub(crate) fn awaits_document(&mut self, tab: String) {
        self.awaited.insert(tab);
    }

    /// Ends the span: the open edit becomes its step, an Enter that
    /// submitted nothing a gesture, and each step that left no page names
    /// its tab's last.
    pub(crate) fn finish(&mut self) {
        self.unsubmitted();
        self.flush();
        for step in &mut self.steps {
            if step.result_url.is_none() {
                let tab = step.tab.as_deref().unwrap_or_default();
                step.result_url = self.pages.get(tab).cloned().or(step.source_url.clone());
            }
        }
    }

    fn unsubmitted(&mut self) {
        if let Some((tab, url)) = self.awaiting_submit.take() {
            self.gesture(&tab, url, "key:Enter".to_owned());
        }
    }

    /// The open edit as its type step.
    fn flush(&mut self) {
        let Some(edit) = self.pending.take() else {
            return;
        };
        let operand = match edit.value {
            Edited::Text(text) => TypeOperand::Literal { text },
            Edited::Secret(kind) => unbound(Some(kind)),
        };
        self.act(&edit.tab, edit.url, "type", edit.target, |locator| {
            ReplayAction::Type {
                locator,
                operand,
                clear: true,
            }
        });
    }

    /// One act on `target`, or its gap.
    fn act(
        &mut self,
        tab: &str,
        url: Option<String>,
        verb: &str,
        target: Result<Mapped, LocatorGap>,
        action: impl FnOnce(String) -> ReplayAction,
    ) {
        let mut step = self.blank(tab, url, verb);
        match target {
            Ok(mapped) => {
                step.target_name = Some(mapped.name);
                step.effect_class = mapped.effect_class.filter(|_| verb == "click");
                step.action = Some(action(mapped.locator));
            }
            Err(cause) => {
                // A press no row names might send (`draft_press_end_policy`).
                if verb == "click" {
                    step.effect_class = Some(EFFECT_UNKNOWN.to_owned());
                }
                let gap = RecordingGapKind::NoLocator { cause };
                self.gap(Some(step.seq), Some(tab.to_owned()), gap);
            }
        }
        self.push(step);
    }

    fn gesture(&mut self, tab: &str, url: Option<String>, gesture: String) {
        let step = self.blank(tab, url, "gesture");
        let gap = RecordingGapKind::Gesture { gesture };
        self.gap(Some(step.seq), Some(tab.to_owned()), gap);
        self.push(step);
    }

    fn blank(&self, tab: &str, url: Option<String>, verb: &str) -> RecordedStep {
        RecordedStep {
            seq: self.next_seq(),
            verb: verb.to_owned(),
            tab: Some(tab.to_owned()),
            result_tab: Some(tab.to_owned()),
            source_url: url.or_else(|| self.pages.get(tab).cloned()),
            result_url: None,
            target_name: None,
            effect_class: None,
            receipt: None,
            action: None,
            failed: None,
            no_effect: false,
        }
    }

    /// The next step's seq.
    pub(crate) fn next_seq(&self) -> u64 {
        let last = self.steps.last().map_or(0, |step| step.seq);
        let gapped = self
            .gaps
            .iter()
            .filter_map(|gap| gap.seq)
            .max()
            .unwrap_or(0);
        last.max(gapped) + 1
    }

    /// Appends `step`, its tab's step before it leaving the page it began
    /// on; a type that clears the field its last step typed replaces it.
    fn push(&mut self, step: RecordedStep) {
        if let (Some(tab), Some(url)) = (&step.tab, &step.source_url) {
            self.settle(tab, url);
        }
        let retyped = match (self.steps.last(), &step.action) {
            (
                Some(last),
                Some(ReplayAction::Type {
                    locator,
                    clear: true,
                    ..
                }),
            ) => last.tab == step.tab && last.failed.is_none() && typed_into(last, locator),
            _ => false,
        };
        if retyped && let Some(last) = self.steps.last_mut() {
            let source_url = last.source_url.take();
            *last = RecordedStep {
                source_url: source_url.or(step.source_url),
                ..step
            };
            return;
        }
        self.steps.push(step);
    }

    /// The last step of `tab` that left no page yet left `url`.
    fn settle(&mut self, tab: &str, url: &str) {
        if let Some(step) = self
            .steps
            .iter_mut()
            .rev()
            .find(|step| step.tab.as_deref() == Some(tab))
            && step.result_url.is_none()
        {
            step.result_url = Some(url.to_owned());
        }
    }
}

/// Whether `step` typed into the row `locator` names.
fn typed_into(step: &RecordedStep, locator: &str) -> bool {
    matches!(&step.action, Some(ReplayAction::Type { locator: typed, .. }) if typed == locator)
}

/// The run's own act as a demonstration keeps it
/// (`demonstration_own_act_policy`, CALLS row): a type of literal text
/// takes the field's whole text after it, clearing it first; a literal or a
/// Fill into a field the page withheld as a secret is never kept as text
/// (FIX 8028), but as an unbound secret of its kind.
fn demonstration_own_act_policy(action: ReplayAction, edited: Option<Edited>) -> ReplayAction {
    match (action, edited) {
        (
            ReplayAction::Type {
                locator,
                operand: TypeOperand::Literal { .. },
                ..
            }
            | ReplayAction::Fill { locator, .. },
            Some(Edited::Secret(kind)),
        ) => ReplayAction::Type {
            locator,
            operand: unbound(Some(kind)),
            clear: true,
        },
        (
            ReplayAction::Type {
                locator,
                operand: TypeOperand::Literal { .. },
                ..
            },
            Some(Edited::Text(text)),
        ) => ReplayAction::Type {
            locator,
            operand: TypeOperand::Literal { text },
            clear: true,
        },
        (action, _) => action,
    }
}

/// A secret the page withheld: of its kind, bound to nothing, for the
/// caller to bind (E7's unbound operand, `secret_slot_policy`).
fn unbound(kind: Option<SecretKind>) -> TypeOperand {
    TypeOperand::Withheld {
        kind,
        cause: OperandGap::Unbound,
    }
}
