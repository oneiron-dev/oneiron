use super::*;
use schemars::JsonSchema;
use std::collections::BTreeMap;

/// The desktop's windows, or only those of the app `app` names.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WindowsInput {
    #[serde(default)]
    pub app: Option<String>,
}

/// One window of the desktop. `window` names it for `self.desktop.window`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DesktopWindow {
    pub window: String,
    pub app: String,
    pub title: String,
    /// The window the session reads and acts on now.
    pub current: bool,
    /// The window in front of all the others.
    pub front: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WindowsOutput {
    pub windows: Vec<DesktopWindow>,
}

/// Moves the session onto another window: later reads and actions are
/// that window's.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WindowInput {
    pub window: String,
}

/// Asks a person to take the desktop or the browser over (CUA-001): `reason`
/// says what the agent needs them to do. Until they hand it back, every
/// desktop verb refuses `desktop_taken_over`, and every browser verb
/// `browser_taken_over`.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoverInput {
    pub reason: String,
}

/// The "Needs you" ask as the run's desktop or browser holds it.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HandoverOutput {
    pub reason: String,
    pub asked_at_ms: u64,
}

/// One input from the person who holds a run's browser (CUA-001), at the
/// pixels of the viewport screen they were last shown, or a page to go to.
/// No press gates it: the person's own input is their press.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BrowserPersonInput {
    Click {
        x: u32,
        y: u32,
        /// `left` (the default), `right` or `middle`.
        #[serde(default)]
        button: Option<String>,
        /// 1 (the default) to 3, for a double or triple click.
        #[serde(default)]
        count: Option<u32>,
    },
    /// Text typed where the page's focus is.
    Type { text: String },
    /// One named key (`enter`, `tab`, `escape`, `backspace`, `delete`,
    /// `space`, the arrows, `home`, `end`, `pageup`, `pagedown`, `f1` to
    /// `f12`) or one character.
    Key { key: String },
    /// Modifiers (`ctrl`, `alt`, `shift`, `meta`) then one key.
    Hotkey { keys: Vec<String> },
    Scroll {
        x: u32,
        y: u32,
        /// `up`, `down`, `left` or `right`.
        direction: String,
        /// Wheel notches, 3 by default.
        #[serde(default)]
        amount: Option<u32>,
    },
    /// Goes to an http or https page.
    Navigate { url: String },
}

/// One tab of a run's browser as its owner sees it (CUA-001): the run's own
/// page, or a tab or popup opened from it since (an OAuth sign-in window, a
/// `target=_blank` link). `tab` names it to the owner's screen and input.
/// The tab in `front` is the one the owner's screen shows and the agent's
/// verbs drive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserTab {
    pub tab: String,
    pub url: String,
    pub title: String,
    pub front: bool,
}

/// The effect classes a browser control can fall in. A vault grant names one
/// of these to set its press.
pub const EFFECT_SEND: &str = "browser.send";
pub const EFFECT_PAY: &str = "browser.pay";
pub const EFFECT_ACCOUNT: &str = "browser.account";
pub const EFFECT_PUBLISH: &str = "browser.publish";
pub const EFFECT_DESTRUCTIVE: &str = "browser.destructive";
pub const EFFECT_CLASSES: &[&str] = &[
    EFFECT_SEND,
    EFFECT_PAY,
    EFFECT_ACCOUNT,
    EFFECT_PUBLISH,
    EFFECT_DESTRUCTIVE,
];

/// The class a click's receipt names when its target names none: a point on
/// no row, or a row with no name. The click runs as any unclassified one
/// (DEC-0006 #6, biased-permissive), and its trail shows it was blind. No
/// grant names it.
pub const EFFECT_UNKNOWN: &str = "browser.unknown";

/// How much press one effect class needs, as the vault's grant sets it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PressMode {
    /// A person's press for every send. The floor without a grant.
    #[default]
    PerSend,
    /// One press covered a reviewed batch; sends run until it is spent.
    PerBatch,
    /// The standing grant covers the class; no press.
    None,
}

impl PressMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PerSend => "per_send",
            Self::PerBatch => "per_batch",
            Self::None => "none",
        }
    }
}

/// The press each effect class runs under for one session, resolved by the
/// host from the vault's standing grants. Unnamed classes need a press per
/// send. A payment stays with a natural person whatever this says.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendPolicy {
    pub modes: BTreeMap<String, PressMode>,
    /// Sends still covered by a reviewed batch's press, per class.
    pub batch: BTreeMap<String, u32>,
}

impl SendPolicy {
    #[must_use]
    pub fn mode_for(&self, class: &str) -> PressMode {
        self.modes.get(class).copied().unwrap_or_default()
    }

    /// Classes no grant moves off a person's press: the agent fills the
    /// cart, the person clicks pay inside the virtual browser.
    #[must_use]
    pub fn person_only(class: &str) -> bool {
        class == EFFECT_PAY
    }
}

/// One step of a batched subgoal program. A mid planner writes one batch per
/// subgoal; each step still crosses its own gated door. A step's `ref` and
/// `targets` take live handles or locators; a replay program holds locators
/// only, resolved as each step runs.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum BatchStep {
    Open {
        url: String,
    },
    Click {
        #[serde(rename = "ref")]
        target: String,
    },
    /// Types literal `text`, or the secret a run-bound handle names
    /// (`secret`), as the `type` verb does: exactly one of the two.
    Type {
        #[serde(rename = "ref")]
        target: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret: Option<String>,
        #[serde(default)]
        clear: bool,
    },
    Select {
        #[serde(rename = "ref")]
        target: String,
        option: String,
    },
    /// Waits until a row `targets` names is on the page, or, with none
    /// named, a row `role` and `name` match, as the `wait_for` verb waits.
    WaitFor {
        #[serde(default)]
        targets: Vec<String>,
        #[serde(default)]
        role: Option<String>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        timeout_ms: Option<u32>,
    },
    Expect {
        #[serde(default, rename = "ref")]
        target: Option<String>,
        #[serde(default)]
        role: Option<String>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        value: Option<String>,
        /// A run-bound secret handle the row must hold, as the `expect`
        /// verb's `secret`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret: Option<String>,
        #[serde(default)]
        absent: bool,
    },
    Screenshot {
        trigger: ScreenshotTrigger,
    },
    /// A desktop key press.
    Key {
        key: String,
        #[serde(default)]
        modifiers: Vec<String>,
        #[serde(default, rename = "ref")]
        target: Option<String>,
    },
    /// A desktop key combination.
    Hotkey {
        keys: Vec<String>,
    },
    /// A desktop scroll.
    Scroll {
        direction: ScrollDirection,
        #[serde(default)]
        amount: Option<u32>,
        #[serde(default, rename = "ref")]
        target: Option<String>,
    },
    /// A routine step: the host's decider picks the step's target, and the
    /// step acts on it.
    Decide(DecideStep),
    /// Types a field's text, replacing what it held, resolved in order (CUA
    /// E6): `supplied` text; else one of its references, several a routine
    /// choice among their ids; else its template; else, with `generate`,
    /// the host's writer, checked yes/no. The receipt names the text's
    /// source and reference. A strict run's generation goes up unasked.
    Fill {
        #[serde(rename = "ref")]
        target: String,
        field: FieldSpec,
    },
}

/// A routine step (the CUA-S1 pattern): a small decider takes the step's
/// choice under the subgoal's one clock. It picks one of the rows `targets`
/// names (or, with none named, the rows `role` and `name` match, as `find`
/// matches them) and the step clicks it, types `text` into it, types the
/// secret a run-bound handle names (`secret`, FIX 8028) into it, or selects
/// `option` in it: at most one of the three. With `locate`, the decider
/// finds the target in a screenshot instead and the step clicks at its
/// centre.
///
/// Past [`ROUTINE_MAX_CANDIDATES`] candidates, the decider reads them in
/// pages of that many, and NONE on one page moves to the next: a step is
/// never refused, cut or sampled for its count (Rule 5).
///
/// The decider may answer NONE or reobserve: the step looks again, with a
/// screenshot from the second such answer in a row, up to
/// [`ROUTINE_LOOKS`] looks. "Too complicated, ask up", or a decider with no
/// answer, stops the batch for the planner.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecideStep {
    pub question: String,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub locate: bool,
    #[serde(default)]
    pub text: Option<String>,
    /// The handle of a secret this run's browser found, typed in place of
    /// `text`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default)]
    pub clear: bool,
    #[serde(default)]
    pub option: Option<String>,
}

/// One batched program: one or more steps, run in order.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchInput {
    /// What this batch is for, recorded on its receipts' run.
    #[serde(default)]
    pub subgoal: Option<String>,
    pub steps: Vec<BatchStep>,
    /// The observation the batch's last observation edits, as `observe`'s
    /// `base`; by default the last one the caller read whole. The steps
    /// between never move it.
    #[serde(default)]
    pub base: Option<ObservationBase>,
    /// The subgoal's one clock, as the Unix milliseconds it ends at, when an
    /// earlier batch of the subgoal started it. Absent, the first routine
    /// step starts it; every later step reads the same one.
    #[serde(default)]
    pub until_ms: Option<u64>,
    /// Routine steps take only a rule's answer, never a model's: the
    /// library's replay check runs so, and so does a strict library run. A
    /// step only a model could answer goes up, no model asked.
    #[serde(default)]
    pub no_model: bool,
}

/// How a batched subgoal program ended. The big model is the fallback only:
/// it takes over on `NEEDS_AGENT`, and a person presses, or has the
/// desktop, on `NEEDS_YOU`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum SubgoalStatus {
    #[serde(rename = "done")]
    Done,
    #[serde(rename = "NEEDS_AGENT")]
    NeedsAgent,
    #[serde(rename = "NEEDS_YOU")]
    NeedsYou,
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BatchOutput {
    pub status: SubgoalStatus,
    pub completed: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_step: Option<usize>,
    /// The stable refusal code of the step that stopped the batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// What stopped the batch; none when it is done.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_cause: Option<BatchStopCause>,
    /// The step that stopped it, with the checks it missed and the page as
    /// read then: what goes up with the stop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_receipt: Option<FailedStepReceipt>,
    /// The batch's wall time, in milliseconds of the monotonic clock, its
    /// waits, decisions and gated effects included. A library run's runs on
    /// through its final postcondition checks, and on a miss the read of
    /// the page it hands back.
    pub elapsed_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<Observation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<EffectReceipt>,
    /// Each routine step's decision, with its receipt, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decisions: Vec<serde_json::Value>,
    /// The subgoal's clock, once a routine step started it: the next batch
    /// of the subgoal passes it on as its `until_ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_ms: Option<u64>,
    /// `observation` is the first page of a longer one: the cursor
    /// `observe` reads the next page from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    /// Each step whose target resolved by its locator, not its own row: an
    /// effect's (as its receipt says too), a wait's, a check's or a routine
    /// step's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rebindings: Vec<StepRebound>,
}

/// Looks one routine step takes before it goes up to the planner.
pub const ROUTINE_LOOKS: u32 = 4;

/// How long a routine step waits, once, for a row its role and name match
/// before it goes up: a page still loading has none yet. Never past the
/// subgoal's clock.
pub const ROUTINE_WAIT_MS: u32 = 5_000;

/// One routine step's question to the host's decider.
pub struct RoutineAsk<'a> {
    pub question: &'a str,
    /// The step's candidates (a Choice), or none for a locate step (a Box
    /// over `image`).
    pub options: Vec<String>,
    /// The screenshot the step read, by its held ref, with its PNG bytes.
    pub image: Option<(&'a str, &'a [u8])>,
    /// The page the step reads: its URL and title.
    pub state: serde_json::Value,
    /// NONE or reobserve answers the subgoal's steps gave in a row before.
    pub misses: u32,
    /// The subgoal's one clock, once started.
    pub until_ms: Option<u64>,
    /// Only a rule may answer, never a model.
    pub no_model: bool,
}

/// The decider's answer, as the driver acts on it.
#[derive(Clone, Debug, PartialEq)]
pub enum RoutineAnswer {
    /// Act on this candidate.
    Act {
        candidate: String,
    },
    /// Act at this point of the step's screenshot, in fractions of it.
    Point {
        x: f64,
        y: f64,
    },
    None,
    Reobserve,
    /// The step goes back to the planner, with the ladder's reason.
    AskUp {
        reason: Option<String>,
    },
    /// A strict run's step that only a model could answer: no model was
    /// asked, and the step goes back to the planner.
    Denied {
        denial: StrictDenial,
    },
    /// The subgoal's clock ran out before an answer: the step stops on it.
    Deadline,
}

#[derive(Clone, Debug)]
pub struct RoutineReply {
    pub answer: RoutineAnswer,
    /// The routine trail's word: NONE or reobserve came twice in a row, so
    /// the next look takes a screenshot (`decider_reobserve`).
    pub screenshot: bool,
    /// The subgoal's clock, as the decider ran it.
    pub until_ms: Option<u64>,
    /// The decision with its receipt, for the batch's answer; a strict
    /// step no rung gave a receipt for keeps a [`StrictDenied`] record.
    pub decision: serde_json::Value,
}

/// The host's routine decider: the engine's decision ladder, behind the
/// driver. A driver without one sends every routine step up.
pub trait RoutineDecider: Send {
    fn decide(&mut self, ask: RoutineAsk<'_>) -> Result<RoutineReply, BrowserError>;
    /// A yes/no check of a Fill's written text (CUA E6): one question, its
    /// state holding the text, answered once.
    ///
    /// # Errors
    ///
    /// The check could not be asked, or its answer not read.
    fn check_text(&mut self, check: TextCheck<'_>) -> Result<TextCheckReply, BrowserError>;
}

/// No decider: a routine step cannot run, so it goes up.
pub struct NoDecider;

impl RoutineDecider for NoDecider {
    fn decide(&mut self, _ask: RoutineAsk<'_>) -> Result<RoutineReply, BrowserError> {
        Err(BrowserError::Decider(
            "this browser host has no routine decider".to_owned(),
        ))
    }

    fn check_text(&mut self, _check: TextCheck<'_>) -> Result<TextCheckReply, BrowserError> {
        Err(BrowserError::Decider(
            "this browser host has no routine decider".to_owned(),
        ))
    }
}
