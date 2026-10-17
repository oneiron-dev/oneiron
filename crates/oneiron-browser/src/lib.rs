//! Browser verbs for code mode (`self.browser.*`), and the CDP driver
//! behind them (feature `driver`).
//!
//! A program reads the page as an outline of rows. Each row has a stable
//! `ref` built from its role, its accessible name and its named ancestors,
//! never from its position, so a ref read in one observation still names the
//! same element after the page changes around it. Every action waits for the
//! page to settle and returns the next observation as a diff.
//!
//! The same verbs drive a Linux desktop (`self.desktop.*`, OF-523): one
//! window of an isolated desktop guest, read as rows from its accessibility
//! tree through cua-driver, with keys, hotkeys, scrolling and the guest's
//! windows on top.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[cfg(feature = "driver")]
mod cdp;
#[cfg(feature = "driver")]
mod desktop;
#[cfg(feature = "driver")]
mod driver;
mod library;
#[cfg(feature = "driver")]
mod mcp;
#[cfg(feature = "driver")]
mod outline;
#[cfg(feature = "driver")]
mod session;

pub use library::{
    LibraryCard, LibraryFindInput, LibraryFindOutput, LibraryRunInput, LibraryRunOutput,
    ProposeInput, ProposeOutput, WORKFLOW_MAX_CHECKS, WORKFLOW_MAX_PARAMS, WORKFLOW_SUBGOAL_BYTES,
    WorkflowCheck, WorkflowLibrary, WorkflowProgram, WorkflowProof, site_of,
};
#[cfg(feature = "driver")]
pub use desktop::{DesktopGuest, DesktopSession};
#[cfg(feature = "driver")]
pub use oneiron_container::{GuestLimits, ImageRef};
#[cfg(feature = "driver")]
pub use session::{BrowserGuest, BrowserSession};

/// One element a program can read or act on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    #[serde(rename = "ref")]
    pub target: String,
    pub role: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub states: Vec<String>,
    pub depth: u16,
}

/// The page as rows. With `full` false it is a diff against the observation
/// `since` named: `rows` are new or changed, `removed` are refs now gone.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub seq: u64,
    pub url: String,
    pub title: String,
    pub full: bool,
    pub rows: Vec<Row>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<String>,
    /// The receipt of the effect that produced this observation, naming the
    /// page it acted on. A plain `observe` carries none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<EffectReceipt>,
    /// The library's programs for the page's site, on an `open`: repeated
    /// work on a site tries them first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub library: Vec<LibraryCard>,
    /// The desktop window shows no accessibility tree: the program reads
    /// it by a `no_accessibility_tree` screenshot and acts by locate steps
    /// or `click_at`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_tree: bool,
}

/// One effect's receipt: what acted, on which page, under which press, and
/// the screenshot taken as its evidence when one could be captured.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EffectReceipt {
    pub seq: u64,
    pub verb: String,
    pub url: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_class: Option<String>,
    /// The press the effect ran under: `per_send`, `per_batch` or `none`.
    pub press: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screenshot: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObserveInput {
    #[serde(default)]
    pub since: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenInput {
    pub url: String,
}

/// Rows whose role equals `role` and whose name contains `name`, ignoring case.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindInput {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindOutput {
    pub rows: Vec<Row>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClickInput {
    #[serde(rename = "ref")]
    pub target: String,
}

/// A click at a point of a held image, as a routine Box's centre gives it:
/// `x`, `y` are fractions of the image from its top-left. The image must
/// still show the page as it is (the same page, scrolled the same); the
/// point maps through it onto the viewport, and the row there takes the
/// click under the press a click on that row would take.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PointInput {
    pub image: String,
    pub x: f64,
    pub y: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypeInput {
    #[serde(rename = "ref")]
    pub target: String,
    pub text: String,
    /// Replace the field's text instead of inserting at the caret.
    #[serde(default)]
    pub clear: bool,
}

/// Picks the option of a `<select>` whose label, text or value is `option`.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectInput {
    #[serde(rename = "ref")]
    pub target: String,
    pub option: String,
}

/// Waits until some row matches `role` and `name`, as `find` matches them.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WaitForInput {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WaitForOutput {
    pub rows: Vec<Row>,
    pub timed_out: bool,
    pub waited_ms: u64,
}

/// A check on the page as it is now: the row named by `ref`, or else the
/// first row `role` and `name` match, is present (or absent) and, when
/// `value` is given, holds exactly that value.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExpectInput {
    #[serde(default, rename = "ref")]
    pub target: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub absent: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpectOutput {
    pub met: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row: Option<Row>,
}

/// Why a screenshot may be taken. There is no screenshot by default: a step
/// reads the outline, and a screenshot needs one of these named triggers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScreenshotTrigger {
    /// The outline is too thin to act on.
    OutlineThin,
    /// The step's postcondition has no predicate to check.
    NoPostcondition,
    /// The decider returned NONE or reobserve for the second time.
    DeciderReobserve,
    /// The page (or desktop) has no accessibility tree.
    NoAccessibilityTree,
    /// The per-effect receipt screenshot. The host takes this one itself.
    EffectReceipt,
}

impl ScreenshotTrigger {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OutlineThin => "outline_thin",
            Self::NoPostcondition => "no_postcondition",
            Self::DeciderReobserve => "decider_reobserve",
            Self::NoAccessibilityTree => "no_accessibility_tree",
            Self::EffectReceipt => "effect_receipt",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScreenshotInput {
    pub trigger: ScreenshotTrigger,
}

/// A screenshot the session holds. It is never captioned: `image` names the
/// bytes for a later image read, and nothing else describes them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScreenshotOutput {
    pub image: String,
    pub media_type: String,
    pub width: u32,
    pub height: u32,
    pub bytes: u64,
    pub trigger: ScreenshotTrigger,
    pub url: String,
    pub title: String,
}

/// Reads back a held image by its ref: the immutable original, described.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ViewInput {
    pub image: String,
}

/// A crop of a held image: the rectangle at (`x`, `y`), `width` by `height`.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CropInput {
    pub image: String,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// A zoom of a held image: the rectangle at (`x`, `y`) scaled up. Without
/// `scale`, the region is scaled to the viewport width, at most fourfold.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ZoomInput {
    pub image: String,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    #[serde(default)]
    pub scale: Option<f32>,
}

/// A held image, or one derived from it by crop or zoom. `source` is the ref
/// it was derived from; a view names itself.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageOutput {
    pub image: String,
    pub media_type: String,
    pub width: u32,
    pub height: u32,
    pub bytes: u64,
    pub source: String,
}

/// A key press, as `"Return"`, `"Tab"` or `"a"`, with `modifiers` (`ctrl`,
/// `shift`, `alt`, `super`) held. It goes to the row `ref` names, focused
/// first, or else to whatever the window has focused. A Return sends, so it
/// takes the press of a send.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyInput {
    pub key: String,
    #[serde(default)]
    pub modifiers: Vec<String>,
    #[serde(default, rename = "ref")]
    pub target: Option<String>,
}

/// A key combination, as `["ctrl", "s"]`: two keys or more, the last one
/// pressed while the others are held.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HotkeyInput {
    pub keys: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScrollDirection {
    Up,
    Down,
    Left,
    Right,
}

impl ScrollDirection {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
            Self::Left => "left",
            Self::Right => "right",
        }
    }
}

/// Scrolls the row `ref` names, or the window, by `amount` steps (one when
/// absent).
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScrollInput {
    pub direction: ScrollDirection,
    #[serde(default)]
    pub amount: Option<u32>,
    #[serde(default, rename = "ref")]
    pub target: Option<String>,
}

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
/// subgoal; each step still crosses its own gated door.
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
    Type {
        #[serde(rename = "ref")]
        target: String,
        text: String,
        #[serde(default)]
        clear: bool,
    },
    Select {
        #[serde(rename = "ref")]
        target: String,
        option: String,
    },
    WaitFor {
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
}

/// A routine step (the CUA-S1 pattern): a small decider takes the step's
/// choice under the subgoal's one clock. It picks one of the rows `targets`
/// names (or, with none named, the rows `role` and `name` match, as `find`
/// matches them) and the step clicks it, types `text` into it or selects
/// `option` in it. With `locate`, the decider finds the target in a
/// screenshot instead and the step clicks at its centre.
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
    #[serde(default)]
    pub clear: bool,
    #[serde(default)]
    pub option: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchInput {
    /// What this batch is for, recorded on its receipts' run.
    #[serde(default)]
    pub subgoal: Option<String>,
    pub steps: Vec<BatchStep>,
    /// The subgoal's one clock, as the Unix milliseconds it ends at, when an
    /// earlier batch of the subgoal started it. Absent, the first routine
    /// step starts it; every later step reads the same one.
    #[serde(default)]
    pub until_ms: Option<u64>,
    /// Routine steps take only a rule's answer, never a model's: the
    /// library's replay check runs so.
    #[serde(default)]
    pub no_model: bool,
}

/// How a batched subgoal program ended. The big model is the fallback only:
/// it takes over on `NEEDS_AGENT`, and a person presses on `NEEDS_YOU`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubgoalStatus {
    #[serde(rename = "done")]
    Done,
    #[serde(rename = "NEEDS_AGENT")]
    NeedsAgent,
    #[serde(rename = "NEEDS_YOU")]
    NeedsYou,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchOutput {
    pub status: SubgoalStatus,
    pub completed: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_step: Option<usize>,
    /// The stable refusal code of the step that stopped the batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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
}

/// Looks one routine step takes before it goes up to the planner.
pub const ROUTINE_LOOKS: u32 = 4;

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
}

#[derive(Clone, Debug)]
pub struct RoutineReply {
    pub answer: RoutineAnswer,
    /// The routine trail's word: NONE or reobserve came twice in a row, so
    /// the next look takes a screenshot (`decider_reobserve`).
    pub screenshot: bool,
    /// The subgoal's clock, as the decider ran it.
    pub until_ms: Option<u64>,
    /// The decision with its receipt, for the batch's answer.
    pub decision: serde_json::Value,
}

/// The host's routine decider: the engine's decision ladder, behind the
/// driver. A driver without one sends every routine step up.
pub trait RoutineDecider: Send {
    fn decide(&mut self, ask: RoutineAsk<'_>) -> Result<RoutineReply, BrowserError>;
}

/// No decider: a routine step cannot run, so it goes up.
pub struct NoDecider;

impl RoutineDecider for NoDecider {
    fn decide(&mut self, _ask: RoutineAsk<'_>) -> Result<RoutineReply, BrowserError> {
        Err(BrowserError::Decider(
            "this browser host has no routine decider".to_owned(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "code", content = "detail", rename_all = "snake_case")]
pub enum BrowserError {
    #[error("this run has no browser")]
    Unbound,
    #[error("invalid browser verb input: {0}")]
    Input(String),
    #[error("the browser guest could not start: {0}")]
    Unavailable(String),
    #[error("the browser guest is gone")]
    GuestLost,
    #[error("the browser sandbox was abandoned after its bridge reconnect window")]
    Abandoned,
    #[error("no element has ref {0} now; observe again")]
    StaleRef(String),
    #[error("element {0} is covered by another element")]
    Covered(String),
    #[error("element {0} is not a <select> with that option")]
    NoOption(String),
    #[error("{0} needs a person's press: the action would send, pay, submit or sign in")]
    NeedsPress(String),
    #[error("this session holds no image {0}")]
    NoImage(String),
    #[error("only http and https pages open: {0}")]
    Url(String),
    #[error("navigation failed: {0}")]
    Navigation(String),
    #[error("timed out waiting for {0}")]
    Timeout(String),
    #[error("browser protocol: {0}")]
    Protocol(String),
    #[error("image {0} no longer shows the page as it is; take a new screenshot")]
    StaleImage(String),
    #[error("the routine step went up to the planner: {0}")]
    AskUp(String),
    #[error("the routine decider gave no answer: {0}")]
    Decider(String),
    #[error("the library holds no workflow {0}")]
    NoWorkflow(String),
    #[error("the workflow library failed: {0}")]
    Library(String),
    #[error("this driver does not serve {0}")]
    Unsupported(String),
}

/// Steps one batched subgoal program may hold.
pub const BATCH_MAX_STEPS: usize = 64;

/// The verbs a browser serves. The CDP driver implements it for a Chromium
/// guest, and the desktop driver for a Linux desktop guest through
/// cua-driver; each refuses the other's own verbs.
pub trait BrowserDriver: Send {
    fn open(&mut self, input: OpenInput) -> Result<Observation, BrowserError>;
    fn observe(&mut self, input: ObserveInput) -> Result<Observation, BrowserError>;
    fn find(&mut self, input: FindInput) -> Result<FindOutput, BrowserError>;
    fn click(&mut self, input: ClickInput) -> Result<Observation, BrowserError>;
    fn click_at(&mut self, input: PointInput) -> Result<Observation, BrowserError>;
    fn type_text(&mut self, input: TypeInput) -> Result<Observation, BrowserError>;
    fn select(&mut self, input: SelectInput) -> Result<Observation, BrowserError>;
    fn wait_for(&mut self, input: WaitForInput) -> Result<WaitForOutput, BrowserError>;
    fn expect(&mut self, input: ExpectInput) -> Result<ExpectOutput, BrowserError>;
    fn screenshot(&mut self, input: ScreenshotInput) -> Result<ScreenshotOutput, BrowserError>;
    fn view(&mut self, input: ViewInput) -> Result<ImageOutput, BrowserError>;
    fn crop(&mut self, input: CropInput) -> Result<ImageOutput, BrowserError>;
    fn zoom(&mut self, input: ZoomInput) -> Result<ImageOutput, BrowserError>;
    /// The PNG bytes of a held image, while the driver holds them.
    fn image_bytes(&self, image: &str) -> Option<Vec<u8>>;

    /// The replay library's programs for a site. A driver with no library
    /// refuses the library verbs.
    fn library_find(
        &mut self,
        _input: LibraryFindInput,
    ) -> Result<LibraryFindOutput, BrowserError> {
        Err(BrowserError::Library(
            "this browser host keeps no library".to_owned(),
        ))
    }

    /// Offers a solved run's program to the library: it joins only once the
    /// solved page and a no-model replay both meet its postcondition.
    fn library_propose(&mut self, _input: ProposeInput) -> Result<ProposeOutput, BrowserError> {
        Err(BrowserError::Library(
            "this browser host keeps no library".to_owned(),
        ))
    }

    /// Runs a library program live; a missed postcondition goes back to the
    /// planner.
    fn library_run(&mut self, _input: LibraryRunInput) -> Result<LibraryRunOutput, BrowserError> {
        Err(BrowserError::Library(
            "this browser host keeps no library".to_owned(),
        ))
    }

    /// A desktop key press.
    fn press_key(&mut self, _input: KeyInput) -> Result<Observation, BrowserError> {
        Err(BrowserError::Unsupported("key".to_owned()))
    }

    /// A desktop key combination.
    fn hotkey(&mut self, _input: HotkeyInput) -> Result<Observation, BrowserError> {
        Err(BrowserError::Unsupported("hotkey".to_owned()))
    }

    /// A desktop scroll.
    fn scroll(&mut self, _input: ScrollInput) -> Result<Observation, BrowserError> {
        Err(BrowserError::Unsupported("scroll".to_owned()))
    }

    /// The desktop's windows.
    fn windows(&mut self, _input: WindowsInput) -> Result<WindowsOutput, BrowserError> {
        Err(BrowserError::Unsupported("windows".to_owned()))
    }

    /// Moves a desktop session onto another window.
    fn window(&mut self, _input: WindowInput) -> Result<Observation, BrowserError> {
        Err(BrowserError::Unsupported("window".to_owned()))
    }

    /// Runs one batched program for a subgoal; a routine step has no
    /// decider here, so it goes up.
    fn batch(&mut self, input: BatchInput) -> Result<BatchOutput, BrowserError> {
        self.batch_with(input, &mut NoDecider)
    }

    /// Runs one batched program for a subgoal, step by step through this
    /// driver's own verbs, so a host wrapper's door still gates each effect,
    /// and its routine steps through `decider` under the subgoal's one clock.
    /// The batch stops at the first refused, timed-out, unmet or sent-up step.
    fn batch_with(
        &mut self,
        input: BatchInput,
        decider: &mut dyn RoutineDecider,
    ) -> Result<BatchOutput, BrowserError> {
        if input.steps.is_empty() || input.steps.len() > BATCH_MAX_STEPS {
            return Err(BrowserError::Input(format!(
                "a batch holds 1 to {BATCH_MAX_STEPS} steps"
            )));
        }
        let mut output = BatchOutput {
            status: SubgoalStatus::Done,
            completed: 0,
            failed_step: None,
            error: None,
            observation: None,
            receipts: Vec::new(),
            decisions: Vec::new(),
            until_ms: input.until_ms,
        };
        let mut routine = Routine {
            decider,
            until_ms: input.until_ms,
            no_model: input.no_model,
            misses: 0,
            decisions: Vec::new(),
        };
        for (index, step) in input.steps.into_iter().enumerate() {
            let outcome: Result<Option<Observation>, BrowserError> = match step {
                BatchStep::Open { url } => self.open(OpenInput { url }).map(Some),
                BatchStep::Click { target } => self.click(ClickInput { target }).map(Some),
                BatchStep::Type {
                    target,
                    text,
                    clear,
                } => self
                    .type_text(TypeInput {
                        target,
                        text,
                        clear,
                    })
                    .map(Some),
                BatchStep::Select { target, option } => {
                    self.select(SelectInput { target, option }).map(Some)
                }
                BatchStep::WaitFor {
                    role,
                    name,
                    timeout_ms,
                } => self
                    .wait_for(WaitForInput {
                        role,
                        name,
                        timeout_ms,
                    })
                    .and_then(|waited| {
                        if waited.timed_out {
                            Err(BrowserError::Timeout("a batch wait_for step".to_owned()))
                        } else {
                            Ok(None)
                        }
                    }),
                BatchStep::Expect {
                    target,
                    role,
                    name,
                    value,
                    absent,
                } => self
                    .expect(ExpectInput {
                        target,
                        role,
                        name,
                        value,
                        absent,
                    })
                    .and_then(|expected| {
                        if expected.met {
                            Ok(None)
                        } else {
                            Err(BrowserError::Input("expect_unmet".to_owned()))
                        }
                    }),
                BatchStep::Screenshot { trigger } => {
                    self.screenshot(ScreenshotInput { trigger }).map(|_| None)
                }
                BatchStep::Key {
                    key,
                    modifiers,
                    target,
                } => self
                    .press_key(KeyInput {
                        key,
                        modifiers,
                        target,
                    })
                    .map(Some),
                BatchStep::Hotkey { keys } => self.hotkey(HotkeyInput { keys }).map(Some),
                BatchStep::Scroll {
                    direction,
                    amount,
                    target,
                } => self
                    .scroll(ScrollInput {
                        direction,
                        amount,
                        target,
                    })
                    .map(Some),
                BatchStep::Decide(step) => routine.step(self, step).map(Some),
            };
            output.decisions.append(&mut routine.decisions);
            output.until_ms = routine.until_ms;
            match outcome {
                Ok(observation) => {
                    output.completed += 1;
                    if let Some(observation) = observation {
                        if let Some(receipt) = &observation.receipt {
                            output.receipts.push(receipt.clone());
                        }
                        output.observation = Some(observation);
                    }
                }
                Err(error) => {
                    output.status = if matches!(error, BrowserError::NeedsPress(_)) {
                        SubgoalStatus::NeedsYou
                    } else {
                        SubgoalStatus::NeedsAgent
                    };
                    output.failed_step = Some(index);
                    output.error = Some(match &error {
                        BrowserError::Input(detail) if detail == "expect_unmet" => {
                            "browser_expect_unmet".to_owned()
                        }
                        _ => error.code().to_owned(),
                    });
                    return Ok(output);
                }
            }
        }
        Ok(output)
    }
}

/// Candidates one routine Choice may offer: the contract's 64 options less
/// NONE, reobserve and "too complicated, ask up".
pub const ROUTINE_MAX_CANDIDATES: usize = 61;

/// A batch's routine steps: the decider, the subgoal's one clock, the NONE
/// and reobserve answers in a row, and the decisions taken.
struct Routine<'d> {
    decider: &'d mut dyn RoutineDecider,
    until_ms: Option<u64>,
    no_model: bool,
    misses: u32,
    decisions: Vec<serde_json::Value>,
}

impl Routine<'_> {
    /// One routine step: look, ask, act. A look reads the outline, and a
    /// screenshot too for a locate step or once the trail says so.
    fn step<D: BrowserDriver + ?Sized>(
        &mut self,
        driver: &mut D,
        step: DecideStep,
    ) -> Result<Observation, BrowserError> {
        if (step.text.is_some() && step.option.is_some())
            || (step.locate
                && (step.text.is_some() || step.option.is_some() || !step.targets.is_empty()))
        {
            return Err(BrowserError::Input(
                "a decide step types text or selects an option, and a locate step only clicks"
                    .to_owned(),
            ));
        }
        let query = FindInput {
            role: step.role.clone(),
            name: step.name.clone(),
        };
        let mut trigger = step.locate.then_some(ScreenshotTrigger::OutlineThin);
        for _ in 0..ROUTINE_LOOKS {
            let page = driver.observe(ObserveInput::default())?;
            // A desktop window with no tree is read by its pixels: a step
            // that only clicks locates its target in a screenshot there.
            let blind = page.no_tree
                && step.text.is_none()
                && step.option.is_none()
                && step.targets.is_empty();
            let locate = step.locate || blind;
            let look = match trigger {
                Some(ScreenshotTrigger::DeciderReobserve) => trigger,
                _ if blind => Some(ScreenshotTrigger::NoAccessibilityTree),
                _ => trigger,
            };
            let candidates: Vec<(String, Row)> = if locate {
                Vec::new()
            } else {
                page.rows
                    .iter()
                    .filter(|row| {
                        if step.targets.is_empty() {
                            query.matches(row)
                        } else {
                            step.targets.contains(&row.target)
                        }
                    })
                    .map(|row| (candidate(row), row.clone()))
                    .collect()
            };
            if !locate && candidates.is_empty() {
                return Err(BrowserError::AskUp(
                    "no row on the page matches the step".to_owned(),
                ));
            }
            if candidates.len() > ROUTINE_MAX_CANDIDATES {
                return Err(BrowserError::Input(format!(
                    "a decide step offers at most {ROUTINE_MAX_CANDIDATES} rows; name its targets, role or name"
                )));
            }
            let shot = match look {
                Some(trigger) => {
                    let shot = driver.screenshot(ScreenshotInput { trigger })?;
                    let png = driver
                        .image_bytes(&shot.image)
                        .ok_or_else(|| BrowserError::NoImage(shot.image.clone()))?;
                    Some((shot.image, png))
                }
                None => None,
            };
            let reply = self.decider.decide(RoutineAsk {
                question: &step.question,
                options: candidates.iter().map(|(label, _)| label.clone()).collect(),
                image: shot
                    .as_ref()
                    .map(|(image, png)| (image.as_str(), png.as_slice())),
                state: serde_json::json!({"url": page.url, "title": page.title}),
                misses: self.misses,
                until_ms: self.until_ms,
                no_model: self.no_model,
            })?;
            self.until_ms = reply.until_ms.or(self.until_ms);
            self.decisions.push(reply.decision);
            match reply.answer {
                RoutineAnswer::Act { candidate } if !locate => {
                    self.misses = 0;
                    let target = candidates
                        .into_iter()
                        .find(|(label, _)| *label == candidate)
                        .map(|(_, row)| row.target)
                        .ok_or_else(|| {
                            BrowserError::Decider(format!("{candidate} is not a candidate"))
                        })?;
                    return match (step.text, step.option) {
                        (Some(text), _) => driver.type_text(TypeInput {
                            target,
                            text,
                            clear: step.clear,
                        }),
                        (None, Some(option)) => driver.select(SelectInput { target, option }),
                        (None, None) => driver.click(ClickInput { target }),
                    };
                }
                RoutineAnswer::Point { x, y } if locate => {
                    self.misses = 0;
                    let (image, _) = shot.ok_or_else(|| {
                        BrowserError::Decider("a point without a screenshot".to_owned())
                    })?;
                    return driver.click_at(PointInput { image, x, y });
                }
                RoutineAnswer::None | RoutineAnswer::Reobserve => {
                    self.misses = self.misses.saturating_add(1);
                    trigger = if reply.screenshot {
                        Some(ScreenshotTrigger::DeciderReobserve)
                    } else {
                        step.locate.then_some(ScreenshotTrigger::OutlineThin)
                    };
                }
                RoutineAnswer::AskUp { reason } => {
                    return Err(BrowserError::AskUp(
                        reason.unwrap_or_else(|| "the decider asked up".to_owned()),
                    ));
                }
                other => {
                    return Err(BrowserError::Decider(format!(
                        "{other:?} does not answer this step"
                    )));
                }
            }
        }
        Err(BrowserError::AskUp(format!(
            "no target after {ROUTINE_LOOKS} looks"
        )))
    }
}

/// A row as a routine Choice offers it: its role and name, then its ref,
/// which tells twins apart. An option holds at most 256 bytes.
fn candidate(row: &Row) -> String {
    let mut label = format!("{} \"{}\"", row.role, row.name);
    if label.len() > 200 {
        let mut end = 200;
        while !label.is_char_boundary(end) {
            end -= 1;
        }
        label.truncate(end);
        label.push('…');
    }
    format!("{label} [{}]", row.target)
}

impl BrowserError {
    /// The stable code a refused verb call answers with. A program reads only
    /// this; the detail stays in the host's log.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unbound => "browser_unbound",
            Self::Input(_) => "browser_input_invalid",
            Self::Unavailable(_) => "browser_unavailable",
            Self::GuestLost => "browser_guest_lost",
            Self::Abandoned => "browser_guest_abandoned",
            Self::StaleRef(_) => "browser_stale_ref",
            Self::Covered(_) => "browser_covered",
            Self::NoOption(_) => "browser_no_option",
            Self::NeedsPress(_) => "needs_press",
            Self::NoImage(_) => "browser_no_image",
            Self::Url(_) => "browser_url_refused",
            Self::Navigation(_) => "browser_navigation_failed",
            Self::Timeout(_) => "browser_timeout",
            Self::Protocol(_) => "browser_protocol",
            Self::StaleImage(_) => "browser_stale_image",
            Self::AskUp(_) => "routine_ask_up",
            Self::Decider(_) => "routine_decider_failed",
            Self::NoWorkflow(_) => "browser_no_workflow",
            Self::Library(_) => "browser_library_failed",
            Self::Unsupported(_) => "browser_unsupported",
        }
    }
}

impl WaitForInput {
    #[must_use]
    pub fn query(&self) -> FindInput {
        FindInput {
            role: self.role.clone(),
            name: self.name.clone(),
        }
    }
}

impl ExpectInput {
    #[must_use]
    pub fn query(&self) -> FindInput {
        FindInput {
            role: self.role.clone(),
            name: self.name.clone(),
        }
    }
}

impl FindInput {
    /// Whether `row` matches: role exactly, name as a case-blind substring.
    #[must_use]
    pub fn matches(&self, row: &Row) -> bool {
        self.role
            .as_ref()
            .is_none_or(|role| row.role.eq_ignore_ascii_case(role))
            && self
                .name
                .as_ref()
                .is_none_or(|name| row.name.to_lowercase().contains(&name.to_lowercase()))
    }
}
