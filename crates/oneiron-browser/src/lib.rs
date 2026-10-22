//! Browser verbs for code mode (`self.browser.*`), and the CDP driver
//! behind them (feature `driver`).
//!
//! A program reads the page as an outline of rows. Each row has a live
//! `ref`, a handle bound to its DOM node in its document and never reused
//! within the session, and a `locator` built from its role, its accessible
//! name and its named ancestors, never from its position, which replay
//! programs store (AB-001). An act on a handle whose node is gone acts on
//! the row its locator names now and says so (`rebound`). Every action waits
//! for the page to settle and returns the next observation, whole or as an
//! ordered edit of one the caller holds (AB-002).
//!
//! The same verbs drive a Linux desktop (`self.desktop.*`, OF-523): one
//! window of an isolated desktop guest, read as rows from its accessibility
//! tree through cua-driver, with keys, hotkeys, scrolling and the guest's
//! windows on top.

use crate::observation::rows_named;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod answer;
#[cfg(feature = "driver")]
mod capture;
#[cfg(feature = "driver")]
mod cdp;
mod demonstration;
#[cfg(feature = "driver")]
mod desktop;
#[cfg(feature = "driver")]
mod driver;
mod engine;
mod fact;
mod field;
mod library;
#[cfg(feature = "driver")]
mod mcp;
mod observation;
#[cfg(feature = "driver")]
mod outline;
mod progress;
mod receipt_evidence;
mod replay;
mod request;
mod retention;
mod row;
mod secret;
mod secret_fields;
#[cfg(feature = "driver")]
mod session;
mod stop;
mod switch;

pub use answer::{
    BrowserAnswer, DesktopAnswer, SessionFenceProof, SessionManifest, SessionSeccomp,
    TakeoverRecord, WindowSwitch, WindowSwitchCause,
};
pub use demonstration::{
    DemonstrationId, DemonstrationOutput, DemonstrationSource, DemonstrationStartInput,
    DemonstrationStarted, DemonstrationStopCause, DemonstrationStopInput, LocatorGap, RecordedStep,
    RecordingGap, RecordingGapKind,
};
#[cfg(feature = "driver")]
pub use desktop::{AbandonedTakeover, DesktopGuest, DesktopSession, PersonInput, Takeover};
pub use engine::BrowserEngine;
pub use fact::{ActionFact, ActionTarget, DialogAnswerFailure, NoEffectReason, ViewportPoint};
pub use field::{
    FIELD_WRITER, FieldSpec, FieldTextReason, FieldWrite, FieldWriteError, FieldWriter,
    FieldWritten, NoWriter, TextCheck, TextCheckReply, TextProvenance, TextReference, TextSource,
    TextVerdict,
};
pub use library::{
    AdmissionRefusal, Admitted, DraftGap, DraftGapKind, DraftInput, DraftOutcome, DraftOutput,
    DraftPage, DraftStep, FiledWorkflow, LibraryCard, LibraryFindInput, LibraryFindOutput,
    LibraryRetireInput, LibraryRetireOutput, LibraryRetiredInput, LibraryRetiredOutput,
    LibraryRunInput, LibraryRunMode, LibraryRunOutput, PressedThrough, ProposeInput, ProposeOutput,
    RecentCounts, ReplayGuest, RetiredCard, RunOutcome, SecretArg, SecretParam, SlotCandidate,
    SlotField, SupersedeOutcome, SupersedeRefusal, WorkflowCheck, WorkflowLibrary, WorkflowProgram,
    WorkflowProof, WorkflowSeed, default_mode, draft_from_steps, effective_mode, model_free,
    site_of, validate_replay_args,
};
#[cfg(feature = "driver")]
pub use library::{filled_checks, program_origin};
pub use observation::{
    HandleInfo, ObservationBase, Rebound, RowSplice, StepRebound, is_live_handle,
};
#[cfg(feature = "driver")]
pub use oneiron_container::{GuestLimits, ImageRef};
pub use progress::NO_PROGRESS_STEPS;
use progress::Progress;
pub use receipt_evidence::{ReceiptEvidence, ReceiptEvidenceSink};
pub use replay::{OperandGap, ReplayAction, StepStop, TypeOperand};
pub use request::DestinationRefusal;
#[cfg(feature = "driver")]
pub use request::{BrowserRequestHandler, RenderedDocument};
pub use retention::HandleRetention;
pub use row::{Row, RowFieldGap, RowGapField, RowGapReason};
pub use secret::{SecretCustody, SecretUse};
pub use secret_fields::{RowSecret, SecretKind, SecretNote};
#[cfg(feature = "driver")]
pub use session::{
    BrowserGuest, BrowserGuestStarter, BrowserSession, CapturedSolvedSpan, FreshGuest, PressGrants,
    SOLVED_PAST_PRESS, SolvedSnapshotGap, StartedGuest,
};
pub use stop::{
    AskUpReason, BatchStopCause, CheckReceipt, ClockScope, FailedStepReceipt, STRICT_DENIED,
    StrictDenial, StrictDenied,
};
use stop::{Stop, elapsed_ms};
pub use switch::{
    EngineSwitchRecord, StoragePhase, SwitchCarried, SwitchComponent, SwitchEngineInput,
    SwitchEngineOutput, SwitchLoss, SwitchNotCarried, SwitchOutcome, SwitchStage,
};

/// The page as rows, in outline order. With `full` it holds every row. Without,
/// it is an ordered edit of observation `base_seq` of the same `scope`, which
/// the caller holds whole: `splice` names the base's rows that give way to
/// `rows`. `seq` names this observation, for a later one to edit.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Observation {
    pub seq: u64,
    /// What the rows were read from: on a page, `page:` and the session,
    /// tab and documents (frame, loader and document root) they came from;
    /// on a desktop, `window:` and the session and window. An observation of
    /// another scope is whole.
    pub scope: String,
    /// The observation this one edits; absent when it is whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_seq: Option<u64>,
    pub url: String,
    pub title: String,
    pub full: bool,
    /// The base's rows that `rows` replace; absent when it is whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub splice: Option<RowSplice>,
    pub rows: Vec<Row>,
    /// Where this page's rows start among the observation's own `rows`, on
    /// an observation answered in pages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
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
    /// The desktop window's tree as far as its walk got (Rule 5): the walk
    /// stopped before the tree's end, so rows past the cut are missing and
    /// the observation is whole, never an edit, and never a base for one.
    /// Every page carries it, and the last page's `walk_next` walks the
    /// window again, longer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial: Option<PartialTree>,
    /// On the last page of a partial observation: the cursor `observe`
    /// takes to walk the window again, longer, as a new whole observation
    /// with its own `seq`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub walk_next: Option<String>,
    /// The handle the act named no longer stood, and the act took the row
    /// its locator names now; or its locator named several rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebound: Option<Rebound>,
    /// What the act proved about its effect: on a page that showed no
    /// change at all within the driver's change window, the act answers at
    /// once with this fact (FIX 6680). Absent when the page changed, and
    /// whenever a read could not prove it did not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact: Option<ActionFact>,
    /// The dialogs a page opened since the last observation whose answer
    /// the browser refused (FIX 6768), on the first page only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dialogs: Vec<DialogAnswerFailure>,
}

/// Where a desktop window's tree walk stopped short of its end (Rule 5):
/// cua-driver reads a window's tree as a pre-order walk under a time
/// budget, and a walk cut at the longest one a read asks for answers what
/// it reached. Every row it carries is real; rows after the cut are
/// missing until a walk on reads them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PartialTree {
    /// Why the walk stopped, as cua-driver names it: `timeout`,
    /// `app_unresponsive`, `app_lookup_timeout` or `huge_container`.
    pub reason: String,
    /// The nodes the walk visited.
    pub visited: u64,
    /// The nodes it found and had not reached when it stopped, at least.
    pub pending: u64,
    /// The walk's time budget, in milliseconds.
    pub walk_ms: u64,
}

/// The agent's verbs moved to another tab of the browser (CUA-001): a tab
/// opened since (a popup, a tab a link opened) came to the front, as a
/// browser shows it, or the tab they drove closed and gave way to the tab
/// that opened it, else the newest. The next answer carries it once, as
/// `switched`. The observations held were of the tab before, so the next
/// observation is whole.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TabSwitch {
    /// The tab the agent's verbs drive now.
    pub tab: String,
    /// Its page when the switch found it.
    pub url: String,
    pub title: String,
    /// The tab they drove before.
    pub from: String,
    pub why: TabSwitchCause,
}

/// Why the agent's verbs moved to another tab.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TabSwitchCause {
    /// A tab opened since came to the front.
    Opened,
    /// The tab they drove closed.
    Closed,
}

/// One effect's receipt: what acted, on which page, under which press, and
/// the screenshot taken as its evidence when one could be captured, with
/// where the host kept it when the session has a receipt sink.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EffectReceipt {
    pub seq: u64,
    pub verb: String,
    pub url: String,
    pub title: String,
    /// The live handle of the row the effect acted on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_name: Option<String>,
    /// That row's semantic locator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_locator: Option<String>,
    /// The handle the call named no longer stood, and the effect acted on
    /// the row its locator names now; or its locator named several rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebound: Option<Rebound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_class: Option<String>,
    /// The press the effect ran under: `per_send`, `per_batch` or `none`.
    pub press: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screenshot: Option<String>,
    /// The capture id of `screenshot`. Each receipt's screenshot is a
    /// capture of its own, kept as its evidence even when its pixels repeat
    /// an earlier capture's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screenshot_evidence: Option<ReceiptEvidence>,
    /// The engine the effect ran on (FIX 6680); absent on a desktop, which
    /// has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<BrowserEngine>,
    /// The act's own fact about its effect, as its observation carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact: Option<ActionFact>,
    /// On a `switch_engine` receipt: the switch's record (FIX 6680).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_switch: Option<EngineSwitchRecord>,
    /// Where the text a type or Fill step typed came from (CUA E6; a
    /// desktop's too, FIX 8899): `supplied` for a `type`, else the Fill's
    /// source. Absent on any other effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_source: Option<TextSource>,
    /// The typed text's reference: a reference's id, a template's digest
    /// (`blake3:` and hex), or the writer call's id; none for supplied text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_ref: Option<String>,
    /// The act as a replay program's step takes it again (CUA E7): its
    /// operands as its verb took them, a secret by its run-bound handle.
    /// Absent on an act no step replays (a `click_at`, an engine switch, a
    /// desktop's act): a draft names it a gap, never skips it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ReplayAction>,
    /// The page the act began on (CUA E7): its URL, before the act moved it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    /// That page's origin (scheme, host and port), parsed from its URL;
    /// absent on a page with no such origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_origin: Option<String>,
    /// That page's title, as an observation shows it (FIX 8011): `url` and
    /// `title` name the page the act left, its result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_title: Option<String>,
    /// The tab the act acted in, by the browser's stable id for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tab: Option<String>,
    /// The tab in front once the act settled: another than `tab` when the
    /// act opened one, or closed its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_tab: Option<String>,
    /// The act's input was sent, then settling or reading the page it left
    /// failed (FIX 8010): that failure's stable code, which its verb then
    /// answered. `url` and `title` name the page as it read after, else
    /// where the act began; no observation backs the receipt, and the
    /// input is never sent again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_unread: Option<String>,
    /// How long the effect took, in milliseconds of the monotonic clock:
    /// from its verb's entry through its screenshot and this receipt,
    /// before the host keeps the screenshot.
    pub duration_ms: u64,
}

/// Observes the page: as an edit of `base`, or, with none named, of the last
/// observation the session's caller read whole; whole with `full`; or, with
/// `cursor`, the next page of an observation an earlier answer paged (its
/// `next`), as the page was then, or a partial one's longer walk (its
/// `walk_next`). A base no longer held, of another scope, or partial gives
/// a whole observation.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObserveInput {
    #[serde(default)]
    pub base: Option<ObservationBase>,
    #[serde(default)]
    pub full: bool,
    #[serde(default)]
    pub cursor: Option<String>,
}

/// One page of an observation (Rule 5): the observation with as many of its
/// rows as fit one answer. A long outline is never cut: `next` names where
/// the rest goes on, and `observe({cursor: next})` reads it. Every page of
/// one observation repeats its `seq`, `scope`, `base_seq` and `splice`, with
/// its own `offset`; the caller applies an edit once it holds every page.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ObservationPage {
    #[serde(flatten)]
    pub observation: Observation,
    /// The cursor of the next page; absent on the last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

impl ObservationPage {
    /// An observation that fits one page.
    #[must_use]
    pub fn whole(observation: Observation) -> Self {
        Self {
            observation,
            next: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenInput {
    pub url: String,
}

/// Rows whose role equals `role` and whose name contains `name`, ignoring
/// case; or, with `cursor`, the next page of a `find` or `wait_for` answer
/// an earlier call paged (its `next`), as the rows were then, or a cut
/// desktop answer's longer search (its `walk_next`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindInput {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub cursor: Option<String>,
}

/// One page of matching rows (Rule 5): as many as fit one answer. Many
/// rows are never cut: `next` names where the rest goes on, and
/// `find({cursor: next})` reads it.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FindOutput {
    pub rows: Vec<Row>,
    /// The cursor of the next page; absent on the last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    /// The desktop window's tree the rows were found in was still cut when
    /// the search ended, as an observation's `partial` says: rows past the
    /// cut were not searched, so the answer is incomplete, never a proof
    /// that no other row matches. A search that found no row walks on,
    /// longer each time, until one matches, the tree ends, or the walk is
    /// at its longest. Every page carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial: Option<PartialTree>,
    /// On the last page of a `partial` answer: the cursor `find` takes to
    /// search the window again, longer, for the same rows, as a new answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub walk_next: Option<String>,
}

/// Clicks the row `ref` names: a live handle, or a locator, which names the
/// first row carrying it now.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClickInput {
    #[serde(rename = "ref")]
    pub target: String,
    /// The observation the answer edits, as `observe`'s `base`; by default
    /// the last one the caller read whole.
    #[serde(default)]
    pub base: Option<ObservationBase>,
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
    /// The observation the answer edits, as `observe`'s `base`; by default
    /// the last one the caller read whole.
    #[serde(default)]
    pub base: Option<ObservationBase>,
}

/// Types into the row `ref` names: literal `text`, or the secret a
/// run-bound handle names (`secret`, FIX 8028), whose bytes the host lends
/// at the send and no answer, receipt or record holds. Exactly one of the
/// two is named. A text that reads like a handle is typed as text.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypeInput {
    #[serde(rename = "ref")]
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The handle (`scN`, or `[secret scN]` as a row shows it) of a secret
    /// this run's browser found, typed in place of `text`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// Replace the field's text instead of inserting at the caret.
    #[serde(default)]
    pub clear: bool,
    /// The observation the answer edits, as `observe`'s `base`; by default
    /// the last one the caller read whole.
    #[serde(default)]
    pub base: Option<ObservationBase>,
}

/// Picks the option of a `<select>` whose label, text or value is `option`.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectInput {
    #[serde(rename = "ref")]
    pub target: String,
    pub option: String,
    /// The observation the answer edits, as `observe`'s `base`; by default
    /// the last one the caller read whole.
    #[serde(default)]
    pub base: Option<ObservationBase>,
}

/// Waits until some row `targets` names is on the page, or, with none named,
/// some row matches `role` and `name`, as `find` matches them. A target is a
/// live handle, matched by its own row, or by the row its locator names now
/// once its node is gone (a rebinding), or a locator. With `cursor` alone it
/// waits for nothing and reads the next page of an earlier answer, or
/// searches a cut desktop answer's window again, longer, as `find` does.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WaitForInput {
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u32>,
    #[serde(default)]
    pub cursor: Option<String>,
}

/// The rows a wait found, in pages as a `find` answer is.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WaitForOutput {
    pub rows: Vec<Row>,
    pub timed_out: bool,
    pub waited_ms: u64,
    /// The cursor of the next page of `rows`; absent on the last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    /// The desktop window's tree the wait last read was still cut, as
    /// `find`'s `partial` says: a wait that found no row walks on at each
    /// look, longer, within its time, so one that timed out cut has not
    /// shown no row is there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial: Option<PartialTree>,
    /// On the last page of a `partial` answer: the cursor `find` takes to
    /// search the window again, longer, as `find`'s `walk_next` does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub walk_next: Option<String>,
    /// Each target that matched by its locator, not its own row.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rebindings: Vec<Rebound>,
}

/// A check on the page as it is now: the row named by `ref` (a live handle,
/// or the row its locator names once its node is gone, or a locator), or
/// else the first row `role` and `name` match, is present (or absent) and,
/// when `value` is given, holds exactly that value, or, when `secret` is,
/// the secret that handle names (FIX 8028): compared where the row is
/// read, against what the page holds, never answered. A secret row's
/// `value` is checked against what its page holds too, not its handle. Its
/// answer holds at most that one row, as it shows, which is always one
/// page.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
    /// The handle of a secret this run's browser found, in place of
    /// `value`: never both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default)]
    pub absent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExpectOutput {
    pub met: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row: Option<Row>,
    /// The desktop window's tree the check read was still cut, as `find`'s
    /// `partial` says. A check that found no row walks on until it does,
    /// the tree ends, or the walk is at its longest; with no `row` here,
    /// rows past the cut were not seen, so the check is unmet: a row there
    /// is neither shown present nor shown absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial: Option<PartialTree>,
    /// The `ref` matched by its locator, not its own row.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rebindings: Vec<Rebound>,
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

/// Takes a screenshot, masked: no secret field's value reaches the image.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScreenshotInput {
    pub trigger: ScreenshotTrigger,
    /// An earlier capture's `capture_id` that the caller still holds. The
    /// screenshot is taken, held and answered whole all the same, and
    /// `unchanged_from` names that capture when this one is the same masked
    /// PNG taken in the same scope. A capture no longer held, of another
    /// scope, or never this session's answers as any screenshot does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_capture: Option<String>,
}

/// A screenshot the session holds. It is never captioned: `image` names the
/// bytes for a later image read, and nothing else describes them.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScreenshotOutput {
    pub image: String,
    pub media_type: String,
    pub width: u32,
    pub height: u32,
    pub bytes: u64,
    pub trigger: ScreenshotTrigger,
    pub url: String,
    pub title: String,
    /// This capture's id, `c<token>:<n>`: one counter for the whole session,
    /// never reused. Every screenshot is a capture of its own, even when its
    /// pixels repeat an earlier one's; a crop or zoom is none.
    pub capture_id: String,
    /// The capture `since_capture` named, when this one's masked PNG is that
    /// one's byte for byte and both were taken in one scope: the same
    /// documents and URL (or window), viewport (or window rectangle),
    /// scroll, dimensions and scale, and masking. The same PNG, nothing
    /// more: not that the page did nothing. A receipt's screenshot never
    /// takes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unchanged_from: Option<String>,
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
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// The observation the answer edits, as `observe`'s `base`; by default
    /// the last one the caller read whole.
    #[serde(default)]
    pub base: Option<ObservationBase>,
}

/// A key combination, as `["ctrl", "s"]`: two keys or more, the last one
/// pressed while the others are held.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HotkeyInput {
    pub keys: Vec<String>,
    /// The observation the answer edits, as `observe`'s `base`; by default
    /// the last one the caller read whole.
    #[serde(default)]
    pub base: Option<ObservationBase>,
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
    /// The observation the answer edits, as `observe`'s `base`; by default
    /// the last one the caller read whole.
    #[serde(default)]
    pub base: Option<ObservationBase>,
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
    /// FIX 8046: a protocol call the engine did not answer in its time (a
    /// CDP method, a desktop driver's tool), by its name. Its code is the
    /// timeout's own; a batch names it the protocol's clock.
    #[error("timed out waiting for {0}")]
    CallTimeout(String),
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
    /// FIX 8073: the workflow a run named was retired, as the library's
    /// record of its retire proves; one with no record stays `NoWorkflow`.
    #[error("the library's workflow {0} was retired")]
    WorkflowRetired(String),
    #[error("the workflow library failed: {0}")]
    Library(String),
    #[error("this driver does not serve {0}")]
    Unsupported(String),
    #[error("a person has the desktop ({0}); it answers again once they hand it back")]
    TakenOver(String),
    #[error("a person has the browser ({0}); it answers again once they hand it back")]
    BrowserTakenOver(String),
    /// Rule 5: a cut tree is no proof a row is gone, so an act on a row the
    /// longest walk on never reached answers this, not `StaleRef`.
    #[error(
        "the window's tree walk stopped before its end at its longest and never reached {0}; observe and walk on with walk_next"
    )]
    TreeCut(String),
    /// C013: the host's memory floor will not admit the live handles a
    /// read would add. Nothing was minted; the session and the handles it
    /// already gave out stay.
    #[error(
        "the host's memory floor admits no more live handles for this browser now; handles already given out still work"
    )]
    MemoryFloor,
    /// FIX 7122: the host's request handler refused a page request's
    /// destination by the host's own rule, in the host's own words. It
    /// carries the host's refusal; it is no refusal class of the browser's.
    #[error("the host refused a page request's destination: {0}")]
    DestinationRefused(DestinationRefusal),
    /// FIX 8028: the secret a type or expect named is not one this run's
    /// host holds for it (another run's, erased, or no custody at all); no
    /// byte of it was sent or compared.
    #[error("the browser's host refused the secret: {0}")]
    SecretRefused(String),
    /// CUA E6: a Fill step's text was not resolved, or the page did not
    /// take it; its batch names the cause.
    #[error("the fill step's text: {0}")]
    FieldText(String),
}

/// One verb's observation as its answer pages it: `act`'s observation, as
/// `driver` pages it.
pub fn paged<D: BrowserDriver + ?Sized>(
    driver: &mut D,
    act: impl FnOnce(&mut D) -> Result<Observation, BrowserError>,
) -> Result<ObservationPage, BrowserError> {
    let observation = act(&mut *driver)?;
    Ok(driver.paged(observation))
}

/// The verbs a browser serves. The CDP driver implements it for a Chromium
/// guest, and the desktop driver for a Linux desktop guest through
/// cua-driver; each refuses the other's own verbs.
pub trait BrowserDriver: Send {
    fn open(&mut self, input: OpenInput) -> Result<Observation, BrowserError>;
    fn observe(&mut self, input: ObserveInput) -> Result<Observation, BrowserError>;

    /// A whole read of the page that no answer gives the caller (a routine
    /// step's look, a batch's progress read): kept apart from the
    /// observations a caller's base names, so it never ages one out (FIX
    /// 8510). A driver that keeps no such apart reads as `observe` does.
    fn observe_hidden(&mut self) -> Result<Observation, BrowserError> {
        self.observe(ObserveInput {
            full: true,
            ..ObserveInput::default()
        })
    }
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

    /// What the driver knows of a live handle it minted: its locator and
    /// last scope. A driver with no live handles knows none.
    fn handle_info(&self, _handle: &str) -> Option<HandleInfo> {
        None
    }

    /// The kind of secret a run-bound handle (`scN`, or as a row shows it)
    /// holds, when a read of this session took it (FIX 8028). A driver that
    /// holds no secrets knows none.
    fn secret_kind(&self, _handle: &str) -> Option<SecretKind> {
        None
    }

    /// `observation` as its first page. A driver that pages keeps the rest
    /// for `observe_page` to read on; one that does not answers it whole.
    fn paged(&mut self, observation: Observation) -> ObservationPage {
        ObservationPage::whole(observation)
    }

    /// One page of an observation: the page as `observe` reads it, or, with
    /// `cursor`, the next page of one an earlier answer paged.
    fn observe_page(&mut self, input: ObserveInput) -> Result<ObservationPage, BrowserError> {
        if input.cursor.is_some() {
            return Err(BrowserError::Input(
                "this driver pages no observation; observe without a cursor".to_owned(),
            ));
        }
        let observation = self.observe(input)?;
        Ok(self.paged(observation))
    }

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

    /// Takes a program out of the library, for every run after.
    fn library_retire(
        &mut self,
        _input: LibraryRetireInput,
    ) -> Result<LibraryRetireOutput, BrowserError> {
        Err(BrowserError::Library(
            "this browser host keeps no library".to_owned(),
        ))
    }

    /// The programs retires took out of the library for a site.
    fn library_retired(
        &mut self,
        _input: LibraryRetiredInput,
    ) -> Result<LibraryRetiredOutput, BrowserError> {
        Err(BrowserError::Library(
            "this browser host keeps no library".to_owned(),
        ))
    }

    /// Drafts a proposal from the driver's own history of effects and
    /// stops for its open page (CUA E7), with no model and no library: a
    /// driver with no such history serves none, and never answers an empty
    /// draft.
    fn library_draft(&mut self, _input: DraftInput) -> Result<DraftOutput, BrowserError> {
        Err(BrowserError::Unsupported("library_draft".to_owned()))
    }

    /// Notes in the driver's history that a step stopped (CUA E7), with the
    /// receipt of an effect it made first, so a draft never takes it for a
    /// step that worked. A driver that keeps no history notes nothing.
    fn note_stop(&mut self, _stop: StepStop) {}

    /// The receipt of the input the last effect verb sent before it failed
    /// (FIX 8010): its settle or its read after failed, and the effect
    /// stands. Taken once; a driver that receipts no such input has none.
    fn sent_receipt(&mut self) -> Option<EffectReceipt> {
        None
    }

    /// The operand the driver's newest receipt typed into `target`, a live
    /// handle or a locator, as it kept it for a replay (CUA E7; FIX 8344,
    /// 8345): a secret by its handle and kind, else its text. None where no
    /// receipt typed there, or the driver keeps no history.
    fn typed_operand(&self, _target: &str) -> Option<TypeOperand> {
        None
    }

    /// The viewport's scroll offset now, in CSS pixels, where the driver
    /// reads one (FIX 8508); none elsewhere.
    fn viewport_offset(&self) -> Option<(f64, f64)> {
        None
    }

    /// Withdraws the newest no-progress stop the driver's history noted
    /// (FIX 8507): the run's final checks met after all. A driver that
    /// keeps no history withdraws nothing.
    fn withdraw_no_progress(&mut self) {}

    /// Starts recording a demonstration of the attached browser (CUA E9a):
    /// only a browser session on a Chromium guest records one; any other
    /// driver records none, and never answers an empty recording.
    fn demonstration_start(
        &mut self,
        _input: DemonstrationStartInput,
    ) -> Result<DemonstrationStarted, BrowserError> {
        Err(BrowserError::Unsupported("demonstration.start".to_owned()))
    }

    /// Stops a demonstration, or takes one that ended, with its steps,
    /// gaps and draft, once (CUA E9a).
    fn demonstration_stop(
        &mut self,
        _input: DemonstrationStopInput,
    ) -> Result<DemonstrationOutput, BrowserError> {
        Err(BrowserError::Unsupported("demonstration.stop".to_owned()))
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

    /// Asks a person to take a desktop or browser session over.
    fn handover(&mut self, _input: HandoverInput) -> Result<HandoverOutput, BrowserError> {
        Err(BrowserError::Unsupported("handover".to_owned()))
    }

    /// Moves a run's browser to another engine, its page carried (FIX
    /// 6680). Only a session its host can start guests for serves it.
    fn switch_engine(
        &mut self,
        _input: SwitchEngineInput,
    ) -> Result<SwitchEngineOutput, BrowserError> {
        Err(BrowserError::Unsupported("switch_engine".to_owned()))
    }

    /// Types a Fill step's resolved text as `type_text` types text, its
    /// receipt naming where the text came from (`provenance`, CUA E6). A
    /// driver whose receipts are stamped before they are kept overrides it;
    /// this one stamps the answer's.
    fn fill_text(
        &mut self,
        input: TypeInput,
        provenance: TextProvenance,
    ) -> Result<Observation, BrowserError> {
        let mut observation = self.type_text(input)?;
        if let Some(receipt) = &mut observation.receipt {
            provenance.stamp(receipt);
        }
        Ok(observation)
    }

    /// Runs one batched program for a subgoal; a routine step has no
    /// decider here, so it goes up, and a Fill has no writer.
    fn batch(&mut self, input: BatchInput) -> Result<BatchOutput, BrowserError> {
        self.batch_with(input, &mut NoDecider, &NoWriter)
    }

    /// Runs one batched program for a subgoal, step by step through this
    /// driver's own verbs, so a host wrapper's door still gates each effect,
    /// and its routine steps through `decider` under the subgoal's one clock,
    /// a Fill's generation through `writer`. The batch stops at the first
    /// refused, timed-out, unmet or sent-up step, never for its count: it
    /// holds one or more steps. It goes up too once [`NO_PROGRESS_STEPS`]
    /// steps in a row acted and left the page as it was (CUA E3): after the
    /// last of them ran, never before. A Fill whose template or options do
    /// not hold stops it before any step runs (CUA E6).
    fn batch_with(
        &mut self,
        input: BatchInput,
        decider: &mut dyn RoutineDecider,
        writer: &dyn FieldWriter,
    ) -> Result<BatchOutput, BrowserError> {
        let started = std::time::Instant::now();
        if input.steps.is_empty() {
            return Err(BrowserError::Input(
                "a batch holds one or more steps".to_owned(),
            ));
        }
        let base = input.base;
        let mut output = BatchOutput {
            status: SubgoalStatus::Done,
            completed: 0,
            failed_step: None,
            error: None,
            stop_cause: None,
            failed_receipt: None,
            elapsed_ms: 0,
            observation: None,
            receipts: Vec::new(),
            decisions: Vec::new(),
            until_ms: input.until_ms,
            next: None,
            rebindings: Vec::new(),
        };
        // Every Fill's template and options, checked before any step, so a
        // bad one stops the batch at no decision's or model's cost (CUA E6
        // `fill_precheck`, CALLS row).
        let unfit = input
            .steps
            .iter()
            .enumerate()
            .find_map(|(index, step)| match step {
                BatchStep::Fill { field, .. } => field.prepare().err().map(|stop| (index, stop)),
                _ => None,
            });
        if let Some((index, stop)) = unfit {
            stop::noted(self, input.steps[index].name(), &stop);
            return Ok(stop::stopped(self, output, index, stop, base, started));
        }
        let mut routine = Routine {
            decider,
            until_ms: input.until_ms,
            no_model: input.no_model,
            misses: 0,
            decisions: Vec::new(),
            base: base.clone(),
            rebindings: Vec::new(),
        };
        // Starts with the batch: a run of unchanged steps is the batch's own.
        let mut monitor = Progress::new();
        for (index, step) in input.steps.into_iter().enumerate() {
            let counts = step.counts_for_progress();
            let name = step.name();
            // The caller's clock is the batch's one clock (FIX 8043): past
            // its `until_ms`, the batch hands up before the step.
            if let Some(stop) = stop::clock_out(routine.until_ms) {
                stop::noted(self, name, &stop);
                return Ok(stop::stopped(self, output, index, stop, base, started));
            }
            monitor.before(self, counts);
            // The targets this step matched by their locators.
            let mut rebindings = Vec::new();
            let outcome: Result<Option<Observation>, Stop> = match step {
                BatchStep::Open { url } => self
                    .open(OpenInput { url })
                    .map(Some)
                    .map_err(Stop::opening),
                BatchStep::Click { target } => self
                    .click(ClickInput {
                        target,
                        base: base.clone(),
                    })
                    .map(Some)
                    .map_err(Stop::from),
                BatchStep::Type {
                    target,
                    text,
                    secret,
                    clear,
                } => self
                    .type_text(TypeInput {
                        target,
                        text,
                        secret,
                        clear,
                        base: base.clone(),
                    })
                    .map(Some)
                    .map_err(Stop::from),
                BatchStep::Select { target, option } => self
                    .select(SelectInput {
                        target,
                        option,
                        base: base.clone(),
                    })
                    .map(Some)
                    .map_err(Stop::from),
                BatchStep::WaitFor {
                    targets,
                    role,
                    name,
                    timeout_ms,
                } => self
                    .wait_for(WaitForInput {
                        targets,
                        role,
                        name,
                        timeout_ms,
                        cursor: None,
                    })
                    .map_err(Stop::from)
                    .and_then(|mut waited| {
                        rebindings.append(&mut waited.rebindings);
                        if waited.timed_out {
                            let scope = ClockScope::Wait;
                            let error = BrowserError::Timeout("a batch wait_for step".to_owned());
                            Err(Stop::new(BatchStopCause::Clock { scope }, error))
                        } else {
                            Ok(None)
                        }
                    }),
                BatchStep::Expect {
                    target,
                    role,
                    name,
                    value,
                    secret,
                    absent,
                } => {
                    let check = ExpectInput {
                        target,
                        role,
                        name,
                        value,
                        secret,
                        absent,
                    };
                    self.expect(check.clone())
                        .map_err(Stop::from)
                        .and_then(|expected| {
                            rebindings.extend(expected.rebindings.iter().cloned());
                            Stop::checked(check, expected).map(|()| None)
                        })
                }
                BatchStep::Screenshot { trigger } => self
                    .screenshot(ScreenshotInput {
                        trigger,
                        since_capture: None,
                    })
                    .map(|_| None)
                    .map_err(Stop::from),
                BatchStep::Key {
                    key,
                    modifiers,
                    target,
                } => self
                    .press_key(KeyInput {
                        key,
                        modifiers,
                        target,
                        base: base.clone(),
                    })
                    .map(Some)
                    .map_err(Stop::from),
                BatchStep::Hotkey { keys } => self
                    .hotkey(HotkeyInput {
                        keys,
                        base: base.clone(),
                    })
                    .map(Some)
                    .map_err(Stop::from),
                BatchStep::Scroll {
                    direction,
                    amount,
                    target,
                } => self
                    .scroll(ScrollInput {
                        direction,
                        amount,
                        target,
                        base: base.clone(),
                    })
                    .map(Some)
                    .map_err(Stop::from),
                BatchStep::Decide(step) => routine.step(self, step).map(Some),
                BatchStep::Fill { target, field } => {
                    field::fill(self, &mut routine, writer, target, field).map(Some)
                }
            };
            output.decisions.append(&mut routine.decisions);
            output.until_ms = routine.until_ms;
            rebindings.append(&mut routine.rebindings);
            if let Ok(Some(observation)) = &outcome {
                rebindings.extend(observation.rebound.clone());
            }
            output
                .rebindings
                .extend(rebindings.into_iter().map(|rebound| StepRebound {
                    step: index,
                    rebound,
                }));
            match outcome {
                Ok(observation) => {
                    output.completed += 1;
                    let mut acted = None;
                    if let Some(observation) = observation {
                        if let Some(receipt) = &observation.receipt {
                            acted = Some(receipt.seq);
                            output.receipts.push(receipt.clone());
                        }
                        output.observation = Some(observation);
                    }
                    // The step's effect is kept; the page read after it
                    // may show it the last of a run that changed nothing.
                    if let Some(page) = monitor.after(self, counts) {
                        self.note_stop(progress::no_progress(name, acted));
                        return Ok(progress::handed_up(output, index, page, started));
                    }
                }
                Err(mut stop) => {
                    // An input the step sent stands with its receipt (FIX
                    // 8010), as a Fill's does.
                    if stop.receipt.is_none() {
                        stop.receipt = self.sent_receipt();
                    }
                    stop::noted(self, name, &stop);
                    return Ok(stop::stopped(self, output, index, stop, base, started));
                }
            }
        }
        output.elapsed_ms = elapsed_ms(started);
        Ok(output)
    }
}

/// Candidates one routine Choice offers: the contract's 64 options less
/// NONE, reobserve and "too complicated, ask up". A step with more asks
/// them in pages of this many (Rule 5), never refused or cut.
pub const ROUTINE_MAX_CANDIDATES: usize = 61;

/// A batch's routine steps: the decider, the subgoal's one clock, the NONE
/// and reobserve answers in a row, the decisions taken, the batch's base,
/// and the targets an acting step matched by their locators.
struct Routine<'d> {
    decider: &'d mut dyn RoutineDecider,
    until_ms: Option<u64>,
    no_model: bool,
    misses: u32,
    decisions: Vec<serde_json::Value>,
    base: Option<ObservationBase>,
    rebindings: Vec<Rebound>,
}

impl Routine<'_> {
    /// A step's wait for a row: [`ROUTINE_WAIT_MS`], or what is left of the
    /// subgoal's clock when that ends sooner.
    fn wait_ms(&self) -> u32 {
        let Some(until) = self.until_ms else {
            return ROUTINE_WAIT_MS;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            });
        u32::try_from(until.saturating_sub(now))
            .unwrap_or(u32::MAX)
            .min(ROUTINE_WAIT_MS)
    }

    /// One routine step: look, ask, act. A look reads the outline, and a
    /// screenshot too for a locate step or once the trail says so. A step
    /// that goes up names its cause.
    fn step<D: BrowserDriver + ?Sized>(
        &mut self,
        driver: &mut D,
        step: DecideStep,
    ) -> Result<Observation, Stop> {
        let entries = [
            step.text.is_some(),
            step.secret.is_some(),
            step.option.is_some(),
        ];
        let entered = entries.iter().filter(|named| **named).count();
        if entered > 1 || (step.locate && (entered > 0 || !step.targets.is_empty())) {
            return Err(BrowserError::Input(
                "a decide step types text, types a secret or selects an option, and a locate step only clicks"
                    .to_owned(),
            )
            .into());
        }
        let query = FindInput {
            role: step.role.clone(),
            name: step.name.clone(),
            cursor: None,
        };
        let mut trigger = step.locate.then_some(ScreenshotTrigger::OutlineThin);
        // No row matches the step: unproven past a cut, the subgoal's clock
        // when it left no time to wait (`clock`), else a missing locator.
        let no_row = |page: &Observation, clock: bool| {
            if page.partial.is_some() {
                let error = BrowserError::AskUp(
                    "no row before the cut of the window's tree walk matches the step; observe and walk on with its walk_next".to_owned(),
                );
                return Stop::new(BatchStopCause::IncompleteObservation, error);
            }
            let cause = if clock {
                BatchStopCause::Clock {
                    scope: ClockScope::Decision,
                }
            } else {
                BatchStopCause::LocatorMissing
            };
            let error = BrowserError::AskUp("no row on the page matches the step".to_owned());
            Stop::new(cause, error)
        };
        let mut waited = false;
        let mut looks = 0;
        while looks < ROUTINE_LOOKS {
            // A look the caller never sees: whole, never its base, and
            // never aging out one (FIX 8510).
            let page = driver.observe_hidden()?;
            // A desktop window with no tree is read by its pixels: a step
            // that only clicks locates its target in a screenshot there.
            let blind = page.no_tree
                && step.text.is_none()
                && step.secret.is_none()
                && step.option.is_none()
                && step.targets.is_empty();
            let locate = step.locate || blind;
            let look = match trigger {
                Some(ScreenshotTrigger::DeciderReobserve) => trigger,
                _ if blind => Some(ScreenshotTrigger::NoAccessibilityTree),
                _ => trigger,
            };
            // Named targets match their own rows, or, a handle whose node
            // is gone, the row its locator names now, as a rebinding.
            let (candidates, rebindings): (Vec<(String, Row)>, Vec<Rebound>) = if locate {
                (Vec::new(), Vec::new())
            } else if step.targets.is_empty() {
                let matched = page
                    .rows
                    .iter()
                    .filter(|row| query.matches(row))
                    .map(|row| (candidate(row), row.clone()))
                    .collect();
                (matched, Vec::new())
            } else {
                let (named, rebindings) =
                    rows_named(&step.targets, &page.rows, &page.scope, |target| {
                        driver.handle_info(target)
                    });
                let named = named
                    .into_iter()
                    .map(|row| (candidate(&row), row))
                    .collect();
                (named, rebindings)
            };
            if !locate && candidates.is_empty() {
                // One bounded wait for the step's targets, or its role and
                // name, then a fresh look. A window with no tree grows no
                // rows, so it does not wait.
                let wait = self.wait_ms();
                if waited || page.no_tree || wait == 0 {
                    return Err(no_row(&page, !waited && !page.no_tree && wait == 0));
                }
                waited = true;
                let rows = driver.wait_for(WaitForInput {
                    targets: step.targets.clone(),
                    role: step.role.clone(),
                    name: step.name.clone(),
                    timeout_ms: Some(wait),
                    cursor: None,
                })?;
                if rows.timed_out {
                    return Err(no_row(&page, false));
                }
                continue;
            }
            looks += 1;
            let shot = match look {
                Some(trigger) => {
                    let shot = driver.screenshot(ScreenshotInput {
                        trigger,
                        since_capture: None,
                    })?;
                    let png = driver
                        .image_bytes(&shot.image)
                        .ok_or_else(|| BrowserError::NoImage(shot.image.clone()))?;
                    Some((shot.image, png))
                }
                None => None,
            };
            let labels: Vec<String> = candidates.iter().map(|(label, _)| label.clone()).collect();
            let reply = self.ask(&step.question, &labels, shot.as_ref(), look_state(&page))?;
            match reply.answer {
                RoutineAnswer::Act { candidate } if !locate => {
                    self.misses = 0;
                    let target = candidates
                        .into_iter()
                        .find(|(label, _)| *label == candidate)
                        .map(|(_, row)| row.target)
                        .ok_or_else(|| {
                            let error =
                                BrowserError::Decider(format!("{candidate} is not a candidate"));
                            Stop::new(asked_up(AskUpReason::WrongAnswer), error)
                        })?;
                    self.rebindings.extend(rebindings);
                    let base = self.base.clone();
                    let acted = match (step.text, step.secret, step.option) {
                        (text, secret, _) if text.is_some() || secret.is_some() => driver
                            .type_text(TypeInput {
                                target,
                                text,
                                secret,
                                clear: step.clear,
                                base,
                            }),
                        (_, _, Some(option)) => driver.select(SelectInput {
                            target,
                            option,
                            base,
                        }),
                        (_, _, None) => driver.click(ClickInput { target, base }),
                    };
                    return acted.map_err(Stop::from);
                }
                RoutineAnswer::Point { x, y } if locate => {
                    self.misses = 0;
                    let (image, _) = shot.ok_or_else(|| {
                        let error =
                            BrowserError::Decider("a point without a screenshot".to_owned());
                        Stop::new(asked_up(AskUpReason::WrongAnswer), error)
                    })?;
                    let clicked = driver.click_at(PointInput {
                        image,
                        x,
                        y,
                        base: self.base.clone(),
                    });
                    return clicked.map_err(Stop::from);
                }
                // A window whose tree walk was cut offered only the rows
                // before the cut: none of them fits, so the step goes up
                // rather than look again at the same cut.
                RoutineAnswer::None if !locate && page.partial.is_some() => {
                    let error = BrowserError::AskUp(
                        "the window's tree walk stopped before its end and no row before the cut fits; observe and walk on with its walk_next".to_owned(),
                    );
                    return Err(Stop::new(BatchStopCause::IncompleteObservation, error));
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
                    let detail = reason.as_deref().unwrap_or("the decider asked up");
                    let detail = detail.to_owned();
                    let reason = AskUpReason::Asked { ladder: reason };
                    return Err(Stop::new(asked_up(reason), BrowserError::AskUp(detail)));
                }
                RoutineAnswer::Denied { denial } => {
                    let error = BrowserError::AskUp(format!(
                        "a strict run's step only a model could answer ({denial:?}); no model was asked"
                    ));
                    let reason = AskUpReason::Strict { denied: denial };
                    return Err(Stop::new(asked_up(reason), error));
                }
                RoutineAnswer::Deadline => {
                    let error = BrowserError::AskUp(
                        "the subgoal's clock ran out before the decider answered".to_owned(),
                    );
                    let scope = ClockScope::Decision;
                    return Err(Stop::new(BatchStopCause::Clock { scope }, error));
                }
                other => {
                    let error =
                        BrowserError::Decider(format!("{other:?} does not answer this step"));
                    return Err(Stop::new(asked_up(AskUpReason::WrongAnswer), error));
                }
            }
        }
        let error = BrowserError::AskUp(format!("no target after {ROUTINE_LOOKS} looks"));
        Err(Stop::new(asked_up(AskUpReason::Looks), error))
    }

    /// One look's ask (Rule 5): the step's candidates, by their labels in
    /// row order, in pages of at most [`ROUTINE_MAX_CANDIDATES`], or none
    /// for a locate step. Many candidates are never refused, cut or
    /// sampled: NONE on a page with more after it asks the next page, and
    /// any other answer, or NONE on the last page, is the look's. Each page
    /// is its own decision, asked under the look's misses, and `state`, the
    /// page the look read, names the page of candidates too.
    fn ask(
        &mut self,
        question: &str,
        candidates: &[String],
        shot: Option<&(String, Vec<u8>)>,
        mut state: serde_json::Value,
    ) -> Result<RoutineReply, BrowserError> {
        let offered: Vec<&[String]> = if candidates.is_empty() {
            vec![candidates]
        } else {
            candidates.chunks(ROUTINE_MAX_CANDIDATES).collect()
        };
        let pages = offered.len();
        for (index, offered) in offered.into_iter().enumerate() {
            if pages > 1 {
                state["candidates"] = serde_json::json!({
                    "page": index + 1,
                    "pages": pages,
                    "rows": candidates.len(),
                });
            }
            let mut reply = self.decider.decide(RoutineAsk {
                question,
                options: offered.to_vec(),
                image: shot.map(|(image, png)| (image.as_str(), png.as_slice())),
                state: state.clone(),
                misses: self.misses,
                until_ms: self.until_ms,
                no_model: self.no_model,
            })?;
            self.until_ms = reply.until_ms.or(self.until_ms);
            self.decisions.push(std::mem::take(&mut reply.decision));
            if index + 1 == pages || !matches!(reply.answer, RoutineAnswer::None) {
                return Ok(reply);
            }
        }
        Err(BrowserError::Decider("the look asked no page".to_owned()))
    }
}

/// What a look's ask reads of `page`: its URL and title, and its cut.
fn look_state(page: &Observation) -> serde_json::Value {
    let mut state = serde_json::json!({"url": page.url, "title": page.title});
    if let Some(partial) = &page.partial {
        state["partial"] = serde_json::json!(partial);
    }
    state
}

/// A routine step's ask-up, for `reason`.
fn asked_up(reason: AskUpReason) -> BatchStopCause {
    BatchStopCause::DeciderAskedUp { reason }
}

/// A row as a routine Choice offers it: its role and name, then its
/// locator, which tells twins apart and reads the same in every session,
/// so a rule standing for the step still answers it. An option holds at
/// most 256 bytes.
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
    format!("{label} [{}]", row.locator)
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
            Self::Timeout(_) | Self::CallTimeout(_) => "browser_timeout",
            Self::Protocol(_) => "browser_protocol",
            Self::StaleImage(_) => "browser_stale_image",
            Self::AskUp(_) => "routine_ask_up",
            Self::Decider(_) => "routine_decider_failed",
            Self::NoWorkflow(_) => "browser_no_workflow",
            Self::WorkflowRetired(_) => "workflow_retired",
            Self::Library(_) => "browser_library_failed",
            Self::Unsupported(_) => "browser_unsupported",
            Self::TakenOver(_) => "desktop_taken_over",
            Self::BrowserTakenOver(_) => "browser_taken_over",
            Self::TreeCut(_) => "desktop_tree_cut",
            Self::MemoryFloor => "browser_memory_floor",
            Self::DestinationRefused(_) => "browser_destination_refused",
            Self::SecretRefused(_) => "browser_secret_refused",
            Self::FieldText(_) => "browser_field_text",
        }
    }
}

impl WaitForInput {
    #[must_use]
    pub fn query(&self) -> FindInput {
        FindInput {
            role: self.role.clone(),
            name: self.name.clone(),
            cursor: None,
        }
    }

    /// Whether `row` is one the wait is for: a row `targets` names by its
    /// ref or its locator, or, with none named, a row `role` and `name`
    /// match. A page's driver matches a live handle whose node is gone by
    /// its locator too (`rows_named`).
    #[must_use]
    pub fn matches(&self, row: &Row) -> bool {
        if self.targets.is_empty() {
            self.query().matches(row)
        } else {
            self.targets
                .iter()
                .any(|target| *target == row.target || *target == row.locator)
        }
    }
}

impl ExpectInput {
    #[must_use]
    pub fn query(&self) -> FindInput {
        FindInput {
            role: self.role.clone(),
            name: self.name.clone(),
            cursor: None,
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
