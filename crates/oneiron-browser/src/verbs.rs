use super::*;
use schemars::JsonSchema;

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
    /// The loadable skills whose site matches the page an `open` landed on
    /// exactly, after its redirects (CUA E10), each with its knowledge
    /// whole: on the answer of the call that opened it, on every page of
    /// that answer, and on no later call's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub site_skills: Vec<SiteSkillMatch>,
    /// Why that open's site skills did not load, by name; the page opened
    /// all the same.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub site_skill_notes: Vec<SiteSkillError>,
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
