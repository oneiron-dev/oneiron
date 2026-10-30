//! A desktop session (OF-523): one Linux desktop in an isolated guest,
//! driven through cua-driver's MCP server on the guest's stdio, with the
//! host's rules in front of it.
//!
//! The desktop runs only inside the guest (an X display, its accessibility
//! bus, a window manager and a fixed app set), never on the host, so no call
//! reaches the owner's own desktop. The session reads one window at a time
//! as rows from its accessibility tree. A row's locator is built from its
//! role, its name and its named ancestors, as a page's is, and is its ref
//! too: a desktop row has no live handle, and its observations' scope names
//! the session and the window, never a page's document. The driver's
//! element tokens, which each newer read retires, never leave the session.
//! A window an action opens in front (a dialog, a document) is where the
//! next step reads, and the next answer names the move once, as `switched`
//! (`why: opened`).
//!
//! Effects follow the browser's rules. A control whose name marks an effect
//! class takes that class's press from the vault's grant, and a Return, or
//! text with a line break, takes the press of a send. Every effect lands a
//! receipt naming its window, with a screenshot of the window as evidence,
//! its password fields blacked out before the image is held. No other
//! screenshot is taken without a named trigger. A click at a point of an
//! image first reads the window once more and checks the pixels around the
//! point still look as they did in that image; that read is compared and
//! dropped, never held or receipted. The row under the point judges the
//! click's press: a read cut before a row is there walks on first, as an
//! act on a row does, and one still cut at its longest with no row there
//! takes the gate's floor press, a person's. A window with no tree says so
//! (`no_tree`), and the program reads it by its pixels.
//!
//! A window's tree is read whole (Rule 5): cua-driver's walk takes a node
//! budget and no offset, so a walk the budget cut is read again with a
//! larger one until it ends. A long tree is answered in pages, as a page's
//! outline is: `next` names the cursor `observe` reads the rest from, and
//! `find` and `wait_for` page their rows the same way. A walk still cut at
//! the longest time a read asks for answers what it reached, marked
//! `partial`, and is never a silent cut: its last page's `walk_next` walks
//! the window again, longer, as a new whole observation with its own seq.
//! A cut is never proof a row is gone. An act on a row, and a `find`,
//! `wait_for` or `expect` that reached no row it seeks, walks on itself,
//! longer each time, until the row is there, the walk reaches the tree's
//! end, or the walk on is at its longest (a wait's time ends it sooner).
//! Only a walk that reached the end shows a row gone (`stale_ref`). An act
//! whose row is still past the cut answers `desktop_tree_cut`; a search
//! answers what it found, `partial`, with a `walk_next` that searches on.
//!
//! A window gone since the last read (a dialog closed, an app quit) gives
//! way to the window in front, and the next answer names the move once, as
//! `switched` (`why: closed`).
//!
//! A person can take the desktop over (CUA-001), asked by the agent's
//! `handover` or not. While the agent waits on its ask, and while a person
//! holds the desktop, every agent verb refuses `desktop_taken_over` and
//! takes no screenshot; the person sees the whole display and drives it
//! through the same driver. Handing it back ends the takeover with its
//! record, which is its receipt.
//!
//! A window's secret fields (FIX 8028, OF-560), classified as a page's are
//! (`secret_fields`), become run-bound handles in place through the host's
//! secret custody: the row shows the handle, its name stays empty as
//! before, and a name or value that echoes the secret shows the handle
//! too. A type or expect may name a handle; its bytes come from the
//! custody at the send or the comparison, and the line-break check of a
//! typed secret reads the bytes. A settle poll's read, which only a hash
//! reads, masks the same fields and holds nothing.

mod acts;
mod images;
mod point;
mod press_holds;
mod reads;
mod session;
mod tree;
mod verbs;

pub use session::{AbandonedTakeover, DesktopGuest, PersonInput, Takeover};

use crate::capture::{self, Capture, Captures, Viewport, crop_region, encode_png, png_dimensions};
use crate::driver::pages::{
    Base, Found, Observations, Read, Search, find_cursor, is_search, is_walk, session_token,
    wait_cursor,
};
use crate::mcp::{Mcp, ToolError, ToolReply};
use crate::observation::match_target;
use crate::secret::{Entry, SecretUse, Secrets, entry};
use crate::secret_fields::{
    FieldFacts, SECRET_MARK, classify, masked, secret_display_policy, secret_echo_policy,
};
use crate::session::{PressBook, effect_class, press_for, receipt_class};
use crate::stop::elapsed_ms;
use crate::{
    BatchInput, BatchOutput, BrowserDriver, BrowserError, ClickInput, CropInput, DesktopWindow,
    EFFECT_SEND, EffectReceipt, ExpectInput, ExpectOutput, FieldWriter, FindInput, FindOutput,
    HandoverInput, HandoverOutput, HotkeyInput, ImageOutput, KeyInput, NoDecider, NoWriter,
    Observation, ObservationPage, ObserveInput, OpenInput, PartialTree, PointInput, PressGrants,
    PressMode, ReceiptEvidenceSink, RoutineDecider, Row, RowSecret, ScreenshotInput,
    ScreenshotOutput, ScreenshotTrigger, ScrollInput, SecretCustody, SecretKind, SecretNote,
    SelectInput, SendPolicy, TakeoverRecord, TextProvenance, TypeInput, ViewInput, WaitForInput,
    WaitForOutput, WindowInput, WindowSwitch, WindowSwitchCause, WindowsInput, WindowsOutput,
    ZoomInput,
};
use images::{looks_as_it_did, mask};
use oneiron_container::{GuestLimits, SessionLease, SessionManifest, SessionTransport};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tree::lines;

/// The browser's settle values: up to 0.6 s for the window to start
/// changing, then 0.15 s with no change, never more than 2 s in all.
const REACTION: Duration = Duration::from_millis(600);
const QUIET: Duration = Duration::from_millis(150);
const SETTLE_CAP: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(100);
/// One driver call's bound. A first tree walk alone may take two seconds.
const CALL: Duration = Duration::from_secs(15);
/// How long the guest's desktop, or an app it opens, has to come up.
const LAUNCH: Duration = Duration::from_secs(30);
const WAIT_DEFAULT: Duration = Duration::from_secs(5);
/// The node budget a window's first walk asks cua-driver for (its own
/// default is 250). A walk the budget cut reads again with at least twice
/// the budget, until the tree is whole.
const FIRST_BUDGET: u64 = 1000;
/// The longest walk a read asks for once a walk ran out of its time (the
/// driver's default is one second): within one driver call's bound.
const WALK_MS_MOST: u64 = 12_000;
/// The longest walk a walk on asks for: cua-driver's own ceiling on
/// `timeout_ms` (120 s in 0.36.0, the guest's pinned build). Each walk on
/// asks four times its last walk's time, up to this; one cut here still
/// walks on at this.
const WALK_ON_MS_MOST: u64 = 120_000;
/// Screenshots the session holds for a later image read.
const MEDIA: usize = 16;
/// The square a click at a point checks, in screenshot pixels each way from
/// the point: it must look as it did in the image the point was read from.
const CLICK_CHECK_RADIUS: u32 = 16;
/// The share of that square's pixels that may have changed (a blinking
/// caret) before the image no longer shows the spot.
const CLICK_CHECK_SLACK: f64 = 0.05;
/// The longest name or value a row carries.
const NAME_CHARS: usize = 200;
/// A zoom without a scale fills this width, at most fourfold.
const ZOOM_WIDTH: u32 = 1366;

pub struct DesktopSession {
    mcp: Mcp,
    guest: Box<dyn SessionLease>,
    manifest: SessionManifest,
    policy: SendPolicy,
    /// The grants' policy as last read and the sends batch presses paid,
    /// as a browser session keeps them (FIX 4613, 4615, 12133).
    presses: PressBook,
    /// The act a press held and the press an owner's answer armed (FIX
    /// 11499).
    press_holds: press_holds::PressHolds,
    /// The receipt of the input the running verb sent whose window did not
    /// read after (FIX 12134), for its batch's stop to carry.
    unread: Option<EffectReceipt>,
    /// Whether the running act's input was sent (FIX 12134).
    input_sent: bool,
    receipts: Vec<EffectReceipt>,
    receipt_seq: u64,
    decider: Option<Box<dyn RoutineDecider>>,
    /// The host's writer of a Fill's text, lent with the decider (FIX
    /// 8899), as a browser session's is.
    field_writer: Option<Box<dyn FieldWriter>>,
    /// Where the text the next type receipt names came from, set by the
    /// Fill that makes it (FIX 8899); a `type`'s is supplied.
    provenance: Option<TextProvenance>,
    receipt_sink: Option<Box<dyn ReceiptEvidenceSink>>,
    /// The window the session reads and acts on.
    window: Option<WindowKey>,
    seq: u64,
    /// This session's token, in its observations' scopes.
    token: String,
    media: VecDeque<Held>,
    /// The session's screenshot capture ids.
    captures: Captures,
    /// The observations a later one may edit, and the paged answers a
    /// cursor may still read on.
    pages: Observations,
    wait_cap: Duration,
    /// Who has the desktop now.
    takeover: Takeover,
    /// The takeover that ended since the agent's last answer.
    returned: Option<TakeoverRecord>,
    /// The move to another window since the agent's last answer.
    switched: Option<WindowSwitch>,
    /// The host's secret custody (FIX 8028); empty until the host gives it.
    secrets: Secrets,
    /// The fields a type entered a secret into, by locator, with its kind:
    /// each reads as that secret from then on.
    typed: HashMap<String, SecretKind>,
    /// A settle poll's read is under way: its secrets are masked, never
    /// held.
    polling: bool,
    /// Where the rows of the last read no poll took stood, as one hash
    /// (FIX 10430).
    view: Option<[u8; 32]>,
}

/// A window: its owner's pid and its X window id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WindowKey {
    pid: u32,
    id: u64,
}

impl WindowKey {
    fn name(self) -> String {
        format!("{}:{}", self.pid, self.id)
    }

    fn parse(name: &str) -> Option<Self> {
        let (pid, id) = name.split_once(':')?;
        Some(Self {
            pid: pid.parse().ok()?,
            id: id.parse().ok()?,
        })
    }
}

/// A window on screen, as the driver lists it.
struct Listed {
    key: WindowKey,
    app: String,
    title: String,
    /// Higher is nearer the front; none when the display cannot tell.
    z: Option<i64>,
}

/// A rectangle in pixels: of the screen, or of a screenshot.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Rect {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
}

impl Rect {
    fn read(value: &Value, width: &str, height: &str) -> Option<Self> {
        let at = |name: &str| value.get(name).and_then(Value::as_f64);
        Some(Self {
            x: at("x")?,
            y: at("y")?,
            w: at(width)?,
            h: at(height)?,
        })
    }

    fn contains(self, x: f64, y: f64) -> bool {
        x >= self.x && y >= self.y && x < self.x + self.w && y < self.y + self.h
    }

    fn same(self, other: Self) -> bool {
        (self.x - other.x).abs() < 1.0
            && (self.y - other.y).abs() < 1.0
            && (self.w - other.w).abs() < 1.0
            && (self.h - other.h).abs() < 1.0
    }
}

/// A row, the driver's token for its element as last read, and where the
/// element is on screen; and, where the row shows a secret in place, what
/// the window holds there, for the read's own checks and hash only.
#[derive(Clone)]
struct Line {
    row: Row,
    token: Option<String>,
    frame: Option<Rect>,
    masked: bool,
    original: Option<String>,
    /// Whether the read reached past the row's whole subtree: a later node
    /// at its raw depth or above came. A row a cut read ends inside is not
    /// closed (FIX 5740, `point`).
    closed: bool,
}

impl Line {
    /// Whether the row's element covers screen point (`x`, `y`).
    fn covers(&self, x: f64, y: f64) -> bool {
        self.frame.is_some_and(|frame| frame.contains(x, y))
    }
}

/// One type's field, as read: the read, the answer's base, the field's
/// element token and ref, and whether its text is replaced.
struct Typing<'a> {
    read: &'a Snapshot,
    base: &'a Base,
    token: &'a str,
    target: &'a str,
    clear: bool,
}

/// Where a secret field is: on screen, and in the read's screenshot.
struct Secret {
    screen: Option<Rect>,
    shot: Option<Rect>,
}

/// One read of a window.
struct Snapshot {
    key: WindowKey,
    app: String,
    title: String,
    /// The window's place on screen.
    bounds: Option<Rect>,
    lines: Vec<Line>,
    secrets: Vec<Secret>,
    no_tree: bool,
    /// Where the walk stopped, when it stopped before the tree's end.
    partial: Option<PartialTree>,
    /// The screenshot, with its pixels per screen pixel.
    shot: Option<(Vec<u8>, f64)>,
}

impl Snapshot {
    fn line(&self, target: &str) -> Result<Line, BrowserError> {
        self.lines
            .iter()
            .find(|line| line.row.target == target)
            .cloned()
            .ok_or_else(|| BrowserError::StaleRef(target.to_owned()))
    }

    /// The row whose element covers screen point (`x`, `y`): the smallest.
    fn line_at(&self, x: f64, y: f64) -> Option<&Line> {
        let area = |line: &&Line| line.frame.map_or(f64::INFINITY, |frame| frame.w * frame.h);
        self.lines
            .iter()
            .filter(|line| line.covers(x, y))
            .min_by(|a, b| area(a).total_cmp(&area(b)))
    }
}

/// A window's place in an observation: its app and its window.
fn url_of(app: &str, key: WindowKey) -> String {
    format!("app:{app}#{}", key.name())
}

/// An image the session holds: its content ref, its PNG bytes, what of
/// which window it shows, and, for a screenshot, its capture.
struct Held {
    image: String,
    png: Arc<Vec<u8>>,
    frame: Frame,
    capture: Option<Capture>,
}

/// What a held image shows: a screen rectangle of `window`, as the window
/// stood at `bounds` when the screenshot was taken at `scale` screenshot
/// pixels per screen pixel. A crop or zoom shows the part it cut.
#[derive(Clone, Debug)]
struct Frame {
    left: f64,
    top: f64,
    width: f64,
    height: f64,
    window: WindowKey,
    bounds: Rect,
    scale: f64,
    /// The whole window's screenshot the image was cut from, masked as held.
    source: Arc<Vec<u8>>,
}

impl Frame {
    /// The frame of the (`x`, `y`, `width`, `height`) region of an image of
    /// `image` pixels that shows this frame.
    fn region(&self, image: (u32, u32), x: u32, y: u32, width: u32, height: u32) -> Self {
        let view = Viewport {
            left: self.left,
            top: self.top,
            width: self.width,
            height: self.height,
        }
        .region(image, x, y, width, height);
        Self {
            left: view.left,
            top: view.top,
            width: view.width,
            height: view.height,
            ..self.clone()
        }
    }
}

impl DesktopSession {
    /// An agent verb's entry: the agent has the desktop and the guest runs.
    fn live(&mut self) -> Result<(), BrowserError> {
        match self.takeover {
            Takeover::Agent => {}
            Takeover::Waiting { .. } => return Err(BrowserError::TakenOver("asked".to_owned())),
            Takeover::Held { .. } => return Err(BrowserError::TakenOver("held".to_owned())),
        }
        self.guest_up()
    }

    fn guest_up(&mut self) -> Result<(), BrowserError> {
        if self.guest.abandoned() {
            return Err(BrowserError::Abandoned);
        }
        if self.guest.is_running() {
            Ok(())
        } else {
            Err(BrowserError::GuestLost)
        }
    }

    fn tool(&self, name: &str, arguments: Value) -> Result<ToolReply, BrowserError> {
        self.mcp
            .tool(name, arguments, Instant::now() + CALL)
            .map_err(BrowserError::from)
    }

    /// One input action, delivered in the foreground: no one else sits at
    /// the guest's desktop, and its virtual display takes no background
    /// input. An action the driver refused comes back refused.
    fn input(&self, name: &str, mut arguments: Value) -> Result<(), ToolError> {
        arguments["delivery_mode"] = Value::from("foreground");
        let reply = self.mcp.tool(name, arguments, Instant::now() + CALL)?;
        if reply.output.get("effect").and_then(Value::as_str) == Some("refused") {
            let code = reply
                .output
                .pointer("/error/code")
                .and_then(Value::as_str)
                .unwrap_or("refused");
            return Err(ToolError::Refused {
                tool: name.to_owned(),
                code: code.to_owned(),
                words: String::new(),
            });
        }
        Ok(())
    }

    /// The windows on screen.
    fn listed(&self) -> Result<Vec<Listed>, BrowserError> {
        let reply = self.tool("list_windows", json!({"on_screen_only": true}))?;
        Ok(reply
            .output
            .get("windows")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|window| {
                Some(Listed {
                    key: WindowKey {
                        pid: u32::try_from(window.get("pid")?.as_u64()?).ok()?,
                        id: window.get("window_id")?.as_u64()?,
                    },
                    app: text_of(window, "app_name"),
                    title: text_of(window, "title"),
                    z: window.get("z_index").and_then(Value::as_i64),
                })
            })
            .collect())
    }
}

/// The front window among those `among` admits: the highest stacked, or
/// the last listed when the display cannot tell.
fn front(listed: &[Listed], among: impl Fn(&Listed) -> bool) -> Option<WindowKey> {
    listed
        .iter()
        .enumerate()
        .filter(|(_, window)| among(window))
        .max_by_key(|(index, window)| (window.z, *index))
        .map(|(_, window)| window.key)
}

/// What a read of a window shows, as one hash: a settled window reads the
/// same. A row showing a secret in place hashes what the window holds
/// there, never its handle, so a poll's read (which holds no secret) and
/// a held read of the same window hash alike.
fn print_of(snapshot: &Snapshot) -> Result<blake3::Hash, BrowserError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(snapshot.key.name().as_bytes());
    for line in &snapshot.lines {
        let encode =
            |row: &Row| serde_json::to_vec(row).map_err(|e| BrowserError::Protocol(e.to_string()));
        if line.masked {
            let mut row = line.row.clone();
            row.name.clear();
            row.value = None;
            row.secret = None;
            hasher.update(&encode(&row)?);
            hasher.update(line.original.as_deref().unwrap_or("").as_bytes());
        } else {
            hasher.update(&encode(&line.row)?);
        }
    }
    Ok(hasher.finalize())
}

/// The window a held answer's `url` names, for `cursor` to walk on.
fn window_of(url: &str, cursor: &str) -> Result<WindowKey, BrowserError> {
    url.rsplit_once('#')
        .and_then(|(_, key)| WindowKey::parse(key))
        .ok_or_else(|| BrowserError::Input(format!("{cursor} names no window")))
}

/// The time a walk on from `cut` asks for: four times the cut walk's, at
/// least [`WALK_MS_MOST`] and at most [`WALK_ON_MS_MOST`].
fn walk_on_ms(cut: &PartialTree) -> u64 {
    cut.walk_ms
        .saturating_mul(4)
        .clamp(WALK_MS_MOST, WALK_ON_MS_MOST)
}

/// The milliseconds left before `until`.
fn ms_left(until: Instant) -> u64 {
    u64::try_from(until.saturating_duration_since(Instant::now()).as_millis()).unwrap_or(u64::MAX)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

fn no_window() -> BrowserError {
    BrowserError::Navigation("the desktop shows no window; open an app".to_owned())
}

/// A driver refusal as the program reads it: a retired token is a stale
/// ref, and a missing option a missing option.
fn refusal(error: ToolError, target: Option<&str>) -> BrowserError {
    match (&error, target) {
        (ToolError::Refused { code, .. }, Some(target))
            if code.contains("stale") || code.contains("snapshot") =>
        {
            BrowserError::StaleRef(target.to_owned())
        }
        (ToolError::Refused { code, .. }, Some(target)) if code == "no_such_option" => {
            BrowserError::NoOption(target.to_owned())
        }
        _ => error.into(),
    }
}

/// The press of a click at screen point (`x`, `y`) whose read is still cut
/// at the walk on's longest with no row under the point (Rule 5): the
/// control there may lie past the cut, so the click takes the gate's floor,
/// a person's press for every send, as a class no grant names does. A
/// press is a gate step, not a refusal: the person presses it.
fn floor_press(x: f64, y: f64) -> BrowserError {
    BrowserError::NeedsPress(format!("the point ({x:.0}, {y:.0}) past the tree's cut"))
}

fn text_of(value: &Value, name: &str) -> String {
    value
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

/// What a window read holds its secrets through (FIX 8028): the session's
/// custody, none for a settle poll's read, which only a hash reads; the
/// fields a type entered a secret into, by locator; and the window's
/// place, as a secret found there names where it was found.
struct SecretView<'a> {
    secrets: Option<&'a Secrets>,
    typed: &'a HashMap<String, SecretKind>,
    origin: &'a str,
}

impl SecretView<'_> {
    /// What a secret field of `kind` holding `value` shows in its value's
    /// place, and its secret: a concealed or empty field holds nothing, a
    /// poll's read holds nothing, and every other value becomes a handle
    /// through the session's custody, one ask per value a read shows
    /// (`taken`).
    fn hold<'v>(
        &self,
        taken: &mut HashMap<(SecretKind, &'v str), Result<String, SecretNote>>,
        kind: SecretKind,
        value: &'v str,
    ) -> (Option<String>, RowSecret) {
        let unheld = |note| RowSecret {
            kind,
            handle: None,
            note,
        };
        if value.trim().is_empty() {
            return (None, unheld(None));
        }
        if masked(value) {
            return (
                Some(SECRET_MARK.to_owned()),
                unheld(Some(SecretNote::Concealed)),
            );
        }
        let Some(secrets) = self.secrets else {
            return (Some(SECRET_MARK.to_owned()), unheld(None));
        };
        let held = taken
            .entry((kind, value))
            .or_insert_with(|| secrets.acquire(kind, value, self.origin))
            .clone();
        let (handle, note) = match held {
            Ok(handle) => (Some(handle), None),
            Err(note) => (None, Some(note)),
        };
        let shown = secret_display_policy(kind, value, handle.as_deref());
        (Some(shown), RowSecret { kind, handle, note })
    }
}
