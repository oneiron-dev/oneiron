//! A desktop session (OF-523): one Linux desktop in an isolated guest,
//! driven through cua-driver's MCP server on the guest's stdio, with the
//! host's rules in front of it.
//!
//! The desktop runs only inside the guest (an X display, its accessibility
//! bus, a window manager and a fixed app set), never on the host, so no call
//! reaches the owner's own desktop. The session reads one window at a time
//! as rows from its accessibility tree. A row's ref is built from its role,
//! its name and its named ancestors, as a page's is, so a ref read once
//! still names the element after the window changes around it; the driver's
//! element tokens, which each newer read retires, never leave the session.
//! A window an action opens in front (a dialog, a document) is where the
//! next step reads.
//!
//! Effects follow the browser's rules. A control whose name marks an effect
//! class takes that class's press from the vault's grant, and a Return, or
//! text with a line break, takes the press of a send. Every effect lands a
//! receipt naming its window, with a screenshot of the window as evidence,
//! its password fields blacked out before the image is held. No other
//! screenshot is taken without a named trigger. A window with no tree says
//! so (`no_tree`), and the program reads it by its pixels.

use crate::driver::{crop_region, encode_png, png_dimensions};
use crate::mcp::{Mcp, ToolError, ToolReply};
use crate::session::{effect_class, press_for, receipt_class};
use crate::{
    BatchInput, BatchOutput, BrowserDriver, BrowserError, ClickInput, CropInput, DesktopWindow,
    EFFECT_SEND, EffectReceipt, ExpectInput, ExpectOutput, FindInput, FindOutput, HotkeyInput,
    ImageOutput, KeyInput, NoDecider, Observation, ObserveInput, OpenInput, PointInput, PressMode,
    ReceiptEvidenceSink, RoutineDecider, Row, ScreenshotInput, ScreenshotOutput, ScreenshotTrigger,
    ScrollInput, SelectInput, SendPolicy, TypeInput, ViewInput, WaitForInput, WaitForOutput,
    WindowInput, WindowsInput, WindowsOutput, ZoomInput,
};
use oneiron_container::{GuestLimits, SessionLease, SessionManifest, SessionTransport};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

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
/// Elements one read of a window asks the driver for (its default is 250).
const MAX_ELEMENTS: u32 = 1000;
/// Observations a `since` diff can name.
const HISTORY: usize = 8;
/// Screenshots the session holds for a later image read.
const MEDIA: usize = 16;
/// The longest name or value a row carries.
const NAME_CHARS: usize = 200;
/// A zoom without a scale fills this width, at most fourfold.
const ZOOM_WIDTH: u32 = 1366;

/// The guest's accessible role names (AT-SPI's), as a page's rows name them.
const ROLES: &[(&str, &str)] = &[
    ("push button", "button"),
    ("toggle button", "button"),
    ("check box", "checkbox"),
    ("radio button", "radio"),
    ("combo box", "combobox"),
    ("spin button", "spinbutton"),
    ("entry", "textbox"),
    ("text", "textbox"),
    ("password text", "textbox"),
    ("editbar", "textbox"),
    ("search box", "searchbox"),
    ("menu item", "menuitem"),
    ("check menu item", "menuitemcheckbox"),
    ("radio menu item", "menuitemradio"),
    ("tear off menu item", "menuitem"),
    ("list item", "option"),
    ("list box", "listbox"),
    ("list", "listbox"),
    ("popup menu", "menu"),
    ("menu bar", "menubar"),
    ("tool bar", "toolbar"),
    ("page tab", "tab"),
    ("page tab list", "tablist"),
    ("tree item", "treeitem"),
    ("tree table", "treegrid"),
    ("table cell", "cell"),
    ("table row", "row"),
    ("status bar", "status"),
];

/// Roles a program reads but does not act on, when they carry a name.
const READS: &[&str] = &[
    "heading",
    "label",
    "static",
    "alert",
    "notification",
    "status",
    "image",
];

/// Roles whose name, when they have one, joins the ref of every row inside.
/// A window's own frame is not one: its title changes as its document does.
const SCOPES: &[&str] = &[
    "dialog",
    "alert",
    "panel",
    "filler",
    "group",
    "grouping",
    "form",
    "section",
    "listbox",
    "table",
    "tree",
    "treegrid",
    "menu",
    "menubar",
    "toolbar",
    "tablist",
    "tab",
    "scroll pane",
    "layered pane",
];

/// Words that mark a text field secret beside a password role.
const SECRET_PHRASES: &[&[&str]] = &[
    &["password"],
    &["passcode"],
    &["passphrase"],
    &["pin"],
    &["card", "number"],
    &["cvv"],
    &["cvc"],
    &["security", "code"],
    &["one", "time"],
    &["otp"],
    &["verification", "code"],
];

/// How the host starts desktop guests. Its bounds are the host's manifest rows.
#[derive(Clone, Debug)]
pub struct DesktopGuest {
    pub runtime: PathBuf,
    pub image: String,
    pub limits: GuestLimits,
    /// The longest `wait_for` one call holds the run for.
    pub wait_cap: Duration,
    /// The press each effect class runs under, from the vault's grants.
    pub policy: SendPolicy,
}

pub struct DesktopSession {
    mcp: Mcp,
    guest: Box<dyn SessionLease>,
    manifest: SessionManifest,
    policy: SendPolicy,
    receipts: Vec<EffectReceipt>,
    receipt_seq: u64,
    decider: Option<Box<dyn RoutineDecider>>,
    receipt_sink: Option<Box<dyn ReceiptEvidenceSink>>,
    /// The window the session reads and acts on.
    window: Option<WindowKey>,
    seq: u64,
    history: VecDeque<(u64, WindowKey, HashMap<String, Row>)>,
    media: VecDeque<Held>,
    wait_cap: Duration,
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
/// element is on screen.
#[derive(Clone)]
struct Line {
    row: Row,
    token: Option<String>,
    frame: Option<Rect>,
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
            .filter(|line| line.frame.is_some_and(|frame| frame.contains(x, y)))
            .min_by(|a, b| area(a).total_cmp(&area(b)))
    }
}

/// A window's place in an observation: its app and its window.
fn url_of(app: &str, key: WindowKey) -> String {
    format!("app:{app}#{}", key.name())
}

/// An image the session holds: its content ref, its PNG bytes and what of
/// which window it shows.
struct Held {
    image: String,
    png: Vec<u8>,
    frame: Frame,
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
}

impl Frame {
    /// The frame of the (`x`, `y`, `width`, `height`) region of an image of
    /// `image` pixels that shows this frame.
    fn region(&self, image: (u32, u32), x: u32, y: u32, width: u32, height: u32) -> Self {
        let across = self.width / f64::from(image.0.max(1));
        let down = self.height / f64::from(image.1.max(1));
        Self {
            left: self.left + f64::from(x) * across,
            top: self.top + f64::from(y) * down,
            width: f64::from(width) * across,
            height: f64::from(height) * down,
            ..self.clone()
        }
    }
}

impl DesktopSession {
    /// The engine selects and proves a backend before attaching the
    /// desktop, as it does for a browser.
    pub fn attach(
        config: &DesktopGuest,
        transport: SessionTransport,
    ) -> Result<Self, BrowserError> {
        if transport.manifest.fence_unproven || transport.manifest.fence_proof.is_none() {
            return Err(BrowserError::Unavailable(
                "desktop session fence unproven".to_owned(),
            ));
        }
        let SessionTransport {
            reader,
            writer,
            manifest,
            lease,
        } = transport;
        // The guest's display and accessibility bus come up before its
        // driver answers.
        let mcp = Mcp::attach(reader, writer, Instant::now() + LAUNCH)?;
        Ok(Self {
            mcp,
            guest: lease,
            manifest,
            policy: config.policy.clone(),
            receipts: Vec::new(),
            receipt_seq: 0,
            decider: None,
            receipt_sink: None,
            window: None,
            seq: 0,
            history: VecDeque::new(),
            media: VecDeque::new(),
            wait_cap: config.wait_cap,
        })
    }

    /// Gives the session's batches the host's routine decider.
    pub fn set_decider(&mut self, decider: Box<dyn RoutineDecider>) {
        self.decider = Some(decider);
    }

    /// Gives the session the host's keeper of receipt screenshots.
    pub fn set_receipt_sink(&mut self, sink: Box<dyn ReceiptEvidenceSink>) {
        self.receipt_sink = Some(sink);
    }

    /// What the guest's container proved, for the run's receipt.
    #[must_use]
    pub fn manifest(&self) -> &SessionManifest {
        &self.manifest
    }

    /// The PNG bytes of a screenshot this session took, while it holds them.
    #[must_use]
    pub fn image(&self, image: &str) -> Option<&[u8]> {
        self.media
            .iter()
            .find(|held| held.image == image)
            .map(|held| held.png.as_slice())
    }

    /// Every effect this session receipted, in order.
    #[must_use]
    pub fn receipts(&self) -> &[EffectReceipt] {
        &self.receipts
    }

    #[must_use]
    pub fn abandoned(&self) -> bool {
        self.guest.abandoned()
    }

    fn live(&mut self) -> Result<(), BrowserError> {
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

    /// The window the session reads, or else the one in front.
    fn window_key(&mut self) -> Result<WindowKey, BrowserError> {
        if let Some(key) = self.window {
            return Ok(key);
        }
        let key = front(&self.listed()?, |_| true).ok_or_else(no_window)?;
        self.window = Some(key);
        Ok(key)
    }

    /// Reads the session's window: its rows, and its screenshot with
    /// `shot`. A window gone since (a dialog closed) gives way to the window
    /// in front now.
    fn snapshot(&mut self, shot: bool) -> Result<Snapshot, BrowserError> {
        let key = self.window_key()?;
        match self.read(key, shot) {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => {
                let listed = self.listed()?;
                if listed.iter().any(|window| window.key == key) {
                    return Err(error);
                }
                let front = front(&listed, |_| true).ok_or_else(no_window)?;
                self.window = Some(front);
                self.read(front, shot)
            }
        }
    }

    fn read(&self, key: WindowKey, shot: bool) -> Result<Snapshot, BrowserError> {
        let mut arguments = json!({
            "pid": key.pid,
            "window_id": key.id,
            "tree_format": "elements",
            "max_elements": MAX_ELEMENTS,
        });
        if !shot {
            arguments["include_screenshot"] = Value::Bool(false);
        }
        let reply = self.tool("get_window_state", arguments)?;
        let state = &reply.output;
        let elements = state
            .get("elements")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        let (lines, secrets) = lines(elements);
        let shot = if shot {
            let png = reply.images.into_iter().next().ok_or_else(|| {
                BrowserError::Protocol("get_window_state sent no screenshot".to_owned())
            })?;
            // The driver names the ratio only when it shrank the image.
            let scale = state
                .get("frame_scale")
                .and_then(Value::as_f64)
                .filter(|scale| scale.is_finite() && *scale > 0.0)
                .unwrap_or(1.0);
            Some((png, scale))
        } else {
            None
        };
        Ok(Snapshot {
            key,
            app: text_of(state, "app_name"),
            title: text_of(state, "window_title"),
            bounds: state
                .get("window_bounds")
                .and_then(|bounds| Rect::read(bounds, "width", "height")),
            no_tree: lines.is_empty()
                || state.get("degraded").and_then(Value::as_bool) == Some(true),
            lines,
            secrets,
            shot,
        })
    }

    fn fingerprint(&mut self) -> Result<blake3::Hash, BrowserError> {
        print_of(&self.snapshot(false)?)
    }

    /// Waits for the window to settle after an action that began at `start`.
    fn settle(&mut self, before: blake3::Hash, start: Instant) -> Result<(), BrowserError> {
        let mut last = before;
        let mut changed_at = None;
        loop {
            std::thread::sleep(POLL);
            let now = Instant::now();
            let print = self.fingerprint()?;
            if print != last {
                last = print;
                changed_at = Some(now);
            }
            let done = match changed_at {
                None => now - start >= REACTION,
                Some(at) => now - at >= QUIET,
            };
            if done || now - start >= SETTLE_CAP {
                return Ok(());
            }
        }
    }

    fn observation(&mut self, since: Option<u64>) -> Result<Observation, BrowserError> {
        let snapshot = self.snapshot(false)?;
        let rows: Vec<Row> = snapshot.lines.into_iter().map(|line| line.row).collect();
        self.seq += 1;
        let current: HashMap<String, Row> = rows
            .iter()
            .map(|row| (row.target.clone(), row.clone()))
            .collect();
        // A diff only against an observation of the same window.
        let before = since
            .and_then(|since| {
                self.history
                    .iter()
                    .find(|(seq, key, _)| *seq == since && *key == snapshot.key)
            })
            .map(|(_, _, rows)| rows);
        let (full, shown, removed) = match before {
            None => (true, rows, Vec::new()),
            Some(before) => {
                let shown = rows
                    .into_iter()
                    .filter(|row| before.get(&row.target) != Some(row))
                    .collect();
                let removed = before
                    .keys()
                    .filter(|r| !current.contains_key(*r))
                    .cloned()
                    .collect();
                (false, shown, removed)
            }
        };
        self.history.push_back((self.seq, snapshot.key, current));
        if self.history.len() > HISTORY {
            self.history.pop_front();
        }
        Ok(Observation {
            seq: self.seq,
            url: url_of(&snapshot.app, snapshot.key),
            title: snapshot.title,
            full,
            rows: shown,
            removed,
            receipt: None,
            library: Vec::new(),
            no_tree: snapshot.no_tree,
        })
    }

    /// Runs `act` on the desktop as `read` saw it, then returns the settled
    /// window as a diff, or whole when the act opened a window in front:
    /// that window is where the next step reads. No read comes between
    /// `read` and the act, since each read retires the last one's tokens.
    fn act(
        &mut self,
        read: &Snapshot,
        act: impl FnOnce(&Self) -> Result<(), BrowserError>,
    ) -> Result<Observation, BrowserError> {
        let since = self.seq;
        let windows: Vec<WindowKey> = self.listed()?.into_iter().map(|w| w.key).collect();
        let before = print_of(read)?;
        let start = Instant::now();
        act(self)?;
        self.settle(before, start)?;
        if let Some(opened) = front(&self.listed()?, |window| !windows.contains(&window.key)) {
            self.window = Some(opened);
            let before = self.fingerprint()?;
            self.settle(before, Instant::now())?;
        }
        self.observation(Some(since))
    }

    fn press(&mut self, class: Option<&str>, row: &Row) -> Result<PressMode, BrowserError> {
        match class {
            Some(class) => press_for(&mut self.policy, class, row),
            None => Ok(PressMode::None),
        }
    }

    /// Stamps `observation` with the receipt of the effect that made it.
    /// The receipt's screenshot is best-effort: an effect that already
    /// happened is receipted even when its evidence could not be captured.
    fn receipt(
        &mut self,
        verb: &str,
        target: Option<&Row>,
        effect_class: Option<&str>,
        press: PressMode,
        observation: &mut Observation,
    ) {
        self.receipt_seq += 1;
        let screenshot = self
            .screenshot(ScreenshotInput {
                trigger: ScreenshotTrigger::EffectReceipt,
            })
            .ok()
            .map(|shot| shot.image);
        let mut receipt = EffectReceipt {
            seq: self.receipt_seq,
            verb: verb.to_owned(),
            url: observation.url.clone(),
            title: observation.title.clone(),
            target: target.map(|row| row.target.clone()),
            target_name: target.map(|row| row.name.clone()),
            effect_class: effect_class.map(str::to_owned),
            press: press.as_str().to_owned(),
            screenshot,
            screenshot_evidence: None,
        };
        // The pixels are kept before the receipt is stored, while the
        // session still holds them.
        if let Some(mut sink) = self.receipt_sink.take() {
            if let Some(png) = receipt
                .screenshot
                .as_deref()
                .and_then(|image| self.image(image))
            {
                receipt.screenshot_evidence = Some(sink.keep(&receipt, png));
            }
            self.receipt_sink = Some(sink);
        }
        self.receipts.push(receipt.clone());
        observation.receipt = Some(receipt);
    }

    /// Holds `png`, showing `frame`, under its content ref; returns ref,
    /// width, height, bytes.
    fn remember(
        &mut self,
        png: Vec<u8>,
        frame: Frame,
    ) -> Result<(String, u32, u32, u64), BrowserError> {
        let (width, height) = png_dimensions(&png)
            .ok_or_else(|| BrowserError::Protocol("image is not a PNG".to_owned()))?;
        let image = format!("blake3:{}", blake3::hash(&png).to_hex());
        let bytes = png.len() as u64;
        self.media.push_back(Held {
            image: image.clone(),
            png,
            frame,
        });
        if self.media.len() > MEDIA {
            self.media.pop_front();
        }
        Ok((image, width, height, bytes))
    }

    fn held(&self, image: &str) -> Result<(Vec<u8>, Frame), BrowserError> {
        self.media
            .iter()
            .find(|held| held.image == image)
            .map(|held| (held.png.clone(), held.frame.clone()))
            .ok_or_else(|| BrowserError::NoImage(image.to_owned()))
    }

    fn matching(&mut self, find: &FindInput) -> Result<Vec<Row>, BrowserError> {
        Ok(self
            .snapshot(false)?
            .lines
            .into_iter()
            .map(|line| line.row)
            .filter(|row| find.matches(row))
            .collect())
    }

    /// The element token of the row `target` names, as read now.
    fn token(snapshot: &Snapshot, target: &str) -> Result<(Line, String), BrowserError> {
        let line = snapshot.line(target)?;
        let token = line
            .token
            .clone()
            .ok_or_else(|| BrowserError::Covered(target.to_owned()))?;
        Ok((line, token))
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

/// What a read of a window shows, as one hash: a settled window reads the same.
fn print_of(snapshot: &Snapshot) -> Result<blake3::Hash, BrowserError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(snapshot.key.name().as_bytes());
    for line in &snapshot.lines {
        let row =
            serde_json::to_vec(&line.row).map_err(|e| BrowserError::Protocol(e.to_string()))?;
        hasher.update(&row);
    }
    Ok(hasher.finalize())
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

/// Whether `key` (`"Return"`, `"ctrl+enter"`) presses Return.
fn is_return(key: &str) -> bool {
    let key = key.rsplit('+').next().unwrap_or(key).trim();
    ["return", "enter", "kp_enter"]
        .iter()
        .any(|name| key.eq_ignore_ascii_case(name))
}

/// A key press as the press refusal names it, when no row takes it.
fn key_row(key: &str) -> Row {
    Row {
        target: String::new(),
        role: "key".to_owned(),
        name: key.to_owned(),
        value: None,
        states: Vec::new(),
        depth: 0,
    }
}

fn text_of(value: &Value, name: &str) -> String {
    value
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn frame_of(element: &Value, name: &str) -> Option<Rect> {
    element
        .get(name)
        .and_then(|frame| Rect::read(frame, "w", "h"))
}

fn clip(text: &str) -> String {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    match text.char_indices().nth(NAME_CHARS) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text,
    }
}

/// Whether `name` holds the words of `phrase` in a row, ignoring case.
fn has_phrase(name: &str, phrase: &[&str]) -> bool {
    let words: Vec<String> = name
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect();
    words
        .windows(phrase.len())
        .any(|w| w.iter().zip(phrase).all(|(a, b)| a == b))
}

/// Reads a window's elements (in tree order, each with its depth) into
/// rows: every element the driver can act on, and every named one a
/// program reads outside a control. Also where its secret fields are.
fn lines(elements: &[Value]) -> (Vec<Line>, Vec<Secret>) {
    let mut scope: Vec<(u64, String)> = Vec::new();
    let mut controls: Vec<u64> = Vec::new();
    let mut seen: HashMap<String, u32> = HashMap::new();
    let mut out = Vec::new();
    let mut secrets = Vec::new();
    for element in elements {
        let depth = element.get("depth").and_then(Value::as_u64).unwrap_or(0);
        while scope.last().is_some_and(|(at, _)| *at >= depth) {
            scope.pop();
        }
        while controls.last().is_some_and(|at| *at >= depth) {
            controls.pop();
        }
        let raw = element
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_lowercase();
        let role = ROLES
            .iter()
            .find(|(from, _)| *from == raw)
            .map_or_else(|| raw.clone(), |(_, to)| (*to).to_owned());
        let label = element
            .get("label")
            .and_then(Value::as_str)
            .map(clip)
            .unwrap_or_default();
        let password = raw.contains("password");
        let secret =
            password || (role == "textbox" && SECRET_PHRASES.iter().any(|p| has_phrase(&label, p)));
        if secret {
            secrets.push(Secret {
                screen: frame_of(element, "frame"),
                shot: frame_of(element, "screenshot_frame"),
            });
        }
        // A password field's own text can stand in for a missing name: it
        // never leaves the session.
        let name = if password { String::new() } else { label };
        let token = element
            .get("element_token")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let read = READS.contains(&role.as_str()) && !name.is_empty() && controls.is_empty();
        if token.is_some() || read {
            let mut key = scope
                .iter()
                .map(|(_, named)| named.as_str())
                .collect::<Vec<_>>()
                .join(" > ");
            key.push_str(&format!(" > {role} \"{name}\""));
            // Identical twins are told apart by their order among themselves.
            let twin = seen.entry(key.clone()).or_insert(0);
            *twin += 1;
            if *twin > 1 {
                key.push_str(&format!(" ~{twin}"));
            }
            let hash = blake3::hash(key.as_bytes()).to_hex();
            let mut states = Vec::new();
            if element.get("enabled").and_then(Value::as_bool) == Some(false) {
                states.push("disabled".to_owned());
            }
            if element.get("selected").and_then(Value::as_bool) == Some(true) {
                states.push("selected".to_owned());
            }
            if secret {
                states.push("secret".to_owned());
            }
            let value = if secret {
                None
            } else {
                element
                    .get("value")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(clip)
            };
            out.push(Line {
                row: Row {
                    target: format!("d{}", &hash[..12]),
                    role: role.clone(),
                    name: name.clone(),
                    value,
                    states,
                    depth: u16::try_from(scope.len()).unwrap_or(u16::MAX),
                },
                frame: frame_of(element, "frame"),
                token,
            });
            if out.last().is_some_and(|line: &Line| line.token.is_some()) {
                controls.push(depth);
            }
        }
        if SCOPES.contains(&role.as_str()) && !name.is_empty() {
            scope.push((depth, format!("{role} \"{name}\"")));
        }
    }
    (out, secrets)
}

/// Blacks out a window's secret fields in its screenshot, before the image
/// is held. A secret field the screenshot cannot place refuses the image.
fn mask(
    png: Vec<u8>,
    bounds: Rect,
    scale: f64,
    secrets: &[Secret],
) -> Result<Vec<u8>, BrowserError> {
    if secrets.is_empty() {
        return Ok(png);
    }
    let mut image = image::load_from_memory(&png)
        .map_err(|e| BrowserError::Protocol(e.to_string()))?
        .to_rgba8();
    let (width, height) = image.dimensions();
    for secret in secrets {
        let rect = secret
            .shot
            .or_else(|| {
                secret.screen.map(|frame| Rect {
                    x: (frame.x - bounds.x) * scale,
                    y: (frame.y - bounds.y) * scale,
                    w: frame.w * scale,
                    h: frame.h * scale,
                })
            })
            .ok_or_else(|| {
                BrowserError::Protocol("a secret field has no place to mask".to_owned())
            })?;
        let span = |from: f64, to: f64, end: u32| {
            let end = f64::from(end);
            (
                from.floor().clamp(0.0, end) as u32,
                to.ceil().clamp(0.0, end) as u32,
            )
        };
        let (x0, x1) = span(rect.x, rect.x + rect.w, width);
        let (y0, y1) = span(rect.y, rect.y + rect.h, height);
        for y in y0..y1 {
            for x in x0..x1 {
                image.put_pixel(x, y, image::Rgba([0, 0, 0, 255]));
            }
        }
    }
    encode_png(&image::DynamicImage::ImageRgba8(image))
}

impl BrowserDriver for DesktopSession {
    /// Opens an app of the guest's set, `app:<name>`, and reads its window.
    fn open(&mut self, input: OpenInput) -> Result<Observation, BrowserError> {
        self.live()?;
        let app = input
            .url
            .strip_prefix("app:")
            .map(str::trim)
            .filter(|app| {
                !app.is_empty()
                    && app.len() <= 64
                    && app
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c))
            })
            .map(str::to_owned);
        let Some(app) = app else {
            return Err(BrowserError::Url(input.url));
        };
        let windows: Vec<WindowKey> = self.listed()?.into_iter().map(|w| w.key).collect();
        let launched = self
            .mcp
            .tool("launch_app", json!({"name": app}), Instant::now() + LAUNCH)
            .map_err(BrowserError::from)?;
        let pid = launched.output.get("pid").and_then(Value::as_u64);
        let owned = |window: &Listed| pid.is_some_and(|pid| u64::from(window.key.pid) == pid);
        // Its new window, or a running app's own window once none opens.
        let deadline = Instant::now() + LAUNCH;
        let key = loop {
            let listed = self.listed()?;
            let opened = front(&listed, |w| !windows.contains(&w.key) && owned(w))
                .or_else(|| front(&listed, |w| !windows.contains(&w.key)));
            if let Some(key) = opened {
                break key;
            }
            if Instant::now() >= deadline {
                break front(&listed, owned)
                    .ok_or_else(|| BrowserError::Timeout(format!("{app} to show a window")))?;
            }
            std::thread::sleep(POLL);
        };
        self.window = Some(key);
        let before = self.fingerprint()?;
        self.settle(before, Instant::now())?;
        let mut observation = self.observation(None)?;
        self.receipt("open", None, None, PressMode::None, &mut observation);
        Ok(observation)
    }

    fn observe(&mut self, input: ObserveInput) -> Result<Observation, BrowserError> {
        self.live()?;
        self.observation(input.since)
    }

    fn find(&mut self, input: FindInput) -> Result<FindOutput, BrowserError> {
        self.live()?;
        Ok(FindOutput {
            rows: self.matching(&input)?,
        })
    }

    fn click(&mut self, input: ClickInput) -> Result<Observation, BrowserError> {
        self.live()?;
        let snapshot = self.snapshot(false)?;
        let (line, token) = Self::token(&snapshot, &input.target)?;
        let class = effect_class(&line.row.name);
        let press = self.press(class, &line.row)?;
        let pid = snapshot.key.pid;
        let mut observation = self.act(&snapshot, |session| {
            session
                .input("click", json!({"pid": pid, "element_token": token}))
                .map_err(|e| refusal(e, Some(input.target.as_str())))
        })?;
        let class = receipt_class(class, Some(&line.row));
        self.receipt("click", Some(&line.row), class, press, &mut observation);
        Ok(observation)
    }

    fn click_at(&mut self, input: PointInput) -> Result<Observation, BrowserError> {
        self.live()?;
        let (_, frame) = self.held(&input.image)?;
        if !(0.0..=1.0).contains(&input.x) || !(0.0..=1.0).contains(&input.y) {
            return Err(BrowserError::Input(
                "a point is two fractions of its image, each from 0 to 1".to_owned(),
            ));
        }
        // The image must still show the window as it stands: the same
        // window, in the same place.
        let snapshot = self.snapshot(false)?;
        if snapshot.key != frame.window
            || !snapshot
                .bounds
                .is_some_and(|bounds| bounds.same(frame.bounds))
        {
            return Err(BrowserError::StaleImage(input.image));
        }
        let x = frame.left + input.x * frame.width;
        let y = frame.top + input.y * frame.height;
        let row = snapshot.line_at(x, y).map(|line| line.row.clone());
        let class = row.as_ref().and_then(|row| effect_class(&row.name));
        let press = match (class, &row) {
            (Some(class), Some(row)) => press_for(&mut self.policy, class, row)?,
            _ => PressMode::None,
        };
        // The driver's window pixels are its screenshot's, from the
        // window's corner.
        let bounds = frame.bounds;
        let across =
            ((x - bounds.x) * frame.scale).clamp(0.0, (bounds.w * frame.scale - 1.0).max(0.0));
        let down =
            ((y - bounds.y) * frame.scale).clamp(0.0, (bounds.h * frame.scale - 1.0).max(0.0));
        let key = snapshot.key;
        let mut observation = self.act(&snapshot, |session| {
            session
                .input(
                    "click",
                    json!({"pid": key.pid, "window_id": key.id, "x": across.round(), "y": down.round()}),
                )
                .map_err(BrowserError::from)
        })?;
        let class = receipt_class(class, row.as_ref());
        self.receipt("click_at", row.as_ref(), class, press, &mut observation);
        Ok(observation)
    }

    fn type_text(&mut self, input: TypeInput) -> Result<Observation, BrowserError> {
        self.live()?;
        let snapshot = self.snapshot(false)?;
        let (line, token) = Self::token(&snapshot, &input.target)?;
        // A line break can press Return, and a Return sends.
        let class = input
            .text
            .contains(|c: char| c == '\n' || c == '\r')
            .then_some(EFFECT_SEND);
        let press = self.press(class, &line.row)?;
        let pid = snapshot.key.pid;
        let mut observation = self.act(&snapshot, |session| {
            let refused = |error: ToolError| refusal(error, Some(input.target.as_str()));
            if input.clear {
                for (key, modifiers) in [("a", vec!["ctrl"]), ("backspace", Vec::new())] {
                    session
                        .input(
                            "press_key",
                            json!({"pid": pid, "element_token": token, "key": key, "modifiers": modifiers}),
                        )
                        .map_err(refused)?;
                }
            }
            if !input.text.is_empty() {
                session
                    .input(
                        "type_text",
                        json!({"pid": pid, "element_token": token, "text": input.text}),
                    )
                    .map_err(refused)?;
            }
            Ok(())
        })?;
        self.receipt("type", Some(&line.row), class, press, &mut observation);
        Ok(observation)
    }

    fn select(&mut self, input: SelectInput) -> Result<Observation, BrowserError> {
        self.live()?;
        let snapshot = self.snapshot(false)?;
        let (line, token) = Self::token(&snapshot, &input.target)?;
        let pid = snapshot.key.pid;
        let mut observation = self.act(&snapshot, |session| {
            session
                .input(
                    "set_value",
                    json!({"pid": pid, "element_token": token, "value": input.option}),
                )
                .map_err(|e| refusal(e, Some(input.target.as_str())))
        })?;
        self.receipt(
            "select",
            Some(&line.row),
            None,
            PressMode::None,
            &mut observation,
        );
        Ok(observation)
    }

    fn wait_for(&mut self, input: WaitForInput) -> Result<WaitForOutput, BrowserError> {
        self.live()?;
        let wanted = input
            .timeout_ms
            .map_or(WAIT_DEFAULT, |ms| Duration::from_millis(ms.into()));
        let bound = wanted.min(self.wait_cap);
        let query = input.query();
        let start = Instant::now();
        loop {
            let rows = self.matching(&query)?;
            let waited = start.elapsed();
            if !rows.is_empty() || waited >= bound {
                let timed_out = rows.is_empty();
                return Ok(WaitForOutput {
                    rows,
                    timed_out,
                    waited_ms: u64::try_from(waited.as_millis()).unwrap_or(u64::MAX),
                });
            }
            std::thread::sleep(POLL * 2);
        }
    }

    fn expect(&mut self, input: ExpectInput) -> Result<ExpectOutput, BrowserError> {
        self.live()?;
        let rows = self.snapshot(false)?.lines.into_iter().map(|line| line.row);
        let query = input.query();
        let row = match &input.target {
            Some(target) => rows.into_iter().find(|row| &row.target == target),
            None => rows.into_iter().find(|row| query.matches(row)),
        };
        let met = match (&row, input.absent) {
            (None, absent) => absent,
            (Some(_), true) => false,
            (Some(row), false) => input
                .value
                .as_ref()
                .is_none_or(|want| row.value.as_ref() == Some(want)),
        };
        Ok(ExpectOutput { met, row })
    }

    fn screenshot(&mut self, input: ScreenshotInput) -> Result<ScreenshotOutput, BrowserError> {
        self.live()?;
        let Snapshot {
            key,
            app,
            title,
            bounds,
            secrets,
            shot,
            ..
        } = self.snapshot(true)?;
        let (png, scale) = shot.ok_or_else(|| {
            BrowserError::Protocol("get_window_state sent no screenshot".to_owned())
        })?;
        let bounds = bounds
            .ok_or_else(|| BrowserError::Protocol("the window's place is unknown".to_owned()))?;
        let png = mask(png, bounds, scale, &secrets)?;
        let frame = Frame {
            left: bounds.x,
            top: bounds.y,
            width: bounds.w,
            height: bounds.h,
            window: key,
            bounds,
            scale,
        };
        let (image, width, height, bytes) = self.remember(png, frame)?;
        Ok(ScreenshotOutput {
            image,
            media_type: "image/png".to_owned(),
            width,
            height,
            bytes,
            trigger: input.trigger,
            url: url_of(&app, key),
            title,
        })
    }

    fn view(&mut self, input: ViewInput) -> Result<ImageOutput, BrowserError> {
        let (png, _) = self.held(&input.image)?;
        let (width, height) = png_dimensions(&png)
            .ok_or_else(|| BrowserError::Protocol("held image is not a PNG".to_owned()))?;
        Ok(ImageOutput {
            image: input.image.clone(),
            media_type: "image/png".to_owned(),
            width,
            height,
            bytes: png.len() as u64,
            source: input.image,
        })
    }

    fn crop(&mut self, input: CropInput) -> Result<ImageOutput, BrowserError> {
        let source = input.image.clone();
        let (png, frame) = self.held(&input.image)?;
        let region = crop_region(&png, input.x, input.y, input.width, input.height)?;
        let frame = frame.region(
            png_dimensions(&png).unwrap_or_default(),
            input.x,
            input.y,
            input.width,
            input.height,
        );
        let (image, width, height, bytes) = self.remember(encode_png(&region)?, frame)?;
        Ok(ImageOutput {
            image,
            media_type: "image/png".to_owned(),
            width,
            height,
            bytes,
            source,
        })
    }

    fn zoom(&mut self, input: ZoomInput) -> Result<ImageOutput, BrowserError> {
        let source = input.image.clone();
        let (png, frame) = self.held(&input.image)?;
        let region = crop_region(&png, input.x, input.y, input.width, input.height)?;
        let frame = frame.region(
            png_dimensions(&png).unwrap_or_default(),
            input.x,
            input.y,
            input.width,
            input.height,
        );
        let scale = input.scale.unwrap_or_else(|| {
            (f64::from(ZOOM_WIDTH) / f64::from(input.width.max(1))).min(4.0) as f32
        });
        if !scale.is_finite() || !(0.1..=8.0).contains(&scale) {
            return Err(BrowserError::Input(format!(
                "zoom scale {scale} is outside 0.1 to 8"
            )));
        }
        let width = ((input.width as f32 * scale).round() as u32).clamp(1, 4096);
        let height = ((input.height as f32 * scale).round() as u32).clamp(1, 4096);
        let zoomed = region.resize_exact(width, height, image::imageops::FilterType::Lanczos3);
        let (image, width, height, bytes) = self.remember(encode_png(&zoomed)?, frame)?;
        Ok(ImageOutput {
            image,
            media_type: "image/png".to_owned(),
            width,
            height,
            bytes,
            source,
        })
    }

    fn image_bytes(&self, image: &str) -> Option<Vec<u8>> {
        self.image(image).map(<[u8]>::to_vec)
    }

    fn press_key(&mut self, input: KeyInput) -> Result<Observation, BrowserError> {
        self.live()?;
        let snapshot = self.snapshot(false)?;
        let aimed = input
            .target
            .as_deref()
            .map(|target| Self::token(&snapshot, target))
            .transpose()?;
        let class = is_return(&input.key).then_some(EFFECT_SEND);
        let row = aimed
            .as_ref()
            .map_or_else(|| key_row(&input.key), |(line, _)| line.row.clone());
        let press = self.press(class, &row)?;
        let key = snapshot.key;
        let mut arguments = json!({"pid": key.pid, "key": input.key, "modifiers": input.modifiers});
        match &aimed {
            Some((_, token)) => arguments["element_token"] = Value::from(token.as_str()),
            None => arguments["window_id"] = Value::from(key.id),
        }
        let mut observation = self.act(&snapshot, |session| {
            session
                .input("press_key", arguments)
                .map_err(|e| refusal(e, input.target.as_deref()))
        })?;
        let target = aimed.as_ref().map(|(line, _)| &line.row);
        self.receipt("key", target, class, press, &mut observation);
        Ok(observation)
    }

    fn hotkey(&mut self, input: HotkeyInput) -> Result<Observation, BrowserError> {
        self.live()?;
        if input.keys.len() < 2 {
            return Err(BrowserError::Input(
                "a hotkey holds two keys or more".to_owned(),
            ));
        }
        let snapshot = self.snapshot(false)?;
        let key = snapshot.key;
        let class = input
            .keys
            .iter()
            .any(|k| is_return(k))
            .then_some(EFFECT_SEND);
        let press = self.press(class, &key_row(&input.keys.join("+")))?;
        let mut observation = self.act(&snapshot, |session| {
            session
                .input(
                    "hotkey",
                    json!({"pid": key.pid, "window_id": key.id, "keys": input.keys}),
                )
                .map_err(BrowserError::from)
        })?;
        self.receipt("hotkey", None, class, press, &mut observation);
        Ok(observation)
    }

    /// A scroll moves the view, not the world: it lands no receipt.
    fn scroll(&mut self, input: ScrollInput) -> Result<Observation, BrowserError> {
        self.live()?;
        let snapshot = self.snapshot(false)?;
        let mut arguments = json!({
            "pid": snapshot.key.pid,
            "direction": input.direction.as_str(),
            "amount": input.amount.unwrap_or(1).clamp(1, 50),
        });
        match &input.target {
            Some(target) => {
                let (_, token) = Self::token(&snapshot, target)?;
                arguments["element_token"] = Value::from(token);
            }
            None => arguments["window_id"] = Value::from(snapshot.key.id),
        }
        self.act(&snapshot, |session| {
            session
                .input("scroll", arguments)
                .map_err(|e| refusal(e, input.target.as_deref()))
        })
    }

    fn windows(&mut self, input: WindowsInput) -> Result<WindowsOutput, BrowserError> {
        self.live()?;
        let listed = self.listed()?;
        let in_front = front(&listed, |_| true);
        let current = self.window;
        Ok(WindowsOutput {
            windows: listed
                .into_iter()
                .filter(|window| {
                    input
                        .app
                        .as_ref()
                        .is_none_or(|app| window.app.eq_ignore_ascii_case(app))
                })
                .map(|window| DesktopWindow {
                    window: window.key.name(),
                    current: current == Some(window.key),
                    front: in_front == Some(window.key),
                    app: window.app,
                    title: window.title,
                })
                .collect(),
        })
    }

    fn window(&mut self, input: WindowInput) -> Result<Observation, BrowserError> {
        self.live()?;
        let key = WindowKey::parse(&input.window)
            .ok_or_else(|| BrowserError::Input(format!("{} names no window", input.window)))?;
        if !self.listed()?.iter().any(|window| window.key == key) {
            return Err(BrowserError::StaleRef(input.window));
        }
        self.window = Some(key);
        self.observation(None)
    }

    fn batch(&mut self, input: BatchInput) -> Result<BatchOutput, BrowserError> {
        let mut decider = self.decider.take();
        let output = match decider.as_deref_mut() {
            Some(decider) => self.batch_with(input, decider),
            None => self.batch_with(input, &mut NoDecider),
        };
        self.decider = decider;
        output
    }
}
