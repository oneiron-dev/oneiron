//! The CDP driver: one page in a browser guest, read as an outline and acted
//! on by ref. The guest runs Lightpanda or Chromium; `lightpanda` holds
//! where a Lightpanda guest is driven differently.
//!
//! Every action waits for the page to settle before it returns, on the values
//! arc-cua measured for Chromium over CDP: up to 0.6 s for the page to start
//! changing, then 0.15 s with no change, never more than 2 s in all.
//! A faster driver than the page only reads a stale page.
//!
//! The driver follows the guest's tabs for a person who holds the browser:
//! a popup or a tab a link opens is attached to as it is found, so the
//! person sees and drives it, and the tab they leave in front is the one
//! the agent's verbs read after. It follows them for the agent's own verbs
//! too: a tab the agent's act opens comes to the front and is the one the
//! act's observation reads, and a front tab that closes while the agent
//! drives it gives way to its opener. The agent's next answer names the
//! switch (`switched`).
//!
//! Every row the driver reads gets its live handle at one place
//! (`handles`); a settle poll reads the outline without minting. An act
//! resolves its target once and keeps that node from its checks to its
//! effect.
//!
//! An act whose page shows no change at all within about a second of its
//! input answers at once, unsettled, with a typed fact saying so (`change`,
//! FIX 6680); one whose page moved settles as above.
//!
//! Where the session keeps storage snapshots, the driver reads the page's
//! stores right before each act's input, with the change check's mark, and
//! once its page settled; a Chromium tab reads itself as it is left
//! (`storage`).
//!
//! A read's secret fields become run-bound handles where they are found,
//! before its rows are built (`secrets`, FIX 8028): a type or expect that
//! names a handle asks the session's custody for its bytes at the send or
//! the comparison, and a screenshot masks the same fields.

mod acts;
mod change;
mod document;
mod frames;
mod handles;
mod lightpanda;
pub(crate) mod pages;
mod person;
pub(crate) mod recorder;
mod row_metadata;
mod secrets;
pub(crate) mod state;
pub(crate) mod storage;
mod tabs;
mod verbs;

pub(crate) use crate::capture::{crop_region, encode_png, png_dimensions};

use crate::capture::{self, Capture, Captures, Viewport};
use crate::cdp::Pipe;
use crate::observation::{HandleInfo, Rebound, match_target, rows_named};
use crate::outline::{self, Line, Masks};
use crate::retention::HandleRetention;
use crate::secret::{Entry, SecretUse, Secrets, bare_handle, entry};
use crate::{
    BrowserDriver, BrowserEngine, BrowserError, BrowserPersonInput, BrowserTab, ClickInput,
    CropInput, ExpectInput, ExpectOutput, FindInput, FindOutput, ImageOutput, Observation,
    ObservationPage, ObserveInput, OpenInput, PartialTree, PointInput, Row, ScreenshotInput,
    ScreenshotOutput, SecretKind, SelectInput, StoragePhase, TabSwitch, TabSwitchCause, TypeInput,
    ViewInput, WaitForInput, WaitForOutput, ZoomInput,
};
use change::Watch;
use handles::Handles;
use pages::{Base, Observations, Read, ReadAt, find_cursor, session_token, wait_cursor};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

const REACTION: Duration = Duration::from_millis(600);
const QUIET: Duration = Duration::from_millis(150);
const SETTLE_CAP: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(50);
/// One protocol call's bound. A call past it means the guest is stuck.
const CALL: Duration = Duration::from_secs(10);
const LOAD: Duration = Duration::from_secs(10);
const WAIT_DEFAULT: Duration = Duration::from_secs(5);
/// The viewport, so a screenshot is never wider than 1,366 px.
const WIDTH: u32 = 1366;
const HEIGHT: u32 = 900;
/// Screenshots the driver holds for a later image read.
const MEDIA: usize = 16;
/// Wheel notches a person's scroll moves when it names none, and the CSS
/// pixels of one.
const SCROLL_NOTCHES: u32 = 3;
const NOTCH_PX: f64 = 100.0;
/// The cause a page read that ran out of its call's time names on the
/// partial page it answers (FIX 8367): the stable timeout code.
const READ_TIMEOUT_CAUSE: &str = "browser_timeout";
/// A loaded page's visible text, read when its tree gives no row (FIX
/// 7717): its body's rendered text, or its text where the engine renders
/// none; null for a page not loaded or with no body.
const BODY_TEXT: &str = "(() => { const d = document; const b = d.body; if (d.readyState !== 'complete' || !b) return null; return typeof b.innerText === 'string' ? b.innerText : b.textContent; })()";
/// CDP's modifier bits.
const ALT: u32 = 1;
const CTRL: u32 = 2;
const META: u32 = 4;
const SHIFT: u32 = 8;

pub(crate) struct CdpDriver {
    pipe: Pipe,
    /// The engine the guest runs the page on.
    engine: BrowserEngine,
    /// The tab in front: the one the agent's verbs and the person's screen
    /// and input drive.
    session: String,
    target: String,
    /// Every tab the driver follows, the one in front among them.
    tabs: Vec<Tab>,
    /// The guest's pages from before the driver opened its own (the
    /// browser's startup page): never followed.
    ignored: HashSet<String>,
    seq: u64,
    media: VecDeque<Held>,
    /// The session's screenshot capture ids.
    captures: Captures,
    /// The observations a later one may edit, and the paged answers.
    pages: Observations,
    /// Every live handle the session minted.
    handles: Handles,
    wait_cap: Duration,
    /// The agent's move to another tab since its last answer, for that
    /// answer to name.
    switched: Option<TabSwitch>,
    /// The tabs the agent's verbs knew at their last look: a tab found
    /// since is one opened for them, even when an owner's look attached it.
    agent_known: HashSet<String>,
    /// The session's hold on its host's secret custody (FIX 8028).
    secrets: Secrets,
    /// The fields a type entered a secret into, by DOM node, with its
    /// kind: each reads as that secret from then on.
    typed: HashMap<u64, SecretKind>,
    /// The DOM nodes the last read showed a secret in, for a screenshot
    /// to mask.
    secret_nodes: Vec<(Option<String>, u64)>,
    /// A closed tab still in front when it closed, whose snapshots go once
    /// another tab is in front (FIX 7411).
    held_closed: Vec<String>,
    /// The last act's input was sent (FIX 8010): its effect stands even
    /// when settling or reading the page after it failed.
    sent: bool,
    /// The last act's input failed after the browser was sent part of it
    /// (FIX 10426): its outcome is unknown.
    unknown: bool,
}

/// One page target the driver follows, with its session on it, and the
/// tab that opened it.
struct Tab {
    target: String,
    session: String,
    opener: Option<String>,
}

/// One key as CDP's key events name it.
struct KeySpec {
    key: String,
    code: String,
    vk: u32,
    text: Option<String>,
}

/// One act's target, resolved once: its row as read now, its DOM node on
/// its own frame session (FIX 11576), and how it rebound when the handle
/// named no longer stood.
pub(crate) struct Target {
    pub(crate) row: Row,
    node: Value,
    session: String,
    rebound: Option<Rebound>,
}

/// An image the driver holds: its content ref, its PNG bytes, what of the
/// page it shows, and, for a screenshot, its capture. The charge for the
/// bytes where they prove a past-threshold reply, given back once the
/// image ages out (FIX 11578).
struct Held {
    image: String,
    png: Vec<u8>,
    frame: Frame,
    capture: Option<Capture>,
    // Dropped for the charge it gives back; never read (FIX 11578).
    #[allow(dead_code)]
    held: Option<crate::cdp::Held>,
}

/// What a held image shows: a viewport rectangle in CSS pixels, on the page
/// at `url` scrolled to `scroll`, as it was when the screenshot was taken.
/// A crop or zoom shows the part of its source's frame it cut.
#[derive(Clone, Debug)]
struct Frame {
    left: f64,
    top: f64,
    width: f64,
    height: f64,
    scroll: (f64, f64),
    url: String,
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
            scroll: self.scroll,
            url: self.url.clone(),
        }
    }
}

impl CdpDriver {
    fn page(&self, method: &str, params: Value) -> Result<Value, BrowserError> {
        self.call_in(&self.session, method, params)
    }

    /// One call on `session` (FIX 11576), a target's own frame session
    /// where its row came from one, as `page` calls on the front tab's.
    fn call_in(&self, session: &str, method: &str, params: Value) -> Result<Value, BrowserError> {
        self.pipe
            .call(Some(session), method, params, Instant::now() + CALL)
    }

    /// The front tab's accessibility nodes as they are now. A loaded page
    /// whose tree gives no row but whose body shows text (Lightpanda's tree
    /// of a bare-text document, FIX 7717) reads as that text, each line a
    /// read-only row (`outline::text_nodes`); a page not loaded, or with no
    /// text, reads as its tree did.
    fn ax_nodes(&self) -> Result<Vec<Value>, BrowserError> {
        let mut nodes = self.page_nodes()?;
        // Its in-page frames' rows read where the page shows them (FIX 205).
        self.graft_frames(&mut nodes);
        if outline::has_rows(&nodes) {
            return Ok(nodes);
        }
        let text = self
            .page(
                "Runtime.evaluate",
                json!({"expression": BODY_TEXT, "returnByValue": true}),
            )
            .ok()
            .filter(|reply| reply.get("exceptionDetails").is_none())
            .and_then(|reply| reply.pointer("/result/value")?.as_str().map(str::to_owned))
            .filter(|text| !text.trim().is_empty());
        Ok(text.map_or(nodes, |text| outline::text_nodes(&text)))
    }

    /// The front tab's own document's accessibility nodes, its frames' not
    /// read: what a settle poll hashes.
    fn page_nodes(&self) -> Result<Vec<Value>, BrowserError> {
        let mut tree = self.page("Accessibility.getFullAXTree", json!({}))?;
        Ok(match tree.get_mut("nodes").map(Value::take) {
            Some(Value::Array(nodes)) => nodes,
            _ => Vec::new(),
        })
    }

    /// The outline as it is now, unminted: a settle poll's read, which
    /// mints no handle and holds no secret, as only its hash is read.
    fn lines(&self) -> Result<Vec<Line>, BrowserError> {
        Ok(outline::lines(&self.page_nodes()?, &Masks::default()))
    }

    /// The outline's rows, hashed for a settle poll: their href, level,
    /// datetimes and gaps stay empty until a capture fills them (FIX 6851),
    /// so a poll hashes the fields it always did.
    fn fingerprint(&self) -> Result<blake3::Hash, BrowserError> {
        let mut hasher = blake3::Hasher::new();
        for line in self.lines()? {
            let row =
                serde_json::to_vec(&line.row).map_err(|e| BrowserError::Protocol(e.to_string()))?;
            hasher.update(&row);
        }
        Ok(hasher.finalize())
    }

    /// Waits for the page to settle after an action that began at `start`.
    fn settle(&self, before: blake3::Hash, start: Instant) -> Result<(), BrowserError> {
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

    /// The engine the guest runs the page on.
    pub(crate) const fn engine(&self) -> BrowserEngine {
        self.engine
    }

    /// The page's URL as it is now.
    pub(crate) fn url(&self) -> Result<String, BrowserError> {
        Ok(self.page_info()?.0)
    }

    /// The page's URL as it is now, and its URL and title as an
    /// observation shows them (FIX 8011, 8340).
    pub(crate) fn page_shown(&self) -> Result<(String, (String, String)), BrowserError> {
        let (url, title) = self.page_info()?;
        let shown = self.shown_page(url.clone(), title);
        Ok((url, shown))
    }

    /// Whether the last act's input was sent, taken (FIX 8010).
    pub(crate) fn take_sent(&mut self) -> bool {
        std::mem::take(&mut self.sent)
    }

    /// Whether the last act's input failed after the browser was sent part
    /// of it, taken (FIX 10426).
    pub(crate) fn take_unknown(&mut self) -> bool {
        std::mem::take(&mut self.unknown)
    }

    /// The page's URL and title as they are now.
    fn page_info(&self) -> Result<(String, String), BrowserError> {
        let info = self.pipe.call(
            None,
            "Target.getTargetInfo",
            json!({"targetId": self.target}),
            Instant::now() + CALL,
        )?;
        let info = info.get("targetInfo").unwrap_or(&Value::Null);
        let field = |name| {
            info.get(name)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        };
        Ok((field("url"), field("title")))
    }

    /// The page as it is now, whole or as an edit of `base`. A read of its
    /// rows that runs out of its call's time answers the page as far as it
    /// reads (FIX 8367): its URL and title, as the browser holds them, and
    /// no rows, cut by `browser_timeout`; the guest and the session stay,
    /// and the cut's `walk_next` reads the page again.
    fn observation(&mut self, base: &Base) -> Result<Observation, BrowserError> {
        // The tab's document before the read: a recorder matches its acts
        // only against a read of their own document (FIX 9412).
        let commits = self.pipe.top_commits(&self.target);
        let capture = match self.capture() {
            Ok(capture) => capture,
            Err(BrowserError::Timeout(_) | BrowserError::CallTimeout(_)) => {
                return self.timed_out();
            }
            Err(error) => return Err(error),
        };
        let (url, title) = self.page_info()?;
        let at = ReadAt {
            tab: self.target.clone(),
            url: url.clone(),
            commits,
        };
        let (url, title) = self.shown_page(url, title);
        self.seq += 1;
        let read = Read {
            seq: self.seq,
            scope: capture.scope,
            url,
            title,
            rows: capture.rows,
            no_tree: false,
            partial: None,
            at: Some(at),
        };
        let mut observation = self.pages.observe(read, base);
        observation.dialogs = self.pipe.take_dialog_failures();
        Ok(observation)
    }

    /// `observation`, read on another guest (a proposal's fresh replay, FIX
    /// 7881), held here for its later pages under a number of this
    /// driver's, so its cursor reads on this session after that guest went.
    pub(crate) fn adopt_page(&mut self, mut observation: Observation) -> ObservationPage {
        self.seq += 1;
        observation.seq = self.seq;
        self.pages.first_adopted(observation)
    }

    /// The page whose rows did not read in their call's time, as a whole
    /// partial observation: never an edit, and never a base for one.
    fn timed_out(&mut self) -> Result<Observation, BrowserError> {
        let (url, title) = self.page_info()?;
        let (url, title) = self.shown_page(url, title);
        self.seq += 1;
        let read = Read {
            seq: self.seq,
            scope: format!("page:{}", self.target),
            url,
            title,
            rows: Vec::new(),
            no_tree: false,
            partial: Some(PartialTree {
                reason: READ_TIMEOUT_CAUSE.to_owned(),
                visited: 0,
                pending: 0,
                walk_ms: u64::try_from(CALL.as_millis()).unwrap_or(u64::MAX),
            }),
            at: None,
        };
        let mut observation = self.pages.observe(read, &Base::Whole);
        observation.dialogs = self.pipe.take_dialog_failures();
        Ok(observation)
    }

    /// The PNG bytes of a screenshot this driver took, while it holds them.
    pub(crate) fn image(&self, image: &str) -> Option<&[u8]> {
        self.media
            .iter()
            .rev()
            .find(|held| held.image == image)
            .map(|held| held.png.as_slice())
    }

    /// Holds `png`, showing `frame`, under its content ref, with its
    /// `capture` when it is a screenshot; returns ref, width, height, bytes.
    fn remember(
        &mut self,
        png: Vec<u8>,
        frame: Frame,
        capture: Option<Capture>,
    ) -> Result<(String, u32, u32, u64), BrowserError> {
        let (width, height) = png_dimensions(&png)
            .ok_or_else(|| BrowserError::Protocol("image is not a PNG".to_owned()))?;
        let image = format!("blake3:{}", blake3::hash(&png).to_hex());
        let bytes = png.len() as u64;
        let held = self.pipe.charge_media(png.len());
        self.media.push_back(Held {
            image: image.clone(),
            png,
            frame,
            capture,
            held,
        });
        if self.media.len() > MEDIA {
            self.media.pop_front();
        }
        Ok((image, width, height, bytes))
    }

    /// The newest held copy of `image`: a repeat screenshot holds the same
    /// ref again, and its own frame is the one the page stands at now.
    fn held(&self, image: &str) -> Result<(Vec<u8>, Frame), BrowserError> {
        self.media
            .iter()
            .rev()
            .find(|held| held.image == image)
            .map(|held| (held.png.clone(), held.frame.clone()))
            .ok_or_else(|| BrowserError::NoImage(image.to_owned()))
    }

    /// The held screenshot capture `id` names, with its content ref.
    fn held_capture(&self, id: &str) -> Option<(String, Capture)> {
        self.media.iter().find_map(|held| {
            let capture = held.capture.as_ref().filter(|capture| capture.id == id)?;
            Some((held.image.clone(), capture.clone()))
        })
    }

    /// The page's scroll offset as it is now, in CSS pixels.
    fn scroll_offset(&self) -> Result<(f64, f64), BrowserError> {
        let scroll = self.page(
            "Runtime.evaluate",
            json!({"expression": "[scrollX, scrollY]", "returnByValue": true}),
        )?;
        let at = |axis: usize| {
            scroll
                .pointer("/result/value")
                .and_then(|value| value.get(axis))
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
        };
        Ok((at(0), at(1)))
    }

    fn call_on(&self, node: &Value, function: &str, args: Value) -> Result<Value, BrowserError> {
        self.call_on_in(&self.session, node, function, args)
    }

    /// `node`'s `function` on `session` (FIX 11576), as `call_on` calls it
    /// on the front tab's session.
    fn call_on_in(
        &self,
        session: &str,
        node: &Value,
        function: &str,
        args: Value,
    ) -> Result<Value, BrowserError> {
        let result = self.call_in(
            session,
            "Runtime.callFunctionOn",
            json!({"objectId": node["objectId"], "functionDeclaration": function, "arguments": args, "returnByValue": true}),
        )?;
        if let Some(error) = result.get("exceptionDetails") {
            return Err(BrowserError::Protocol(self.thrown_text(error)));
        }
        Ok(result
            .pointer("/result/value")
            .cloned()
            .unwrap_or(Value::Null))
    }

    /// What a script the driver ran threw, as an error names it: the page
    /// controls that text, so each secret the run's reads took shows its
    /// handle there, as in a title or a URL (FIX 11581).
    fn thrown_text(&self, error: &Value) -> String {
        let text = error
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or("script error");
        self.secrets
            .mask_known(text)
            .unwrap_or_else(|| text.to_owned())
    }

    /// Waits until the front tab's document has loaded, up to `deadline`:
    /// whether it did.
    fn loaded(&self, deadline: Instant) -> Result<bool, BrowserError> {
        loop {
            let state = self.page(
                "Runtime.evaluate",
                json!({"expression": "document.readyState", "returnByValue": true}),
            )?;
            if state.pointer("/result/value").and_then(Value::as_str) == Some("complete") {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(POLL);
        }
    }

    fn matching(&mut self, keep: impl Fn(&Row) -> bool) -> Result<Vec<Row>, BrowserError> {
        Ok(self.capture()?.rows.into_iter().filter(keep).collect())
    }

    fn key_event(&self, kind: &str, key: &KeySpec, modifiers: u32) -> Result<(), BrowserError> {
        let mut event = json!({
            "type": kind,
            "key": key.key,
            "code": key.code,
            "windowsVirtualKeyCode": key.vk,
            "modifiers": modifiers,
        });
        if kind == "keyDown"
            && let Some(text) = &key.text
        {
            event["text"] = Value::from(text.as_str());
            event["unmodifiedText"] = Value::from(text.as_str());
        }
        self.page("Input.dispatchKeyEvent", event).map(drop)
    }
}

/// A point of the person's screen, which shows the viewport at one pixel
/// per CSS pixel.
fn viewport_point(x: u32, y: u32) -> Result<(f64, f64), BrowserError> {
    if x >= WIDTH || y >= HEIGHT {
        return Err(BrowserError::Input(format!(
            "({x}, {y}) is off the {WIDTH} by {HEIGHT} screen"
        )));
    }
    Ok((f64::from(x), f64::from(y)))
}

/// A named key, or one character, as CDP's key events take it.
fn key_of(name: &str) -> Result<KeySpec, BrowserError> {
    let named = |key: &str, vk: u32| KeySpec {
        key: key.to_owned(),
        code: key.to_owned(),
        vk,
        text: None,
    };
    let mut chars = name.chars();
    if let (Some(ch), None) = (chars.next(), chars.next()) {
        let upper = ch.to_ascii_uppercase();
        let (code, vk) = if ch.is_ascii_alphabetic() {
            (format!("Key{upper}"), u32::from(upper))
        } else if ch.is_ascii_digit() {
            (format!("Digit{ch}"), u32::from(ch))
        } else if ch == ' ' {
            ("Space".to_owned(), 32)
        } else {
            (String::new(), 0)
        };
        return Ok(KeySpec {
            key: ch.to_string(),
            code,
            vk,
            text: Some(ch.to_string()),
        });
    }
    let lower = name.to_ascii_lowercase();
    if let Some(n) = lower
        .strip_prefix('f')
        .and_then(|n| n.parse::<u32>().ok())
        .filter(|n| (1..=12).contains(n))
    {
        return Ok(named(&format!("F{n}"), 111 + n));
    }
    Ok(match lower.as_str() {
        "enter" | "return" => KeySpec {
            text: Some("\r".to_owned()),
            ..named("Enter", 13)
        },
        "tab" => named("Tab", 9),
        "escape" | "esc" => named("Escape", 27),
        "backspace" => named("Backspace", 8),
        "delete" => named("Delete", 46),
        "space" => KeySpec {
            key: " ".to_owned(),
            code: "Space".to_owned(),
            vk: 32,
            text: Some(" ".to_owned()),
        },
        "up" | "arrowup" => named("ArrowUp", 38),
        "down" | "arrowdown" => named("ArrowDown", 40),
        "left" | "arrowleft" => named("ArrowLeft", 37),
        "right" | "arrowright" => named("ArrowRight", 39),
        "home" => named("Home", 36),
        "end" => named("End", 35),
        "pageup" => named("PageUp", 33),
        "pagedown" => named("PageDown", 34),
        _ => {
            return Err(BrowserError::Input(format!(
                "{name} is no key the browser takes"
            )));
        }
    })
}

/// A hotkey modifier: its CDP bit and its own key.
fn modifier_of(name: &str) -> Result<(u32, KeySpec), BrowserError> {
    let (bit, key, code, vk) = match name.to_ascii_lowercase().as_str() {
        "ctrl" | "control" => (CTRL, "Control", "ControlLeft", 17),
        "alt" | "option" => (ALT, "Alt", "AltLeft", 18),
        "meta" | "cmd" | "command" | "super" => (META, "Meta", "MetaLeft", 91),
        "shift" => (SHIFT, "Shift", "ShiftLeft", 16),
        _ => {
            return Err(BrowserError::Input(format!(
                "{name} is no modifier: ctrl, alt, shift or meta"
            )));
        }
    };
    Ok((
        bit,
        KeySpec {
            key: key.to_owned(),
            code: code.to_owned(),
            vk,
            text: None,
        },
    ))
}

/// The guest's page targets as they are now, as CDP lists them.
fn page_targets(pipe: &Pipe) -> Result<Vec<Value>, BrowserError> {
    let listed = pipe.call(None, "Target.getTargets", json!({}), Instant::now() + CALL)?;
    Ok(listed
        .get("targetInfos")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|info| info.get("type").and_then(Value::as_str) == Some("page"))
        .cloned()
        .collect())
}

fn target_id(info: &Value) -> String {
    info.get("targetId")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

/// Attaches a session to page `target` and readies it as every tab the
/// driver drives: its outline and DOM read, its viewport the driver's, and
/// on `engine` Chromium its stores read as each document is left.
fn attach_tab(pipe: &Pipe, target: &str, engine: BrowserEngine) -> Result<String, BrowserError> {
    let deadline = Instant::now() + CALL;
    let attached = pipe.call(
        None,
        "Target.attachToTarget",
        json!({"targetId": target, "flatten": true}),
        deadline,
    )?;
    let session = str_field(&attached, "sessionId")?;
    for (method, params) in [
        ("Accessibility.enable", json!({})),
        ("DOM.enable", json!({})),
        (
            "Emulation.setDeviceMetricsOverride",
            json!({"width": WIDTH, "height": HEIGHT, "deviceScaleFactor": 1, "mobile": false}),
        ),
    ] {
        pipe.call(Some(&session), method, params, Instant::now() + CALL)?;
    }
    // The change check counts the tab's navigation events; a tab whose Page
    // events never started is driven as before, and proves no act inert.
    let by = Instant::now() + CALL;
    let enabled = pipe.call(Some(&session), "Page.enable", json!({}), by);
    if enabled.is_ok() {
        pipe.watch_navigations(&session, target);
        storage::hook_exits(pipe, &session, engine);
        // A tab found while a demonstration records is recorded too.
        pipe.record_on(&session, target, target, Instant::now() + CALL);
    }
    Ok(session)
}

fn str_field(value: &Value, name: &str) -> Result<String, BrowserError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| BrowserError::Protocol(format!("reply without {name}")))
}
