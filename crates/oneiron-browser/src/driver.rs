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

mod change;
mod document;
mod handles;
mod lightpanda;
pub(crate) mod pages;
mod row_metadata;
mod secrets;
pub(crate) mod state;
pub(crate) mod storage;

use crate::capture::{self, Capture, Captures};
use crate::cdp::Pipe;
use crate::observation::{HandleInfo, Rebound, match_target, rows_named};
use crate::outline::{self, Line, Masks};
use crate::retention::HandleRetention;
use crate::secret::{Entry, Secrets, bare_handle, entry};
use crate::{
    BrowserDriver, BrowserEngine, BrowserError, BrowserPersonInput, BrowserTab, ClickInput,
    CropInput, ExpectInput, ExpectOutput, FindInput, FindOutput, ImageOutput, Observation,
    ObservationPage, ObserveInput, OpenInput, PointInput, Row, ScreenshotInput, ScreenshotOutput,
    SecretKind, SelectInput, StoragePhase, TabSwitch, TabSwitchCause, TypeInput, ViewInput,
    WaitForInput, WaitForOutput, ZoomInput,
};
use base64::Engine as _;
use change::Watch;
use handles::Handles;
use pages::{Base, Observations, Read, find_cursor, session_token, wait_cursor};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Cursor;
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
    secret_nodes: Vec<u64>,
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

/// One act's target, resolved once: its row as read now, its DOM node, and
/// how it rebound when the handle named no longer stood.
pub(crate) struct Target {
    pub(crate) row: Row,
    node: Value,
    rebound: Option<Rebound>,
}

/// An image the driver holds: its content ref, its PNG bytes, what of the
/// page it shows, and, for a screenshot, its capture.
struct Held {
    image: String,
    png: Vec<u8>,
    frame: Frame,
    capture: Option<Capture>,
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
        let across = self.width / f64::from(image.0.max(1));
        let down = self.height / f64::from(image.1.max(1));
        Self {
            left: self.left + f64::from(x) * across,
            top: self.top + f64::from(y) * down,
            width: f64::from(width) * across,
            height: f64::from(height) * down,
            scroll: self.scroll,
            url: self.url.clone(),
        }
    }
}

impl CdpDriver {
    /// Opens one blank page in the guest, which runs it on `engine`, and
    /// attaches to it. With the host's proxy, every page the guest opens
    /// after it (a popup, a tab a link opens) reaches the network only
    /// through the proxy, as it does. The live-handle registry is charged
    /// through `retention`; the secrets its reads find are held through
    /// the session's `secrets`.
    pub(crate) fn attach(
        pipe: Pipe,
        engine: BrowserEngine,
        wait_cap: Duration,
        retention: Box<dyn HandleRetention>,
        secrets: Secrets,
    ) -> Result<Self, BrowserError> {
        let ignored = page_targets(&pipe)?
            .iter()
            .map(target_id)
            .filter(|id| !id.is_empty())
            .collect();
        let created = pipe.call(
            None,
            "Target.createTarget",
            json!({"url": "about:blank"}),
            Instant::now() + CALL,
        )?;
        let target = str_field(&created, "targetId")?;
        let session = attach_tab(&pipe, &target, engine)?;
        let token = session_token();
        let driver = Self {
            pipe,
            engine,
            session: session.clone(),
            target: target.clone(),
            tabs: vec![Tab {
                target: target.clone(),
                session,
                opener: None,
            }],
            ignored,
            seq: 0,
            media: VecDeque::new(),
            captures: Captures::new(&token),
            pages: Observations::default(),
            handles: Handles::new(token, retention),
            wait_cap,
            switched: None,
            agent_known: HashSet::from([target.clone()]),
            secrets,
            typed: HashMap::new(),
            secret_nodes: Vec::new(),
        };
        if driver.pipe.mediated() {
            let deadline = Instant::now() + CALL;
            driver.pipe.claim_network(&target);
            crate::cdp::enable_network(&driver.pipe, &driver.session, deadline)?;
            if driver.follows_pages() {
                crate::cdp::follow_pages(&driver.pipe, deadline)?;
            }
        }
        Ok(driver)
    }

    /// The tabs as they are now, each tab or popup opened since followed
    /// and each closed one dropped. With `front_new`, a tab found opened
    /// comes to the front, as a browser shows a popup; a front tab that
    /// closed gives way to the tab that opened it, else the newest left,
    /// and with none left a blank one opens.
    pub(crate) fn tabs(&mut self, front_new: bool) -> Result<Vec<BrowserTab>, BrowserError> {
        let pages = page_targets(&self.pipe)?;
        let open: HashSet<String> = pages.iter().map(target_id).collect();
        let front_opener = self
            .tabs
            .iter()
            .find(|tab| tab.target == self.target)
            .and_then(|tab| tab.opener.clone());
        // A closed tab's page drops what the pipe kept of it (FIX 6767), and
        // its snapshots once another tab is in front (FIX 6891).
        let pipe = &self.pipe;
        let mut closed = Vec::new();
        self.tabs.retain(|tab| {
            let kept = open.contains(&tab.target);
            if !kept {
                pipe.forget_page(&tab.session);
                closed.push(tab.target.clone());
            }
            kept
        });
        let mut opened = None;
        for info in &pages {
            let id = target_id(info);
            if id.is_empty()
                || self.ignored.contains(&id)
                || self.tabs.iter().any(|tab| tab.target == id)
            {
                continue;
            }
            self.chromium_only("a second tab")?;
            let session = attach_tab(&self.pipe, &id, self.engine)?;
            let opener = info
                .get("openerId")
                .and_then(Value::as_str)
                .map(str::to_owned);
            self.tabs.push(Tab {
                target: id.clone(),
                session,
                opener,
            });
            opened = Some(id);
        }
        let front_gone = !self.tabs.iter().any(|tab| tab.target == self.target);
        let next = match opened {
            Some(id) if front_new => Some(id),
            _ if front_gone => front_opener
                .filter(|opener| self.tabs.iter().any(|tab| &tab.target == opener))
                .or_else(|| self.tabs.last().map(|tab| tab.target.clone())),
            _ => None,
        };
        match next {
            Some(id) => self.bring_to_front(&id)?,
            None if self.tabs.is_empty() => self.open_tab()?,
            None => {}
        }
        self.drop_closed(&closed);
        Ok(self
            .tabs
            .iter()
            .map(|tab| {
                let info = pages.iter().find(|info| target_id(info) == tab.target);
                let field = |name: &str| {
                    info.and_then(|info| info.get(name))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned()
                };
                BrowserTab {
                    tab: tab.target.clone(),
                    url: field("url"),
                    title: field("title"),
                    front: tab.target == self.target,
                }
            })
            .collect())
    }

    /// Follows the tabs for the agent's verbs (CUA-001): a front tab that
    /// closed gives way, as [`Self::tabs`] has it, and the newest tab opened
    /// since the agent's last look comes to the front, as a browser shows a
    /// popup. A move to another tab is kept for the agent's next answer;
    /// moves before that answer join into one, from the tab the agent drove
    /// last it was told. Answers why the front moved, if it did.
    pub(crate) fn follow(&mut self) -> Result<Option<TabSwitchCause>, BrowserError> {
        let from = self.target.clone();
        let tabs = self.tabs(false)?;
        let opened = tabs
            .iter()
            .rev()
            .find(|tab| !self.agent_known.contains(&tab.tab))
            .map(|tab| tab.tab.clone());
        self.agent_known = tabs.iter().map(|tab| tab.tab.clone()).collect();
        if let Some(opened) = &opened {
            self.bring_to_front(opened)?;
        }
        if self.target == from {
            return Ok(None);
        }
        let why = if tabs.iter().any(|tab| tab.tab == from) {
            TabSwitchCause::Opened
        } else {
            TabSwitchCause::Closed
        };
        let (url, title) = tabs
            .into_iter()
            .find(|tab| tab.tab == self.target)
            .map_or_else(
                || (String::new(), String::new()),
                |tab| (tab.url, tab.title),
            );
        let from = self.switched.take().map_or(from, |earlier| earlier.from);
        if from != self.target {
            self.switched = Some(TabSwitch {
                tab: self.target.clone(),
                url,
                title,
                from,
                why,
            });
        }
        Ok(Some(why))
    }

    /// The agent's move to another tab since its last answer, once.
    pub(crate) fn take_switched(&mut self) -> Option<TabSwitch> {
        self.switched.take()
    }

    /// The agent takes the tabs as they stand, as a person hands the
    /// browser back: none of them counts as opened for its next verb.
    pub(crate) fn know_tabs(&mut self) {
        self.agent_known = self.tabs.iter().map(|tab| tab.target.clone()).collect();
        self.switched = None;
    }

    /// Brings followed tab `target` to the front.
    pub(crate) fn bring_to_front(&mut self, target: &str) -> Result<(), BrowserError> {
        let session = self
            .tabs
            .iter()
            .find(|tab| tab.target == target)
            .map(|tab| tab.session.clone())
            .ok_or_else(|| BrowserError::Input(format!("{target} is no tab of this browser")))?;
        self.pipe.call(
            None,
            "Target.activateTarget",
            json!({"targetId": target}),
            Instant::now() + CALL,
        )?;
        if self.target != target {
            self.target = target.to_owned();
            self.session = session;
            // The observations held were of the other tab.
            self.forget_observations();
        }
        Ok(())
    }

    /// Opens a blank tab in front, once every tab closed.
    fn open_tab(&mut self) -> Result<(), BrowserError> {
        self.chromium_only("a new tab once every tab closed")?;
        let created = self.pipe.call(
            None,
            "Target.createTarget",
            json!({"url": "about:blank"}),
            Instant::now() + CALL,
        )?;
        let target = str_field(&created, "targetId")?;
        let session = attach_tab(&self.pipe, &target, self.engine)?;
        self.tabs.push(Tab {
            target: target.clone(),
            session,
            opener: None,
        });
        self.bring_to_front(&target)
    }

    fn page(&self, method: &str, params: Value) -> Result<Value, BrowserError> {
        self.pipe
            .call(Some(&self.session), method, params, Instant::now() + CALL)
    }

    /// The front tab's accessibility nodes as they are now.
    fn ax_nodes(&self) -> Result<Vec<Value>, BrowserError> {
        let mut tree = self.page("Accessibility.getFullAXTree", json!({}))?;
        Ok(match tree.get_mut("nodes").map(Value::take) {
            Some(Value::Array(nodes)) => nodes,
            _ => Vec::new(),
        })
    }

    /// The outline as it is now, unminted: a settle poll's read, which
    /// mints no handle and holds no secret, as only its hash is read.
    fn lines(&self) -> Result<Vec<Line>, BrowserError> {
        Ok(outline::lines(&self.ax_nodes()?, &Masks::default()))
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

    /// The page as it is now, whole or as an edit of `base`.
    fn observation(&mut self, base: &Base) -> Result<Observation, BrowserError> {
        let capture = self.capture()?;
        let (url, title) = self.page_info()?;
        self.seq += 1;
        let read = Read {
            seq: self.seq,
            scope: capture.scope,
            url,
            title,
            rows: capture.rows,
            no_tree: false,
            partial: None,
        };
        Ok(self.pages.observe(read, base))
    }

    /// The row `target` names on the page as it is now, and its DOM node,
    /// for one act to classify, press, act on and receipt. A live handle
    /// takes its own node while its document holds it and it is still
    /// connected; once the node is gone, the first row its locator names now
    /// (`rebound`). A locator takes the first row carrying it. An unknown
    /// handle, or no row, is a stale ref.
    pub(crate) fn resolve_target(&mut self, target: &str) -> Result<Target, BrowserError> {
        let stale = || BrowserError::StaleRef(target.to_owned());
        let capture = self.capture()?;
        let known = self.handles.info(target);
        let (at, rebound) = match_target(target, &capture.rows, &capture.scope, known.as_ref())
            .ok_or_else(stale)?;
        let node = capture.nodes[at].ok_or_else(stale)?;
        let resolved = self.page("DOM.resolveNode", json!({"backendNodeId": node}))?;
        let object = resolved
            .pointer("/object/objectId")
            .cloned()
            .ok_or_else(stale)?;
        let node = json!({"backendNodeId": node, "objectId": object});
        // Read in its document now, and still in it when resolved.
        let connected =
            self.call_on(&node, "function() { return this.isConnected; }", json!([]))?;
        if connected != Value::Bool(true) {
            return Err(stale());
        }
        Ok(Target {
            row: capture.rows[at].clone(),
            node,
            rebound,
        })
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
        self.media.push_back(Held {
            image: image.clone(),
            png,
            frame,
            capture,
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

    /// The viewport point, in CSS pixels, at fractions `x`, `y` of a held
    /// image, while the page still shows what the image does: the same URL,
    /// scrolled the same.
    pub(crate) fn point(&self, input: &PointInput) -> Result<(f64, f64), BrowserError> {
        let (_, frame) = self.held(&input.image)?;
        if !(0.0..=1.0).contains(&input.x) || !(0.0..=1.0).contains(&input.y) {
            return Err(BrowserError::Input(
                "a point is two fractions of its image, each from 0 to 1".to_owned(),
            ));
        }
        let scroll = self.scroll_offset()?;
        let (url, _) = self.page_info()?;
        if url != frame.url
            || (scroll.0 - frame.scroll.0).abs() >= 1.0
            || (scroll.1 - frame.scroll.1).abs() >= 1.0
        {
            return Err(BrowserError::StaleImage(input.image.clone()));
        }
        let x = frame.left + input.x * frame.width;
        let y = frame.top + input.y * frame.height;
        Ok((
            x.clamp(0.0, f64::from(WIDTH) - 1.0),
            y.clamp(0.0, f64::from(HEIGHT) - 1.0),
        ))
    }

    /// The outline row at viewport point (`x`, `y`): the row read from the
    /// element there, or from its nearest ancestor that makes one. None when
    /// no row covers the point.
    pub(crate) fn row_at(&mut self, x: f64, y: f64) -> Result<Option<Row>, BrowserError> {
        self.chromium_only("click_at")?;
        let hit = self.page(
            "DOM.getNodeForLocation",
            json!({"x": x.round() as i64, "y": y.round() as i64, "ignorePointerEventsNone": true}),
        )?;
        let Some(hit) = hit.get("backendNodeId").and_then(Value::as_u64) else {
            return Ok(None);
        };
        // The rows come minted, as every read's do.
        let capture = self.capture()?;
        let nodes = capture.ax.as_slice();
        let by_id: HashMap<&str, &Value> = nodes
            .iter()
            .filter_map(|node| Some((node.get("nodeId")?.as_str()?, node)))
            .collect();
        let backend = |node: &Value| node.get("backendDOMNodeId").and_then(Value::as_u64);
        let mut node = nodes.iter().find(|node| backend(*node) == Some(hit));
        // An ancestor walk, bounded as the outline's depth is not.
        for _ in 0..256 {
            let Some(current) = node else {
                break;
            };
            if let Some(at) = backend(current)
                && let Some(row) = capture.nodes.iter().position(|read| *read == Some(at))
            {
                return Ok(Some(capture.rows[row].clone()));
            }
            node = current
                .get("parentId")
                .and_then(Value::as_str)
                .and_then(|id| by_id.get(id).copied());
        }
        Ok(None)
    }

    /// A left click at viewport point (`x`, `y`).
    fn mouse_click(&self, x: f64, y: f64) -> Result<(), BrowserError> {
        for kind in ["mouseMoved", "mousePressed", "mouseReleased"] {
            self.page(
                "Input.dispatchMouseEvent",
                json!({"type": kind, "x": x, "y": y, "button": "left", "clickCount": 1}),
            )?;
        }
        Ok(())
    }

    /// Clicks at viewport point (`x`, `y`), where `row` is when one covers
    /// it, then returns the settled page, as an edit of `base`.
    pub(crate) fn click_point(
        &mut self,
        x: f64,
        y: f64,
        row: Option<&Row>,
        base: &Base,
    ) -> Result<Observation, BrowserError> {
        let watch = Watch::Click(change::point_target(x, y, row));
        self.act(base, &watch, |_| Ok(()), |driver| driver.mouse_click(x, y))
    }

    /// Clicks resolved `target`, then returns the settled page, as an edit
    /// of `base`, naming the target's rebound. The click lands at the centre
    /// of the target's box, and only when the target, not a cover, is there.
    pub(crate) fn click_target(
        &mut self,
        target: &Target,
        base: &Base,
    ) -> Result<Observation, BrowserError> {
        let node = &target.node;
        let covered = || BrowserError::Covered(target.row.target.clone());
        self.page(
            "DOM.scrollIntoViewIfNeeded",
            json!({"backendNodeId": node["backendNodeId"]}),
        )?;
        let model = self.page(
            "DOM.getBoxModel",
            json!({"backendNodeId": node["backendNodeId"]}),
        )?;
        let quad: Vec<f64> = model
            .pointer("/model/content")
            .and_then(Value::as_array)
            .map(|q| q.iter().filter_map(Value::as_f64).collect())
            .unwrap_or_default();
        if quad.len() != 8 {
            return Err(covered());
        }
        let x = (quad[0] + quad[2] + quad[4] + quad[6]) / 4.0;
        let y = (quad[1] + quad[3] + quad[5] + quad[7]) / 4.0;
        // The point must land on the element or inside it, not on a cover.
        let hit = self.call_on(
            node,
            "function(x, y) { const e = document.elementFromPoint(x, y); return !!e && (e === this || this.contains(e)); }",
            json!([{"value": x}, {"value": y}]),
        )?;
        if hit != Value::Bool(true) {
            return Err(covered());
        }
        let watch = Watch::Click(change::row_target(&target.row));
        let mut observation =
            self.act(base, &watch, |_| Ok(()), |driver| driver.mouse_click(x, y))?;
        observation.rebound.clone_from(&target.rebound);
        Ok(observation)
    }

    /// Types `entry` into resolved `target` (replacing its text with
    /// `clear`), then returns the settled page, as `click_target` does. A
    /// secret's bytes come from the session's custody at the send itself;
    /// the field reads as that secret from then on.
    pub(crate) fn type_target(
        &mut self,
        target: &Target,
        entry: Entry<'_>,
        clear: bool,
        base: &Base,
    ) -> Result<Observation, BrowserError> {
        let node = &target.node;
        if let Entry::Secret(handle) = entry
            && let Some(backend) = node["backendNodeId"].as_u64()
        {
            let kind = self.secrets.kind_of(bare_handle(handle));
            self.typed
                .insert(backend, kind.unwrap_or(SecretKind::Password));
        }
        let watch = Watch::Entry(change::row_target(&target.row), node);
        let mut observation = self.act(
            base,
            &watch,
            |driver| {
                driver.page("DOM.focus", json!({"backendNodeId": node["backendNodeId"]}))?;
                if clear {
                    driver.call_on(
                        node,
                        "function() { if (typeof this.select === 'function') this.select(); else getSelection().selectAllChildren(this); }",
                        json!([]),
                    )?;
                }
                Ok(())
            },
            |driver| match entry {
                Entry::Text(text) => driver
                    .page("Input.insertText", json!({"text": text}))
                    .map(drop),
                Entry::Secret(handle) => driver.secrets.with_value(handle, &mut |text: &str| {
                    driver
                        .page("Input.insertText", json!({"text": text}))
                        .map(drop)
                }),
            },
        )?;
        observation.rebound.clone_from(&target.rebound);
        Ok(observation)
    }

    /// Picks `option` of resolved `target`, a `<select>`, by its label,
    /// text or value, then returns the settled page, as `click_target` does.
    pub(crate) fn select_target(
        &mut self,
        target: &Target,
        option: &str,
        base: &Base,
    ) -> Result<Observation, BrowserError> {
        let node = &target.node;
        let watch = Watch::Entry(change::row_target(&target.row), node);
        let mut observation = self.act(base, &watch, |_| Ok(()), |driver| {
            let picked = driver.call_on(
                node,
                "function(want) {
                    if (this.tagName !== 'SELECT') return false;
                    const o = [...this.options].find(o => o.label === want || o.text.trim() === want || o.value === want);
                    if (!o) return false;
                    this.value = o.value;
                    this.dispatchEvent(new Event('input', {bubbles: true}));
                    this.dispatchEvent(new Event('change', {bubbles: true}));
                    return true;
                }",
                json!([{"value": option}]),
            )?;
            if picked == Value::Bool(true) {
                Ok(())
            } else {
                Err(BrowserError::NoOption(target.row.target.clone()))
            }
        })?;
        observation.rebound.clone_from(&target.rebound);
        Ok(observation)
    }

    fn call_on(&self, node: &Value, function: &str, args: Value) -> Result<Value, BrowserError> {
        let result = self.page(
            "Runtime.callFunctionOn",
            json!({"objectId": node["objectId"], "functionDeclaration": function, "arguments": args, "returnByValue": true}),
        )?;
        if let Some(error) = result.get("exceptionDetails") {
            return Err(BrowserError::Protocol(
                error
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or("script error")
                    .to_owned(),
            ));
        }
        Ok(result
            .pointer("/result/value")
            .cloned()
            .unwrap_or(Value::Null))
    }

    /// Runs `setup`, then `act`, the input, on the page, then returns the
    /// settled page as an edit of `base`. A tab the act opened comes to the
    /// front and is read whole once it loads, as is the tab a front tab the
    /// act closed gave way to; the agent's next answer names the switch. A
    /// page `watch` proves unchanged answers at once, with its fact.
    fn act(
        &mut self,
        base: &Base,
        watch: &Watch<'_>,
        setup: impl FnOnce(&Self) -> Result<(), BrowserError>,
        act: impl FnOnce(&Self) -> Result<(), BrowserError>,
    ) -> Result<Observation, BrowserError> {
        let before = self.fingerprint()?;
        let start = Instant::now();
        // An act that closed its own tab can fail or stop settling as the
        // tab goes; the tab it gave way to is then the act's result.
        let set = setup(self);
        let mark = if set.is_ok() { self.mark(watch) } else { None };
        let acted = set.and_then(|()| act(self));
        let fact = match (&acted, mark) {
            (Ok(()), Some(mark)) => self.no_effect(&mark, watch, Instant::now()),
            _ => None,
        };
        let settled = match &acted {
            Ok(()) if fact.is_none() => self.settle(before, start),
            _ => Ok(()),
        };
        // A look at the tabs that fails leaves the front where it was: the
        // act's effect stands either way, and its receipt with it. A tab a
        // Lightpanda guest cannot follow is the act's answer only once the
        // page it acted on no longer reads.
        let (moved, refused) = self.follow_or_refusal();
        match moved {
            None => {
                acted?;
                settled?;
            }
            Some(TabSwitchCause::Opened) => acted?,
            Some(TabSwitchCause::Closed) => {}
        }
        if moved.is_some() {
            // The tab now in front settles before it is read; one still
            // loading once its time is up reads as it stands.
            let _ = self.loaded(Instant::now() + LOAD);
            if let Ok(before) = self.fingerprint() {
                let _ = self.settle(before, Instant::now());
            }
        }
        self.checkpoint(StoragePhase::PostAct);
        let mut observation = self
            .observation(base)
            .map_err(|error| refused.unwrap_or(error))?;
        // A tab the act opened or closed is an effect: no fact stands.
        observation.fact = fact.filter(|_| moved.is_none());
        Ok(observation)
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

    /// Forgets every observation, so the next one is whole: a person drove
    /// the page meanwhile. The live handles stay: none is ever reused.
    pub(crate) fn forget_observations(&mut self) {
        self.pages.clear();
    }

    /// The front tab's viewport as a PNG for the person who holds the
    /// browser: unmasked, never held among the driver's images and never a
    /// receipt.
    pub(crate) fn person_screen(&self) -> Result<Vec<u8>, BrowserError> {
        let shot = self.page("Page.captureScreenshot", json!({"format": "png"}))?;
        let data = shot.get("data").and_then(Value::as_str).unwrap_or("");
        base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|e| BrowserError::Protocol(e.to_string()))
    }

    /// One input from the person who holds the browser, at viewport pixels:
    /// sent as it is, with no settle, no observation and no receipt.
    pub(crate) fn person_input(&self, input: BrowserPersonInput) -> Result<(), BrowserError> {
        match input {
            BrowserPersonInput::Click {
                x,
                y,
                button,
                count,
            } => self.person_click(viewport_point(x, y)?, button.as_deref(), count),
            BrowserPersonInput::Type { text } => self
                .page("Input.insertText", json!({"text": text}))
                .map(drop),
            BrowserPersonInput::Key { key } => self.key_press(&key_of(&key)?, 0),
            BrowserPersonInput::Hotkey { keys } => self.person_hotkey(&keys),
            BrowserPersonInput::Scroll {
                x,
                y,
                direction,
                amount,
            } => {
                let (x, y) = viewport_point(x, y)?;
                let (across, down) = match direction.as_str() {
                    "up" => (0.0, -1.0),
                    "down" => (0.0, 1.0),
                    "left" => (-1.0, 0.0),
                    "right" => (1.0, 0.0),
                    other => {
                        return Err(BrowserError::Input(format!(
                            "{other} is no scroll direction: up, down, left or right"
                        )));
                    }
                };
                let px = f64::from(amount.unwrap_or(SCROLL_NOTCHES)) * NOTCH_PX;
                self.page(
                    "Input.dispatchMouseEvent",
                    json!({"type": "mouseWheel", "x": x, "y": y, "deltaX": across * px, "deltaY": down * px}),
                )
                .map(drop)
            }
            BrowserPersonInput::Navigate { url } => {
                let navigated = self.page("Page.navigate", json!({"url": url}))?;
                match navigated.get("errorText").and_then(Value::as_str) {
                    Some(error) => Err(BrowserError::Navigation(error.to_owned())),
                    None => Ok(()),
                }
            }
        }
    }

    fn person_click(
        &self,
        (x, y): (f64, f64),
        button: Option<&str>,
        count: Option<u32>,
    ) -> Result<(), BrowserError> {
        let button = button.unwrap_or("left");
        if !matches!(button, "left" | "right" | "middle") {
            return Err(BrowserError::Input(format!(
                "{button} is no mouse button: left, right or middle"
            )));
        }
        let count = count.unwrap_or(1);
        if !(1..=3).contains(&count) {
            return Err(BrowserError::Input(
                "a click counts 1 to 3 presses".to_owned(),
            ));
        }
        self.page(
            "Input.dispatchMouseEvent",
            json!({"type": "mouseMoved", "x": x, "y": y}),
        )?;
        for click in 1..=count {
            for kind in ["mousePressed", "mouseReleased"] {
                self.page(
                    "Input.dispatchMouseEvent",
                    json!({"type": kind, "x": x, "y": y, "button": button, "clickCount": click}),
                )?;
            }
        }
        Ok(())
    }

    /// Holds the modifiers `keys` names first, presses its last key, then
    /// lets the modifiers go, even when the press failed.
    fn person_hotkey(&self, keys: &[String]) -> Result<(), BrowserError> {
        let Some((last, held)) = keys.split_last() else {
            return Err(BrowserError::Input("a hotkey names its keys".to_owned()));
        };
        let held = held
            .iter()
            .map(String::as_str)
            .map(modifier_of)
            .collect::<Result<Vec<_>, _>>()?;
        let key = key_of(last)?;
        let mut modifiers = 0;
        let mut down = Vec::new();
        let mut pressed = Ok(());
        for (bit, spec) in &held {
            modifiers |= bit;
            pressed = self.key_down_bare(spec, modifiers);
            if pressed.is_err() {
                break;
            }
            down.push((*bit, spec));
        }
        if pressed.is_ok() {
            pressed = self.key_press(&key, modifiers);
        }
        for (bit, spec) in down.into_iter().rev() {
            modifiers &= !bit;
            let released = self.key_event("keyUp", spec, modifiers);
            if pressed.is_ok() {
                pressed = released;
            }
        }
        pressed
    }

    /// One key down and up under `modifiers`. It types its text unless a
    /// modifier other than shift is held.
    fn key_press(&self, key: &KeySpec, modifiers: u32) -> Result<(), BrowserError> {
        let typed = modifiers & !SHIFT == 0 && key.text.is_some();
        if typed {
            self.key_event("keyDown", key, modifiers)?;
        } else {
            self.key_down_bare(key, modifiers)?;
        }
        self.key_event("keyUp", key, modifiers)
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
    }
    Ok(session)
}

impl BrowserDriver for CdpDriver {
    fn open(&mut self, input: OpenInput) -> Result<Observation, BrowserError> {
        let watch = Watch::Navigate(input.url.clone());
        let mark = self.mark(&watch);
        let navigated = self.page("Page.navigate", json!({"url": input.url}))?;
        if let Some(error) = navigated.get("errorText").and_then(Value::as_str) {
            return Err(BrowserError::Navigation(error.to_owned()));
        }
        // A navigate that started nothing answers at once, with its fact;
        // one that started loads as it always did, however late.
        let fact = match mark {
            Some(mark) if !change::navigation_started(&navigated) => {
                self.no_effect(&mark, &watch, Instant::now())
            }
            _ => None,
        };
        if fact.is_none() {
            if !self.loaded_or_refused(Instant::now() + LOAD)? {
                return Err(BrowserError::Timeout(format!("{} to load", input.url)));
            }
            let before = self.fingerprint()?;
            self.settle(before, Instant::now())?;
        }
        self.checkpoint(StoragePhase::PostAct);
        let mut observation = self.observation(&Base::Whole)?;
        observation.fact = fact;
        Ok(observation)
    }

    fn observe(&mut self, input: ObserveInput) -> Result<Observation, BrowserError> {
        let base = Base::of_observe(&input)?;
        match input.cursor.as_deref() {
            // Unpaged, a cursor reads the whole rest of its observation.
            Some(cursor) => self.pages.rest(cursor),
            None => self.observation(&base),
        }
    }

    fn paged(&mut self, observation: Observation) -> ObservationPage {
        self.pages.first(observation)
    }

    fn observe_page(&mut self, input: ObserveInput) -> Result<ObservationPage, BrowserError> {
        let base = Base::of_observe(&input)?;
        match input.cursor.as_deref() {
            Some(cursor) => self.pages.next(cursor),
            None => {
                let observation = self.observation(&base)?;
                Ok(self.pages.first(observation))
            }
        }
    }

    fn find(&mut self, input: FindInput) -> Result<FindOutput, BrowserError> {
        let (rows, next) = match find_cursor(&input)? {
            Some(cursor) => self.pages.next_rows(cursor)?,
            None => {
                let rows = self.matching(|row| input.matches(row))?;
                self.pages.first_rows(rows)
            }
        };
        Ok(FindOutput {
            rows,
            next,
            partial: None,
            walk_next: None,
        })
    }

    fn click(&mut self, input: ClickInput) -> Result<Observation, BrowserError> {
        let target = self.resolve_target(&input.target)?;
        self.click_target(&target, &Base::of(input.base))
    }

    fn click_at(&mut self, input: PointInput) -> Result<Observation, BrowserError> {
        self.chromium_only("click_at")?;
        let (x, y) = self.point(&input)?;
        self.click_point(x, y, None, &Base::of(input.base))
    }

    fn type_text(&mut self, input: TypeInput) -> Result<Observation, BrowserError> {
        let entry = entry(input.text.as_deref(), input.secret.as_deref())?;
        let target = self.resolve_target(&input.target)?;
        self.type_target(&target, entry, input.clear, &Base::of(input.base))
    }

    fn select(&mut self, input: SelectInput) -> Result<Observation, BrowserError> {
        let target = self.resolve_target(&input.target)?;
        self.select_target(&target, &input.option, &Base::of(input.base))
    }

    fn wait_for(&mut self, input: WaitForInput) -> Result<WaitForOutput, BrowserError> {
        if let Some(cursor) = wait_cursor(&input)? {
            let (rows, next) = self.pages.next_rows(cursor)?;
            return Ok(WaitForOutput {
                rows,
                timed_out: false,
                waited_ms: 0,
                next,
                partial: None,
                walk_next: None,
                rebindings: Vec::new(),
            });
        }
        let wanted = input
            .timeout_ms
            .map_or(WAIT_DEFAULT, |ms| Duration::from_millis(ms.into()));
        let bound = wanted.min(self.wait_cap);
        let start = Instant::now();
        loop {
            let capture = self.capture()?;
            // A named handle matches its own row, or, once its node is
            // gone, the row its locator names now, as a rebinding.
            let (rows, rebindings) = if input.targets.is_empty() {
                let query = input.query();
                let rows = capture
                    .rows
                    .into_iter()
                    .filter(|row| query.matches(row))
                    .collect();
                (rows, Vec::new())
            } else {
                rows_named(&input.targets, &capture.rows, &capture.scope, |target| {
                    self.handles.info(target)
                })
            };
            let waited = start.elapsed();
            if !rows.is_empty() || waited >= bound {
                let timed_out = rows.is_empty();
                let (rows, next) = self.pages.first_rows(rows);
                return Ok(WaitForOutput {
                    rows,
                    timed_out,
                    waited_ms: u64::try_from(waited.as_millis()).unwrap_or(u64::MAX),
                    next,
                    partial: None,
                    walk_next: None,
                    rebindings,
                });
            }
            std::thread::sleep(POLL * 2);
        }
    }

    fn expect(&mut self, input: ExpectInput) -> Result<ExpectOutput, BrowserError> {
        if input.value.is_some() && input.secret.is_some() {
            return Err(BrowserError::Input(
                "an expect names a value or a secret, never both".to_owned(),
            ));
        }
        let capture = self.capture()?;
        let (at, rebindings) = match &input.target {
            // The named handle's own row, or once its node is gone the row
            // its locator names now: an old handle is never met silently.
            Some(target) => {
                let known = self.handles.info(target);
                match match_target(target, &capture.rows, &capture.scope, known.as_ref()) {
                    Some((at, rebound)) => (Some(at), rebound.into_iter().collect()),
                    None => (None, Vec::new()),
                }
            }
            None => {
                let query = input.query();
                let at = capture.rows.iter().position(|row| query.matches(row));
                (at, Vec::new())
            }
        };
        // A secret is compared with what the page holds, never its handle.
        let met = match (at, input.absent) {
            (None, absent) => absent,
            (Some(_), true) => false,
            (Some(at), false) => self.secrets.holds(
                capture.rows[at].value.as_deref(),
                capture.originals[at].as_deref(),
                input.value.as_deref(),
                input.secret.as_deref(),
            )?,
        };
        let row = at.map(|at| capture.rows[at].clone());
        Ok(ExpectOutput {
            met,
            row,
            partial: None,
            rebindings,
        })
    }

    fn screenshot(&mut self, input: ScreenshotInput) -> Result<ScreenshotOutput, BrowserError> {
        // The capture it names, read before this one can age it out.
        let base = capture::compared(&input).and_then(|id| self.held_capture(id));
        let scroll = self.scroll_offset()?;
        // The documents shown before and after: a capture the page moved
        // under never compares. A sample that fails costs only that.
        let before = self.shown_documents().ok();
        let (masked, masking) = self.mask_secrets();
        let captured =
            masking.and_then(|()| self.page("Page.captureScreenshot", json!({"format": "png"})));
        let restored = self.unmask_secrets(&masked);
        let shot = captured?;
        restored?;
        let after = self.shown_documents().ok();
        let data = shot.get("data").and_then(Value::as_str).unwrap_or("");
        let png = base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|e| BrowserError::Protocol(e.to_string()))?;
        let (url, title) = self.page_info()?;
        let frame = Frame {
            left: 0.0,
            top: 0.0,
            width: f64::from(WIDTH),
            height: f64::from(HEIGHT),
            scroll,
            url: url.clone(),
        };
        let size = png_dimensions(&png).unwrap_or_default();
        let scope = before
            .filter(|before| after.as_ref() == Some(before))
            .map(|documents| capture::Scope {
                shows: format!("page:{documents}|{url}"),
                rect: [frame.left, frame.top, frame.width, frame.height],
                scroll: Some(scroll),
                size,
                scale: f64::from(size.0) / frame.width,
                masking: capture::MASKING,
            });
        let taken = self.captures.next(scope);
        let (image, width, height, bytes) = self.remember(png, frame, Some(taken.clone()))?;
        Ok(ScreenshotOutput {
            unchanged_from: capture::unchanged_from(base, &image, &taken),
            image,
            media_type: "image/png".to_owned(),
            width,
            height,
            bytes,
            trigger: input.trigger,
            url,
            title,
            capture_id: taken.id,
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
        let (image, width, height, bytes) = self.remember(encode_png(&region)?, frame, None)?;
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
        let scale = input
            .scale
            .unwrap_or_else(|| (f64::from(WIDTH) / f64::from(input.width.max(1))).min(4.0) as f32);
        if !scale.is_finite() || !(0.1..=8.0).contains(&scale) {
            return Err(BrowserError::Input(format!(
                "zoom scale {scale} is outside 0.1 to 8"
            )));
        }
        let width = ((input.width as f32 * scale).round() as u32).clamp(1, 4096);
        let height = ((input.height as f32 * scale).round() as u32).clamp(1, 4096);
        let zoomed = region.resize_exact(width, height, image::imageops::FilterType::Lanczos3);
        let (image, width, height, bytes) = self.remember(encode_png(&zoomed)?, frame, None)?;
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

    fn handle_info(&self, handle: &str) -> Option<HandleInfo> {
        self.handles.info(handle)
    }
}

/// A PNG's width and height from its IHDR, when the bytes are a PNG.
pub(crate) fn png_dimensions(png: &[u8]) -> Option<(u32, u32)> {
    let dimension = |at: usize| png.get(at..at + 4)?.try_into().ok().map(u32::from_be_bytes);
    Some((dimension(16)?, dimension(20)?))
}

/// The (`x`, `y`, `width`, `height`) region of a held PNG.
pub(crate) fn crop_region(
    png: &[u8],
    x: u32,
    y: u32,
    width: u32,
    height: u32,
) -> Result<image::DynamicImage, BrowserError> {
    let image = image::load_from_memory(png).map_err(|e| BrowserError::Protocol(e.to_string()))?;
    if width == 0
        || height == 0
        || x.checked_add(width).is_none_or(|end| end > image.width())
        || y.checked_add(height).is_none_or(|end| end > image.height())
    {
        return Err(BrowserError::Input(format!(
            "region {x},{y} {width}x{height} does not fit the {}x{} image",
            image.width(),
            image.height()
        )));
    }
    Ok(image.crop_imm(x, y, width, height))
}

pub(crate) fn encode_png(image: &image::DynamicImage) -> Result<Vec<u8>, BrowserError> {
    let mut out = Cursor::new(Vec::new());
    image
        .write_to(&mut out, image::ImageFormat::Png)
        .map_err(|e| BrowserError::Protocol(e.to_string()))?;
    Ok(out.into_inner())
}

fn str_field(value: &Value, name: &str) -> Result<String, BrowserError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| BrowserError::Protocol(format!("reply without {name}")))
}
