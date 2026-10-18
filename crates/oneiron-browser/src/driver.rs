//! The CDP driver: one page in a Chromium guest, read as an outline and acted
//! on by ref.
//!
//! Every action waits for the page to settle before it returns, on the values
//! arc-cua measured for Chromium over CDP: up to 0.6 s for the page to start
//! changing, then 0.15 s with no change, never more than 2 s in all.
//! A faster driver than the page only reads a stale page.

use crate::cdp::Pipe;
use crate::outline::{self, Line};
use crate::{
    BrowserDriver, BrowserError, BrowserPersonInput, ClickInput, CropInput, ExpectInput,
    ExpectOutput, FindInput, FindOutput, ImageOutput, Observation, ObservationPage, ObserveInput,
    OpenInput, PointInput, Row, ScreenshotInput, ScreenshotOutput, SelectInput, TypeInput,
    ViewInput, WaitForInput, WaitForOutput, ZoomInput,
};
use base64::Engine as _;
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
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
/// Observations a `since` diff can name.
const HISTORY: usize = 8;
/// Screenshots the driver holds for a later image read.
const MEDIA: usize = 16;
/// The most bytes of rows, then removed refs, as JSON, one observation
/// answer carries (Rule 5: a long outline goes on in pages, never cut).
/// Half the 512 KiB past which a code-mode answer crosses as a stored
/// result, so a page crosses inline with its receipt and manifest.
const OBSERVE_PAGE_BYTES: usize = 256 * 1024;
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
    session: String,
    target: String,
    seq: u64,
    history: VecDeque<(u64, HashMap<String, Row>)>,
    media: VecDeque<Held>,
    /// The paged observations whose later pages a cursor may still read,
    /// the last [`HISTORY`] of them.
    pages: VecDeque<Paged>,
    wait_cap: Duration,
}

/// An observation answered in pages: every row and removed ref it had, so
/// a cursor reads on from where its page ended.
struct Paged {
    seq: u64,
    url: String,
    title: String,
    full: bool,
    rows: Vec<Row>,
    removed: Vec<String>,
}

/// One key as CDP's key events name it.
struct KeySpec {
    key: String,
    code: String,
    vk: u32,
    text: Option<String>,
}

/// An image the driver holds: its content ref, its PNG bytes and what of
/// the page it shows.
struct Held {
    image: String,
    png: Vec<u8>,
    frame: Frame,
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
    /// Opens one blank page in the guest and attaches to it.
    pub(crate) fn attach(pipe: Pipe, wait_cap: Duration) -> Result<Self, BrowserError> {
        let deadline = Instant::now() + CALL;
        let created = pipe.call(
            None,
            "Target.createTarget",
            json!({"url": "about:blank"}),
            deadline,
        )?;
        let target = str_field(&created, "targetId")?;
        let attached = pipe.call(
            None,
            "Target.attachToTarget",
            json!({"targetId": target, "flatten": true}),
            deadline,
        )?;
        let session = str_field(&attached, "sessionId")?;
        let driver = Self {
            pipe,
            session,
            target,
            seq: 0,
            history: VecDeque::new(),
            media: VecDeque::new(),
            pages: VecDeque::new(),
            wait_cap,
        };
        for (method, params) in [
            ("Accessibility.enable", json!({})),
            ("DOM.enable", json!({})),
            (
                "Emulation.setDeviceMetricsOverride",
                json!({"width": WIDTH, "height": HEIGHT, "deviceScaleFactor": 1, "mobile": false}),
            ),
        ] {
            driver.page(method, params)?;
        }
        if driver.pipe.mediated() {
            crate::cdp::enable_network(&driver.pipe, &driver.session, Instant::now() + CALL)?;
        }
        Ok(driver)
    }

    fn page(&self, method: &str, params: Value) -> Result<Value, BrowserError> {
        self.pipe
            .call(Some(&self.session), method, params, Instant::now() + CALL)
    }

    fn lines(&self) -> Result<Vec<Line>, BrowserError> {
        let tree = self.page("Accessibility.getFullAXTree", json!({}))?;
        let nodes = tree
            .get("nodes")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        Ok(outline::lines(nodes))
    }

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

    fn observation(&mut self, since: Option<u64>) -> Result<Observation, BrowserError> {
        let rows: Vec<Row> = self.lines()?.into_iter().map(|line| line.row).collect();
        let (url, title) = self.page_info()?;
        self.seq += 1;
        let current: HashMap<String, Row> = rows
            .iter()
            .map(|row| (row.target.clone(), row.clone()))
            .collect();
        let before = since
            .and_then(|since| self.history.iter().find(|(seq, _)| *seq == since))
            .map(|(_, rows)| rows);
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
        self.history.push_back((self.seq, current));
        if self.history.len() > HISTORY {
            self.history.pop_front();
        }
        Ok(Observation {
            seq: self.seq,
            url,
            title,
            full,
            rows: shown,
            removed,
            receipt: None,
            library: Vec::new(),
            no_tree: false,
        })
    }

    /// The row `target` names on the page as it is now.
    pub(crate) fn row(&self, target: &str) -> Result<Row, BrowserError> {
        self.lines()?
            .into_iter()
            .map(|line| line.row)
            .find(|row| row.target == target)
            .ok_or_else(|| BrowserError::StaleRef(target.to_owned()))
    }

    /// The PNG bytes of a screenshot this driver took, while it holds them.
    pub(crate) fn image(&self, image: &str) -> Option<&[u8]> {
        self.media
            .iter()
            .find(|held| held.image == image)
            .map(|held| held.png.as_slice())
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
    pub(crate) fn row_at(&self, x: f64, y: f64) -> Result<Option<Row>, BrowserError> {
        let hit = self.page(
            "DOM.getNodeForLocation",
            json!({"x": x.round() as i64, "y": y.round() as i64, "ignorePointerEventsNone": true}),
        )?;
        let Some(hit) = hit.get("backendNodeId").and_then(Value::as_u64) else {
            return Ok(None);
        };
        let tree = self.page("Accessibility.getFullAXTree", json!({}))?;
        let nodes = tree
            .get("nodes")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        let lines = outline::lines(nodes);
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
                && let Some(line) = lines.iter().find(|line| line.backend_node == Some(at))
            {
                return Ok(Some(line.row.clone()));
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

    /// Clicks at viewport point (`x`, `y`), then returns the settled page.
    pub(crate) fn click_point(&mut self, x: f64, y: f64) -> Result<Observation, BrowserError> {
        self.act(|driver| driver.mouse_click(x, y))
    }

    /// Blacks out password, card and one-time-code fields, or restores them.
    /// A stored screenshot is masked like an observation: no secret field's
    /// value reaches the image.
    fn mask_secrets(&self, mask: bool) -> Result<(), BrowserError> {
        let script = if mask {
            "document.querySelectorAll('input[type=password],input[autocomplete^=\"cc-\"],input[autocomplete=\"one-time-code\"]').forEach(e => { e.dataset.oneironMask = e.style.cssText; e.style.setProperty('background', '#000', 'important'); e.style.setProperty('color', '#000', 'important'); e.style.setProperty('-webkit-text-security', 'disc', 'important'); })"
        } else {
            "document.querySelectorAll('[data-oneiron-mask]').forEach(e => { e.style.cssText = e.dataset.oneironMask; delete e.dataset.oneironMask; })"
        };
        self.page(
            "Runtime.evaluate",
            json!({"expression": script, "returnByValue": true}),
        )?;
        Ok(())
    }

    /// The DOM node behind `target` on the page as it is now.
    fn resolve(&self, target: &str) -> Result<(Row, Value), BrowserError> {
        let line = self
            .lines()?
            .into_iter()
            .find(|line| line.row.target == target)
            .ok_or_else(|| BrowserError::StaleRef(target.to_owned()))?;
        let node = line
            .backend_node
            .ok_or_else(|| BrowserError::StaleRef(target.to_owned()))?;
        let resolved = self.page("DOM.resolveNode", json!({"backendNodeId": node}))?;
        let object = resolved
            .pointer("/object/objectId")
            .cloned()
            .ok_or_else(|| BrowserError::StaleRef(target.to_owned()))?;
        Ok((line.row, json!({"backendNodeId": node, "objectId": object})))
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

    /// Runs `act` on the page, then returns the settled page as a diff.
    fn act(
        &mut self,
        act: impl FnOnce(&Self) -> Result<(), BrowserError>,
    ) -> Result<Observation, BrowserError> {
        let since = self.seq;
        let before = self.fingerprint()?;
        let start = Instant::now();
        act(self)?;
        self.settle(before, start)?;
        self.observation(Some(since))
    }

    fn matching(&self, keep: impl Fn(&Row) -> bool) -> Result<Vec<Row>, BrowserError> {
        Ok(self
            .lines()?
            .into_iter()
            .map(|line| line.row)
            .filter(keep)
            .collect())
    }

    /// The paged observation `cursor` reads on, and where its next page
    /// starts. A cursor whose observation has left the held ones refuses.
    fn continued(&self, cursor: &str) -> Result<(&Paged, (usize, usize)), BrowserError> {
        let parsed = cursor.split_once('.').and_then(|(seq, at)| {
            let (rows, removed) = at.split_once('.')?;
            Some((
                seq.parse::<u64>().ok()?,
                (rows.parse::<usize>().ok()?, removed.parse::<usize>().ok()?),
            ))
        });
        let Some((seq, from)) = parsed else {
            return Err(BrowserError::Input(format!(
                "{cursor} is no observation cursor"
            )));
        };
        let held = self
            .pages
            .iter()
            .find(|held| held.seq == seq)
            .ok_or_else(|| {
                BrowserError::Input(format!(
                    "observation {seq} is no longer held for its later pages; observe again"
                ))
            })?;
        Ok((held, from))
    }

    /// Forgets every observation, so the next one is whole: a person drove
    /// the page meanwhile.
    pub(crate) fn forget_observations(&mut self) {
        self.history.clear();
        self.pages.clear();
    }

    /// The viewport as a PNG for the person who holds the browser: unmasked,
    /// never held among the driver's images and never a receipt.
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
            pressed = self.key_event("rawKeyDown", spec, modifiers);
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
        self.key_event(if typed { "keyDown" } else { "rawKeyDown" }, key, modifiers)?;
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

/// The page of `rows`, then `removed`, that starts at `from` and fits
/// [`OBSERVE_PAGE_BYTES`] as JSON, and where the next page starts, when one
/// does. A page takes at least one entry, so every page moves on.
fn page_of(
    rows: &[Row],
    removed: &[String],
    from: (usize, usize),
) -> (Vec<Row>, Vec<String>, Option<(usize, usize)>) {
    let mut bytes = 0;
    let mut page_rows = Vec::new();
    let mut page_removed = Vec::new();
    let (mut at_row, mut at_removed) = (from.0.min(rows.len()), from.1.min(removed.len()));
    while at_row < rows.len() {
        let len = json_len(&rows[at_row]);
        if !page_rows.is_empty() && bytes + len > OBSERVE_PAGE_BYTES {
            return (page_rows, page_removed, Some((at_row, at_removed)));
        }
        bytes += len;
        page_rows.push(rows[at_row].clone());
        at_row += 1;
    }
    while at_removed < removed.len() {
        let len = json_len(&removed[at_removed]);
        let empty = page_rows.is_empty() && page_removed.is_empty();
        if !empty && bytes + len > OBSERVE_PAGE_BYTES {
            return (page_rows, page_removed, Some((at_row, at_removed)));
        }
        bytes += len;
        page_removed.push(removed[at_removed].clone());
        at_removed += 1;
    }
    (page_rows, page_removed, None)
}

/// One entry's bytes in a page's JSON, with its comma.
fn json_len(value: &impl serde::Serialize) -> usize {
    serde_json::to_vec(value).map_or(0, |bytes| bytes.len()) + 1
}

fn cursor_of(seq: u64, (rows, removed): (usize, usize)) -> String {
    format!("{seq}.{rows}.{removed}")
}

impl BrowserDriver for CdpDriver {
    fn open(&mut self, input: OpenInput) -> Result<Observation, BrowserError> {
        let navigated = self.page("Page.navigate", json!({"url": input.url}))?;
        if let Some(error) = navigated.get("errorText").and_then(Value::as_str) {
            return Err(BrowserError::Navigation(error.to_owned()));
        }
        let deadline = Instant::now() + LOAD;
        loop {
            let state = self.page(
                "Runtime.evaluate",
                json!({"expression": "document.readyState", "returnByValue": true}),
            )?;
            if state.pointer("/result/value").and_then(Value::as_str) == Some("complete") {
                break;
            }
            if Instant::now() >= deadline {
                return Err(BrowserError::Timeout(format!("{} to load", input.url)));
            }
            std::thread::sleep(POLL);
        }
        let before = self.fingerprint()?;
        self.settle(before, Instant::now())?;
        self.observation(None)
    }

    fn observe(&mut self, input: ObserveInput) -> Result<Observation, BrowserError> {
        let Some(cursor) = input.cursor.as_deref() else {
            return self.observation(input.since);
        };
        // Unpaged, a cursor reads the whole rest of its observation.
        let (held, (rows, removed)) = self.continued(cursor)?;
        Ok(Observation {
            seq: held.seq,
            url: held.url.clone(),
            title: held.title.clone(),
            full: held.full,
            rows: held.rows.get(rows..).unwrap_or_default().to_vec(),
            removed: held.removed.get(removed..).unwrap_or_default().to_vec(),
            receipt: None,
            library: Vec::new(),
            no_tree: false,
        })
    }

    fn paged(&mut self, mut observation: Observation) -> ObservationPage {
        let (rows, removed, Some(next)) = page_of(&observation.rows, &observation.removed, (0, 0))
        else {
            return ObservationPage::whole(observation);
        };
        let seq = observation.seq;
        let held = Paged {
            seq,
            url: observation.url.clone(),
            title: observation.title.clone(),
            full: observation.full,
            rows: std::mem::replace(&mut observation.rows, rows),
            removed: std::mem::replace(&mut observation.removed, removed),
        };
        self.pages.retain(|paged| paged.seq != seq);
        self.pages.push_back(held);
        if self.pages.len() > HISTORY {
            self.pages.pop_front();
        }
        ObservationPage {
            observation,
            next: Some(cursor_of(seq, next)),
        }
    }

    fn observe_page(&mut self, input: ObserveInput) -> Result<ObservationPage, BrowserError> {
        let Some(cursor) = input.cursor.as_deref() else {
            let observation = self.observation(input.since)?;
            return Ok(self.paged(observation));
        };
        if input.since.is_some() {
            return Err(BrowserError::Input(
                "observe reads since or a cursor, not both".to_owned(),
            ));
        }
        let (held, from) = self.continued(cursor)?;
        let (rows, removed, next) = page_of(&held.rows, &held.removed, from);
        Ok(ObservationPage {
            observation: Observation {
                seq: held.seq,
                url: held.url.clone(),
                title: held.title.clone(),
                full: held.full,
                rows,
                removed,
                receipt: None,
                library: Vec::new(),
                no_tree: false,
            },
            next: next.map(|at| cursor_of(held.seq, at)),
        })
    }

    fn find(&mut self, input: FindInput) -> Result<FindOutput, BrowserError> {
        Ok(FindOutput {
            rows: self.matching(|row| input.matches(row))?,
        })
    }

    fn click(&mut self, input: ClickInput) -> Result<Observation, BrowserError> {
        let (_, node) = self.resolve(&input.target)?;
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
            return Err(BrowserError::Covered(input.target));
        }
        let x = (quad[0] + quad[2] + quad[4] + quad[6]) / 4.0;
        let y = (quad[1] + quad[3] + quad[5] + quad[7]) / 4.0;
        // The point must land on the element or inside it, not on a cover.
        let hit = self.call_on(
            &node,
            "function(x, y) { const e = document.elementFromPoint(x, y); return !!e && (e === this || this.contains(e)); }",
            json!([{"value": x}, {"value": y}]),
        )?;
        if hit != Value::Bool(true) {
            return Err(BrowserError::Covered(input.target));
        }
        self.click_point(x, y)
    }

    fn click_at(&mut self, input: PointInput) -> Result<Observation, BrowserError> {
        let (x, y) = self.point(&input)?;
        self.click_point(x, y)
    }

    fn type_text(&mut self, input: TypeInput) -> Result<Observation, BrowserError> {
        let (_, node) = self.resolve(&input.target)?;
        self.act(|driver| {
            driver.page("DOM.focus", json!({"backendNodeId": node["backendNodeId"]}))?;
            if input.clear {
                driver.call_on(
                    &node,
                    "function() { if (typeof this.select === 'function') this.select(); else getSelection().selectAllChildren(this); }",
                    json!([]),
                )?;
            }
            driver.page("Input.insertText", json!({"text": input.text}))?;
            Ok(())
        })
    }

    fn select(&mut self, input: SelectInput) -> Result<Observation, BrowserError> {
        let (_, node) = self.resolve(&input.target)?;
        let target = input.target.clone();
        self.act(|driver| {
            let picked = driver.call_on(
                &node,
                "function(want) {
                    if (this.tagName !== 'SELECT') return false;
                    const o = [...this.options].find(o => o.label === want || o.text.trim() === want || o.value === want);
                    if (!o) return false;
                    this.value = o.value;
                    this.dispatchEvent(new Event('input', {bubbles: true}));
                    this.dispatchEvent(new Event('change', {bubbles: true}));
                    return true;
                }",
                json!([{"value": input.option}]),
            )?;
            if picked == Value::Bool(true) { Ok(()) } else { Err(BrowserError::NoOption(target)) }
        })
    }

    fn wait_for(&mut self, input: WaitForInput) -> Result<WaitForOutput, BrowserError> {
        let wanted = input
            .timeout_ms
            .map_or(WAIT_DEFAULT, |ms| Duration::from_millis(ms.into()));
        let bound = wanted.min(self.wait_cap);
        let start = Instant::now();
        loop {
            let rows = self.matching(|row| input.matches(row))?;
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
        let rows = self.lines()?.into_iter().map(|line| line.row);
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
        let scroll = self.scroll_offset()?;
        self.mask_secrets(true)?;
        let captured = self.page("Page.captureScreenshot", json!({"format": "png"}));
        let restored = self.mask_secrets(false);
        let shot = captured?;
        restored?;
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
        let (image, width, height, bytes) = self.remember(png, frame)?;
        Ok(ScreenshotOutput {
            image,
            media_type: "image/png".to_owned(),
            width,
            height,
            bytes,
            trigger: input.trigger,
            url,
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
