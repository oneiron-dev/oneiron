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
    BrowserDriver, BrowserError, ClickInput, CropInput, ExpectInput, ExpectOutput, FindInput,
    FindOutput, ImageOutput, Observation, ObserveInput, OpenInput, PointInput, Row,
    ScreenshotInput, ScreenshotOutput, SelectInput, TypeInput, ViewInput, WaitForInput,
    WaitForOutput, ZoomInput,
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

pub(crate) struct CdpDriver {
    pipe: Pipe,
    session: String,
    target: String,
    seq: u64,
    history: VecDeque<(u64, HashMap<String, Row>)>,
    media: VecDeque<Held>,
    wait_cap: Duration,
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
    fn scroll(&self) -> Result<(f64, f64), BrowserError> {
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
        let scroll = self.scroll()?;
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

    fn matching(&self, find: &FindInput) -> Result<Vec<Row>, BrowserError> {
        Ok(self
            .lines()?
            .into_iter()
            .map(|line| line.row)
            .filter(|row| find.matches(row))
            .collect())
    }
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
        self.observation(input.since)
    }

    fn find(&mut self, input: FindInput) -> Result<FindOutput, BrowserError> {
        Ok(FindOutput {
            rows: self.matching(&input)?,
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
        let scroll = self.scroll()?;
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
