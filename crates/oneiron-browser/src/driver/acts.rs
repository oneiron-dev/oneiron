use super::*;

/// Whether an act's input whose call failed, after the browser was sent
/// one of its calls, has an unknown outcome (`unknown_outcome_policy`,
/// CALLS row, FIX 10426): its call ran out of time, the guest went, or the
/// browser answered an error, so the input may have taken effect, wholly
/// or in part. The driver's own refusals (a cover, a missing option) are
/// answers about the page, and land no receipt.
fn unknown_outcome_policy(error: &BrowserError) -> bool {
    matches!(
        error,
        BrowserError::CallTimeout(_) | BrowserError::GuestLost | BrowserError::Protocol(_)
    )
}

impl CdpDriver {
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
        let watch = Watch::Click(change::point_target(x, y, row), None);
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
        let watch = Watch::Click(change::row_target(&target.row), Some(node));
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
                Entry::Secret(handle) => {
                    let use_ = SecretUse::Type;
                    driver.secrets.with_value(handle, use_, &mut |text: &str| {
                        driver
                            .page("Input.insertText", json!({"text": text}))
                            .map(drop)
                    })
                }
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
        let written = crate::cdp::written_here();
        let acted = set.and_then(|()| act(self));
        // Sent: a failure from here on leaves the effect standing (FIX 8010).
        self.sent = acted.is_ok();
        // A call of the input failed once the browser was sent part of it:
        // the effect may stand, its outcome unknown (FIX 10426).
        self.unknown = acted.as_ref().is_err_and(|error| {
            unknown_outcome_policy(error) && crate::cdp::written_here() > written
        });
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
        // A tab the act opened or closed is an effect, and so is an outline
        // that moved (FIX 8006): no fact stands.
        let fact = fact
            .filter(|_| moved.is_none())
            .filter(|_| self.fingerprint().is_ok_and(|after| after == before));
        observation.fact = fact;
        Ok(observation)
    }
}
