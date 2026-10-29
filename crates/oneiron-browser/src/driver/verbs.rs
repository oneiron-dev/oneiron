use super::*;
use base64::Engine as _;

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
            // A partial page's `walk_next` reads the page again, whole.
            Some(cursor) if pages::is_walk(cursor) => self.observation(&Base::Whole),
            // Unpaged, a cursor reads the whole rest of its observation.
            Some(cursor) => self.pages.rest(cursor),
            None => self.observation(&base),
        }
    }

    fn paged(&mut self, observation: Observation) -> ObservationPage {
        self.pages.first(observation)
    }

    fn observe_hidden(&mut self) -> Result<Observation, BrowserError> {
        self.pages.hiding(true);
        let read = self.observation(&Base::Whole);
        self.pages.hiding(false);
        read
    }

    fn observe_page(&mut self, input: ObserveInput) -> Result<ObservationPage, BrowserError> {
        let base = Base::of_observe(&input)?;
        match input.cursor.as_deref() {
            // A partial page's `walk_next` reads the page again, whole.
            Some(cursor) if pages::is_walk(cursor) => {
                let observation = self.observation(&Base::Whole)?;
                Ok(self.pages.first(observation))
            }
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
            // Only the capture whose rows the wait returns reads the DOM
            // (`capture_dom_policy`, FIX 6965): a poll that finds them is
            // read again whole, and the last poll is read whole.
            let last = start.elapsed() >= bound;
            let probe = self.capture_read(last)?;
            let mut found = self.waited_rows(&input, probe);
            if !last && !found.0.is_empty() {
                let whole = self.capture()?;
                found = self.waited_rows(&input, whole);
            }
            let (rows, rebindings) = found;
            let waited = start.elapsed();
            if !rows.is_empty() || last {
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

impl CdpDriver {
    /// The rows of `capture` a wait waits for: those its role and name
    /// match, or the rows its handles name, a named handle matching its own
    /// row or, once its node is gone, the row its locator names now, as a
    /// rebinding.
    fn waited_rows(
        &self,
        input: &WaitForInput,
        capture: handles::Capture,
    ) -> (Vec<Row>, Vec<crate::Rebound>) {
        if input.targets.is_empty() {
            let query = input.query();
            let rows = capture
                .rows
                .into_iter()
                .filter(|row| query.matches(row))
                .collect();
            return (rows, Vec::new());
        }
        rows_named(&input.targets, &capture.rows, &capture.scope, |target| {
            self.handles.info(target)
        })
    }
}
