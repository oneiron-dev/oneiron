use super::*;

/// Whether `key` (`"Return"`, `"ctrl+enter"`) presses Return.
fn is_return(key: &str) -> bool {
    let key = key.rsplit('+').next().unwrap_or(key).trim();
    ["return", "enter", "kp_enter"]
        .iter()
        .any(|name| key.eq_ignore_ascii_case(name))
}

/// Whether `key` activates the control it goes to, as a click would.
fn is_activation(key: &str) -> bool {
    is_return(key)
        || key
            .rsplit('+')
            .next()
            .unwrap_or(key)
            .trim()
            .eq_ignore_ascii_case("space")
}

/// A key press as the press refusal names it, when no row takes it.
fn key_row(key: &str) -> Row {
    Row {
        target: String::new(),
        locator: String::new(),
        role: "key".to_owned(),
        name: key.to_owned(),
        value: None,
        states: Vec::new(),
        depth: 0,
        href: None,
        level: None,
        datetimes: Vec::new(),
        unavailable: Vec::new(),
        secret: None,
    }
}

impl BrowserDriver for DesktopSession {
    /// Opens an app of the guest's set, `app:<name>`, and reads its window.
    fn open(&mut self, input: OpenInput) -> Result<Observation, BrowserError> {
        let started = Instant::now();
        self.begin_verb();
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
        let mut observation = self.observation(&Base::Whole)?;
        self.receipt(
            "open",
            None,
            None,
            PressMode::None,
            &mut observation,
            started,
        );
        Ok(observation)
    }

    fn view_fingerprint(&self) -> Option<[u8; 32]> {
        self.view
    }

    fn observe_hidden(&mut self) -> Result<Observation, BrowserError> {
        self.pages.hiding(true);
        let read = self.observe(ObserveInput {
            full: true,
            ..ObserveInput::default()
        });
        self.pages.hiding(false);
        read
    }

    fn observe(&mut self, input: ObserveInput) -> Result<Observation, BrowserError> {
        self.live()?;
        let base = Base::of_observe(&input)?;
        match input.cursor.as_deref() {
            // A partial observation's `walk_next` walks the window again,
            // longer, as a new observation, which the caller reads whole.
            Some(cursor) if is_walk(cursor) => {
                let observation = self.walk_next(cursor)?;
                self.pages.deliver(observation.seq);
                Ok(observation)
            }
            // Unpaged, a page cursor reads the whole rest of its observation.
            Some(cursor) => self.pages.rest(cursor),
            None => self.observation(&base),
        }
    }

    fn paged(&mut self, observation: Observation) -> ObservationPage {
        self.pages.first(observation)
    }

    fn observe_page(&mut self, input: ObserveInput) -> Result<ObservationPage, BrowserError> {
        self.live()?;
        let base = Base::of_observe(&input)?;
        match input.cursor.as_deref() {
            Some(cursor) if is_walk(cursor) => {
                let observation = self.walk_next(cursor)?;
                Ok(self.pages.first(observation))
            }
            Some(cursor) => self.pages.next(cursor),
            None => {
                let observation = self.observation(&base)?;
                Ok(self.pages.first(observation))
            }
        }
    }

    /// Rows the window holds now: a read cut before any matches walks on
    /// first, and a search still cut answers `partial` and its `walk_next`.
    fn find(&mut self, input: FindInput) -> Result<FindOutput, BrowserError> {
        self.live()?;
        let found = match find_cursor(&input)? {
            Some(cursor) if is_search(cursor) => self.search_on(cursor)?,
            Some(cursor) => self.pages.next_found(cursor)?,
            None => {
                let query = WaitForInput {
                    role: input.role.clone(),
                    name: input.name.clone(),
                    ..WaitForInput::default()
                };
                let first = self.snapshot(false)?;
                let snapshot = self.search(first, None, |row| query.matches(row))?;
                self.rows_of(snapshot, query)
            }
        };
        Ok(FindOutput {
            rows: found.rows,
            next: found.next,
            partial: found.partial,
            walk_next: found.walk_next,
        })
    }

    fn click(&mut self, input: ClickInput) -> Result<Observation, BrowserError> {
        let started = Instant::now();
        self.begin_verb();
        self.live()?;
        let snapshot = self.reach(&input.target)?;
        let (line, token) = Self::token(&snapshot, &input.target)?;
        let class = effect_class(&line.row.name);
        let press = self.press_or_hold("click", &input, class, Some(&line.row), &snapshot)?;
        let pid = snapshot.key.pid;
        let acted = self.act(&snapshot, &Base::of(input.base), |session| {
            session
                .input("click", json!({"pid": pid, "element_token": token}))
                .map_err(|e| refusal(e, Some(input.target.as_str())))
        });
        let class = receipt_class(class, Some(&line.row));
        self.sent(
            "click",
            &snapshot,
            Some(&line.row),
            class,
            press,
            started,
            acted,
        )
    }

    fn click_at(&mut self, input: PointInput) -> Result<Observation, BrowserError> {
        self.click_point(input)
    }

    fn type_text(&mut self, input: TypeInput) -> Result<Observation, BrowserError> {
        let started = Instant::now();
        self.begin_verb();
        let entry = entry(input.text.as_deref(), input.secret.as_deref())?;
        self.live()?;
        let snapshot = self.reach(&input.target)?;
        let (line, token) = Self::token(&snapshot, &input.target)?;
        // The act's own input, as a held press keeps it: for a secret the
        // handle only, never its bytes, which the custody lends again at
        // the answered send.
        let operands = serde_json::to_value(&input).unwrap_or_default();
        let base = Base::of(input.base);
        let typing = Typing {
            read: &snapshot,
            base: &base,
            token: &token,
            target: &input.target,
            clear: input.clear,
        };
        let observation = match entry {
            Entry::Text(text) => self.enter(&typing, &line.row, text, &operands, started)?,
            // The secret's bytes come from the custody at the send itself,
            // and its line-break check reads them there; the field reads
            // as that secret from then on.
            Entry::Secret(handle) => {
                let kind = self.secrets.kind_of(handle);
                let kind = kind.unwrap_or(SecretKind::Password);
                self.typed.insert(line.row.locator.clone(), kind);
                let secrets = self.secrets.clone();
                let mut entered = None;
                secrets.with_value(handle, SecretUse::Type, &mut |text: &str| {
                    entered = Some(self.enter(&typing, &line.row, text, &operands, started)?);
                    Ok(())
                })?;
                entered.ok_or_else(|| {
                    BrowserError::SecretRefused(format!("{handle} lent no bytes to the type"))
                })?
            }
        };
        Ok(observation)
    }

    fn fill_text(
        &mut self,
        input: TypeInput,
        provenance: TextProvenance,
    ) -> Result<Observation, BrowserError> {
        self.provenance = Some(provenance);
        let typed = self.type_text(input);
        // A type that failed before its receipt keeps none.
        self.provenance = None;
        typed
    }

    fn select(&mut self, input: SelectInput) -> Result<Observation, BrowserError> {
        let started = Instant::now();
        self.begin_verb();
        self.live()?;
        let snapshot = self.reach(&input.target)?;
        let (line, token) = Self::token(&snapshot, &input.target)?;
        let pid = snapshot.key.pid;
        let base = Base::of(input.base);
        let acted = self.act(&snapshot, &base, |session| {
            session
                .input(
                    "set_value",
                    json!({"pid": pid, "element_token": token, "value": input.option}),
                )
                .map_err(|e| refusal(e, Some(input.target.as_str())))
        });
        self.sent(
            "select",
            &snapshot,
            Some(&line.row),
            None,
            PressMode::None,
            started,
            acted,
        )
    }

    /// Waits for rows within its time: each look that finds none walks on
    /// from the longest cut a look reached, never the same capped walk
    /// again (Rule 5), and a wait that ends cut answers `partial` and its
    /// `walk_next`.
    fn wait_for(&mut self, input: WaitForInput) -> Result<WaitForOutput, BrowserError> {
        self.live()?;
        let start = Instant::now();
        if let Some(cursor) = wait_cursor(&input)? {
            let found = if is_search(cursor) {
                self.search_on(cursor)?
            } else {
                self.pages.next_found(cursor)?
            };
            return Ok(WaitForOutput {
                rows: found.rows,
                timed_out: false,
                waited_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
                next: found.next,
                partial: found.partial,
                walk_next: found.walk_next,
                rebindings: Vec::new(),
            });
        }
        let wanted = input
            .timeout_ms
            .map_or(WAIT_DEFAULT, |ms| Duration::from_millis(ms.into()));
        let bound = wanted.min(self.wait_cap);
        let until = start + bound;
        let query = WaitForInput {
            timeout_ms: None,
            cursor: None,
            ..input
        };
        let mut cut: Option<PartialTree> = None;
        loop {
            let first = self.snapshot_on(false, cut.as_ref(), Some(until))?;
            let snapshot = self.search(first, Some(until), |row| query.matches(row))?;
            if let Some(now) = &snapshot.partial
                && cut.as_ref().is_none_or(|was| now.walk_ms >= was.walk_ms)
            {
                cut = Some(now.clone());
            }
            let waited = start.elapsed();
            let any = snapshot.lines.iter().any(|line| query.matches(&line.row));
            if any || waited >= bound {
                let found = self.rows_of(snapshot, query);
                return Ok(WaitForOutput {
                    rows: found.rows,
                    timed_out: !any,
                    waited_ms: u64::try_from(waited.as_millis()).unwrap_or(u64::MAX),
                    next: found.next,
                    partial: found.partial,
                    walk_next: found.walk_next,
                    rebindings: Vec::new(),
                });
            }
            std::thread::sleep(POLL * 2);
        }
    }

    /// Checks a row: one not found walks on past a cut first, and only a
    /// read that reached the tree's end shows it absent.
    fn expect(&mut self, input: ExpectInput) -> Result<ExpectOutput, BrowserError> {
        if input.value.is_some() && input.secret.is_some() {
            return Err(BrowserError::Input(
                "an expect names a value or a secret, never both".to_owned(),
            ));
        }
        self.live()?;
        let query = input.query();
        // A desktop row's ref is its locator: a target matches it either way.
        let named = |row: &Row| match &input.target {
            Some(target) => *target == row.target || *target == row.locator,
            None => query.matches(row),
        };
        let first = self.snapshot(false)?;
        let snapshot = self.search(first, None, named)?;
        let partial = snapshot.partial;
        let (rows, originals): (Vec<Row>, Vec<Option<String>>) = snapshot
            .lines
            .into_iter()
            .map(|line| (line.row, line.original))
            .unzip();
        let at = match &input.target {
            Some(target) => match_target(target, &rows, "", None).map(|(at, _)| at),
            None => rows.iter().position(|row| query.matches(row)),
        };
        // A secret is compared with what the window holds, never its handle.
        let met = match (at, input.absent) {
            // Rule 5: no row seen in a read still cut is neither present
            // nor absent, so the check is unmet either way.
            (None, absent) => absent && partial.is_none(),
            (Some(_), true) => false,
            (Some(at), false) => self.secrets.holds(
                rows[at].value.as_deref(),
                originals[at].as_deref(),
                input.value.as_deref(),
                input.secret.as_deref(),
            )?,
        };
        let row = at.map(|at| rows[at].clone());
        Ok(ExpectOutput {
            met,
            row,
            partial,
            rebindings: Vec::new(),
        })
    }

    fn screenshot(&mut self, input: ScreenshotInput) -> Result<ScreenshotOutput, BrowserError> {
        self.live()?;
        // The capture it names, read before this one can age it out.
        let base = capture::compared(&input).and_then(|id| self.held_capture(id));
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
        let png = Arc::new(mask(png, bounds, scale, &secrets)?);
        let frame = Frame {
            left: bounds.x,
            top: bounds.y,
            width: bounds.w,
            height: bounds.h,
            window: key,
            bounds,
            scale,
            source: Arc::clone(&png),
        };
        let url = url_of(&app, key);
        let taken = self.captures.next(Some(capture::Scope {
            shows: format!("window:{}.{}.{}|{url}", self.token, key.pid, key.id),
            rect: [bounds.x, bounds.y, bounds.w, bounds.h],
            scroll: None,
            size: png_dimensions(&png).unwrap_or_default(),
            scale,
            masking: capture::MASKING,
        }));
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
        let (image, width, height, bytes) =
            self.remember(Arc::new(encode_png(&region)?), frame, None)?;
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
        let (image, width, height, bytes) =
            self.remember(Arc::new(encode_png(&zoomed)?), frame, None)?;
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
        let started = Instant::now();
        self.begin_verb();
        self.live()?;
        let snapshot = match input.target.as_deref() {
            Some(target) => self.reach(target)?,
            None => self.snapshot(false)?,
        };
        let aimed = input
            .target
            .as_deref()
            .map(|target| Self::token(&snapshot, target))
            .transpose()?;
        // An activation key aimed at an effect-named control does what a
        // click on it does, and takes its class; any other Return sends.
        let class = aimed
            .as_ref()
            .filter(|_| is_activation(&input.key))
            .and_then(|(line, _)| effect_class(&line.row.name))
            .or_else(|| is_return(&input.key).then_some(EFFECT_SEND));
        let row = aimed
            .as_ref()
            .map_or_else(|| key_row(&input.key), |(line, _)| line.row.clone());
        let press = self.press_or_hold("key", &input, class, Some(&row), &snapshot)?;
        let key = snapshot.key;
        let mut arguments = json!({"pid": key.pid, "key": input.key, "modifiers": input.modifiers});
        match &aimed {
            Some((_, token)) => arguments["element_token"] = Value::from(token.as_str()),
            None => arguments["window_id"] = Value::from(key.id),
        }
        let base = Base::of(input.base);
        let acted = self.act(&snapshot, &base, |session| {
            session
                .input("press_key", arguments)
                .map_err(|e| refusal(e, input.target.as_deref()))
        });
        let target = aimed.as_ref().map(|(line, _)| &line.row);
        self.sent("key", &snapshot, target, class, press, started, acted)
    }

    fn hotkey(&mut self, input: HotkeyInput) -> Result<Observation, BrowserError> {
        let started = Instant::now();
        self.begin_verb();
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
        let row = key_row(&input.keys.join("+"));
        let press = self.press_or_hold("hotkey", &input, class, Some(&row), &snapshot)?;
        let base = Base::of(input.base);
        let acted = self.act(&snapshot, &base, |session| {
            session
                .input(
                    "hotkey",
                    json!({"pid": key.pid, "window_id": key.id, "keys": input.keys}),
                )
                .map_err(BrowserError::from)
        });
        self.sent("hotkey", &snapshot, None, class, press, started, acted)
    }

    /// A scroll moves the view, not the world: it lands no receipt.
    fn scroll(&mut self, input: ScrollInput) -> Result<Observation, BrowserError> {
        self.begin_verb();
        self.live()?;
        let snapshot = match input.target.as_deref() {
            Some(target) => self.reach(target)?,
            None => self.snapshot(false)?,
        };
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
        let base = Base::of(input.base);
        self.act(&snapshot, &base, |session| {
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
        self.observation(&Base::Whole)
    }

    fn handover(&mut self, input: HandoverInput) -> Result<HandoverOutput, BrowserError> {
        self.live()?;
        // Only a browser records a person's span (CUA E9b).
        if input.demonstrate {
            return Err(BrowserError::Unsupported(
                "a desktop demonstration".to_owned(),
            ));
        }
        // The reason stands whole, as given (FIX 8012): blankness alone
        // refuses it, never its length.
        let reason = input.reason;
        if reason.trim().is_empty() {
            return Err(BrowserError::Input(
                "a handover gives its reason".to_owned(),
            ));
        }
        let asked_at_ms = now_ms();
        self.takeover = Takeover::Waiting {
            reason: reason.clone(),
            asked_at_ms,
        };
        Ok(HandoverOutput {
            reason,
            asked_at_ms,
        })
    }

    fn sent_receipt(&mut self) -> Option<EffectReceipt> {
        self.unread.take()
    }

    fn batch(&mut self, input: BatchInput) -> Result<BatchOutput, BrowserError> {
        let mut decider = self.decider.take();
        // The host's writer, where it lent one (FIX 8899); with none, a
        // Fill's generation stops `writer_unavailable`.
        let writer = self.field_writer.take();
        let lent: &dyn FieldWriter = match writer.as_deref() {
            Some(writer) => writer,
            None => &NoWriter,
        };
        let output = match decider.as_deref_mut() {
            Some(decider) => self.batch_with(input, decider, lent),
            None => self.batch_with(input, &mut NoDecider, lent),
        };
        self.decider = decider;
        self.field_writer = writer;
        let mut output = output?;
        // The batch's last observation pages as an answer pages it, and its
        // failed step's with a cursor of its own (FIX 8044).
        if let Some(observation) = output.observation.take() {
            let page = self.pages.first(observation);
            output.observation = Some(page.observation);
            output.next = page.next;
        }
        if let Some(failed) = output.failed_receipt.as_mut()
            && let Some(observation) = failed.observation.take()
        {
            let page = self.pages.first(observation);
            failed.observation = Some(page.observation);
            failed.next = page.next;
        }
        Ok(output)
    }
}
