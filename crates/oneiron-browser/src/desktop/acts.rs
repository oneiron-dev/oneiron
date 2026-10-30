use super::*;

/// What a read of a window shows of its rows' places, as one hash
/// (`desktop_scroll_proof_policy`, CALLS row, FIX 10430): the window, then
/// each row's locator and its frame on screen less the window's own place,
/// in row order. Two reads of one window that differ show rows that moved,
/// as a scroll that moved the view does; a window moved whole shows its
/// rows where they were. A cut walk, a read with no tree, or one whose rows
/// carry no frame proves nothing: none.
pub(super) fn desktop_scroll_proof_policy(snapshot: &Snapshot) -> Option<[u8; 32]> {
    if snapshot.partial.is_some()
        || snapshot.no_tree
        || snapshot.lines.iter().all(|line| line.frame.is_none())
    {
        return None;
    }
    let (left, top) = snapshot
        .bounds
        .as_ref()
        .map_or((0.0, 0.0), |at| (at.x, at.y));
    let mut hasher = blake3::Hasher::new();
    hasher.update(snapshot.key.name().as_bytes());
    for line in &snapshot.lines {
        hasher.update(b"\n");
        hasher.update(line.row.locator.as_bytes());
        if let Some(frame) = &line.frame {
            for value in [frame.x - left, frame.y - top, frame.w, frame.h] {
                hasher.update(&value.to_bits().to_le_bytes());
            }
        }
    }
    Some(*hasher.finalize().as_bytes())
}

impl DesktopSession {
    /// A new effect verb keeps no earlier verb's unread receipt (FIX
    /// 12134), as a browser session's verb entry clears it: a stale one is
    /// never stamped on this verb's stop.
    pub(super) fn begin_verb(&mut self) {
        self.unread = None;
        self.input_sent = false;
    }

    /// Runs `act` on the desktop as `read` saw it, then returns the settled
    /// window as an edit of `base`, or whole when the act opened a window in
    /// front: that window is where the next step reads, and the move is kept
    /// for the agent's next answer as [`Self::switch`] keeps it. No read comes
    /// between `read` and the act, since each read retires the last one's
    /// tokens.
    pub(super) fn act(
        &mut self,
        read: &Snapshot,
        base: &Base,
        act: impl FnOnce(&Self) -> Result<(), BrowserError>,
    ) -> Result<Observation, BrowserError> {
        self.begin_verb();
        let windows: Vec<WindowKey> = self.listed()?.into_iter().map(|w| w.key).collect();
        let before = print_of(read)?;
        let start = Instant::now();
        let acted = act(self);
        // Sent: a failure from here on leaves the effect standing (FIX
        // 12134).
        self.input_sent = acted.is_ok();
        acted?;
        self.settle(before, start)?;
        let listed = self.listed()?;
        if let Some(opened) = front(&listed, |window| !windows.contains(&window.key)) {
            self.switch(read.key, opened, &listed, WindowSwitchCause::Opened);
            let before = self.fingerprint()?;
            self.settle(before, Instant::now())?;
        }
        self.observation(base)
    }

    /// Stamps `observation` with the receipt of the effect that made it,
    /// which its verb entered at `started`. The receipt's screenshot is
    /// best-effort: an effect that already happened is receipted even when
    /// its evidence could not be captured.
    pub(super) fn receipt(
        &mut self,
        verb: &str,
        target: Option<&Row>,
        effect_class: Option<&str>,
        press: PressMode,
        observation: &mut Observation,
        started: Instant,
    ) {
        let receipt = self.land(
            verb,
            target,
            effect_class,
            press,
            &observation.url,
            &observation.title,
            None,
            started,
        );
        observation.receipt = Some(receipt);
    }

    /// An effect verb's act answer (FIX 12134, the desktop twin of the
    /// browser session's FIX 8010 rule): an input the guest took stands
    /// even when settling or reading the window after it failed. Its
    /// receipt lands then, naming the window as the act's read `read` saw
    /// it and the failure's code, kept for the host to take once through
    /// `sent_receipt`; the input is never sent again. A failure before
    /// the send lands none.
    pub(super) fn sent(
        &mut self,
        verb: &str,
        read: &Snapshot,
        target: Option<&Row>,
        effect_class: Option<&str>,
        press: PressMode,
        started: Instant,
        answer: Result<Observation, BrowserError>,
    ) -> Result<Observation, BrowserError> {
        match answer {
            Ok(mut observation) => {
                self.receipt(verb, target, effect_class, press, &mut observation, started);
                Ok(observation)
            }
            Err(error) => {
                if self.input_sent {
                    let title = self
                        .secrets
                        .mask_known(&read.title)
                        .unwrap_or_else(|| read.title.clone());
                    let receipt = self.land(
                        verb,
                        target,
                        effect_class,
                        press,
                        &url_of(&read.app, read.key),
                        &title,
                        Some(error.code().to_owned()),
                        started,
                    );
                    self.unread = Some(receipt);
                }
                Err(error)
            }
        }
    }

    /// Lands `verb`'s receipt, as the window it left at `url`/`title`
    /// (shown, so a secret rides it by its handle alone), in the session's
    /// receipts and the host's evidence; `result_unread` names the failure
    /// of the read after a sent input (FIX 12134), where there was one.
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is one fact a receipt keeps"
    )]
    fn land(
        &mut self,
        verb: &str,
        target: Option<&Row>,
        effect_class: Option<&str>,
        press: PressMode,
        url: &str,
        title: &str,
        result_unread: Option<String>,
        started: Instant,
    ) -> EffectReceipt {
        self.receipt_seq += 1;
        // Never compared: each receipt's screenshot is a capture of its own.
        let (screenshot, capture_id) = self
            .screenshot(ScreenshotInput {
                trigger: ScreenshotTrigger::EffectReceipt,
                since_capture: None,
            })
            .ok()
            .map(|shot| (shot.image, shot.capture_id))
            .unzip();
        let mut receipt = EffectReceipt {
            seq: self.receipt_seq,
            verb: verb.to_owned(),
            url: url.to_owned(),
            title: title.to_owned(),
            target: target.map(|row| row.target.clone()),
            target_name: target.map(|row| row.name.clone()),
            target_locator: target.map(|row| row.locator.clone()),
            rebound: None,
            effect_class: effect_class.map(str::to_owned),
            press: press.as_str().to_owned(),
            screenshot,
            capture_id,
            screenshot_evidence: None,
            engine: None,
            fact: None,
            engine_switch: None,
            text_source: None,
            text_ref: None,
            // A desktop act replays in no browser program (CUA E7).
            action: None,
            source_url: None,
            source_origin: None,
            audience: None,
            source_title: None,
            tab: None,
            result_tab: None,
            result_unread,
            outcome: None,
            // Stamped before the host keeps the screenshot.
            duration_ms: elapsed_ms(started),
        };
        // A type's text provenance, before the host keeps the receipt (FIX
        // 8899): a Fill's own, else supplied.
        if verb == "type" {
            let typed = self.provenance.take();
            typed
                .unwrap_or_else(TextProvenance::supplied)
                .stamp(&mut receipt);
        }
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
        receipt
    }

    /// Holds `png`, showing `frame`, under its content ref, with its
    /// `capture` when it is a screenshot; returns ref, width, height, bytes.
    pub(super) fn remember(
        &mut self,
        png: Arc<Vec<u8>>,
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
    /// ref again, and its own frame is the one the window stands at now.
    pub(super) fn held(&self, image: &str) -> Result<(Vec<u8>, Frame), BrowserError> {
        self.media
            .iter()
            .rev()
            .find(|held| held.image == image)
            .map(|held| (held.png.to_vec(), held.frame.clone()))
            .ok_or_else(|| BrowserError::NoImage(image.to_owned()))
    }

    /// The held screenshot capture `id` names, with its content ref.
    pub(super) fn held_capture(&self, id: &str) -> Option<(String, Capture)> {
        self.media.iter().find_map(|held| {
            let capture = held.capture.as_ref().filter(|capture| capture.id == id)?;
            Some((held.image.clone(), capture.clone()))
        })
    }

    /// Types `text` into the field `typing` names, under the press its
    /// line breaks take (a Return sends): the settled window, receipted as
    /// every type is (its type began at `started`).
    pub(super) fn enter(
        &mut self,
        typing: &Typing<'_>,
        row: &Row,
        text: &str,
        operands: &Value,
        started: Instant,
    ) -> Result<Observation, BrowserError> {
        // A line break can press Return, and a Return sends.
        let class = text
            .contains(|c: char| c == '\n' || c == '\r')
            .then_some(EFFECT_SEND);
        let press = self.press_or_hold("type", operands, class, Some(row), typing.read)?;
        let (pid, token) = (typing.read.key.pid, typing.token);
        let acted = self.act(typing.read, typing.base, |session| {
            let refused = |error: ToolError| refusal(error, Some(typing.target));
            if typing.clear {
                for (key, modifiers) in [("a", vec!["ctrl"]), ("backspace", Vec::new())] {
                    session
                        .input(
                            "press_key",
                            json!({"pid": pid, "element_token": token, "key": key, "modifiers": modifiers}),
                        )
                        .map_err(refused)?;
                }
            }
            if !text.is_empty() {
                session
                    .input(
                        "type_text",
                        json!({"pid": pid, "element_token": token, "text": text}),
                    )
                    .map_err(refused)?;
            }
            Ok(())
        });
        self.sent("type", typing.read, Some(row), class, press, started, acted)
    }

    /// The element token of the row `target` names, as read now.
    pub(super) fn token(snapshot: &Snapshot, target: &str) -> Result<(Line, String), BrowserError> {
        let line = snapshot.line(target)?;
        let token = line
            .token
            .clone()
            .ok_or_else(|| BrowserError::Covered(target.to_owned()))?;
        Ok((line, token))
    }
}
