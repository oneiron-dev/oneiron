use super::*;

impl DesktopSession {
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
        let windows: Vec<WindowKey> = self.listed()?.into_iter().map(|w| w.key).collect();
        let before = print_of(read)?;
        let start = Instant::now();
        act(self)?;
        self.settle(before, start)?;
        let listed = self.listed()?;
        if let Some(opened) = front(&listed, |window| !windows.contains(&window.key)) {
            self.switch(read.key, opened, &listed, WindowSwitchCause::Opened);
            let before = self.fingerprint()?;
            self.settle(before, Instant::now())?;
        }
        self.observation(base)
    }

    pub(super) fn press(
        &mut self,
        class: Option<&str>,
        row: &Row,
    ) -> Result<PressMode, BrowserError> {
        match class {
            Some(class) => press_for(&mut self.policy, class, row),
            None => Ok(PressMode::None),
        }
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
            url: observation.url.clone(),
            title: observation.title.clone(),
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
            source_title: None,
            tab: None,
            result_tab: None,
            result_unread: None,
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
        observation.receipt = Some(receipt);
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
    /// line breaks take (a Return sends): the class and press it ran under,
    /// and the settled window.
    pub(super) fn enter(
        &mut self,
        typing: &Typing<'_>,
        row: &Row,
        text: &str,
    ) -> Result<(Option<&'static str>, PressMode, Observation), BrowserError> {
        // A line break can press Return, and a Return sends.
        let class = text
            .contains(|c: char| c == '\n' || c == '\r')
            .then_some(EFFECT_SEND);
        let press = self.press(class, row)?;
        let (pid, token) = (typing.read.key.pid, typing.token);
        let observation = self.act(typing.read, typing.base, |session| {
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
        })?;
        Ok((class, press, observation))
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
