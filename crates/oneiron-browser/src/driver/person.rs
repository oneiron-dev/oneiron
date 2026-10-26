use super::*;
use base64::Engine as _;

impl CdpDriver {
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
}
