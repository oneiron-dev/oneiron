//! The act a desktop press held, kept for the host to bind (FIX 11499),
//! and the one press an owner's answer arms for it: the desktop twin of
//! the browser session's holds (`session/held.rs`), under the same rule
//! that an armed press runs its exact act and never moves to another
//! target.
//!
//! A desktop act has no tab, page or document, so its hold names what
//! stands for them: the window by its key (`tab`), the window's place as
//! an observation names it ([`url_of`], as `page`), and no document, for
//! a desktop row has no live handle. A click at a point with no row under
//! it (the floor press in `point.rs`) holds nothing: it names no row the
//! answered pass could resolve again, so it binds no wait (CALLS).

use serde::Serialize;

use super::*;
use crate::{HeldPress, PressNeed};

/// The session's held act and its armed press.
#[derive(Default)]
pub(super) struct PressHolds {
    /// The last act a press held, until the host takes it.
    last: Option<HeldPress>,
    /// The one press an owner's answer armed, for its exact act.
    armed: Option<HeldPress>,
    /// The wait the host bound a held act to, by its id, until a press is
    /// armed or the run calls again.
    awaiting: Option<String>,
}

impl DesktopSession {
    /// The act the session's last refused press held, once: the host binds
    /// it after the call that refused it.
    pub fn take_held_press(&mut self) -> Option<HeldPress> {
        self.press_holds.last.take()
    }

    /// Arms one press for exactly `held`'s act, as an owner's answer gives
    /// it: the next press check takes it. `false` for a class only a
    /// person's own press runs, which no answer arms.
    pub fn arm_press(&mut self, held: HeldPress) -> bool {
        if SendPolicy::person_only(&held.class) {
            return false;
        }
        self.press_holds.awaiting = None;
        self.press_holds.armed = Some(held);
        true
    }

    /// Records the wait, by its id, an act this session held is bound to:
    /// the host sets it once it bound the act, and clears it when its run
    /// calls again. An armed press clears it too.
    pub fn await_press_answer(&mut self, wait: Option<String>) {
        self.press_holds.awaiting = wait;
    }

    /// The wait an act this session held is bound to, by its id; whether
    /// its owner still has to answer is the wait's own to say.
    #[must_use]
    pub fn press_wait(&self) -> Option<&str> {
        self.press_holds.awaiting.as_deref()
    }

    /// Drops an armed press no press check took. `true` when one was armed.
    pub fn disarm_press(&mut self) -> bool {
        self.press_holds.armed.take().is_some()
    }

    /// The policy a classified send runs under now: the grants read again
    /// where the host reads them live, less the sends already paid, as a
    /// browser session's press runs (FIX 4613, 4615, 12133). With no live
    /// read given, it is the policy as last set, less those paid sends.
    pub(super) fn press_policy(&mut self) -> &mut SendPolicy {
        self.policy = self.presses.refresh();
        &mut self.policy
    }

    /// The press act `act` of `class` on `row`, given `operands` (the
    /// act's own input as its verb received it), runs under on the window
    /// `read` read. An armed press is taken first: the same act, with the
    /// same input, resolved to the same row of the same window of the same
    /// guest, runs under it, a person's press per send that pays no batch,
    /// and any other act is refused. With none armed, a classified act
    /// takes its grant's press, and one refused keeps what it was for the
    /// host; an act no class marks needs none.
    pub(super) fn press_or_hold(
        &mut self,
        act: &str,
        operands: &impl Serialize,
        class: Option<&str>,
        row: Option<&Row>,
        read: &Snapshot,
    ) -> Result<PressMode, BrowserError> {
        let page = url_of(&read.app, read.key);
        let tab = read.key.name();
        if let Some(armed) = self.press_holds.armed.take() {
            let same = class.zip(row).is_some_and(|(class, row)| {
                armed.act == act
                    && armed.class == class
                    && armed.role == row.role
                    && armed.name == row.name
                    && armed.locator == row.locator
                    && armed.page.as_deref() == Some(page.as_str())
                    && armed.tab == tab
                    && armed.generation == self.manifest.generation
                    && serde_json::to_value(operands).is_ok_and(|given| given == armed.operands)
            });
            if same {
                return Ok(PressMode::PerSend);
            }
            let target = row.map_or_else(
                || "the point's row".to_owned(),
                |row| format!("{} \"{}\"", row.role, row.name),
            );
            return Err(BrowserError::NeedsPress(format!(
                "{target}, not the {} \"{}\" ({}) its press was given for",
                armed.role, armed.name, armed.class
            )));
        }
        let (Some(class), Some(row)) = (class, row) else {
            return Ok(PressMode::None);
        };
        let pressed = press_for(self.press_policy(), class, row);
        if let Ok(PressMode::PerBatch) = pressed {
            self.presses.paid(class);
        }
        if pressed.is_err() {
            let need = if SendPolicy::person_only(class) {
                PressNeed::PersonOnly
            } else if self.policy.mode_for(class) == PressMode::PerBatch {
                PressNeed::BatchSpent
            } else {
                PressNeed::PerSend
            };
            self.press_holds.last = Some(HeldPress {
                act: act.to_owned(),
                operands: serde_json::to_value(operands).unwrap_or_default(),
                class: class.to_owned(),
                role: row.role.clone(),
                name: row.name.clone(),
                locator: row.locator.clone(),
                page: Some(page),
                tab,
                document: None,
                generation: self.manifest.generation.clone(),
                need,
            });
        }
        pressed
    }
}
