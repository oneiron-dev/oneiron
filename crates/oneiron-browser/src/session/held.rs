//! The act a press held, kept for the host to bind (FIX 10423), and the one
//! press an owner's answer arms for it.
//!
//! A classified act whose grant gives it no press is refused as before, and
//! the session keeps what that act was: its verb and its own input, the row
//! it resolved to, the page it began on, the guest it ran in, and why its
//! grant gave no press. The host takes it after the call ([`take_held_press`])
//! and may bind it to a consent wait.
//!
//! An owner's answer arms one press for that exact act ([`arm_press`]). The
//! next press check takes it, whatever it meets: the same act, with the same
//! input, resolved to the same row on the same page of the same guest, runs
//! under that person's press, which pays no reviewed batch; any other act is
//! refused as needing a press, so the press never moves to another target. A
//! payment is a person's own act: no answer arms a press for it.
//!
//! [`take_held_press`]: BrowserSession::take_held_press
//! [`arm_press`]: BrowserSession::arm_press

use super::BrowserSession;
use crate::{BrowserError, PressMode, Row, SendPolicy};
use serde::{Deserialize, Serialize};

/// Why a held act's grant gave it no press.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PressNeed {
    /// Its class runs under a press per send.
    PerSend,
    /// Its class runs under a reviewed batch's press, and the batch is spent.
    BatchSpent,
    /// Its class is a person's own act (a payment): only a person's press in
    /// the browser runs it.
    PersonOnly,
}

impl PressNeed {
    /// The stable word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PerSend => "per_send",
            Self::BatchSpent => "batch_spent",
            Self::PersonOnly => "person_only",
        }
    }
}

/// One act a press held, as its session froze it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HeldPress {
    /// The session verb of the act: `click` or `click_at`.
    pub act: String,
    /// The act's own input, as it was given to the verb.
    pub operands: serde_json::Value,
    /// The effect class the row's name marks on its page.
    pub class: String,
    /// The row the act resolved to: its role, name and locator.
    pub role: String,
    pub name: String,
    pub locator: String,
    /// The page the act began on.
    pub page: Option<String>,
    /// The guest the act ran in, by its manifest's generation.
    pub generation: String,
    pub need: PressNeed,
}

/// The session's held act and its armed press.
#[derive(Default)]
pub(super) struct Holds {
    /// The last act a press held, until the host takes it.
    last: Option<HeldPress>,
    /// The one press an owner's answer armed, for its exact act.
    armed: Option<HeldPress>,
    /// The host bound a held act to a wait its owner has not answered.
    awaiting: bool,
}

impl BrowserSession {
    /// The act the session's last refused press held, once: the host binds
    /// it after the call that refused it.
    pub fn take_held_press(&mut self) -> Option<HeldPress> {
        self.held.last.take()
    }

    /// Arms one press for exactly `held`'s act, as an owner's answer gives
    /// it: the next press check takes it. `false` for a class only a
    /// person's press in the browser runs, which no answer arms.
    pub fn arm_press(&mut self, held: HeldPress) -> bool {
        if SendPolicy::person_only(&held.class) {
            return false;
        }
        self.held.awaiting = false;
        self.held.armed = Some(held);
        true
    }

    /// Records whether an act this session held waits on its owner's
    /// answer: the host sets it once it bound the act to a wait, and clears
    /// it when its run calls again. An armed press clears it too.
    pub fn await_press_answer(&mut self, awaiting: bool) {
        self.held.awaiting = awaiting;
    }

    /// Whether an act this session held waits on its owner's answer.
    #[must_use]
    pub const fn awaits_press_answer(&self) -> bool {
        self.held.awaiting
    }

    /// Drops an armed press no press check took. `true` when one was armed.
    pub fn disarm_press(&mut self) -> bool {
        self.held.armed.take().is_some()
    }

    /// The press act `act` of `class` on `row`, given `operands`, runs
    /// under on page `page`. An armed press is taken first: the same act on
    /// the same row runs under it, a person's press per send that pays no
    /// batch, and any other act is refused. With none armed, a classified
    /// act takes its grant's press ([`Self::press_for`]), and one refused
    /// keeps what it was for the host; an act no class marks needs none.
    pub(super) fn press_or_hold(
        &mut self,
        act: &str,
        operands: &impl Serialize,
        class: Option<&str>,
        row: Option<&Row>,
        page: Option<&str>,
    ) -> Result<PressMode, BrowserError> {
        if let Some(armed) = self.held.armed.take() {
            let same = class.zip(row).is_some_and(|(class, row)| {
                armed.act == act
                    && armed.class == class
                    && armed.role == row.role
                    && armed.name == row.name
                    && armed.locator == row.locator
                    && armed.page.as_deref() == page
                    && armed.generation == self.manifest.generation
                    && serde_json::to_value(operands).is_ok_and(|given| given == armed.operands)
            });
            if same {
                return Ok(PressMode::PerSend);
            }
            self.press_refused = class.map(str::to_owned);
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
        let pressed = self.press_for(class, row);
        if pressed.is_err() {
            let need = if SendPolicy::person_only(class) {
                PressNeed::PersonOnly
            } else if self.policy.mode_for(class) == PressMode::PerBatch {
                PressNeed::BatchSpent
            } else {
                PressNeed::PerSend
            };
            self.held.last = Some(HeldPress {
                act: act.to_owned(),
                operands: serde_json::to_value(operands).unwrap_or_default(),
                class: class.to_owned(),
                role: row.role.clone(),
                name: row.name.clone(),
                locator: row.locator.clone(),
                page: page.map(str::to_owned),
                generation: self.manifest.generation.clone(),
                need,
            });
        }
        pressed
    }
}
