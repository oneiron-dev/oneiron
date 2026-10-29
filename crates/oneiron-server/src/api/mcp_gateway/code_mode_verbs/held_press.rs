//! A code run's held browser presses (FIX 10423): the act a refused press
//! held, taken from the run's browser after each call, bound to the code
//! consent wait at the call's own site, and the mark that keeps a parked
//! browser up while its owner's answer is open.
//! `RunGuests::begin_press_call`, `bound_refusal`, `take_held_press` and
//! `hold_stopped_batch` are its call surface.

use super::*;
use oneiron::code_run::CodeConsentBrowserAction;
use oneiron_browser::{HeldPress, PressNeed};

/// Binds the act a press held on a code run's browser `verb` call to the
/// code consent wait at the call's own site, and asks the owner (FIX
/// 10423): the act and its own input, the row it resolved to, its page and
/// guest, and for a batch its answer at the stop (`stopped`). Returns the
/// wait the run parks on. None, and the call answers as before, for a call
/// no code run's site carries (a host door's), a payment, which stays a
/// person's own press in the browser, or a wait that was not minted or
/// asked.
fn hold_press(
    verb: AgentVerb,
    origin: &HostWriteOrigin,
    memory: &Memory<'_>,
    held: HeldPress,
    stopped: Option<&Value>,
) -> Option<oneiron::EntityId> {
    if held.need == PressNeed::PersonOnly {
        return None;
    }
    let action = CodeConsentBrowserAction {
        act: format!("self.browser.{}", held.act),
        operands: held.operands.to_string(),
        class: held.class,
        role: held.role,
        name: held.name,
        locator: held.locator,
        page: held.page,
        session: held.generation,
        need: held.need.as_str().to_owned(),
        stopped: stopped.map(Value::to_string),
    };
    memory
        .clone()
        .with_host_origin(origin.clone())
        .hold_browser_press(verb, action)
        .inspect_err(|error| {
            tracing::warn!(
                code = %error.code,
                message = %error.message,
                "a held browser press bound no wait; the call answers as before"
            );
        })
        .ok()
        .flatten()
}

impl RunBrowser {
    /// The act the run's browser's last refused press held, once (FIX
    /// 10423); none where its guest never started.
    pub(super) fn take_held_press(&self) -> Option<HeldPress> {
        self.session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()?
            .take_held_press()
    }

    /// Records whether the run's browser holds an act whose bound wait its
    /// owner has not answered: its parked seat then idles as an open ask
    /// does (FIX 10423).
    pub(super) fn await_press_answer(&self, awaiting: bool) {
        if let Some(session) = self
            .session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            session.await_press_answer(awaiting);
        }
    }
}

impl RunGuests {
    /// The act the run's browser's last refused press held, once (FIX
    /// 10423).
    pub(super) fn take_held_press(&self) -> Option<HeldPress> {
        self.browser.as_ref()?.take_held_press()
    }

    /// Records whether the run's browser waits on its owner's answer to a
    /// held act (FIX 10423).
    fn await_press_answer(&self, awaiting: bool) {
        if let Some(browser) = &self.browser {
            browser.await_press_answer(awaiting);
        }
    }

    /// Before a call: only this call's held press binds a wait, and a run
    /// that calls again waits on no earlier one.
    pub(super) fn begin_press_call(&self) {
        drop(self.take_held_press());
        self.await_press_answer(false);
    }

    /// A browser call's refusal, once the act its press held binds the
    /// wait at the call's own site: worded as that bound wait. Any other
    /// refusal stands as it is.
    pub(super) fn bound_refusal(
        &self,
        verb: AgentVerb,
        origin: &HostWriteOrigin,
        memory: &Memory<'_>,
        refused: AgentVerbRefusalWords,
    ) -> AgentVerbRefusalWords {
        if let Some(held) = self.take_held_press()
            && refused.code == BrowserError::NeedsPress(String::new()).code()
            && let Some(wait) = hold_press(verb, origin, memory, held, None)
        {
            self.await_press_answer(true);
            return browser_guest::bound_words(refused, wait);
        }
        refused
    }

    /// A batch a press stopped: its held step, `held`, binds the wait at
    /// the call's own site with the batch's answer at the stop, `output`,
    /// and the run parks on it.
    pub(super) fn hold_stopped_batch(
        &self,
        verb: AgentVerb,
        origin: &HostWriteOrigin,
        memory: &Memory<'_>,
        held: Option<HeldPress>,
        output: &Value,
    ) {
        if let Some(held) = held
            && hold_press(verb, origin, memory, held, Some(output)).is_some()
        {
            self.await_press_answer(true);
        }
    }
}
