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
/// 10423): the act and its own input, the row it resolved to, its page,
/// tab, document and guest, and the call's answer as the act found it
/// (`stopped`: a batch's at its stop, or the page a lone act began on).
/// Returns the wait the run parks on. None, and the call answers as
/// before, for a call no code run's site carries (a host door's), a
/// payment, which stays a person's own press in the browser, or a wait
/// that was not minted or asked.
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
        tab: held.tab,
        document: held.document,
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

    /// The page as a held act found it (FIX 10423), as a click's answer
    /// reads: a whole read that ages no base the caller reads by, for its
    /// run to resume with when the act does not run. None where the page
    /// does not read.
    pub(super) fn held_page(&self) -> Option<Value> {
        let mut session = self.session.lock().unwrap_or_else(PoisonError::into_inner);
        let driver = session.as_mut()?;
        let observation = driver.observe_hidden().ok()?;
        let page = oneiron_browser::ObservationPage::whole(observation);
        let mut answer = serde_json::to_value(oneiron_browser::BrowserAnswer::of(page)).ok()?;
        let object = answer.as_object_mut()?;
        object.insert(
            "session_manifest".into(),
            serde_json::to_value(driver.manifest()).ok()?,
        );
        object.insert("engine".into(), Value::from(driver.engine().as_str()));
        Some(answer)
    }

    /// Records the wait an act the run's browser held is bound to: while
    /// that wait is open, its parked seat idles as an open ask does (FIX
    /// 10423).
    pub(super) fn await_press_answer(&self, wait: Option<oneiron::EntityId>) {
        if let Some(session) = self
            .session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            session.await_press_answer(wait.map(|wait| wait.to_hex()));
        }
    }
}

impl RunGuests {
    /// The act the run's browser's last refused press held, once (FIX
    /// 10423).
    pub(super) fn take_held_press(&self) -> Option<HeldPress> {
        self.browser.as_ref()?.take_held_press()
    }

    /// Records the wait an act the run's browser held is bound to (FIX
    /// 10423).
    fn await_press_answer(&self, wait: Option<oneiron::EntityId>) {
        if let Some(browser) = &self.browser {
            browser.await_press_answer(wait);
        }
    }

    /// Before a call: only this call's held press binds a wait, and a run
    /// that calls again waits on no earlier one.
    pub(super) fn begin_press_call(&self) {
        drop(self.take_held_press());
        self.await_press_answer(None);
    }

    /// A browser call's refusal, once the act its press held binds the
    /// wait at the call's own site with the page it began on: worded as
    /// that bound wait. Any other refusal stands as it is, and so does one
    /// whose page does not read.
    pub(super) fn bound_refusal(
        &self,
        verb: AgentVerb,
        origin: &HostWriteOrigin,
        memory: &Memory<'_>,
        refused: AgentVerbRefusalWords,
    ) -> AgentVerbRefusalWords {
        if let Some(held) = self.take_held_press()
            && refused.code == BrowserError::NeedsPress(String::new()).code()
            && let Some(page) = self.browser.as_ref().and_then(RunBrowser::held_page)
            && let Some(wait) = hold_press(verb, origin, memory, held, Some(&page))
        {
            self.await_press_answer(Some(wait));
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
            && let Some(wait) = hold_press(verb, origin, memory, held, Some(output))
        {
            self.await_press_answer(Some(wait));
        }
    }
}
