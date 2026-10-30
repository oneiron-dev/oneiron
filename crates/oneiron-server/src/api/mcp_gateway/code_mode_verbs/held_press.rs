//! A code run's held browser and desktop presses (FIX 10423, FIX 11499):
//! the act a refused press held, taken from the run's guest after each
//! call, bound to the code consent wait at the call's own site, and the
//! mark that keeps a parked guest up while its owner's answer is open.
//! `RunGuests::begin_press_call`, `bound_refusal`, `take_held_press` and
//! `hold_stopped_batch` are its call surface.

use super::*;
use oneiron::code_run::CodeConsentBrowserAction;
use oneiron::runtime_hooks::{VerbHookPre, VerbHookPreSnapshot};
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
    hook_pre: Option<VerbHookPreSnapshot>,
) -> Option<oneiron::EntityId> {
    if held.need == PressNeed::PersonOnly {
        return None;
    }
    let family = if verb.as_str().starts_with("self.desktop.") {
        "self.desktop"
    } else {
        "self.browser"
    };
    let action = CodeConsentBrowserAction {
        act: format!("{family}.{}", held.act),
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
        hook_pre,
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

impl RunDesktop {
    /// The act the run's desktop's last refused press held, once (FIX
    /// 11499); none where its guest never started.
    pub(super) fn take_held_press(&self) -> Option<HeldPress> {
        self.session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()?
            .take_held_press()
    }

    /// The window as a held act found it (FIX 11499), as a desktop click's
    /// answer reads: [`RunBrowser::held_page`] for the desktop, which
    /// carries no engine line.
    pub(super) fn held_page(&self) -> Option<Value> {
        let mut session = self.session.lock().unwrap_or_else(PoisonError::into_inner);
        let driver = session.as_mut()?;
        let observation = driver.observe_hidden().ok()?;
        let page = oneiron_browser::ObservationPage::whole(observation);
        let mut answer = serde_json::to_value(oneiron_browser::DesktopAnswer::of(page)).ok()?;
        let object = answer.as_object_mut()?;
        object.insert(
            "session_manifest".into(),
            serde_json::to_value(driver.manifest()).ok()?,
        );
        Some(answer)
    }

    /// Records the wait an act the run's desktop held is bound to (FIX
    /// 11499).
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
    /// The act the run's guest's last refused press held, once (FIX
    /// 10423, FIX 11499): the browser's first, then the desktop's; one
    /// call drives one guest, so at most one holds.
    pub(super) fn take_held_press(&self) -> Option<HeldPress> {
        self.browser
            .as_ref()
            .and_then(RunBrowser::take_held_press)
            .or_else(|| self.desktop.as_ref().and_then(RunDesktop::take_held_press))
    }

    /// Records the wait an act the call of `verb` held is bound to, on
    /// that verb's guest (FIX 10423, FIX 11499).
    fn await_press_answer(&self, verb: AgentVerb, wait: Option<oneiron::EntityId>) {
        if verb.as_str().starts_with("self.desktop.") {
            if let Some(desktop) = &self.desktop {
                desktop.await_press_answer(wait);
            }
        } else if let Some(browser) = &self.browser {
            browser.await_press_answer(wait);
        }
    }

    /// The page or window as a held act of `verb` found it, from that
    /// verb's guest.
    fn held_page(&self, verb: AgentVerb) -> Option<Value> {
        if verb.as_str().starts_with("self.desktop.") {
            self.desktop.as_ref().and_then(RunDesktop::held_page)
        } else {
            self.browser.as_ref().and_then(RunBrowser::held_page)
        }
    }

    /// Before a call: only this call's held press binds a wait, and a run
    /// that calls again waits on no earlier one.
    pub(super) fn begin_press_call(&self) {
        if let Some(browser) = &self.browser {
            drop(browser.take_held_press());
            browser.await_press_answer(None);
        }
        if let Some(desktop) = &self.desktop {
            drop(desktop.take_held_press());
            desktop.await_press_answer(None);
        }
    }

    /// A guest call's refusal, once the act its press held binds the
    /// wait at the call's own site with the page it began on: worded as
    /// that bound wait. Any other refusal stands as it is, and so does one
    /// whose page does not read.
    pub(super) fn bound_refusal(
        &self,
        verb: AgentVerb,
        origin: &HostWriteOrigin,
        memory: &Memory<'_>,
        pre: &VerbHookPre,
        refused: AgentVerbRefusalWords,
    ) -> AgentVerbRefusalWords {
        if let Some(held) = self.take_held_press()
            && refused.code == BrowserError::NeedsPress(String::new()).code()
            && let Some(page) = self.held_page(verb)
            && let Some(wait) = hold_press(
                verb,
                origin,
                memory,
                held,
                Some(&page),
                VerbHookPreSnapshot::from_pre(pre),
            )
        {
            self.await_press_answer(verb, Some(wait));
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
        hook_pre: Option<VerbHookPreSnapshot>,
        output: &Value,
    ) {
        if let Some(held) = held
            && let Some(wait) = hold_press(verb, origin, memory, held, Some(output), hook_pre)
        {
            self.await_press_answer(verb, Some(wait));
        }
    }
}
