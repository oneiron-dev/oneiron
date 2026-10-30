//! The change check (FIX 6680, BROWSER-SPLIT). Right before an act sends
//! its input, after the driver's own setup (its scroll, hit test and
//! focus), the driver marks the page: its URL, its scroll position, the
//! documents it shows, its DOM mutations so far, its navigation events so
//! far, its open tabs and, for a type or select, the target's value. After
//! the input it reads them again, at the driver's poll, until one moved or
//! [`CHANGE_CHECK_WINDOW`] ends. A page on which one moved goes on as every
//! act always has: it settles, its tabs are followed, and it is read. A page
//! on which none moved answers at once, unsettled, with an [`ActionFact`].
//!
//! Only a read of every signal proves a page unchanged. A read that fails,
//! or that does not answer within the window (one deadline bounds the reads
//! too), proves nothing: the act goes on as it always did, with no fact.
//! An `open` whose navigate answered with a new document, or that started
//! a navigation, changed the page however slowly it then loads; only a
//! navigate that answered with no error and started nothing reads as no
//! effect.
//!
//! The DOM's mutations are counted by one `MutationObserver` per document,
//! started by the first mark on it, in the driver's own isolated world
//! ([`CHANGE_WORLD`]) where the engine makes one, so the page's scripts
//! never see it (FIX 6764); an engine that makes none keeps it in the
//! page's world, as before. A click on a row reads its control's state too
//! (checked, selected, its ARIA states), which no DOM mutation shows (FIX
//! 8006); and a fact the act's own observation contradicts (its outline
//! moved) is dropped by the act.
//!
//! Where the session keeps storage snapshots, the mark's one evaluation also
//! reads the page's stores (`storage`, BROWSER-SPLIT PR3b); that part is
//! taken off before the mark is kept, so the check compares only what it
//! always did, and the polls never read it.

use super::storage::{MarkRead, split_mark};
use super::{CdpDriver, POLL, target_id};
use crate::{ActionFact, ActionTarget, BrowserEngine, NoEffectReason, Row, ViewportPoint};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

/// How long after an act's input its page is watched for a change before
/// the act answers with its fact, and the deadline of every read the watch
/// takes, its mark's included.
pub(crate) const CHANGE_CHECK_WINDOW: Duration = Duration::from_millis(1000);

/// The page's own signals, read in one evaluation: its URL, its scroll
/// position and its document's DOM mutations so far. The first read on a
/// document starts its count.
const PAGE_SIGNALS: &str = "(() => { const d = document; let s = d.oneironChange; if (!s) { s = {n: 0}; s.o = new MutationObserver(r => { s.n += r.length; }); s.o.observe(d, {subtree: true, childList: true, attributes: true, characterData: true}); Object.defineProperty(d, 'oneironChange', {value: s}); } s.n += s.o.takeRecords().length; return [location.href, scrollX, scrollY, s.n]; })()";

/// The isolated world the change check's observer lives in, apart from the
/// page's scripts and from every other world the driver makes.
const CHANGE_WORLD: &str = "oneironChange";

/// A clicked control's state, which a toggle moves without a DOM mutation:
/// its checked, selected and indeterminate properties and its ARIA states.
const CONTROL_STATE: &str = "function() { const a = n => this.getAttribute(n); return [this.checked, this.selected, this.indeterminate, this.value, a('aria-checked'), a('aria-pressed'), a('aria-selected'), a('aria-expanded')]; }";

/// What one act's change check watches, and names in its fact. A row's
/// node reads on its own frame session beside it (FIX 11576).
pub(super) enum Watch<'a> {
    /// A click on a row, its node's state read too, or at a point.
    Click(ActionTarget, Option<(&'a Value, &'a str)>),
    /// A type or select into a row: its value too, read off its node.
    Entry(ActionTarget, &'a Value, &'a str),
    /// An open of a URL.
    Navigate(String),
}

impl Watch<'_> {
    /// The fact a page unchanged for `watched` after the input proves.
    fn fact(&self, engine: BrowserEngine, watched: Duration) -> ActionFact {
        let reason = NoEffectReason::NoObservableChange;
        let window_ms = u64::try_from(watched.as_millis()).unwrap_or(u64::MAX);
        match self {
            Self::Click(target, _) => ActionFact::ClickNoEffect {
                engine,
                target: target.clone(),
                reason,
                window_ms,
            },
            Self::Entry(target, ..) => ActionFact::TypeNoEffect {
                engine,
                target: target.clone(),
                reason,
                window_ms,
            },
            Self::Navigate(url) => ActionFact::NavigateNoEffect {
                engine,
                url: url.clone(),
                reason,
                window_ms,
            },
        }
    }
}

/// Every signal of the page at one read.
#[derive(PartialEq)]
pub(super) struct Mark {
    /// The URL, scroll position and DOM mutation count, as one evaluation
    /// answered them.
    page: Value,
    /// The target's value, for a type or select; its control's state, for
    /// a click on a row.
    value: Value,
    documents: String,
    navigations: u64,
    tabs: Vec<String>,
}

/// The target a receipt names for `row`: its handle, name and locator.
pub(super) fn row_target(row: &Row) -> ActionTarget {
    ActionTarget {
        target: Some(row.target.clone()),
        name: Some(row.name.clone()),
        locator: Some(row.locator.clone()),
        point: None,
    }
}

/// The target of a click at viewport point (`x`, `y`): the point, and the
/// row there when one covers it.
pub(super) fn point_target(x: f64, y: f64, row: Option<&Row>) -> ActionTarget {
    ActionTarget {
        target: row.map(|row| row.target.clone()),
        name: row.map(|row| row.name.clone()),
        locator: row.map(|row| row.locator.clone()),
        point: Some(ViewportPoint { x, y }),
    }
}

/// Whether a navigate's answer names the new document it started.
pub(super) fn navigation_started(answer: &Value) -> bool {
    answer
        .get("loaderId")
        .and_then(Value::as_str)
        .is_some_and(|loader| !loader.is_empty())
}

impl CdpDriver {
    /// The page's signals right before an act's input; none when a read
    /// failed or did not answer in the window, and the act then proves
    /// nothing. The page's stores, read with them, go to the session's
    /// snapshots.
    pub(super) fn mark(&self, watch: &Watch<'_>) -> Option<Mark> {
        let deadline = Instant::now() + CHANGE_CHECK_WINDOW;
        let mut read = MarkRead::NotRun;
        let mark = self.signals(watch, deadline, Some(&mut read));
        self.keep_mark_read(read, deadline);
        mark
    }

    /// Reads the page at the driver's poll from `sent`, when the input
    /// went, against its `mark`: the fact, once every signal read the same
    /// until the window's end; none at the first that moved, and none at a
    /// read that failed or did not answer by the window's end.
    pub(super) fn no_effect(
        &self,
        mark: &Mark,
        watch: &Watch<'_>,
        sent: Instant,
    ) -> Option<ActionFact> {
        let deadline = sent + CHANGE_CHECK_WINDOW;
        loop {
            std::thread::sleep(POLL);
            if self.signals(watch, deadline, None)? != *mark {
                return None;
            }
            let watched = sent.elapsed();
            if watched + POLL >= CHANGE_CHECK_WINDOW {
                return Some(watch.fact(self.engine, watched));
            }
        }
    }

    /// Every signal of the front tab, each read answered by `deadline`;
    /// for a mark, its `stores` read too, taken off the page's signals.
    fn signals(
        &self,
        watch: &Watch<'_>,
        deadline: Instant,
        stores: Option<&mut MarkRead>,
    ) -> Option<Mark> {
        // A tab whose navigation events are not counted proves nothing.
        let navigations = self.pipe.navigations(&self.session)?;
        let marked = stores.and_then(|read| {
            let expression = self.mark_signals(PAGE_SIGNALS)?;
            Some((expression, read))
        });
        let world = self.change_world(deadline);
        let evaluate = |expression: &str| {
            let mut params = json!({"expression": expression, "returnByValue": true});
            if let Some(context) = &world {
                params["contextId"] = context.clone();
            }
            params
        };
        let page = match marked {
            Some((expression, read)) => {
                let answer =
                    self.signal("Runtime.evaluate", evaluate(expression.as_str()), deadline);
                split_mark(answer, read)?
            }
            None => self.signal("Runtime.evaluate", evaluate(PAGE_SIGNALS), deadline)?,
        };
        let value = match watch {
            Watch::Entry(_, node, session) => self.signal_in(
                session,
                "Runtime.callFunctionOn",
                json!({"objectId": node["objectId"], "functionDeclaration": "function() { return this.value; }", "returnByValue": true}),
                deadline,
            )?,
            Watch::Click(_, Some((node, session))) => self.signal_in(
                session,
                "Runtime.callFunctionOn",
                json!({"objectId": node["objectId"], "functionDeclaration": CONTROL_STATE, "returnByValue": true}),
                deadline,
            )?,
            Watch::Click(_, None) | Watch::Navigate(_) => Value::Null,
        };
        let documents = self.shown_documents_by(deadline).ok()?;
        let listed = self
            .pipe
            .call(None, "Target.getTargets", json!({}), deadline)
            .ok()?;
        let mut tabs: Vec<String> = listed
            .get("targetInfos")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|info| info.get("type").and_then(Value::as_str) == Some("page"))
            .map(target_id)
            .collect();
        tabs.sort_unstable();
        Some(Mark {
            page,
            value,
            documents,
            navigations,
            tabs,
        })
    }

    /// The front tab's change world, for its document now (FIX 6764): the
    /// same world each time, a new context once a new document stands.
    /// None where the engine makes no isolated world, and the check reads
    /// in the page's world.
    fn change_world(&self, deadline: Instant) -> Option<Value> {
        let world = self
            .pipe
            .call(
                Some(&self.session),
                "Page.createIsolatedWorld",
                json!({"frameId": self.target, "worldName": CHANGE_WORLD}),
                deadline,
            )
            .ok()?;
        world.get("executionContextId").cloned()
    }

    /// One read on the front tab, answered by `deadline`: its value, none
    /// when it failed, threw or did not answer in time.
    fn signal(&self, method: &str, params: Value, deadline: Instant) -> Option<Value> {
        self.signal_in(&self.session, method, params, deadline)
    }

    /// One read on `session` (FIX 11576), as `signal` reads on the front
    /// tab's: its value, none when it failed, threw or did not answer.
    fn signal_in(
        &self,
        session: &str,
        method: &str,
        params: Value,
        deadline: Instant,
    ) -> Option<Value> {
        let answer = self
            .pipe
            .call(Some(session), method, params, deadline)
            .ok()?;
        if answer.get("exceptionDetails").is_some() {
            return None;
        }
        Some(
            answer
                .pointer("/result/value")
                .cloned()
                .unwrap_or(Value::Null),
        )
    }
}
