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
//! started by the first mark on it.

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

/// What one act's change check watches, and names in its fact.
pub(super) enum Watch<'a> {
    /// A click on a row, or at a point.
    Click(ActionTarget),
    /// A type or select into a row: its value too, read off its node.
    Entry(ActionTarget, &'a Value),
    /// An open of a URL.
    Navigate(String),
}

impl Watch<'_> {
    /// The fact a page unchanged for `watched` after the input proves.
    fn fact(&self, engine: BrowserEngine, watched: Duration) -> ActionFact {
        let reason = NoEffectReason::NoObservableChange;
        let window_ms = u64::try_from(watched.as_millis()).unwrap_or(u64::MAX);
        match self {
            Self::Click(target) => ActionFact::ClickNoEffect {
                engine,
                target: target.clone(),
                reason,
                window_ms,
            },
            Self::Entry(target, _) => ActionFact::TypeNoEffect {
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
    /// The target's value, for a type or select.
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
    /// nothing.
    pub(super) fn mark(&self, watch: &Watch<'_>) -> Option<Mark> {
        self.signals(watch, Instant::now() + CHANGE_CHECK_WINDOW)
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
            if self.signals(watch, deadline)? != *mark {
                return None;
            }
            let watched = sent.elapsed();
            if watched + POLL >= CHANGE_CHECK_WINDOW {
                return Some(watch.fact(self.engine, watched));
            }
        }
    }

    /// Every signal of the front tab, each read answered by `deadline`.
    fn signals(&self, watch: &Watch<'_>, deadline: Instant) -> Option<Mark> {
        // A tab whose navigation events are not counted proves nothing.
        let navigations = self.pipe.navigations(&self.session)?;
        let page = self.signal(
            "Runtime.evaluate",
            json!({"expression": PAGE_SIGNALS, "returnByValue": true}),
            deadline,
        )?;
        let value = match watch {
            Watch::Entry(_, node) => self.signal(
                "Runtime.callFunctionOn",
                json!({"objectId": node["objectId"], "functionDeclaration": "function() { return this.value; }", "returnByValue": true}),
                deadline,
            )?,
            Watch::Click(_) | Watch::Navigate(_) => Value::Null,
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

    /// One read on the front tab, answered by `deadline`: its value, none
    /// when it failed, threw or did not answer in time.
    fn signal(&self, method: &str, params: Value, deadline: Instant) -> Option<Value> {
        let answer = self
            .pipe
            .call(Some(&self.session), method, params, deadline)
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
