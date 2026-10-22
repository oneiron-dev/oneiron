//! The driver's reads of a page's storage for the session's snapshots (FIX
//! 6680, BROWSER-SPLIT PR3b), on both engines: one read of both stores of
//! the page's origin, in the page, within bounds, before its items cross.
//!
//! - Right before an act's input it rides the change check's mark: the
//!   mark's one `Runtime.evaluate` carries it beside the page's signals,
//!   and it is taken off before the mark is kept, so the check compares
//!   what it always did, in its window. The check's polls never read it.
//! - Once an act's or an open's page settled, before it is read, one more
//!   `Runtime.evaluate`; so before a person's input and at hand-back.
//! - On Chromium the tab's document reads itself as it is left: at attach
//!   the driver adds a binding to an isolated world of its own and a script
//!   every new document of the tab runs in that world, the live one too.
//!   On `pagehide` the script sends its read through the binding. No page
//!   script sees the world, the binding or the listener, and no storage
//!   method is wrapped. Lightpanda 1.0.0 fires no `pagehide`: a switch
//!   names the tail of each departed origin it did not see.
//!
//! A read that did not answer, threw, or stands at an opaque origin is kept
//! as that, never as an empty store. Values cross into the snapshots only.

use super::state::utf16;
use super::{CALL, CdpDriver};
use crate::cdp::{Pipe, web_origin};
use crate::session::storage::{Sample, Sink, StoreSample, switch_state_limits};
use crate::{BrowserEngine, StoragePhase, SwitchLoss};
use serde_json::{Value, json};
use std::time::Instant;

/// The isolated world the Chromium exit read runs in.
pub(crate) const EXIT_WORLD: &str = "oneiron";
/// The binding the exit read sends through, bound to that world only.
pub(crate) const EXIT_BINDING: &str = "oneironStorageExit";

/// Both stores of the page's origin, read in the page: at most `__ITEMS__`
/// items and `__STORE__` UTF-16 code units of keys and values in one store,
/// and `__CHARS__` in both. Answers the page's URL, its origin, whether it
/// relaxed `document.domain`, then each store as its count, its items (null
/// past a bound) and their code units; a count of -1 where it threw.
const STORES_READ: &str = "((t, m, q) => { const r = (g, a) => { try { const s = window[g]; const n = s.length; if (n > m) return [n, null, 0]; const p = []; let c = 0; for (let i = 0; i < n; i++) { const k = s.key(i); if (k === null) continue; const v = s.getItem(k); if (v === null) continue; c += k.length + v.length; if (c > q || c > a) return [n, null, c]; p.push([k, v]); } return [n, p, c]; } catch (e) { return [-1, null, 0]; } }; const l = r('localStorage', t); const s = r('sessionStorage', t - (l[1] ? l[2] : 0)); let d = false; try { d = document.domain !== location.hostname; } catch (e) {} return [location.href, location.origin, d, l, s]; })(__CHARS__, __ITEMS__, __STORE__)";

/// The script each new document of a Chromium tab runs in the driver's
/// world: its top frame sends its stores' read through the binding as the
/// document is left, from a capturing listener added before any page
/// script runs, so no page listener stops it first.
const EXIT_PRELOAD: &str = "(() => { const w = window; if (w !== w.top || w.__oneironExit) return; const send = w.__BINDING__; if (typeof send !== 'function') return; w.__oneironExit = true; w.addEventListener('pagehide', () => { try { send(JSON.stringify(__READ__)); } catch (e) {} }, true); })()";

/// How far the driver reads a page's stores in `phase` on `engine`, none
/// where it takes no such read (`switch_storage_capture_policy`, CALLS row,
/// open; Engine 10-21 01:4x): right before each act's input, inside the
/// change check's mark and its window, and before a person's input, within
/// the smaller pre-input bound; once an act's or an open's page settled and
/// at hand-back, within the read bound; as a document is left, on Chromium
/// only, through the driver's own world and binding. Lightpanda 1.0.0
/// fires no `pagehide`: a switch reports each departed origin's unseen
/// tail. Never on the check's polls, never by wrapping a storage method,
/// and never a switch of its own. A switch reads the current origin's
/// stores itself, one at a time, within PR3's bounds on one store.
pub(crate) fn switch_storage_capture_policy(
    engine: BrowserEngine,
    phase: StoragePhase,
) -> Option<usize> {
    let limits = switch_state_limits();
    match phase {
        StoragePhase::PreInput => Some(limits.input_chars),
        StoragePhase::PostAct | StoragePhase::HandBack => Some(limits.read_chars),
        StoragePhase::Exit => (engine == BrowserEngine::Chromium).then_some(limits.read_chars),
        StoragePhase::SwitchExport => None,
    }
}

/// The read of both stores, `chars` UTF-16 code units of both at most.
fn stores_read(chars: usize) -> String {
    let limits = switch_state_limits();
    STORES_READ
        .replace("__CHARS__", &chars.to_string())
        .replace("__ITEMS__", &limits.items.to_string())
        .replace("__STORE__", &limits.store_chars.to_string())
}

/// What one read of a page found.
pub(crate) enum PageRead {
    /// The stores of a web origin.
    Sample(Sample),
    /// A document at web URL origin `0` whose own origin is opaque.
    Opaque(String),
    /// A document with no web origin of its own.
    Other,
}

/// One read as the page answered it, checked again here within `chars`:
/// the page's URL, and what it found. None for an answer that is no read.
/// `relaxed` counts only on Lightpanda, which keys a relaxed document's
/// storage by its effective domain; Chromium keys it by origin.
pub(crate) fn page_read(
    read: &Value,
    chars: usize,
    engine: BrowserEngine,
) -> Option<(String, PageRead)> {
    let href = read[0].as_str()?.to_owned();
    let origin = read[1].as_str()?;
    let relaxed = read[2].as_bool()? && engine == BrowserEngine::Lightpanda;
    if web_origin(origin).as_deref() != Some(origin) {
        let found = match web_origin(&href) {
            Some(at) if origin == "null" => PageRead::Opaque(at),
            _ => PageRead::Other,
        };
        return Some((href, found));
    }
    let mut left = u64::try_from(chars).unwrap_or(u64::MAX);
    let local = store_read(&read[3], &mut left);
    let session = store_read(&read[4], &mut left);
    let sample = Sample {
        origin: origin.to_owned(),
        relaxed,
        stores: [local, session],
    };
    Some((href, PageRead::Sample(sample)))
}

/// One store of a read, within its bounds and the `left` code units both
/// stores share.
fn store_read(store: &Value, left: &mut u64) -> StoreSample {
    let limits = switch_state_limits();
    let Some(count) = store[0].as_i64() else {
        return StoreSample::Lost;
    };
    let Ok(count) = u64::try_from(count) else {
        return StoreSample::Threw;
    };
    let Some(items) = store[1].as_array() else {
        return StoreSample::Over { count };
    };
    let mut pairs = Vec::with_capacity(items.len().min(limits.items));
    let mut chars = 0;
    for item in items {
        let (Some(key), Some(value)) = (item[0].as_str(), item[1].as_str()) else {
            return StoreSample::Lost;
        };
        chars += utf16(key) + utf16(value);
        pairs.push((key.to_owned(), value.to_owned()));
        if pairs.len() > limits.items {
            return StoreSample::Over { count };
        }
    }
    let bound = u64::try_from(limits.store_chars).unwrap_or(u64::MAX);
    if chars > bound || chars > *left {
        return StoreSample::Over { count };
    }
    *left -= chars;
    StoreSample::Items { pairs, chars }
}

/// The value an evaluate answered, none when it failed or threw.
fn evaluated(answer: Option<Value>) -> Option<Value> {
    let mut answer = answer?;
    if answer.get("exceptionDetails").is_some() {
        return None;
    }
    answer.pointer_mut("/result/value").map(Value::take)
}

/// What the change check's mark read of the stores.
pub(super) enum MarkRead {
    /// The mark's evaluate never ran: the tab's navigations are not counted.
    NotRun,
    /// Its evaluate did not answer, or threw.
    Failed,
    /// Its stores' part.
    Answered(Value),
}

/// Takes the stores' part off the mark's answer, leaving the page's signals
/// as the check compares them.
pub(super) fn split_mark(answer: Option<Value>, read: &mut MarkRead) -> Option<Value> {
    let Some(Value::Array(mut parts)) = answer else {
        *read = MarkRead::Failed;
        return None;
    };
    *read = match parts.pop() {
        Some(stores) if parts.len() == 4 => MarkRead::Answered(stores),
        _ => MarkRead::Failed,
    };
    Some(Value::Array(parts))
}

/// Installs the exit read on Chromium page `session`, once its Page domain
/// is on: the binding in the driver's world first, then the script every
/// new document runs there, run at once in the live one. Best effort: a
/// tab without it is read at its other points only.
pub(super) fn hook_exits(pipe: &Pipe, session: &str, engine: BrowserEngine) {
    let Some(chars) = switch_storage_capture_policy(engine, StoragePhase::Exit) else {
        return;
    };
    if !pipe.collects() {
        return;
    }
    let deadline = Instant::now() + CALL;
    let binding = json!({"name": EXIT_BINDING, "executionContextName": EXIT_WORLD});
    if pipe
        .call(Some(session), "Runtime.addBinding", binding, deadline)
        .is_err()
    {
        return;
    }
    let read = stores_read(chars);
    let source = EXIT_PRELOAD
        .replace("__BINDING__", EXIT_BINDING)
        .replace("__READ__", &read);
    let script = json!({"source": source, "worldName": EXIT_WORLD, "runImmediately": true});
    let _ = pipe.call(
        Some(session),
        "Page.addScriptToEvaluateOnNewDocument",
        script,
        deadline,
    );
}

impl CdpDriver {
    /// The mark's evaluate with the stores' read beside the page's signals,
    /// within the pre-input bound; none when the session keeps no snapshots.
    pub(super) fn mark_signals(&self, signals: &str) -> Option<String> {
        if !self.pipe.collects() {
            return None;
        }
        let chars = switch_storage_capture_policy(self.engine, StoragePhase::PreInput)?;
        let stores = stores_read(chars);
        let tail = "]; })()";
        let head = signals.strip_suffix(tail)?;
        Some(format!(
            "{head}, (() => {{ try {{ return {stores}; }} catch (e) {{ return null; }} }})(){tail}"
        ))
    }

    /// Keeps the read the change check's mark took before an act's input;
    /// a mark whose evaluate never ran reads the stores alone, by its
    /// `deadline`.
    pub(super) fn keep_mark_read(&self, read: MarkRead, deadline: Instant) {
        if !self.pipe.collects() {
            return;
        }
        let read = match read {
            MarkRead::Answered(read) => Some(read),
            MarkRead::Failed => None,
            MarkRead::NotRun => self.read_stores(StoragePhase::PreInput, deadline),
        };
        self.keep_read(StoragePhase::PreInput, read);
    }

    /// Drops the snapshots of the `closed` tabs (FIX 6891), each once
    /// another tab is in front: a switch reads only the tab in front, so no
    /// switch or carry reads a closed tab's again, and no other tab reads
    /// another's. A closed tab still in front, where the front could not
    /// move, keeps its snapshots.
    pub(super) fn drop_closed(&self, closed: &[String]) {
        for tab in closed.iter().filter(|tab| **tab != self.target) {
            self.pipe.drop_snapshots(tab);
        }
    }

    /// Keeps this driver's pages' storage reads through `sink` from now on:
    /// for a session that keeps snapshots from after its attach.
    pub(crate) fn collect(&self, sink: Sink) {
        self.pipe.collect(sink);
    }

    /// Books this driver's CDP messages past the pipe's framing threshold
    /// to `charge` on the host's memory floor (FIX 7988), so they read on.
    pub(crate) fn book_inbound(&self, charge: Box<dyn crate::retention::HandleRetention>) {
        self.pipe.book_inbound(charge);
    }

    /// Keeps a read of the front tab's stores another step took: a
    /// switch's fresh export.
    pub(crate) fn keep(&self, phase: StoragePhase, sample: Sample) {
        self.pipe.keep_sample(&self.target, phase, sample);
    }

    /// Reads the front tab's stores for the session's snapshots, as of
    /// `phase`: one `Runtime.evaluate`, none where the session keeps no
    /// snapshots. Best effort: it changes nothing else.
    pub(crate) fn checkpoint(&self, phase: StoragePhase) {
        if !self.pipe.collects() {
            return;
        }
        let read = self.read_stores(phase, Instant::now() + CALL);
        self.keep_read(phase, read);
    }

    /// The bound one read in `phase` takes on this engine.
    fn read_chars(&self, phase: StoragePhase) -> usize {
        let fallback = switch_state_limits().read_chars;
        switch_storage_capture_policy(self.engine, phase).unwrap_or(fallback)
    }

    fn read_stores(&self, phase: StoragePhase, deadline: Instant) -> Option<Value> {
        let expression = stores_read(self.read_chars(phase));
        let answer = self.pipe.call(
            Some(&self.session),
            "Runtime.evaluate",
            json!({"expression": expression, "returnByValue": true}),
            deadline,
        );
        evaluated(answer.ok())
    }

    /// Keeps one read of the front tab; one that did not answer is the
    /// loss of the origin the tab committed last.
    fn keep_read(&self, phase: StoragePhase, read: Option<Value>) {
        let chars = self.read_chars(phase);
        let found = read.and_then(|read| page_read(&read, chars, self.engine));
        match found {
            Some((_, PageRead::Sample(sample))) => {
                self.pipe.keep_sample(&self.target, phase, sample);
            }
            Some((_, PageRead::Opaque(origin))) => {
                let reason = SwitchLoss::OpaqueOrigin;
                self.pipe.exclude(&self.target, origin, reason);
            }
            Some((_, PageRead::Other)) => {}
            None => {
                if let Some(origin) = self.pipe.top_origin(&self.target) {
                    let sample = Sample {
                        origin,
                        relaxed: false,
                        stores: [StoreSample::Lost, StoreSample::Lost],
                    };
                    self.pipe.keep_sample(&self.target, phase, sample);
                }
            }
        }
    }
}
