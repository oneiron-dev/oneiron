//! What the pipe keeps of its pages' storage for the session's snapshots
//! (FIX 6680, BROWSER-SPLIT PR3b), on the routing of both transports. Once
//! the session gave the pipe its sink, the driver's reads go through it, and
//! the reader keeps two kinds of event, never calling CDP itself: the read a
//! Chromium document sends through the driver's binding as it is left
//! (`Runtime.bindingCalled`), taken only from a watched page's session, its
//! top frame, by the binding's own name, and never from a seed document;
//! and an in-page frame the browser attaches as its own target, named when
//! its origin is not its page's, at its attach and at each document it
//! loads after (FIX 6892). In-page frames the page itself commits,
//! and opaque and non-web documents, are named where their commit is read
//! (`state`). None of them is carried.

use super::{Pipe, web_origin};
use crate::driver::storage::{EXIT_BINDING, PageRead, page_read, switch_storage_capture_policy};
use crate::session::storage::{Sample, Sink};
use crate::{BrowserEngine, StoragePhase, SwitchLoss};
use serde_json::Value;

impl Pipe {
    /// Keeps this pipe's pages' storage reads through `sink` from now on.
    pub(crate) fn collect(&self, sink: Sink) {
        let _ = self.sink.set(sink);
    }

    /// The bound one read after an act, at hand-back or on exit takes: the
    /// session's snapshots' own (FIX 10335), else its default.
    pub(crate) fn snapshot_read_chars(&self) -> usize {
        self.sink.get().map_or_else(
            || crate::session::storage::switch_state_limits().read_chars,
            Sink::read_chars,
        )
    }

    /// Whether this pipe keeps its pages' storage reads.
    pub(crate) fn collects(&self) -> bool {
        self.sink.get().is_some()
    }

    /// Keeps one read of page `tab`'s stores, in `phase`.
    pub(crate) fn keep_sample(&self, tab: &str, phase: StoragePhase, sample: Sample) {
        if let Some(sink) = self.sink.get() {
            sink.keep(tab, phase, sample);
        }
    }

    /// Drops what the session's snapshots hold of page `tab`, closed and
    /// no longer in front (FIX 6891).
    pub(crate) fn drop_snapshots(&self, tab: &str) {
        if let Some(sink) = self.sink.get() {
            sink.drop_tab(tab);
        }
    }

    /// Names `origin`, shown by page `tab`, as storage no switch carries.
    pub(crate) fn exclude(&self, tab: &str, origin: String, reason: SwitchLoss) {
        if let Some(sink) = self.sink.get() {
            sink.exclude(tab, origin, reason);
        }
    }

    /// Keeps what one event the browser sent says of a page's storage.
    pub(super) fn note_storage(&self, event: &Value) {
        if !self.collects() {
            return;
        }
        match event["method"].as_str() {
            Some("Runtime.bindingCalled") => self.keep_exit(event),
            Some("Target.attachedToTarget") => self.note_frame_target(event),
            Some("Fetch.requestPaused") => self.note_frame_document(event),
            _ => {}
        }
    }

    /// Keeps the read a Chromium document sent as it was left.
    fn keep_exit(&self, event: &Value) {
        let params = &event["params"];
        if params["name"].as_str() != Some(EXIT_BINDING) {
            return;
        }
        let (Some(session), Some(payload)) =
            (event["sessionId"].as_str(), params["payload"].as_str())
        else {
            return;
        };
        let Some(tab) = self.page_of(session) else {
            return;
        };
        let Ok(read) = serde_json::from_str::<Value>(payload) else {
            return;
        };
        let engine = BrowserEngine::Chromium;
        let bound = self.snapshot_read_chars();
        let Some(chars) = switch_storage_capture_policy(engine, StoragePhase::Exit, bound) else {
            return;
        };
        match page_read(&read, chars, engine) {
            Some((href, _)) if self.is_seed(&href) => {}
            Some((_, PageRead::Sample(sample))) => {
                self.keep_sample(&tab, StoragePhase::Exit, sample);
            }
            Some((_, PageRead::Opaque(origin))) => {
                self.exclude(&tab, origin, SwitchLoss::OpaqueOrigin);
            }
            Some((_, PageRead::Other)) | None => {}
        }
    }

    /// Names an in-page frame the browser attached as its own target when
    /// its origin is not its page's.
    fn note_frame_target(&self, event: &Value) {
        let info = &event["params"]["targetInfo"];
        if info["type"].as_str() != Some("iframe") {
            return;
        }
        let Some(tab) = event["sessionId"].as_str().and_then(|s| self.page_of(s)) else {
            return;
        };
        if let Some(frame) = event["params"]["sessionId"].as_str()
            && let Ok(mut pages) = self.pages.lock()
        {
            pages.frames.insert(frame.to_owned(), tab.clone());
        }
        self.name_frame_origin(&tab, info["url"].as_str());
    }

    /// Names the origin of a document an attached in-page frame loads
    /// after its attach: its own session's main-document request, as it
    /// pauses.
    fn note_frame_document(&self, event: &Value) {
        let params = &event["params"];
        if params["resourceType"].as_str() != Some("Document") {
            return;
        }
        let Some(session) = event["sessionId"].as_str() else {
            return;
        };
        let tab = self
            .pages
            .lock()
            .ok()
            .and_then(|pages| pages.frames.get(session).cloned());
        if let Some(tab) = tab {
            self.name_frame_origin(&tab, params.pointer("/request/url").and_then(Value::as_str));
        }
    }

    /// Names `url`'s origin, an in-page frame of page `tab` shows, when it
    /// is not its page's.
    fn name_frame_origin(&self, tab: &str, url: Option<&str>) {
        let Some(origin) = url.and_then(web_origin) else {
            return;
        };
        if self.top_origin(tab).as_deref() != Some(origin.as_str()) {
            self.exclude(tab, origin, SwitchLoss::CrossOriginFrame);
        }
    }
}
