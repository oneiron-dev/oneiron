//! What the pipe keeps of its pages for an engine switch (FIX 6680,
//! BROWSER-SPLIT PR3, PR3b): the page each watched session drives, the web
//! origins each page committed at its top level, the one it stands at, and
//! the one-shot seed document a switch loads a carried origin's storage
//! into.
//!
//! The registry rides the routing of both transports: a top-level
//! `Page.frameNavigated` (a frame with no parent) of a watched session
//! queues its page's origin, once each, in the order first committed; a
//! seed document's commit is never a visit. Where the session keeps storage
//! snapshots, a commit no switch carries storage of is named to them, value
//! free: an in-page frame of another origin than its page's, a top-level
//! document at an opaque origin, and a non-web one (`about:` documents and
//! the browser's error pages hold none of their own). Nothing here calls
//! CDP from the reader. A page whose target is destroyed, or whose session
//! detached or was pruned with its tab, drops its binding, its queued
//! origins and its navigation count (FIX 6767); the session keeps the
//! history of the tabs it drained, outside the pipe and the engine.
//!
//! The seed slot holds at most one armed document: one page session, its
//! main frame, one exact HTTP(S) URL. The `Fetch.requestPaused` of that URL
//! on that session takes the slot before any relay worker is dispatched,
//! and its own worker answers it locally with an inert page, so the seed's
//! URL never reaches the network. Every other request crosses the host as
//! before (`requests`).

use super::Pipe;
use crate::SwitchLoss;
use crate::session::storage::switch_state_limits;
use base64::Engine as _;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

/// The inert page a seed request is answered with: no script and no
/// subresource, so no request follows it.
const SEED_PAGE: &str = "<!doctype html><meta charset=\"utf-8\"><title></title>";
/// How long the seed request's answer may take.
const SEED_CALL: Duration = Duration::from_secs(10);

/// One page's committed top-level web origins, not yet drained.
#[derive(Clone, Debug, Default)]
pub(crate) struct Visits {
    /// In the order first committed, once each.
    pub(crate) origins: Vec<String>,
    /// Origins that gave way to newer ones past the switch's bound.
    pub(crate) evicted: u64,
}

impl Visits {
    /// Adds `origin` once, the oldest giving way past `bound`.
    pub(crate) fn add(&mut self, origin: String, bound: usize) {
        if self.origins.contains(&origin) {
            return;
        }
        self.origins.push(origin);
        if self.origins.len() > bound {
            self.origins.remove(0);
            self.evicted += 1;
        }
    }
}

/// The pipe's watched pages.
#[derive(Default)]
pub(super) struct Pages {
    /// The page target each watched session drives.
    bound: HashMap<String, String>,
    /// Each page's origins not yet drained.
    visits: HashMap<String, Visits>,
    /// The web origin each page's top frame committed last.
    tops: HashMap<String, String>,
    /// The seed URLs armed on this pipe: their commits are no visits.
    seeds: HashSet<String>,
    /// The page target of each in-page frame the browser attached as its
    /// own target, by that frame's own session (FIX 6892).
    pub(super) frames: HashMap<String, String>,
}

/// An armed seed document.
pub(super) struct Seed {
    session: String,
    /// The page's main frame, when the page named it.
    frame: Option<String>,
    url: String,
    /// Whether the seed request was answered.
    done: Sender<Result<(), String>>,
}

impl Pipe {
    /// Binds page `session` to its page `target`.
    pub(super) fn bind_page(&self, session: &str, target: &str) {
        if let Ok(mut pages) = self.pages.lock() {
            pages.bound.insert(session.to_owned(), target.to_owned());
        }
    }

    /// Keeps what one event the browser sent says of the watched pages: a
    /// top-level commit queues its origin, and a page gone drops its own.
    pub(super) fn note_page(&self, event: &Value) {
        let params = &event["params"];
        match event["method"].as_str() {
            Some("Page.frameNavigated") => self.visit(event),
            Some("Target.detachedFromTarget") => {
                if let Some(session) = params["sessionId"].as_str() {
                    self.forget_page(session);
                }
            }
            Some("Target.targetDestroyed") => {
                if let Some(target) = params["targetId"].as_str() {
                    self.forget_target(target);
                }
            }
            _ => {}
        }
    }

    /// Queues the web origin a watched page's main frame committed, and
    /// names a commit no switch carries storage of.
    fn visit(&self, event: &Value) {
        let frame = &event["params"]["frame"];
        let inner = frame
            .get("parentId")
            .is_some_and(|parent| !parent.is_null());
        if inner && !self.collects() {
            return;
        }
        let session = event["sessionId"].as_str();
        let (Some(session), Some(url)) = (session, frame["url"].as_str()) else {
            return;
        };
        let origin = web_origin(url);
        let Ok(mut pages) = self.pages.lock() else {
            return;
        };
        if pages.seeds.contains(url) {
            return;
        }
        let Some(target) = pages.bound.get(session).cloned() else {
            return;
        };
        let (named, reason) = match origin {
            Some(origin) if inner => {
                let other = pages.tops.get(&target) != Some(&origin);
                (other.then_some(origin), SwitchLoss::CrossOriginFrame)
            }
            Some(origin) => {
                pages.tops.insert(target.clone(), origin.clone());
                let opaque = frame["securityOrigin"].as_str() == Some("null");
                let named = opaque.then(|| origin.clone());
                let bound = switch_state_limits().origins;
                pages
                    .visits
                    .entry(target.clone())
                    .or_default()
                    .add(origin, bound);
                (named, SwitchLoss::OpaqueOrigin)
            }
            None if inner => (None, SwitchLoss::NotWebPage),
            None => {
                pages.tops.remove(&target);
                (non_web(url), SwitchLoss::NotWebPage)
            }
        };
        drop(pages);
        if let Some(named) = named {
            self.exclude(&target, named, reason);
        }
    }

    /// The page target watched session `session` drives.
    pub(super) fn page_of(&self, session: &str) -> Option<String> {
        self.pages.lock().ok()?.bound.get(session).cloned()
    }

    /// The web origin page `tab`'s top frame committed last.
    pub(crate) fn top_origin(&self, tab: &str) -> Option<String> {
        self.pages.lock().ok()?.tops.get(tab).cloned()
    }

    /// Whether `url` is a seed document's, armed on this pipe.
    pub(super) fn is_seed(&self, url: &str) -> bool {
        self.pages
            .lock()
            .is_ok_and(|pages| pages.seeds.contains(url))
    }

    /// Drops page `session`: its binding, its navigation count and its
    /// main-document notes, and its page's queued origins once no session
    /// drives that page.
    pub(crate) fn forget_page(&self, session: &str) {
        if let Ok(mut navigations) = self.navigations.lock() {
            navigations.remove(session);
        }
        self.forget_documents(session);
        if let Ok(mut pages) = self.pages.lock() {
            pages.frames.remove(session);
        }
        if let Ok(mut pages) = self.pages.lock()
            && let Some(target) = pages.bound.remove(session)
            && !pages.bound.values().any(|bound| *bound == target)
        {
            pages.visits.remove(&target);
            pages.tops.remove(&target);
        }
    }

    /// Drops page `target`, every session on it and its queued origins.
    fn forget_target(&self, target: &str) {
        let mut sessions = Vec::new();
        if let Ok(pages) = self.pages.lock() {
            for (session, bound) in &pages.bound {
                if bound == target {
                    sessions.push(session.clone());
                }
            }
        }
        for session in &sessions {
            self.forget_page(session);
        }
        if let Ok(mut pages) = self.pages.lock() {
            pages.visits.remove(target);
            pages.tops.remove(target);
        }
    }

    /// Every page's origins queued since the last drain, by page target.
    pub(crate) fn drain_visits(&self) -> HashMap<String, Visits> {
        match self.pages.lock() {
            Ok(mut pages) => std::mem::take(&mut pages.visits),
            Err(_) => HashMap::new(),
        }
    }

    /// Arms the one-shot seed document: the next request of `url` on page
    /// `session` is answered locally with an inert page, as its main frame
    /// `frame`'s document. The receiver answers once it was, or why not. A
    /// slot armed before gives way.
    pub(crate) fn arm_seed(
        &self,
        session: &str,
        frame: Option<String>,
        url: &str,
    ) -> Receiver<Result<(), String>> {
        let (done, answered) = mpsc::channel();
        if let Ok(mut pages) = self.pages.lock() {
            pages.seeds.insert(url.to_owned());
        }
        if let Ok(mut slot) = self.seed.lock() {
            *slot = Some(Seed {
                session: session.to_owned(),
                frame,
                url: url.to_owned(),
                done,
            });
        }
        answered
    }

    /// Disarms the seed slot: a seed that failed or was given up.
    pub(crate) fn disarm_seed(&self) {
        if let Ok(mut slot) = self.seed.lock() {
            slot.take();
        }
    }

    /// The armed seed, taken, when `event`, a `Fetch.requestPaused` on page
    /// `session`, asks its URL.
    pub(super) fn take_seed(&self, session: &str, event: &Value) -> Option<Seed> {
        let url = event
            .pointer("/params/request/url")
            .and_then(Value::as_str)?;
        let mut slot = self.seed.lock().ok()?;
        let matches = slot
            .as_ref()
            .is_some_and(|seed| seed.session == session && seed.url == url);
        if matches { slot.take() } else { None }
    }
}

/// Answers paused request `id` of page `session`, the armed `seed`'s URL,
/// with the inert page, from its own thread: the reader never waits for its
/// own CDP reply. A request of the seed's URL that is no GET of its main
/// frame's document is failed instead, never fetched.
pub(super) fn fulfill_seed(pipe: Pipe, session: String, id: String, seed: Seed, event: &Value) {
    let params = &event["params"];
    let get = params.pointer("/request/method").and_then(Value::as_str) == Some("GET");
    let document = params["resourceType"]
        .as_str()
        .is_none_or(|kind| kind == "Document");
    let frame = params["frameId"].as_str();
    let main = match (seed.frame.as_deref(), frame) {
        (Some(want), Some(frame)) => want == frame,
        _ => true,
    };
    let page = get && document && main;
    std::thread::spawn(move || {
        let deadline = Instant::now() + SEED_CALL;
        let answered = if page {
            pipe.call(
                Some(&session),
                "Fetch.fulfillRequest",
                json!({"requestId": id, "responseCode": 200, "responseHeaders": [
                    {"name": "Content-Type", "value": "text/html; charset=utf-8"},
                    {"name": "Cache-Control", "value": "no-store"}
                ], "body": base64::engine::general_purpose::STANDARD.encode(SEED_PAGE)}),
                deadline,
            )
            .map(drop)
            .map_err(|error| error.code().to_owned())
        } else {
            let _ = pipe.call(
                Some(&session),
                "Fetch.failRequest",
                json!({"requestId": id, "errorReason": "BlockedByClient"}),
                deadline,
            );
            Err("the seed URL was asked for as no main-frame document".to_owned())
        };
        let _ = seed.done.send(answered);
    });
}

/// The scheme of a top-level document with no web origin, as storage no
/// switch carries is named (`file:`, `data:`); none for `about:` documents,
/// which hold their creator's origin's storage or none, and for the
/// browser's error pages.
fn non_web(url: &str) -> Option<String> {
    let (scheme, _) = url.split_once(':')?;
    let scheme = scheme.to_ascii_lowercase();
    let own = !matches!(scheme.as_str(), "about" | "chrome-error");
    own.then(|| format!("{scheme}:"))
}

/// The web origin of `url` as a browser writes it: `scheme://host`, with a
/// port only when it is not the scheme's own; none for a URL that is no
/// http or https page.
pub(crate) fn web_origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default = match scheme.as_str() {
        "http" => "80",
        "https" => "443",
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) if !port.contains(']') => (host, port),
        _ => (host_port, ""),
    };
    if host.is_empty() {
        return None;
    }
    let host = host.to_ascii_lowercase();
    Some(if port.is_empty() || port == default {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    })
}
