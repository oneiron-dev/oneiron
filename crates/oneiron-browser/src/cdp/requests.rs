//! Each paused request's custody (FIX 7122), on the routing of both
//! transports. A `Fetch.requestPaused` the seed slot did not take is
//! performed by the host's request handler where the session has one, in
//! place of the run's relay, never both; else by the relay as before. Either
//! way it is one request, never followed past a redirect: the next hop
//! pauses again and comes here as its own. A destination refusal the handler
//! answers is kept in the session's custody before the request fails, so a
//! navigation or an act that the failure ends answers it, not a generic
//! error; every other failure fails only its request, as before.
//!
//! The answer to each main-document request is noted by its page session
//! and frame: the URL answered and its status, for the session's rendered
//! document to name the status of the document it shows. Once the frame
//! commits that URL, the note is bound to the document the commit names
//! (its loader), so a script's same-document move (pushState, replaceState,
//! a fragment) keeps the status the document was answered with (FIX 7407).
//! The note never changes what the page is answered.

use super::Pipe;
use crate::{BrowserError, DestinationRefusal, SpooledResponse};
use oneiron_container::{EgressRelay, HttpRequest, HttpResponse};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// By page session and frame, the last document request the session
/// answered.
pub(super) type Documents = Arc<Mutex<HashMap<(String, String), Answered>>>;

/// A frame's last document request the session answered: the URL it asked,
/// its status, and the document the frame committed it as, once it did.
pub(super) struct Answered {
    asked: String,
    status: u16,
    loader: Option<String>,
}

/// A paused request's answer, whole on today's path or piece-readable where
/// the host's handler explicitly provides one.
pub(super) enum PausedResponse {
    Whole(HttpResponse),
    Spooled(SpooledResponse),
}

impl PausedResponse {
    fn status(&self) -> u16 {
        match self {
            Self::Whole(response) => response.status,
            Self::Spooled(response) => response.status,
        }
    }
}

impl Pipe {
    /// Performs `request`, paused by page `session` in `event`: through the
    /// host's handler where the session has one, else through `relay`. Its
    /// answer, or none where it failed.
    pub(super) fn fetch_paused(
        &self,
        relay: &Arc<dyn EgressRelay>,
        session: &str,
        event: &Value,
        request: HttpRequest,
    ) -> Option<PausedResponse> {
        let answered = match self.custody.handler() {
            None => relay.fetch(request).ok().map(PausedResponse::Whole),
            Some(handler) if handler.provides_spooled() => match handler.fetch_spooled(request) {
                Ok(response) => Some(PausedResponse::Spooled(response)),
                Err(BrowserError::DestinationRefused(refusal)) => {
                    self.custody.refuse(refusal);
                    None
                }
                Err(_) => None,
            },
            Some(handler) => match handler.fetch(request) {
                Ok(response) => Some(PausedResponse::Whole(response)),
                Err(BrowserError::DestinationRefused(refusal)) => {
                    self.custody.refuse(refusal);
                    None
                }
                Err(_) => None,
            },
        };
        if let Some(response) = &answered {
            self.note_document(session, event, response.status());
        }
        answered
    }

    /// Notes the answer to a document request of page `session`, by its
    /// frame.
    fn note_document(&self, session: &str, event: &Value, status: u16) {
        let params = &event["params"];
        if params["resourceType"].as_str() != Some("Document") {
            return;
        }
        let url = params.pointer("/request/url").and_then(Value::as_str);
        let (Some(frame), Some(url)) = (params["frameId"].as_str(), url) else {
            return;
        };
        if let Ok(mut documents) = self.documents.lock() {
            let at = (session.to_owned(), frame.to_owned());
            let answered = Answered {
                asked: url.to_owned(),
                status,
                loader: None,
            };
            documents.insert(at, answered);
        }
    }

    /// Binds a frame's answered document to the document its commit names
    /// (`Page.frameNavigated`), when the frame committed the URL the
    /// session answered.
    pub(super) fn note_commit(&self, event: &Value) {
        if event["method"].as_str() != Some("Page.frameNavigated") {
            return;
        }
        let frame = &event["params"]["frame"];
        let (Some(session), Some(id), Some(url), Some(loader)) = (
            event["sessionId"].as_str(),
            frame["id"].as_str(),
            frame["url"].as_str(),
            frame["loaderId"].as_str(),
        ) else {
            return;
        };
        if let Ok(mut documents) = self.documents.lock()
            && let Some(answered) = documents.get_mut(&(session.to_owned(), id.to_owned()))
            && answered.asked == url
        {
            answered.loader = Some(loader.to_owned());
        }
    }

    /// The status of the last document request of `frame` on page `session`
    /// the session answered, as [`document_status_policy`] names it for the
    /// frame showing `url` as the document `loader` names.
    pub(crate) fn document_status(
        &self,
        session: &str,
        frame: &str,
        url: &str,
        loader: Option<&str>,
    ) -> Option<u16> {
        let documents = self.documents.lock().ok()?;
        let at = (session.to_owned(), frame.to_owned());
        document_status_policy(documents.get(&at)?, url, loader)
    }

    /// Drops page `session`'s notes, as its session detached.
    pub(super) fn forget_documents(&self, session: &str) {
        if let Ok(mut documents) = self.documents.lock() {
            documents.retain(|(at, _), _| at != session);
        }
    }

    /// The destination refusal not yet delivered, left in place.
    pub(crate) fn refusal_pending(&self) -> Option<DestinationRefusal> {
        self.custody.pending()
    }
}

/// The status a rendered document names (`document_status_policy`, CALLS
/// row, open): that of the last document request its main frame made that
/// the session answered. Once the frame committed it, only while the frame
/// still shows that document (`loader`, as the frame tree names it now),
/// whatever URL a same-document move gave it since (FIX 7407); before, or
/// where no loader is named, only while the frame shows the URL that
/// request asked (`shown`, both without a fragment). Another document (a
/// new load the session never answered, an error page) names none; a
/// status is never invented.
fn document_status_policy(answered: &Answered, shown: &str, loader: Option<&str>) -> Option<u16> {
    match (answered.loader.as_deref(), loader) {
        (Some(bound), Some(now)) => (bound == now).then_some(answered.status),
        _ => (answered.asked == shown).then_some(answered.status),
    }
}
