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
//! document to name the status of the document it shows. The note never
//! changes what the page is answered.

use super::Pipe;
use crate::{BrowserError, DestinationRefusal};
use oneiron_container::{EgressRelay, HttpRequest, HttpResponse};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// By page session and frame, the URL of the last document request the
/// session answered and that answer's status.
pub(super) type Documents = Arc<Mutex<HashMap<(String, String), (String, u16)>>>;

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
    ) -> Option<HttpResponse> {
        let answered = match self.custody.handler() {
            None => relay.fetch(request).ok(),
            Some(handler) => match handler.fetch(request) {
                Ok(response) => Some(response),
                Err(BrowserError::DestinationRefused(refusal)) => {
                    self.custody.refuse(refusal);
                    None
                }
                Err(_) => None,
            },
        };
        if let Some(response) = &answered {
            self.note_document(session, event, response.status);
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
            documents.insert(at, (url.to_owned(), status));
        }
    }

    /// The status of the last document request of `frame` on page `session`
    /// the session answered, as [`document_status_policy`] names it for the
    /// frame showing `url`.
    pub(crate) fn document_status(&self, session: &str, frame: &str, url: &str) -> Option<u16> {
        let documents = self.documents.lock().ok()?;
        let at = (session.to_owned(), frame.to_owned());
        let (asked, status) = documents.get(&at)?;
        document_status_policy(asked, url, *status)
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
/// the session answered, only while the frame shows the URL that request
/// asked (`asked`, the frame's `shown`, both without a fragment). A frame
/// showing another URL (one a script moved it to, an error page, a
/// navigation the session never answered) names none; a status is never
/// invented.
fn document_status_policy(asked: &str, shown: &str, status: u16) -> Option<u16> {
    (asked == shown).then_some(status)
}
