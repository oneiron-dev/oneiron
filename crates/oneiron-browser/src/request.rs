//! A host's custody of a browser session's requests (FIX 7122). A host may
//! hand a session a [`BrowserRequestHandler`] when it attaches it: then
//! every HTTP(S) request a page of the session makes (a navigation, each
//! redirect hop, each subresource, on every tab it follows and on an engine
//! switch's target) is paused and handed to that handler in place of the
//! run's relay, one request at a time, never both and never followed past a
//! redirect. The browser decides nothing here: the handler checks the
//! destination by the host's own rule and performs the request, and a
//! refusal it answers comes back as a [`DestinationRefusal`], data the host
//! filled. A session given no handler takes its relay as before.
//!
//! The session keeps the first refusal not yet delivered. A navigation or
//! an act answers it in place of its own success, `open` stops waiting for
//! its load on it, and the host can take it at any time. What the session
//! renders reads as a [`RenderedDocument`].

#[cfg(feature = "driver")]
use crate::BrowserError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[cfg(feature = "driver")]
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// A request's destination the host refused by its own rule, in the host's
/// words: its reason code and its message. The browser never fills it and
/// never reads a reason from an address, a status or a string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DestinationRefusal {
    pub reason: String,
    pub message: String,
}

impl std::fmt::Display for DestinationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.reason)
    }
}

/// The host's custody of a session's requests: it performs each one.
#[cfg(feature = "driver")]
pub trait BrowserRequestHandler: Send + Sync {
    /// Check the destination and perform this ONE request; never follow
    /// redirects. A redirect's answer goes back to the browser, whose next
    /// hop is handed here as its own request. A refusal by the host's rule
    /// answers [`BrowserError::DestinationRefused`]; any other failure
    /// answers its own error, and fails only its request.
    fn fetch(
        &self,
        request: oneiron_container::HttpRequest,
    ) -> Result<oneiron_container::HttpResponse, BrowserError>;
}

/// The page in front as the session renders it now.
#[cfg(feature = "driver")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedDocument {
    /// The document's markup as it stands: its doctype, then its root
    /// element.
    pub html: String,
    /// The URL the page stands at.
    pub final_url: String,
    /// The HTTP status of the main-frame document response the session
    /// fulfilled for the URL the main frame shows; none where no such
    /// response is known (a script moved the URL, the frame shows an error
    /// page, or no response crossed the session). Never invented.
    pub status: Option<u16>,
}

/// A session's custody of its requests, shared by the session and each
/// engine's pipe it attaches, a switch's target's too: the host's handler,
/// if it gave one, and the first refusal not yet delivered.
#[cfg(feature = "driver")]
#[derive(Clone)]
pub(crate) struct Custody {
    handler: Option<Arc<dyn BrowserRequestHandler>>,
    refused: Arc<Mutex<Option<DestinationRefusal>>>,
}

#[cfg(feature = "driver")]
impl Custody {
    /// The custody of a session the host gave `handler`, holding no refusal.
    pub(crate) fn new(handler: Option<Arc<dyn BrowserRequestHandler>>) -> Self {
        Self {
            handler,
            refused: Arc::default(),
        }
    }

    /// The host's handler, where it gave one.
    pub(crate) fn handler(&self) -> Option<&Arc<dyn BrowserRequestHandler>> {
        self.handler.as_ref()
    }

    /// Keeps `refusal` until it is delivered; the first one not yet
    /// delivered stands.
    pub(crate) fn refuse(&self, refusal: DestinationRefusal) {
        let mut slot = self.slot();
        if slot.is_none() {
            *slot = Some(refusal);
        }
    }

    /// The refusal not yet delivered, left in place.
    pub(crate) fn pending(&self) -> Option<DestinationRefusal> {
        self.slot().clone()
    }

    /// The refusal not yet delivered, taken: it is delivered now.
    pub(crate) fn take(&self) -> Option<DestinationRefusal> {
        self.slot().take()
    }

    fn slot(&self) -> MutexGuard<'_, Option<DestinationRefusal>> {
        self.refused.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
