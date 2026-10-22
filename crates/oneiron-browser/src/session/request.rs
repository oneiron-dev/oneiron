//! The session's side of the host's custody of its requests (FIX 7122,
//! `crate::request`): the destination refusal the host's handler gave,
//! delivered once, and the rendered document a host reads.
//!
//! A refusal not yet delivered answers in place of a navigation's or an
//! act's success, and in place of the load failure or the timeout it caused;
//! an effect it followed keeps its receipt. A session the host gave no
//! handler never holds one, and answers as always.

use super::BrowserSession;
use crate::{BrowserError, DestinationRefusal, RenderedDocument};

impl BrowserSession {
    /// The destination refusal the host's handler gave a request of this
    /// session that no answer delivered yet, taken: after a navigation that
    /// failed with the browser's own words, or a request refused once its
    /// page loaded. None for a session the host gave no handler.
    pub fn take_destination_refusal(&mut self) -> Option<DestinationRefusal> {
        self.custody.take()
    }

    /// The page in front as rendered now: its markup, the URL it stands at,
    /// and the status of the main-frame document response the session
    /// fulfilled for that URL, where it knows one. A refusal not yet
    /// delivered answers in its place.
    pub fn document(&mut self) -> Result<RenderedDocument, BrowserError> {
        self.undelivered()?;
        let read = self.live()?.document();
        let document = self.crossed(read)?;
        self.undelivered()?;
        Ok(document)
    }

    /// A navigation's or an act's answer once its requests crossed the
    /// host: a failure [`destination_refusal_policy`] gives way answers the
    /// refusal not yet delivered, taken, where there is one. Every other
    /// answer stands.
    pub(super) fn crossed<T>(&self, answer: Result<T, BrowserError>) -> Result<T, BrowserError> {
        match answer {
            Err(error) if destination_refusal_policy(&error) => Err(self
                .custody
                .take()
                .map_or(error, BrowserError::DestinationRefused)),
            answer => answer,
        }
    }

    /// The refusal not yet delivered, taken, in place of a navigation's or
    /// an act's success, once its effect's receipt landed
    /// ([`destination_refusal_policy`]).
    pub(super) fn undelivered(&self) -> Result<(), BrowserError> {
        match self.custody.take() {
            Some(refused) => Err(BrowserError::DestinationRefused(refused)),
            None => Ok(()),
        }
    }
}

/// Which failures of a navigation or an act give way to a destination
/// refusal not yet delivered (`destination_refusal_policy`, CALLS row,
/// open): a load that failed, ran out of time, or stopped on the refusal
/// itself, as a refused request ends one. A success gives way too, once its
/// effect's receipt landed: the effect stands, and its answer is the
/// refusal. Every other failure (a press the act needs, a person holding
/// the browser, a stale ref, an engine's own refusal) stands, the refusal
/// kept for the next navigation or act, or the host's take.
fn destination_refusal_policy(error: &BrowserError) -> bool {
    matches!(
        error,
        BrowserError::Navigation(_)
            | BrowserError::Timeout(_)
            | BrowserError::CallTimeout(_)
            | BrowserError::DestinationRefused(_)
    )
}
