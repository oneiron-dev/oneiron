//! A media rung's backend with its replies' bytes held (FIX 8615): each of
//! its calls (an answer, a job's submit, poll or cancel) runs holding the
//! bytes of every reply read for it on the media-reply line of the vault
//! whose runtime built the rung (FIX 9321), from the first byte read, across
//! the adapter's decode, until the decoded answer leaves the adapter. That
//! answer's own bytes are charged beside them as it leaves (FIX 10626), so
//! the line holds the encoded reply and its decode together at the
//! boundary; a full line records the crossing and refuses nothing.
//! Everything else is the wrapped backend's.
use std::sync::Arc;

use oneiron::llm::BrokerIsolation;
use oneiron::llm::media::MediaPart;
use oneiron::llm::media::{
    MediaBackend, MediaFuture, MediaJobState, MediaProgressFuture, MediaRequest, MediaResponse,
    ReferenceCompatibility,
};
use oneiron::{BudgetLease, LlmResult, ModelId};

use crate::models::ModelHostBudgets;
use crate::models::http::{charge_read, holding_replies};

/// `0`, its calls holding their replies' bytes on `1`'s media-reply line.
pub(super) struct BookedReplies(
    pub(super) Arc<dyn MediaBackend>,
    pub(super) ModelHostBudgets,
);

impl MediaBackend for BookedReplies {
    fn run<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse> {
        Box::pin(holding_replies(&self.1, async move {
            let answer = self.0.run(request, lease).await;
            if let Ok(response) = &answer {
                charge_decoded(response);
            }
            answer
        }))
    }

    /// FIX 9517: a call stopped part way keeps what it completed.
    fn run_progress<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
    ) -> MediaProgressFuture<'a> {
        Box::pin(holding_replies(&self.1, async move {
            let answer = self.0.run_progress(request, lease).await;
            if let Ok(response) = &answer {
                charge_decoded(response);
            }
            answer
        }))
    }

    fn submit<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, String> {
        Box::pin(holding_replies(&self.1, self.0.submit(request, lease)))
    }

    fn poll<'a>(
        &'a self,
        model: &'a ModelId,
        job: &'a str,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaJobState> {
        Box::pin(holding_replies(&self.1, self.0.poll(model, job, lease)))
    }

    fn cancel<'a>(
        &'a self,
        model: &'a ModelId,
        job: &'a str,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, ()> {
        Box::pin(holding_replies(&self.1, self.0.cancel(model, job, lease)))
    }

    fn reference_compatibility(&self, request: &MediaRequest) -> ReferenceCompatibility {
        self.0.reference_compatibility(request)
    }

    fn preflight(&self, request: &MediaRequest) -> LlmResult<()> {
        self.0.preflight(request)
    }

    fn broker_isolation(&self) -> Option<BrokerIsolation> {
        self.0.broker_isolation()
    }
}

/// Charges `response`'s decoded bytes on the line of the media call this
/// task runs, held with its replies' until the call ends (FIX 10626).
fn charge_decoded(response: &MediaResponse) {
    let bytes = response
        .parts
        .iter()
        .map(|part| match part {
            MediaPart::Text { text } => text.len(),
            MediaPart::Image { bytes, .. }
            | MediaPart::Audio { bytes, .. }
            | MediaPart::Video { bytes, .. } => bytes.len(),
            MediaPart::Embedding { vector } => std::mem::size_of_val(vector.as_slice()),
        })
        .sum();
    // The call holds the charge: the reply it returns keeps nothing.
    drop(charge_read(bytes));
}
