//! A media rung's backend with its replies' bytes held (FIX 8615): each of
//! its calls (an answer, a job's submit, poll or cancel) runs holding the
//! bytes of every reply read for it on the media-reply line, from the first
//! byte read, across the adapter's decode, until the decoded answer leaves
//! the adapter. Everything else is the wrapped backend's.
use std::sync::Arc;

use oneiron::llm::BrokerIsolation;
use oneiron::llm::media::{
    MediaBackend, MediaFuture, MediaJobState, MediaRequest, MediaResponse, ReferenceCompatibility,
};
use oneiron::{BudgetLease, LlmResult, ModelId};

use crate::models::http::holding_replies;

/// `0`, its calls holding their replies' bytes.
pub(super) struct BookedReplies(pub(super) Arc<dyn MediaBackend>);

impl MediaBackend for BookedReplies {
    fn run<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse> {
        Box::pin(holding_replies(self.0.run(request, lease)))
    }

    fn submit<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, String> {
        Box::pin(holding_replies(self.0.submit(request, lease)))
    }

    fn poll<'a>(
        &'a self,
        model: &'a ModelId,
        job: &'a str,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaJobState> {
        Box::pin(holding_replies(self.0.poll(model, job, lease)))
    }

    fn cancel<'a>(
        &'a self,
        model: &'a ModelId,
        job: &'a str,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, ()> {
        Box::pin(holding_replies(self.0.cancel(model, job, lease)))
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
