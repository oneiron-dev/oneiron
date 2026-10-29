//! One call's deadline across its whole walk (FIX 7792, FIX 8134, FIX 8213):
//! every rung it sends, every wait for an offer back and the owner's
//! fallback share it. A caller with a deadline of its own ends the call
//! there: a send still out is dropped, every permit admitted is settled (a
//! dispatched one keeps its reservation as spend) and the call ends with a
//! timeout, never a rate refusal. A raw or media call names no deadline but
//! its caller's presence: it waits for offers back until one is back, and a
//! caller that leaves ends it. Every other call keeps the vault's longest
//! wait as the bound of its waits alone.
use std::future::Future;
use std::time::Duration;

use oneiron::llm::media::MediaRequest;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::{
    LlmError, LlmRequest, LlmResponse, LlmResult, LlmStream, ModelId, RetryableLlmError,
};
use tokio::time::Instant;

use super::super::media::{MediaAnswer, RungVoices};
use super::super::walk::Walk;
use super::{Call, OfferLadder};

/// How long one call may take.
#[derive(Clone, Copy, Debug)]
pub enum CallDeadline {
    /// The caller's own deadline: sends, waits and fallbacks all end by it.
    Caller(Instant),
    /// No deadline but the caller's presence: the call waits for offers
    /// back for as long as its caller holds it.
    Open,
    /// The bound of the call's waits for offers back alone, the vault's
    /// longest wait or a caller's wait budget; sends are not bounded.
    Waits(Instant),
}

impl CallDeadline {
    /// The caller's deadline, `left` from now.
    #[must_use]
    pub fn caller_in(left: Duration) -> Self {
        Instant::now()
            .checked_add(left)
            .map_or(Self::Open, Self::Caller)
    }

    /// Waits for offers back bounded by `budget` from now, in all.
    #[must_use]
    pub fn waits_within(budget: Duration) -> Self {
        Instant::now()
            .checked_add(budget)
            .map_or(Self::Open, Self::Waits)
    }

    /// The seconds a wait for an offer back may still take: the rest of the
    /// deadline's, or no bound for an open call.
    pub(super) fn wait_secs(self) -> u64 {
        match self {
            Self::Open => u64::MAX,
            Self::Caller(at) | Self::Waits(at) => {
                at.saturating_duration_since(Instant::now()).as_secs()
            }
        }
    }

    /// Whether the caller's own deadline has passed. Only it ends a call.
    pub(super) fn expired(self) -> bool {
        matches!(self, Self::Caller(at) if Instant::now() >= at)
    }

    /// `work`, up to the caller's deadline: `None` once it passed first.
    pub(super) async fn bound<T>(self, work: impl Future<Output = T>) -> Option<T> {
        match self {
            Self::Caller(at) => tokio::time::timeout_at(at, work).await.ok(),
            Self::Open | Self::Waits(_) => Some(work.await),
        }
    }

    /// The end of a call its caller's deadline stopped: incomplete, a
    /// timeout.
    pub(super) fn expiry() -> LlmError {
        RetryableLlmError::Timeout.into()
    }
}

impl OfferLadder {
    /// The vault's longest wait, from now, as the bound of a call's waits.
    pub(super) fn host_wait(&self) -> CallDeadline {
        CallDeadline::waits_within(Duration::from_secs(self.rests.max_wait_secs()))
    }

    /// The call's end with no answer: past a caller's deadline, or with a
    /// caller's deadline before any offer it waits for is back, a timeout
    /// once the owner is asked about the parked offers; otherwise
    /// [`Self::unanswered`].
    pub(super) fn ended(&self, call: Call<'_>, walk: Walk) -> LlmError {
        if matches!(call.deadline, CallDeadline::Caller(_))
            && (call.deadline.expired() || walk.limited())
        {
            self.ask_parked(&walk, call.needs, call.run.principal());
            return CallDeadline::expiry();
        }
        self.unanswered(call, walk)
    }

    /// [`Self::generate_while`] on `deadline` (FIX 8213): a caller's own
    /// deadline bounds every send, wait and fallback; an open one waits
    /// for offers back as long as its caller holds the call.
    pub async fn generate_by(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
        deadline: CallDeadline,
    ) -> LlmResult<LlmResponse> {
        self.generate_from(run, request, selector, may_send, deadline, true, None)
            .await
            .map(|(response, _)| response)
    }

    /// [`Self::generate_by`], with the model of the rung that answered, the
    /// owner's fallback included (FIX 7792).
    pub async fn generate_served_by(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
        deadline: CallDeadline,
    ) -> LlmResult<(LlmResponse, ModelId)> {
        self.generate_from(run, request, selector, may_send, deadline, true, None)
            .await
    }

    /// [`Self::generate_exact_within`] on `deadline` (FIX 7792): only a
    /// ladder that is one picked model takes the call.
    pub async fn generate_exact_by(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
        deadline: CallDeadline,
    ) -> LlmResult<LlmResponse> {
        if !self.picked || self.rungs.len() != 1 {
            return Err(oneiron::FatalLlmError::InvalidRequest.into());
        }
        self.generate_from(run, request, selector, may_send, deadline, false, None)
            .await
            .map(|(response, _)| response)
    }

    /// [`Self::stream`] on `deadline` (FIX 8213).
    pub fn stream_by(
        self: &std::sync::Arc<Self>,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        deadline: CallDeadline,
    ) -> LlmResult<LlmStream<'static>> {
        self.stream_from(run, request, selector, true, deadline)
    }

    /// [`Self::media`] on `deadline` (FIX 8134): the caller's one deadline
    /// across every rung, wait and fallback.
    pub(in crate::models) async fn media_by(
        &self,
        run: &RunAdmission,
        request: MediaRequest,
        selector: Option<&str>,
        voices: Option<&RungVoices>,
        deadline: CallDeadline,
    ) -> LlmResult<MediaAnswer> {
        self.media_from(run, request, selector, deadline, true, voices)
            .await
    }
}
