//! A live hearing's rate and quota refusals (FIX 9515).
//! Entry: classify_soniox_limit.
//!
//! Soniox says a limit inside the open socket, as an error frame. It is read
//! in the providers' one vocabulary ([`oneiron::llm::limit`]): a rate limit,
//! a spent window or spent credit, with the waits it names. The hearing does
//! not fail on it, and it never spends the one reconnect a dropped socket
//! gets: the segment is set aside as a drop's is (its lease settles what it
//! admitted, its final words carry, what Soniox did not make final and the
//! cuts it did not answer wait in order), the offer rests where the vault
//! keeps rests, and the same admitted hearing opens its next segment once
//! the offer is back. A spent window or spent credit asks the owner the
//! existing quota question; the owner's choices, never this code, decide a
//! payment or a fallback, and no deadline ends the wait while the call
//! lasts. Audio heard meanwhile waits, whole (Rule 5).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use oneiron::RetryableLlmError;
use oneiron::llm::limit;
use oneiron::voice_cascade::soniox::SonioxUpdate;
use tokio::time::Instant;

use super::{SonioxLive, SonioxRung, invalid};
use crate::models::cooldown::{Asked, OfferCooldowns, Refusal, WAIT_SLICE};
use crate::models::ladder::OfferLadder;

/// The Soniox error codes that are a limit: a rate limit or spent quota, and
/// spent credit.
const LIMIT_ERROR_CODES: [u64; 2] = [429, 402];

/// The longest a hearing waits between looks when no vault keeps the
/// offer's rest and the refusal named no wait: a pace, not a deadline.
const UNKEPT_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// The limit a Soniox error frame says, in the providers' one vocabulary;
/// `None` for any other frame.
pub(super) fn classify_soniox_limit(frame: &serde_json::Value) -> Option<RetryableLlmError> {
    let code = frame.get("error_code")?.as_u64()?;
    if !LIMIT_ERROR_CODES.contains(&code) {
        return None;
    }
    let status = u16::try_from(code).ok()?;
    let message = frame
        .get("error_message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    // Its words read as any provider's error body's.
    let body = serde_json::json!({ "error": { "message": message } });
    Some(limit::limit_refusal(status, &BTreeMap::new(), &body))
}

/// A limit refusal as the offer's rest takes it; `None` for any other
/// error. One mapping for every caller that rests an offer on a limit.
pub(in crate::models) fn limit_refusal_of(error: &RetryableLlmError) -> Option<Refusal<'_>> {
    match error {
        RetryableLlmError::RateLimited {
            retry_after,
            resets_at,
        } => Some(Refusal {
            retry_after: *retry_after,
            resets_at,
            spent: None,
        }),
        RetryableLlmError::QuotaSpent {
            kind,
            retry_after,
            resets_at,
        } => Some(Refusal {
            retry_after: *retry_after,
            resets_at,
            spent: Some(*kind),
        }),
        _ => None,
    }
}

/// A live hearing waiting for its offer back after a limit.
pub(super) struct LiveAsrQuotaWait {
    /// Where the offer's rest is kept, with the rung's offer, when a vault
    /// keeps it: the wait ends once the rest does, or once the owner's
    /// answer clears it.
    kept: Option<(Arc<OfferCooldowns>, Arc<SonioxRung>)>,
    /// Without a kept rest: when the refusal's own wait ends.
    until: Instant,
    /// The next look.
    next: Pin<Box<tokio::time::Sleep>>,
}

impl LiveAsrQuotaWait {
    /// Rests `rung`'s offer for `refusal` where `rests` keeps rests, and
    /// asks the owner when a window or credit was spent. `strikes` counts
    /// the limits in a row, for the pace when no rest is kept.
    fn start(
        rung: &Arc<SonioxRung>,
        rests: Option<&Arc<OfferCooldowns>>,
        refusal: &RetryableLlmError,
        strikes: u32,
    ) -> Self {
        let kept = rests.zip(rung.offer.as_ref()).and_then(|(rests, offer)| {
            let rest = rests.rest(offer, &rung.model, limit_refusal_of(refusal)?)?;
            if rest.spent.is_some() {
                let asked = Asked {
                    provider: &rung.provider,
                    wire_model: &rung.model,
                };
                // No other wire takes a live hearing: no fallback is offered
                // here, and the owner's other choices stand.
                rests.ask(
                    offer,
                    rest,
                    asked,
                    &[rung.provider.as_str()],
                    &|_: &OfferLadder| false,
                );
            }
            Some((Arc::clone(rests), Arc::clone(rung)))
        });
        let asked = match refusal {
            RetryableLlmError::RateLimited { retry_after, .. }
            | RetryableLlmError::QuotaSpent { retry_after, .. } => *retry_after,
            _ => None,
        };
        let pace = asked.map_or_else(
            || Duration::from_secs(1u64 << strikes.min(6)).min(UNKEPT_BACKOFF_MAX),
            Duration::from_secs,
        );
        let now = Instant::now();
        let first = if kept.is_some() { WAIT_SLICE } else { pace };
        Self {
            kept,
            until: now + pace,
            next: Box::pin(tokio::time::sleep_until(now + first)),
        }
    }

    /// Ready once the offer is back: its kept rest ended or was cleared, or,
    /// with none kept, the refusal's own wait passed.
    fn poll_back(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            if self.next.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            let back = match &self.kept {
                Some((rests, rung)) => rung
                    .offer
                    .as_ref()
                    .is_none_or(|offer| rests.resting(offer, &rung.model).is_none()),
                None => Instant::now() >= self.until,
            };
            if back {
                return Poll::Ready(());
            }
            let next = match &self.kept {
                Some(_) => Instant::now() + WAIT_SLICE,
                None => self.until,
            };
            self.next.as_mut().reset(next);
        }
    }
}

impl SonioxLive {
    /// A limit Soniox said on the open segment: the segment is set aside as
    /// a dropped one is, without spending the hearing's one reconnect, and
    /// the next opens once the offer is back. The words it made final carry.
    pub(super) fn hold_for_limit(
        &mut self,
        refusal: RetryableLlmError,
    ) -> oneiron::Result<Vec<SonioxUpdate>> {
        let segment = self.segment.take().ok_or_else(|| invalid("no segment"))?;
        tracing::warn!(
            limit = %refusal,
            "live transcribe offer limited; the hearing waits for it"
        );
        self.limit_strikes = self.limit_strikes.saturating_add(1);
        self.limited = Some(LiveAsrQuotaWait::start(
            &self.rung,
            self.rests.as_ref(),
            &refusal,
            self.limit_strikes - 1,
        ));
        self.set_aside(segment)
    }

    /// Ready once no limit holds the hearing: the next segment may open.
    pub(super) fn poll_limit(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let Some(wait) = &mut self.limited else {
            return Poll::Ready(());
        };
        if wait.poll_back(cx).is_pending() {
            return Poll::Pending;
        }
        self.limited = None;
        Poll::Ready(())
    }
}
