//! Slot-list/hold/book anti-abuse enforcement guards.

use std::num::NonZeroU32;
use std::sync::Arc;

use axum::extract::State;
use oneiron::Vault;
use oneiron::booking::anti_abuse::{
    BookingAbuseVerdict, BookingAntiAbuseRuleRow, BookingQuarantineAdmission, BookingRateDecision,
    BookingRequestFacts, admit_quarantine_submission, applicable_booking_anti_abuse_rules,
    book_rate_knobs, evaluate_booking_book_request, evaluate_booking_hold_request,
    evaluate_booking_slot_list_request, hold_rate_knobs, observe_book_request,
    observe_hold_request, observe_slot_list_request, server_submission_fingerprint,
    slot_list_rate_knobs,
};

use super::support::{correction_body, engine_error, log_rate_block, now_secs};
use crate::error::ApiError;
use crate::server::SyncServer;

/// The hashed identity behind one rate bucket. With an email available the
/// engine keys the book window on the IP+email pair, so two people behind
/// one corporate NAT keep independent budgets; raw addresses never cross
/// into persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BookingRateKey {
    pub ip_hash: [u8; 32],
    pub email_hash: Option<[u8; 32]>,
}

/// How a guard call disposes of the request. Route handlers translate:
/// `SilentOk` answers exactly like an ordinary 200, `RetryAfter` carries the
/// `Retry-After` hint, `PromptCorrection` is a 200-class correction body,
/// and `QuarantineAndAccept` accepts while routing to owner review.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BookingHttpDisposition {
    Continue,
    SilentOk,
    RetryAfter { seconds: u64 },
    PromptCorrection { body: String },
    QuarantineAndAccept,
}

/// Loads every row that governs this request: the page-wide stack PLUS the
/// named event type's exact stack. A page-wide owner configuration must
/// keep applying when a request carries an event type, so the adapter never
/// loads by exact scope alone.
pub(super) fn load_rows(
    vault: &Vault,
    facts: &BookingRequestFacts,
) -> std::result::Result<Vec<BookingAntiAbuseRuleRow>, ApiError> {
    applicable_booking_anti_abuse_rules(vault, &facts.page_ref, &facts.event_type)
        .map_err(engine_error)
}

/// Maps an engine verdict onto the public disposition. Returns `None` for
/// `Allow` so the caller can move on to its endpoint-specific counter.
/// `SilentHttp200Reject` performs no write and emits no request-bound log:
/// from the outside the answer is just 200.
pub(super) fn disposition_from_verdict(
    endpoint: &'static str,
    facts: &BookingRequestFacts,
    verdict: BookingAbuseVerdict,
) -> std::result::Result<Option<BookingHttpDisposition>, ApiError> {
    match verdict {
        BookingAbuseVerdict::Allow => Ok(None),
        BookingAbuseVerdict::SilentHttp200Reject => Ok(Some(BookingHttpDisposition::SilentOk)),
        BookingAbuseVerdict::PromptCorrection { field, message } => {
            Ok(Some(BookingHttpDisposition::PromptCorrection {
                body: correction_body(field, &message),
            }))
        }
        BookingAbuseVerdict::RateLimited { retry_after_secs } => {
            log_rate_block(endpoint, &facts.ip_hash, retry_after_secs);
            Ok(Some(BookingHttpDisposition::RetryAfter {
                seconds: retry_after_secs,
            }))
        }
        BookingAbuseVerdict::Quarantine { .. } => {
            // Book admission owns quarantine's duplicate/quota/write transaction.
            Err(ApiError::internal_server_error(
                "quarantine requires book admission",
            ))
        }
    }
}

/// Slot-list guard: silent bot rejects, then the per-IP minute window, with
/// the response cache discharging requests before any quota is spent.
///
/// # Errors
///
/// [`ApiError`] internal-server on engine or storage failure.
pub(crate) async fn enforce_slot_list(
    State(server): State<Arc<SyncServer>>,
    facts: BookingRequestFacts,
    cache_hit: bool,
) -> std::result::Result<BookingHttpDisposition, ApiError> {
    let vault = &server.vault;
    let rows = load_rows(vault, &facts)?;
    let Some((per_minute_per_ip, _)) =
        slot_list_rate_knobs(&rows, &facts.page_ref, &facts.event_type)
    else {
        return Ok(BookingHttpDisposition::Continue);
    };
    let now = now_secs()?;
    // A fresh cached listing answers without spending quota; the handler
    // serves the body through `cached_slot_list_body`.
    if cache_hit {
        return Ok(BookingHttpDisposition::Continue);
    }
    match observe_slot_list_request(vault, &facts.ip_hash, per_minute_per_ip, now)
        .map_err(engine_error)?
    {
        BookingRateDecision::Allowed => {
            let verdict = evaluate_booking_slot_list_request(&rows, &facts);
            if let Some(disposition) = disposition_from_verdict("slot-list", &facts, verdict)? {
                return Ok(disposition);
            }
            Ok(BookingHttpDisposition::Continue)
        }
        BookingRateDecision::Exceeded { retry_after_secs } => {
            log_rate_block("slot-list", &facts.ip_hash, retry_after_secs);
            Ok(BookingHttpDisposition::RetryAfter {
                seconds: retry_after_secs,
            })
        }
    }
}

/// Hold guard: silent bot rejects, the one-active-hold-per-session verdict
/// from the engine, then the per-IP minute window.
///
/// # Errors
///
/// [`ApiError`] internal-server on engine or storage failure.
pub(crate) async fn enforce_hold(
    State(server): State<Arc<SyncServer>>,
    facts: BookingRequestFacts,
) -> std::result::Result<BookingHttpDisposition, ApiError> {
    let vault = &server.vault;
    let rows = load_rows(vault, &facts)?;
    let verdict = evaluate_booking_hold_request(&rows, &facts);
    if let Some(disposition) = disposition_from_verdict("hold", &facts, verdict)? {
        return Ok(disposition);
    }
    if let Some((max_active_per_session, _)) =
        hold_rate_knobs(&rows, &facts.page_ref, &facts.event_type)
        && facts.active_holds_for_session >= max_active_per_session
    {
        return Ok(BookingHttpDisposition::RetryAfter { seconds: 60 });
    }
    let Some((_, per_minute_per_ip)) = hold_rate_knobs(&rows, &facts.page_ref, &facts.event_type)
    else {
        return Ok(BookingHttpDisposition::Continue);
    };
    match observe_hold_request(vault, &facts.ip_hash, per_minute_per_ip, now_secs()?)
        .map_err(engine_error)?
    {
        BookingRateDecision::Allowed => Ok(BookingHttpDisposition::Continue),
        BookingRateDecision::Exceeded { retry_after_secs } => {
            log_rate_block("hold", &facts.ip_hash, retry_after_secs);
            Ok(BookingHttpDisposition::RetryAfter {
                seconds: retry_after_secs,
            })
        }
    }
}

/// Book guard: silent bot rejects, the active-future-booking verdict from
/// the engine, then the minute window keyed on the combined IP+email pair
/// whenever an email is available.
///
/// # Errors
///
/// [`ApiError`] internal-server on engine or storage failure.
pub(crate) async fn enforce_book(
    State(server): State<Arc<SyncServer>>,
    mut facts: BookingRequestFacts,
) -> std::result::Result<BookingHttpDisposition, ApiError> {
    // This is the trusted production admission boundary: never honour a
    // fingerprint supplied by the transport.
    facts.submission_fingerprint = server_submission_fingerprint(&facts);
    let vault = &server.vault;
    let rows = load_rows(vault, &facts)?;
    let verdict = evaluate_booking_book_request(&rows, &facts);
    let is_quarantine = matches!(verdict, BookingAbuseVerdict::Quarantine { .. });
    let per_minute_per_ip = match book_rate_knobs(&rows, &facts.page_ref, &facts.event_type) {
        Some((per_minute_per_ip, _)) => per_minute_per_ip,
        // Quarantine is a write path, so it must always consume a bounded
        // bucket even when the owner has not configured BookRate.
        None if is_quarantine => NonZeroU32::new(1).expect("one is non-zero"),
        None => {
            return disposition_from_verdict("book", &facts, verdict)
                .map(|disposition| disposition.unwrap_or(BookingHttpDisposition::Continue));
        }
    };
    let key = BookingRateKey {
        ip_hash: facts.ip_hash,
        email_hash: facts.email_hash,
    };
    if !is_quarantine
        && let Some(disposition) = disposition_from_verdict("book", &facts, verdict.clone())?
    {
        return Ok(disposition);
    }
    if let BookingAbuseVerdict::Quarantine { reason } = &verdict {
        // This one engine door serializes exact-retry lookup, aggregate quota,
        // and first durable quarantine write.
        match admit_quarantine_submission(vault, &facts, reason, per_minute_per_ip, now_secs()?)
            .map_err(engine_error)?
        {
            BookingQuarantineAdmission::Accepted(receipt) => {
                tracing::info!(
                    endpoint = "book",
                    claim_ref = %receipt.claim_ref,
                    "booking anti-abuse quarantine accepted"
                );
                return Ok(BookingHttpDisposition::QuarantineAndAccept);
            }
            BookingQuarantineAdmission::RateLimited { retry_after_secs } => {
                log_rate_block("book", &facts.ip_hash, retry_after_secs);
                return Ok(BookingHttpDisposition::RetryAfter {
                    seconds: retry_after_secs,
                });
            }
        }
    }
    // A non-quarantine request consumes its identity confirmation bucket.
    match observe_book_request(
        vault,
        &key.ip_hash,
        key.email_hash.as_ref(),
        per_minute_per_ip,
        now_secs()?,
    )
    .map_err(engine_error)?
    {
        BookingRateDecision::Allowed => Ok(BookingHttpDisposition::Continue),
        BookingRateDecision::Exceeded { retry_after_secs } => {
            log_rate_block("book", &facts.ip_hash, retry_after_secs);
            Ok(BookingHttpDisposition::RetryAfter {
                seconds: retry_after_secs,
            })
        }
    }
}
