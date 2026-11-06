//! Slot-list/hold/book/amend anti-abuse enforcement guards.

use std::num::NonZeroU32;
use std::sync::Arc;

use axum::extract::State;
use oneiron::Vault;
use oneiron::booking::anti_abuse::{
    BookingAbuseVerdict, BookingAntiAbuseRuleRow, BookingQuarantineAdmission,
    BookingQuarantineRestoreInput, BookingRateDecision, BookingRequestFacts,
    admit_quarantine_submission, admit_quarantine_submission_without_quota,
    admit_restorable_quarantine_submission, applicable_booking_anti_abuse_rules, book_rate_knobs,
    evaluate_booking_amend_request, evaluate_booking_book_request, evaluate_booking_hold_request,
    evaluate_booking_slot_list_request, hold_rate_knobs, observe_book_request,
    observe_hold_request, observe_slot_list_request, server_submission_fingerprint,
    slot_list_rate_knobs,
};
use oneiron::limit_ask::EngineLimit;

use super::support::{correction_body, engine_error, log_rate_block};
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

/// The caller one booking request is admitted for (FIX 128-131).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BookingCaller {
    /// A pre-auth visitor: the owner's anti-abuse windows govern it.
    Anonymous,
    /// An authenticated caller, keyed by the hash of its actor. It never
    /// spends the owner's per-minute windows: its calls are counted against
    /// `[limits]` rows that ask and serve.
    Authenticated { actor: [u8; 32] },
}

/// Counts one authenticated call under `row` and measures the actor's calls
/// this minute against it: past it the row asks, and the call goes on.
fn measure_calls(
    server: &SyncServer,
    row: EngineLimit,
    actor: &[u8; 32],
) -> std::result::Result<(), ApiError> {
    let calls = server
        .booking_calls
        .count(row, actor, server.booking_now_secs()?);
    let _ = server.vault.measure_limit(row, calls);
    Ok(())
}

/// How a guard call disposes of the request. Route handlers translate:
/// `SilentOk` answers exactly like an ordinary 200, `RetryAfter` carries the
/// `Retry-After` hint and the bound it is past, `PromptCorrection` is a
/// 200-class correction body, and `QuarantineAndAccept` accepts while routing
/// to owner review.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BookingHttpDisposition {
    Continue,
    SilentOk,
    RetryAfter { seconds: u64, bound: u64 },
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
                // The engine's verdict names no bound.
                bound: 0,
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

/// Spends one token from the book minute bucket and translates the outcome.
///
/// Confirmation and amendment share this bucket: both are writes on the same
/// page, so a caller cannot mint fresh budget by switching between the two.
fn spend_book_bucket(
    server: &SyncServer,
    endpoint: &'static str,
    key: &BookingRateKey,
    per_minute_per_ip: NonZeroU32,
) -> std::result::Result<BookingHttpDisposition, ApiError> {
    match observe_book_request(
        &server.vault,
        &key.ip_hash,
        key.email_hash.as_ref(),
        per_minute_per_ip,
        server.booking_now_secs()?,
    )
    .map_err(engine_error)?
    {
        BookingRateDecision::Allowed => Ok(BookingHttpDisposition::Continue),
        BookingRateDecision::Exceeded { retry_after_secs } => {
            log_rate_block(endpoint, &key.ip_hash, retry_after_secs);
            Ok(BookingHttpDisposition::RetryAfter {
                seconds: retry_after_secs,
                bound: u64::from(per_minute_per_ip.get()),
            })
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
    caller: BookingCaller,
) -> std::result::Result<BookingHttpDisposition, ApiError> {
    let vault = &server.vault;
    let rows = load_rows(vault, &facts)?;
    // FIX 128: an authenticated listing is counted, never windowed.
    if let BookingCaller::Authenticated { actor } = caller {
        measure_calls(
            &server,
            EngineLimit::BookingAvailabilityCallsPerMinute,
            &actor,
        )?;
    }
    let Some((per_minute_per_ip, _)) =
        slot_list_rate_knobs(&rows, &facts.page_ref, &facts.event_type)
    else {
        return Ok(BookingHttpDisposition::Continue);
    };
    let now = server.booking_now_secs()?;
    // A fresh cached listing answers without spending quota; the handler
    // serves the body through `cached_slot_list_body`.
    if cache_hit {
        return Ok(BookingHttpDisposition::Continue);
    }
    if matches!(caller, BookingCaller::Authenticated { .. }) {
        let verdict = evaluate_booking_slot_list_request(&rows, &facts);
        return disposition_from_verdict("slot-list", &facts, verdict)
            .map(|disposition| disposition.unwrap_or(BookingHttpDisposition::Continue));
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
                bound: u64::from(per_minute_per_ip.get()),
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
    caller: BookingCaller,
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
        return Ok(BookingHttpDisposition::RetryAfter {
            seconds: 60,
            bound: u64::from(max_active_per_session),
        });
    }
    // FIX 129: an authenticated hold is counted, never windowed.
    if let BookingCaller::Authenticated { actor } = caller {
        measure_calls(&server, EngineLimit::BookingHoldCallsPerMinute, &actor)?;
        return Ok(BookingHttpDisposition::Continue);
    }
    let Some((_, per_minute_per_ip)) = hold_rate_knobs(&rows, &facts.page_ref, &facts.event_type)
    else {
        return Ok(BookingHttpDisposition::Continue);
    };
    match observe_hold_request(
        vault,
        &facts.ip_hash,
        per_minute_per_ip,
        server.booking_now_secs()?,
    )
    .map_err(engine_error)?
    {
        BookingRateDecision::Allowed => Ok(BookingHttpDisposition::Continue),
        BookingRateDecision::Exceeded { retry_after_secs } => {
            log_rate_block("hold", &facts.ip_hash, retry_after_secs);
            Ok(BookingHttpDisposition::RetryAfter {
                seconds: retry_after_secs,
                bound: u64::from(per_minute_per_ip.get()),
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
// The executor's confirms go through `enforce_book_restorable`; this form
// keeps no submission.
#[allow(dead_code)]
pub(crate) async fn enforce_book(
    State(server): State<Arc<SyncServer>>,
    facts: BookingRequestFacts,
) -> std::result::Result<BookingHttpDisposition, ApiError> {
    enforce_book_restorable(State(server), facts, None, BookingCaller::Anonymous).await
}

/// [`enforce_book`] for a confirm whose raw submission the boundary holds:
/// a quarantine keeps it restorable (FIX 7851), so the owner's restore books
/// it through the ordinary booking writer.
///
/// # Errors
///
/// As [`enforce_book`].
pub(crate) async fn enforce_book_restorable(
    State(server): State<Arc<SyncServer>>,
    mut facts: BookingRequestFacts,
    restore: Option<BookingQuarantineRestoreInput<'_>>,
    caller: BookingCaller,
) -> std::result::Result<BookingHttpDisposition, ApiError> {
    // This is the trusted production admission boundary: never honour a
    // fingerprint supplied by the transport.
    facts.submission_fingerprint = server_submission_fingerprint(&facts);
    let vault = &server.vault;
    let rows = load_rows(vault, &facts)?;
    let verdict = evaluate_booking_book_request(&rows, &facts);
    // FIX 130, 131: an authenticated confirm is counted, never windowed. A
    // quarantined one is still kept for the owner's review, through the same
    // admission and its exact-retry replay, with no per-minute quota.
    if let BookingCaller::Authenticated { actor } = caller {
        if let BookingAbuseVerdict::Quarantine { reason } = &verdict {
            measure_calls(
                &server,
                EngineLimit::BookingQuarantineCallsPerMinute,
                &actor,
            )?;
            return admit_quarantine(&server, &facts, reason, None, restore.as_ref());
        }
        if let Some(disposition) = disposition_from_verdict("book", &facts, verdict)? {
            return Ok(disposition);
        }
        measure_calls(&server, EngineLimit::BookingWriteCallsPerMinute, &actor)?;
        return Ok(BookingHttpDisposition::Continue);
    }
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
        return admit_quarantine(
            &server,
            &facts,
            reason,
            Some(per_minute_per_ip),
            restore.as_ref(),
        );
    }
    // A non-quarantine request consumes its identity confirmation bucket.
    spend_book_bucket(&server, "book", &key, per_minute_per_ip)
}

/// Keeps a quarantined confirm for the owner's review. This one engine door
/// serializes exact-retry lookup, the page-wide aggregate quota
/// (`per_minute_per_ip`), and first durable quarantine write. An
/// authenticated caller's submission (`None`) spends no token of that
/// quota, so it never takes an anonymous visitor's place (FIX 131).
fn admit_quarantine(
    server: &SyncServer,
    facts: &BookingRequestFacts,
    reason: &str,
    per_minute_per_ip: Option<NonZeroU32>,
    restore: Option<&BookingQuarantineRestoreInput<'_>>,
) -> std::result::Result<BookingHttpDisposition, ApiError> {
    let vault = &server.vault;
    let now = server.booking_now_secs()?;
    let admission = match (per_minute_per_ip, restore) {
        (None, restore) => {
            admit_quarantine_submission_without_quota(vault, facts, reason, now, restore)
        }
        (Some(per_minute), Some(restore)) => {
            admit_restorable_quarantine_submission(vault, facts, reason, per_minute, now, restore)
        }
        (Some(per_minute), None) => {
            admit_quarantine_submission(vault, facts, reason, per_minute, now)
        }
    };
    match admission.map_err(engine_error)? {
        BookingQuarantineAdmission::Accepted(receipt) => {
            tracing::info!(
                endpoint = "book",
                claim_ref = %receipt.claim_ref,
                "booking anti-abuse quarantine accepted"
            );
            Ok(BookingHttpDisposition::QuarantineAndAccept)
        }
        BookingQuarantineAdmission::RateLimited { retry_after_secs } => {
            log_rate_block("book", &facts.ip_hash, retry_after_secs);
            Ok(BookingHttpDisposition::RetryAfter {
                seconds: retry_after_secs,
                bound: per_minute_per_ip.map_or(0, |per_minute| u64::from(per_minute.get())),
            })
        }
    }
}

/// Amend guard for cancel and reschedule. An amendment presents an action
/// token, never a form, so the book-time controls have no evidence to read
/// and cannot refuse it; ARCH-0062 keeps it on "the same solver rules". What
/// survives is the write bucket, spent on whatever identity the facts carry —
/// for a token amendment the admission boundary supplies no email, so that is
/// the IP hash alone.
///
/// # Errors
///
/// [`ApiError`] internal-server on engine or storage failure.
pub(crate) async fn enforce_amend(
    State(server): State<Arc<SyncServer>>,
    facts: BookingRequestFacts,
    caller: BookingCaller,
) -> std::result::Result<BookingHttpDisposition, ApiError> {
    let vault = &server.vault;
    let rows = load_rows(vault, &facts)?;
    let verdict = evaluate_booking_amend_request(&rows, &facts);
    if let Some(disposition) = disposition_from_verdict("amend", &facts, verdict)? {
        return Ok(disposition);
    }
    // FIX 130: an authenticated amendment is counted with its confirms,
    // never windowed.
    if let BookingCaller::Authenticated { actor } = caller {
        measure_calls(&server, EngineLimit::BookingWriteCallsPerMinute, &actor)?;
        return Ok(BookingHttpDisposition::Continue);
    }
    let Some((per_minute_per_ip, _)) = book_rate_knobs(&rows, &facts.page_ref, &facts.event_type)
    else {
        return Ok(BookingHttpDisposition::Continue);
    };
    let key = BookingRateKey {
        ip_hash: facts.ip_hash,
        email_hash: facts.email_hash,
    };
    spend_book_bucket(&server, "amend", &key, per_minute_per_ip)
}
