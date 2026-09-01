use oneiron::booking::agent_api::{
    BookingBookInput, BookingBookResult, BookingIntakeAnswer, BookingOperationRequest,
    BookingOperationResponse, SelectedSlot,
};
use oneiron::booking::anti_abuse::{
    BookingRequestFacts, EmailValidationEvidence, booking_email_hash, booking_ip_hash,
    booking_session_hash,
};
use oneiron::booking::{
    ActiveHoldSource, BOOKING_BOOKER_CONTACT_PREDICATE, BOOKING_SOURCE_PAGE_PREDICATE,
    BOOKING_STATUS_PREDICATE, BookingBookerContactValue, BookingSourcePageValue, BookingStatus,
    BookingStatusValue, SessionKey, VaultActiveHoldSource,
};
use oneiron::registry::ENTITY_TYPE_EVENT;
use oneiron::{CalendarReadRequest, ClaimLifecycleStatus, EntityId, TimeRange, Vault};

use super::BookingTransportContext;
use super::constants::{INTAKE_DOMAIN, SELECTED_SLOT_DOMAIN};
use super::helpers::{domain_digest, engine_read_error};
use super::subject::{booker_contact_ref, session_key};
use crate::api::booking_anti_abuse::BookingHttpDisposition;
use crate::error::ApiError;
use crate::server::SyncServer;

// -------------------------------------------------------------------------
// Admission
// -------------------------------------------------------------------------

/// Builds the ONE-1817 facts for one request.
///
/// The identity inputs — source address, booker email, visitor session, and
/// the authenticated actor — are derived the same way for both transports, so
/// a caller cannot get a fresh budget by switching doors.
pub(super) fn admission_facts(
    server: &SyncServer,
    page_ref: EntityId,
    request: &BookingOperationRequest,
    transport: &BookingTransportContext,
    now: u64,
) -> Result<BookingRequestFacts, ApiError> {
    let mut ip_material = transport.source_ip.to_string();
    if let Some(actor) = transport.actor_key() {
        // An authenticated connector actor keys its own bucket, so two agents
        // behind one address keep independent budgets — the same reason the
        // engine keys the book window on the IP+email pair.
        ip_material.push('\0');
        ip_material.push_str(&actor);
    }
    let ip_hash = booking_ip_hash(&ip_material);

    let (event_type, session_ref, booker_email, selected_slot, intake) = match request {
        BookingOperationRequest::Availability(input) => (
            Some(input.event_type.clone()),
            Some(input.session_ref.as_str()),
            None,
            None,
            None,
        ),
        BookingOperationRequest::Book(BookingBookInput::Hold(input)) => (
            Some(input.event_type.clone()),
            Some(input.session_ref.as_str()),
            None,
            Some(input.selected_slot),
            None,
        ),
        BookingOperationRequest::Book(BookingBookInput::Confirm(input)) => (
            None,
            Some(input.session_ref.as_str()),
            Some(input.booker_email.as_str()),
            None,
            Some(input.intake.as_slice()),
        ),
        BookingOperationRequest::Reschedule(input) => {
            (None, None, None, Some(input.selected_slot), None)
        }
        BookingOperationRequest::Cancel(_) => (None, None, None, None, None),
    };

    let session_hash = session_ref.map(booking_session_hash);
    let email_hash = booker_email.map(booking_email_hash);
    let live_session_holds = match session_ref {
        Some(reference) => {
            active_holds_for_session(server, page_ref, &session_key(page_ref, reference), now)?
        }
        None => 0,
    };
    let live_email_bookings = match booker_email {
        Some(email) => active_future_bookings_for_email(server, page_ref, email, now)?,
        None => 0,
    };
    let intake_chars: usize = intake.map_or(0, |answers| {
        answers
            .iter()
            .map(|answer| answer.value.chars().count())
            .sum()
    });

    Ok(BookingRequestFacts {
        page_ref,
        event_type,
        ip_hash,
        email_hash,
        session_hash,
        // The honeypot field and the time-to-submit floor are evidence about
        // an HTML form fill. This surface has neither: it carries no honeypot
        // input and no form session, so both signals are asserted as absent
        // rather than fabricated. Every control that does have evidence here —
        // the minute windows, the hold cap, the email checks, and the
        // active-booking cap — is fed real values above and below.
        started_at_millis: 0,
        submitted_at_millis: now.saturating_mul(1_000),
        // Overwritten by the book guard at its trusted admission boundary.
        submission_fingerprint: [0_u8; 32],
        selected_slot_hash: selected_slot_hash(selected_slot),
        intake_content_hash: intake_content_hash(intake),
        honeypot_nonempty: false,
        intake_chars,
        active_future_bookings_for_email: live_email_bookings,
        active_holds_for_session: live_session_holds,
        email: booker_email.map(|email| EmailValidationEvidence {
            syntax_valid: is_syntactically_valid_email(email),
            // MX resolution and disposable-domain lists are network lookups
            // this surface does not perform. `None` and `false` are the
            // engine's "no signal" readings, never a negative one.
            mx_present: None,
            disposable_domain: false,
        }),
    })
}

/// Projects a non-`Continue` admission disposition onto an answer.
///
/// `Continue` returns `None` and the executor proceeds. Every other
/// disposition returns here, so a declined request reaches neither the parser,
/// the oracle, nor the lifecycle.
pub(super) fn admission_short_circuit(
    request: &BookingOperationRequest,
    disposition: BookingHttpDisposition,
) -> Result<Option<BookingOperationResponse>, ApiError> {
    match disposition {
        BookingHttpDisposition::Continue => Ok(None),
        // Silent reject and quarantine-and-accept both answer exactly like an
        // ordinary success and write no booking. The benign shape per
        // operation is the empty one: no slots, no lifecycle receipt, and the
        // caller's own action token echoed back.
        BookingHttpDisposition::SilentOk | BookingHttpDisposition::QuarantineAndAccept => {
            Ok(Some(benign_response(request)))
        }
        BookingHttpDisposition::PromptCorrection { body } => Err(prompt_correction_error(&body)),
        BookingHttpDisposition::RetryAfter { seconds } => {
            let state = format!("booking_retry_after_{seconds}s");
            Err(ApiError::new(
                format!("booking admission is rate limited; retry after {seconds} seconds"),
                crate::error::ApiErrorDetails::InvalidState { state: Some(state) },
                [format!(
                    "Wait {seconds} seconds before retrying this booking request."
                )],
            ))
        }
    }
}

/// The success-shaped answer a silent rejection returns.
fn benign_response(request: &BookingOperationRequest) -> BookingOperationResponse {
    match request {
        BookingOperationRequest::Availability(_) => BookingOperationResponse::Availability {
            slots: Vec::new(),
            flex_used: false,
        },
        BookingOperationRequest::Book(_) => {
            BookingOperationResponse::Book(BookingBookResult::SlotTaken {
                alternatives: Vec::new(),
            })
        }
        BookingOperationRequest::Reschedule(input) => BookingOperationResponse::Reschedule {
            reschedule_token: input.reschedule_token.clone(),
        },
        BookingOperationRequest::Cancel(input) => BookingOperationResponse::Cancel {
            cancel_token: input.cancel_token.clone(),
        },
    }
}

/// Re-projects the engine's correction body onto the typed API error.
///
/// The engine owns the field and the sentence; this only chooses the envelope.
fn prompt_correction_error(body: &str) -> ApiError {
    let parsed: Option<serde_json::Value> = serde_json::from_str(body).ok();
    let field = parsed
        .as_ref()
        .and_then(|value| value.get("field"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let message = parsed
        .as_ref()
        .and_then(|value| value.get("message"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("this booking request needs a correction before it can proceed")
        .to_owned();
    ApiError::bad_request(message, field.as_deref())
}

/// How many live holds this session already holds on this page.
///
/// Derived from the merged hold source rather than a second hold store: the
/// difference between the unfiltered view and the view that hides this session
/// IS this session's live hold count.
fn active_holds_for_session(
    server: &SyncServer,
    page_ref: EntityId,
    session_key: &SessionKey,
    now: u64,
) -> Result<u8, ApiError> {
    let window = TimeRange {
        start: now,
        end: u64::MAX,
    };
    let all = VaultActiveHoldSource::new(&server.vault)
        .active_holds(page_ref, window, now, None)?
        .len();
    let others = VaultActiveHoldSource::excluding(&server.vault, *session_key)
        .active_holds(page_ref, window, now, None)?
        .len();
    Ok(u8::try_from(all.saturating_sub(others)).unwrap_or(u8::MAX))
}

/// How many active future bookings this email already holds on this page.
///
/// Read from the committed booking claims the lifecycle writes, so the cap
/// counts the same bookings a cancellation would remove.
fn active_future_bookings_for_email(
    server: &SyncServer,
    page_ref: EntityId,
    email: &str,
    now: u64,
) -> Result<u8, ApiError> {
    let contact_ref = booker_contact_ref(email)?;
    let vault = &server.vault;
    let mut count: u8 = 0;
    let mut after: Option<EntityId> = None;
    loop {
        let page = vault
            .entities_by_type_page(ENTITY_TYPE_EVENT, after.as_ref(), 512)
            .map_err(engine_read_error)?;
        if page.is_empty() {
            break;
        }
        after = page.last().copied();
        for event_ref in page {
            if booking_is_active_future_for(vault, event_ref, page_ref, contact_ref, now)? {
                count = count.saturating_add(1);
            }
        }
    }
    Ok(count)
}

/// Whether one EVENT is this page's active, still-upcoming booking for one
/// contact. Every axis is read from the lifecycle's own claim family; the
/// occurrence comes from the calendar surface's own read-only projection
/// rather than a second header decoder.
fn booking_is_active_future_for(
    vault: &Vault,
    event_ref: EntityId,
    page_ref: EntityId,
    contact_ref: EntityId,
    now: u64,
) -> Result<bool, ApiError> {
    let claim_ids = vault
        .claims_for_subject(&event_ref)
        .map_err(engine_read_error)?;
    let (mut same_page, mut same_contact, mut confirmed) = (false, false, false);
    for claim_id in claim_ids {
        let Some(body) = vault.get_claim(&claim_id).map_err(engine_read_error)? else {
            continue;
        };
        if body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        match body.predicate.as_str() {
            BOOKING_SOURCE_PAGE_PREDICATE => {
                same_page = decode_claim_value::<BookingSourcePageValue>(&body.value)
                    .is_some_and(|value| value.page_ref == page_ref);
            }
            BOOKING_BOOKER_CONTACT_PREDICATE => {
                same_contact = decode_claim_value::<BookingBookerContactValue>(&body.value)
                    .is_some_and(|value| value.contact_ref == contact_ref);
            }
            BOOKING_STATUS_PREDICATE => {
                confirmed = decode_claim_value::<BookingStatusValue>(&body.value)
                    .is_some_and(|value| value.status == BookingStatus::Confirmed);
            }
            _ => {}
        }
    }
    if !(same_page && same_contact && confirmed) {
        return Ok(false);
    }
    // Still upcoming: a booking already in the past holds no future slot and
    // must not consume the cap. Over-counting here would BLOCK a visitor the
    // engine's under-block posture says to admit.
    let occurrence = oneiron::calendar::query::read_event(
        vault,
        &CalendarReadRequest {
            event_ref: event_ref.to_hex(),
        },
    )
    .map_err(engine_read_error)?;
    Ok(occurrence.is_none_or(|view| view.end_utc.is_none_or(|end| end > now)))
}

/// Decodes one opaque MessagePack claim value into a typed booking value.
fn decode_claim_value<T: serde::de::DeserializeOwned>(value: &rmpv::Value) -> Option<T> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).ok()?;
    rmp_serde::from_slice(&bytes).ok()
}

fn selected_slot_hash(slot: Option<SelectedSlot>) -> [u8; 32] {
    // One presence byte plus two big-endian u64s.
    let mut material = Vec::with_capacity(17);
    match slot {
        Some(slot) => {
            material.push(1);
            material.extend_from_slice(&slot.start_utc.to_be_bytes());
            material.extend_from_slice(&slot.end_utc.to_be_bytes());
        }
        None => material.push(0),
    }
    domain_digest(SELECTED_SLOT_DOMAIN, &material)
}

fn intake_content_hash(intake: Option<&[BookingIntakeAnswer]>) -> [u8; 32] {
    let mut material = Vec::new();
    match intake {
        Some(answers) => {
            material.push(1);
            material.extend_from_slice(&(answers.len() as u64).to_be_bytes());
            for answer in answers {
                material.extend_from_slice(&(answer.field_key.len() as u64).to_be_bytes());
                material.extend_from_slice(answer.field_key.as_bytes());
                material.extend_from_slice(&(answer.value.len() as u64).to_be_bytes());
                material.extend_from_slice(answer.value.as_bytes());
            }
        }
        None => material.push(0),
    }
    domain_digest(INTAKE_DOMAIN, &material)
}

/// A deliberately structural check: an address shaped like an address. Deeper
/// evidence is the engine's `EmailValidationEvidence`, and this surface
/// supplies only what it can actually observe.
fn is_syntactically_valid_email(email: &str) -> bool {
    let email = email.trim();
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !email.contains(char::is_whitespace)
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}
