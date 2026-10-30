//! The shared executor (ONE-1819): the one door from a machine-readable
//! booking request to the merged solver and lifecycle, and its listing for
//! the served `vault.booking.*` doors (FIX 4781).

use oneiron::booking::anti_abuse::BookingQuarantineRestoreInput;

use super::*;
use crate::api::booking_anti_abuse::enforce_book_restorable;

/// The one door from a booking request to the merged booking capabilities.
///
/// The order is mandatory and is the contract of this function:
///
/// 1. validate the opaque page token, the operation shape, and the caller
///    keys, resolve the page subject internally, and bind any submitted action
///    token to that same page;
/// 2. call ONE-1817 admission exactly once, in the class this operation
///    belongs to — listing, hold, confirmation, or amendment. Cancel and
///    reschedule are amendments: they present an action token rather than a
///    form, so the book-time form controls never see them;
/// 3. normalize free text through ONE-1816 and replace it with a canonical
///    `ConstraintObject`;
/// 4. call the merged oracle — for availability as the answer, for a hold as
///    the offerability gate a slot must pass before any verb is enqueued — and
///    let the home-node writer revalidate every mutation it executes;
/// 5. project only operation-safe response data.
///
/// A blocked request returns at step 2 and reaches neither the parser, the
/// oracle, nor the lifecycle.
///
/// # Errors
///
/// [`ApiError`] for a malformed request, an unresolvable page, a declined
/// admission, a refused lifecycle transition, or a storage failure.
pub(crate) async fn execute_booking_operation(
    server: &Arc<SyncServer>,
    page_token: &str,
    request: BookingOperationRequest,
    transport: impl Into<BookingAdmissionContext>,
) -> Result<BookingOperationResponse, ApiError> {
    execute(server, page_token, request, transport.into())
        .await
        .map(|(response, _)| response)
}

/// [`execute_booking_operation`], beside the rows its answer was derived
/// from (FIX 4781), from the same execution. An availability answer on a
/// credential transport lists the publication's rows (the page, its
/// publication claim and the event-type claims it validated) and its
/// solve's (the calendar binding's claims and every row the listing oracle
/// read), or the cached solve's, whose entry kept them; a silent admission
/// answer lists the publication's alone. A hold lists the publication's and
/// its offerability solve's (FIX 5483): the hold writer reads only
/// node-local rows beside them. A confirm, reschedule or cancel lists the
/// publication's and its home-node writer's read set, which its receipt
/// keeps so a replay lists the same rows (FIX 5483). A public HTTP request
/// lists unknown (`None`): no listing door serves it.
///
/// # Errors
///
/// As [`execute_booking_operation`].
pub(crate) async fn execute_booking_operation_listing(
    server: &Arc<SyncServer>,
    page_token: &str,
    request: BookingOperationRequest,
    transport: impl Into<BookingAdmissionContext>,
) -> Result<(BookingOperationResponse, Option<Vec<EntityId>>), ApiError> {
    execute(server, page_token, request, transport.into()).await
}

async fn execute(
    server: &Arc<SyncServer>,
    page_token: &str,
    request: BookingOperationRequest,
    transport: BookingAdmissionContext,
) -> Result<(BookingOperationResponse, Option<Vec<EntityId>>), ApiError> {
    // ── 1. shape, keys, and the page subject ────────────────────────────
    // A request that books only a published page (an anonymous visitor, a
    // credential caller, a stale owner sign-in: FIX 5327) never reaches the
    // owner's own page resolver below.
    let (public_authority, listed) = if transport.requires_publication {
        let (page_ref, publication, rows) =
            public::resolve_public_booking_page_listing(server, page_token)?;
        let authority = oneiron::booking::publication::PublicBookingAuthority {
            page_ref,
            publication,
        };
        (Some(authority), Some(rows))
    } else {
        (None, None)
    };
    let page_ref = match &public_authority {
        Some(authority) => authority.page_ref,
        None => resolve_booking_page(server, page_token)?,
    };
    if let Some(authority) = &public_authority {
        public_availability::validate_public_request(&authority.publication, &request)?;
    }
    validate_operation_shape(&request)?;
    if transport.credential.is_none() {
        validate::validate_anonymous_intake_count(&request)?;
    }
    check_action_token_page(&server.vault, page_ref, &request)?;

    // ── 2. the one admission call ───────────────────────────────────────
    let cache = public_availability::cached_response(
        server,
        page_ref,
        &request,
        public_authority.as_ref(),
    )?;
    // An authenticated caller past a window waits for it and is admitted
    // again (`turn::Turn`), so the clock and the facts are read each time.
    let mut turn = turn::Turn::new(server, &transport);
    // A confirm's email domain is looked up once per request, not per turn.
    let mut email_domain = None;
    let (now, disposition) = loop {
        let now = now_secs()?;
        let mut facts = admission_facts(server, page_ref, &request, &transport, now)?;
        if let BookingOperationRequest::Book(BookingBookInput::Confirm(input)) = &request {
            let evidence = match email_domain {
                Some(evidence) => evidence,
                None => *email_domain.insert(
                    email_evidence::email_domain_evidence(server, &facts, &input.booker_email)
                        .await?,
                ),
            };
            evidence.apply(&mut facts);
        }
        let disposition = match &request {
            BookingOperationRequest::Availability(_) => {
                enforce_slot_list(State(Arc::clone(server)), facts, cache.is_some()).await?
            }
            BookingOperationRequest::Book(BookingBookInput::Hold(_)) => {
                enforce_hold(State(Arc::clone(server)), facts).await?
            }
            BookingOperationRequest::Book(BookingBookInput::Confirm(input)) => {
                let hold_token = OpaqueLifecycleToken(input.hold_token.clone());
                let restore = BookingQuarantineRestoreInput {
                    session_key: session_key(page_ref, &input.session_ref),
                    hold_token: &hold_token,
                    booker_email: &input.booker_email,
                    intake: &input.intake,
                };
                enforce_book_restorable(State(Arc::clone(server)), facts, Some(restore)).await?
            }
            BookingOperationRequest::Reschedule(_) | BookingOperationRequest::Cancel(_) => {
                enforce_amend(State(Arc::clone(server)), facts).await?
            }
        };
        if let Some(disposition) = turn.after(disposition).await? {
            break (now, disposition);
        }
    };
    if let Some(response) = admission_short_circuit(&request, disposition)? {
        tracing::debug!(
            transport = transport.transport.as_str(),
            operation = request.operation().as_str(),
            "booking admission answered without solving or writing"
        );
        return Ok((response, listed));
    }

    if let Some((response, sources)) = cache {
        public_availability::recheck(server, public_authority.as_ref())?;
        let listed = listed.zip(sources).map(|(mut rows, sources)| {
            rows.extend(sources);
            rows
        });
        return Ok((response, listed));
    }

    // ── 3, 4, 5. parse, dispatch, project ───────────────────────────────
    match request {
        BookingOperationRequest::Availability(mut input) => {
            // Free text is parsed first; only its object reaches the oracle.
            if let Some(BookingConstraintInput::FreeText(text)) = &input.constraint {
                // The page's publication-time sponsor pays an anonymous
                // visitor's parse while one is stored and live (FIX 5288).
                // An authenticated caller pays as itself either way.
                let sponsor = public_authority
                    .as_ref()
                    .and_then(|authority| authority.publication.sponsor);
                let (object, visitor_tz) = free_text::parse_free_text(
                    server,
                    &transport,
                    sponsor,
                    text.clone(),
                    input.visitor_tz.clone(),
                    now,
                )
                .await?;
                input.constraint = Some(BookingConstraintInput::Object(object));
                if let Some(visitor_tz) = visitor_tz {
                    input.visitor_tz = visitor_tz;
                }
            }
            let (response, sources) = public_availability::solve(
                server,
                page_ref,
                input,
                now,
                public_authority.as_ref(),
            )?;
            let listed = listed.map(|mut rows| {
                rows.extend(sources);
                rows
            });
            Ok((response, listed))
        }
        BookingOperationRequest::Book(BookingBookInput::Hold(input)) => {
            let (response, sources) =
                execute_hold(server, page_ref, input, now, public_authority).await?;
            let listed = listed.map(|mut rows| {
                rows.extend(sources);
                rows
            });
            Ok((response, listed))
        }
        BookingOperationRequest::Book(BookingBookInput::Confirm(mut input)) => {
            admission::strip_form_honeypot(&transport, &mut input.intake);
            let (response, reads) =
                execute_confirm(server, page_ref, input, now, public_authority).await?;
            Ok((response, with_reads(listed, reads)))
        }
        BookingOperationRequest::Reschedule(input) => {
            let (response, reads) =
                execute_reschedule(server, page_ref, input, now, public_authority).await?;
            Ok((response, with_reads(listed, reads)))
        }
        BookingOperationRequest::Cancel(input) => {
            let (response, reads) =
                execute_cancel(server, page_ref, input, now, public_authority).await?;
            Ok((response, with_reads(listed, reads)))
        }
    }
}

/// The publication's listed rows, joined by a writer's read set.
fn with_reads(listed: Option<Vec<EntityId>>, reads: Vec<EntityId>) -> Option<Vec<EntityId>> {
    listed.map(|mut rows| {
        rows.extend(reads);
        rows
    })
}
