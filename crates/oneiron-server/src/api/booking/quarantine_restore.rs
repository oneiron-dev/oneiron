//! `POST /v1/owner/booking/quarantine/{claim_ref}/restore`: the owner's
//! restore of a quarantined confirm (FIX 7851). It books the restorable
//! submission the quarantine kept through the ordinary lifecycle writer, a
//! hold and a confirm on the held slot, then records the booking on the
//! submission and resolves its inbox card in one write.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::Json;
use oneiron::booking::anti_abuse::{
    booking_quarantined_submission, record_quarantined_submission_restored,
};
use oneiron::booking::{
    BookingVerbReceipt, BookingVerbRequest, ConfirmSpec, HoldLeaseSpec, HoldSpec, RankedSlot,
};
use oneiron::{EntityId, TimeRange};
use serde::Serialize;

use super::helpers::{booking_error, now_secs};
use super::lifecycle::run_booking_verb;
use super::subject::{resolve_booker_contact, session_key};
use super::unexpected_receipt;
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::server::SyncServer;

/// What one owner restore did.
#[derive(Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub(crate) enum BookingQuarantineRestoreResponse {
    /// The submission is booked, by this restore or an earlier one, and its
    /// inbox card is resolved.
    Restored { event_ref: String },
    /// The held slot is no longer offered: nothing was booked and the card
    /// stays open, beside the slots the solver offers instead.
    SlotTaken { alternatives: Vec<RankedSlot> },
}

/// Books one quarantined confirm's restorable submission for the owner and
/// resolves its inbox card (FIX 7851).
#[utoipa::path(
    post,
    path = "/v1/owner/booking/quarantine/{claim_ref}/restore",
    params(
        ("claim_ref" = String, Path, description = "The quarantine claim's 32-hex id, the one its inbox card names.")
    ),
    responses(
        (status = 200, description = "The submission was booked and its inbox card resolved, or its held slot is taken and the alternatives are listed.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed claim id, or the lifecycle refused the booking.", body = ApiError, content_type = "application/json"),
        (status = 403, description = "The caller does not act as this vault's owner.", body = ApiError, content_type = "application/json"),
        (status = 404, description = "This quarantine claim kept no restorable submission.", body = ApiError, content_type = "application/json")
    )
)]
pub(crate) async fn restore_quarantined_booking(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(claim_ref): Path<String>,
) -> Result<Json<BookingQuarantineRestoreResponse>, ApiError> {
    let proof = crate::api::owner(&auth, &server)?;
    let claim = EntityId::from_hex(&claim_ref)
        .map_err(|_| ApiError::bad_request("claim_ref is a 32-hex id", Some("claim_ref")))?;
    let submission = booking_quarantined_submission(&server.vault, &claim)
        .map_err(booking_error)?
        .ok_or_else(|| ApiError::not_found("booking quarantine submission", Some(&claim_ref)))?;
    if let Some(event_ref) = submission.restored_event_ref {
        return Ok(Json(BookingQuarantineRestoreResponse::Restored {
            event_ref: event_ref.to_hex(),
        }));
    }
    let now = now_secs()?;
    let page_ref = submission.page_ref;
    // One session and one idempotency key per quarantine claim, so the
    // restore's hold and confirm are the claim's own.
    let restore_ref = format!("booking.quarantine.restore:{}", claim.to_hex());
    let session = session_key(page_ref, &restore_ref);
    let (held, _) = run_booking_verb(
        &server,
        BookingVerbRequest::Hold(HoldSpec {
            page_ref,
            event_type: submission.event_type.clone(),
            slot: TimeRange {
                start: submission.slot_start_utc,
                end: submission.slot_end_utc,
            },
            session_key: session,
            visitor_tz: submission.visitor_tz.clone(),
            constraint: submission.constraint.clone(),
            lease: HoldLeaseSpec::Ordinary,
            idempotency_key: Some(format!("{restore_ref}:hold")),
        }),
        Some(session),
        now,
        None,
    )
    .await?;
    let hold_token = match held {
        BookingVerbReceipt::Held(held) => held.token,
        BookingVerbReceipt::SlotTaken { alternatives } => {
            return Ok(Json(BookingQuarantineRestoreResponse::SlotTaken {
                alternatives,
            }));
        }
        other => return Err(unexpected_receipt("quarantine restore hold", &other)),
    };
    let booker_contact = resolve_booker_contact(&server, &submission.booker_email, now, None)?;
    let (confirmed, _) = run_booking_verb(
        &server,
        BookingVerbRequest::Confirm(ConfirmSpec {
            hold_token,
            session_key: session,
            booker_contact,
            intake: submission.intake,
            idempotency_key: Some(format!("{restore_ref}:confirm")),
        }),
        Some(session),
        now,
        None,
    )
    .await?;
    match confirmed {
        BookingVerbReceipt::Confirmed(receipt) => {
            let event_ref = receipt.calendar.event_ref;
            let vault_server = Arc::clone(&server);
            tokio::task::spawn_blocking(move || {
                record_quarantined_submission_restored(
                    &vault_server.vault,
                    &proof,
                    &claim,
                    event_ref,
                    now,
                )
            })
            .await
            .map_err(|_| ApiError::internal_server_error("quarantine restore record stopped"))?
            .map_err(booking_error)?;
            Ok(Json(BookingQuarantineRestoreResponse::Restored {
                event_ref: event_ref.to_hex(),
            }))
        }
        BookingVerbReceipt::SlotTaken { alternatives } => {
            Ok(Json(BookingQuarantineRestoreResponse::SlotTaken {
                alternatives,
            }))
        }
        other => Err(unexpected_receipt("quarantine restore confirm", &other)),
    }
}
