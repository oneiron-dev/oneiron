//! Rung 2's press (INBOX-RESIDUE PR-3b-3c): the owner releases one held
//! first send, `vault.booking.rung2.release_once`.
//!
//! The cold-send law holds a rung-2 first send to a stranger, and that hold
//! names no generic digest: native mail's one-send approval covers the whole
//! request (the agent, its identity, the recipient, the logical send and the
//! content ref). So the owner names the send by its ref, and the host rebuilds
//! that request from the send the vault kept: the exact words, to the one
//! address the visitor gave, from the page agent's own mailbox. One approval
//! for those words, then the send, inline on the caller's blocking thread, as
//! a campaign press is, with no pump: rung 2 sends once per session.
//!
//! A second press approves nothing more. The first press's approval stands,
//! and the send answers from what the ledger recorded, so the visitor gets
//! one email however often the owner presses.

use oneiron::ErrorKind;
use oneiron::booking::rung2::{BOOKING_RUNG2_SEND_REF_PREFIX, Rung2FirstSend};
use oneiron::channel_identity_provider::native_mail::{NativeMailAdapter, NativeMailHost};
use oneiron::consent::AuthenticatedOwner;
use oneiron::task_verb::sdk::{BookingRung2ReleaseOnceResponse, BookingRung2ReleaseOutcome};
use oneiron::{EntityId, Vault};

use super::helpers::engine_read_error;
use super::rung2::{Rung2Dispatched, dispatch_on_pack, native_mail_unavailable};
use super::validate::validate_session_ref;
use crate::error::ApiError;
use crate::server::SyncServer;

/// The owner's press on the held first send `send_ref` names, through the
/// host's native mail pack. Blocks on the mail server: run it on a blocking
/// thread.
pub(crate) fn release_rung2_first_send(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    send_ref: &str,
) -> Result<BookingRung2ReleaseOnceResponse, ApiError> {
    server
        .builtin_handles
        .with_native_mail_pack(|pack| {
            release_kept_first_send(
                &server.vault,
                owner,
                pack.adapter(),
                send_ref,
                |vault, kept| dispatch_on_pack(pack, vault, kept),
            )
        })
        .unwrap_or_else(|| Err(native_mail_unavailable()))
}

/// Approves the kept send `send_ref` names once with the owner's proof, then
/// hands it to `dispatch`. `adapter` names the Message-ID it is kept under.
pub(super) fn release_kept_first_send<H: NativeMailHost>(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    adapter: &NativeMailAdapter<H>,
    send_ref: &str,
    dispatch: impl FnOnce(&Vault, &Rung2FirstSend) -> Result<Rung2Dispatched, ApiError>,
) -> Result<BookingRung2ReleaseOnceResponse, ApiError> {
    let (page_ref, session_ref) = parse_rung2_send_ref(send_ref)?;
    let kept = vault
        .booking_rung2_first_send(adapter, page_ref, session_ref)
        .map_err(engine_read_error)?
        .ok_or_else(rung2_send_not_found)?;
    let request = kept.dispatch_request().map_err(|error| {
        tracing::warn!(kind = ?error.kind(), "a kept rung-2 first send does not rebuild");
        ApiError::internal_server_error("booking rung-2 first send unavailable")
    })?;
    match adapter.approve_send_once(vault, owner, &request) {
        Ok(_) => {}
        // An earlier press approved these words: the send below answers
        // from what the ledger recorded, and nothing is approved twice.
        Err(error) if error.kind() == ErrorKind::ConsentApproveOnceSpent => {}
        Err(error) if error.kind() == ErrorKind::ConsentOwnerNotAuthenticated => {
            return Err(ApiError::forbidden_scope("owner"));
        }
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "the owner's rung-2 press was not minted");
            return Err(ApiError::invalid_state(Some(
                "booking_rung2_send_unreleasable",
            )));
        }
    }
    let outcome = match dispatch(vault, &kept)? {
        Rung2Dispatched::Sent => BookingRung2ReleaseOutcome::Sent,
        Rung2Dispatched::Held => BookingRung2ReleaseOutcome::Held,
    };
    Ok(BookingRung2ReleaseOnceResponse {
        send_ref: kept.send_ref,
        message_id: kept.message_id,
        outcome,
    })
}

/// The page and the session a send ref names: `booking-rung2:<page hex>:
/// <session>`, as `rung2_send_ref` writes it. The session is a front
/// session's ref, so a ref the host could not have written is refused.
fn parse_rung2_send_ref(send_ref: &str) -> Result<(EntityId, &str), ApiError> {
    let malformed = || {
        ApiError::bad_request(
            "send_ref must be a booking rung-2 send ref",
            Some("send_ref"),
        )
    };
    let (page_hex, session_ref) = send_ref
        .strip_prefix(BOOKING_RUNG2_SEND_REF_PREFIX)
        .and_then(|rest| rest.split_once(':'))
        .ok_or_else(malformed)?;
    let page_ref = EntityId::from_hex(page_hex).map_err(|_| malformed())?;
    validate_session_ref(session_ref).map_err(|_| malformed())?;
    Ok((page_ref, session_ref))
}

/// No first send is kept under the ref: no visitor of that page session
/// asked for one.
fn rung2_send_not_found() -> ApiError {
    ApiError::not_found("booking rung-2 send", None)
}
