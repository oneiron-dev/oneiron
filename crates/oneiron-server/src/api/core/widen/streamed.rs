//! Large widen-accept bodies: `expected_delta` streamed from disk, never one string.
//! Bodies past the in-memory line arrive here already spooled under the
//! transfer custody policy; the delta member decodes into a hex file beside the
//! spool, and the native file-backed accept compares it without a
//! request-sized delta heap. Scope is the unbounded delta only: the head
//! decodes with the request's own unknown-field rule, and head, proposal_ref
//! and unknown-field growth stay an explicit OPEN residual. No new gate, cap,
//! digest, or error kind is added.

use std::sync::Arc;

use axum::Json;
use serde::Deserialize;

use super::{CoreAcceptWidenResponse, WidenHolder, widen_refusal};
use crate::api::body_spool::{
    BodySpool, BulkMember, HexFileSink, HexRefusal, SpooledHex, Unspooled, create_failed,
    invalid_json,
};
use crate::api::clock_ingress;
use crate::error::{ApiError, EnvelopedApiError};
use crate::machine::DiskClaim;
use crate::server::SyncServer;

/// The member that carries the frozen delta, as lowercase hex.
const DELTA_MEMBER: &str = "expected_delta";

/// An accept's head beside its streamed delta: every member but the delta,
/// judged with the request's own unknown-field rule.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptHead {
    proposal_ref: String,
}

/// A spooled accept, decoded: the proposal it answers, the delta's bytes in
/// a file of their own, and the body spool's stored-copy room, which covers
/// the decoded file too (decoded bytes never pass the raw body's length).
/// The room is only held, never read; field order is load-bearing: the
/// decoded file closes before the transferred room is given back.
pub(super) struct AcceptBulk {
    proposal_ref: String,
    field: SpooledHex,
    _room: Option<Arc<DiskClaim>>,
}

/// A bulk decode as the transfer worker ran it: the head and the field, each
/// fallible on its own so malformed JSON is told before a sink refusal, and
/// the body spool's room for the decoded file's last read.
pub(super) struct BulkDecoded {
    head: Result<AcceptHead, crate::api::body_spool::JsonInvalid>,
    field: Result<SpooledHex, HexRefusal>,
    room: Option<Arc<DiskClaim>>,
}

/// Builds the transfer-worker's bulk reader: the delta member into a hex file,
/// every other member into the accept's head. Runs on the transfer worker.
pub(super) fn bulk_decoder(
    server: &SyncServer,
) -> impl FnOnce(BodySpool) -> Result<BulkDecoded, Unspooled> + Send + 'static {
    let vault = Arc::clone(server.vault());
    move |mut spool: BodySpool| {
        let file = vault.archive_spool_file().map_err(create_failed)?;
        let mut sink = HexFileSink::new(file);
        let head = spool.object::<AcceptHead>(&mut [BulkMember::required(DELTA_MEMBER, &mut sink)]);
        Ok(BulkDecoded {
            head,
            field: sink.into_field(),
            room: spool.into_room(),
        })
    }
}

/// Joins a bulk decode: malformed JSON first (as the parser reports it), then
/// the field's own refusal, then the accept's spooled input.
fn join_bulk(decoded: Result<BulkDecoded, Unspooled>) -> Result<AcceptBulk, ApiError> {
    let decoded = decoded.map_err(Unspooled::refusal)?;
    let head = decoded.head.map_err(|_| invalid_json())?;
    let field = match decoded.field {
        Ok(field) => field,
        Err(HexRefusal::InvalidHex) => {
            return Err(ApiError::bad_request(
                "invalid expected_delta",
                Some("expected_delta"),
            ));
        }
        Err(HexRefusal::NoRoom) => return Err(Unspooled::NoRoom.refusal()),
        Err(HexRefusal::Failed) => return Err(Unspooled::Failed.refusal()),
    };
    Ok(AcceptBulk {
        proposal_ref: head.proposal_ref,
        field,
        _room: decoded.room,
    })
}

/// Answers a spooled accept off the runtime, `bulk` whole into the worker:
/// the holder's owner proof first, then the native file-backed accept over
/// the spooled bytes, with the same refusals and response as the small path.
/// The blocking closure passes `bulk` by value into [`run_bulk`], so the room
/// it holds lives through the native call's last read even if the awaiting
/// HTTP future is cancelled; nothing of `bulk` stays in the async frame.
pub(super) async fn answer_bulk(
    server: Arc<SyncServer>,
    holder: WidenHolder,
    decoded: Result<BulkDecoded, Unspooled>,
) -> Result<Json<CoreAcceptWidenResponse>, EnvelopedApiError> {
    let bulk = join_bulk(decoded)?;
    clock_ingress::run_blocking(move || run_bulk(server, holder, bulk))
        .await
        .map_err(|_| ApiError::internal_server_error("widen approval failed"))?
}

/// Runs a spooled accept on a blocking thread. Owns `bulk` whole: the spooled
/// input, and the stored-copy room it holds, drops only here, after the
/// native call's last read.
fn run_bulk(
    server: Arc<SyncServer>,
    holder: WidenHolder,
    bulk: AcceptBulk,
) -> Result<Json<CoreAcceptWidenResponse>, EnvelopedApiError> {
    let (owner, credential) = holder.owner(&server)?;
    let (file, len) = bulk.field.file();
    let receipt = server
        .vault()
        .accept_widen_reader(&owner, credential, &bulk.proposal_ref, file, len)
        .map_err(|error| widen_refusal(&error, "widen approval failed"))?;
    Ok(Json(CoreAcceptWidenResponse {
        decision_id: receipt.decision_id().to_hex(),
        grant_ref: receipt
            .grant_ref()
            .ok_or_else(|| ApiError::invalid_state(Some("consent_widen_receipt")))?,
    }))
}
