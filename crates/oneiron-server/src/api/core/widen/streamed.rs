//! Large widen-accept bodies: both strings streamed from disk, never one head.
//! Bodies past the in-memory line arrive already spooled under the transfer
//! custody policy. Both known string members stream to anonymous files; names
//! are matched without copying an unknown name or value. Native validation
//! keeps its existing holder-before-reference order. No new gate or cap.

use std::sync::Arc;

use axum::Json;

use super::{CoreAcceptWidenResponse, WidenHolder, widen_refusal};
use crate::api::body_spool::{
    BodySpool, BulkMember, HexFileSink, HexRefusal, SpooledField, SpooledHex, TextFileSink,
    Unspooled, create_failed, decode_memory_refused, invalid_json,
};
use crate::api::clock_ingress;
use crate::error::{ApiError, EnvelopedApiError};
use crate::machine::{DiskClaim, MemoryRefusal};
use crate::server::SyncServer;

/// The member that carries the frozen delta, as lowercase hex.
const DELTA_MEMBER: &str = "expected_delta";

/// A spooled accept: both decoded files and the body spool's stored-copy
/// room. Their combined length cannot exceed the raw body's length. Field
/// order keeps both files alive until the final read and closes them before
/// the transferred room is given back.
pub(super) struct AcceptBulk {
    reference: SpooledField,
    field: SpooledHex,
    _room: Option<Arc<DiskClaim>>,
}

/// Each result stays separate so malformed JSON is told before any sink
/// refusal, and the disk room stays with both decoded files.
pub(super) type BulkDecoded = Result<DecodedFields, MemoryRefusal>;

pub(super) struct DecodedFields {
    json: Result<(), crate::api::body_spool::JsonInvalid>,
    field: Result<SpooledHex, HexRefusal>,
    reference: Result<SpooledField, Unspooled>,
    room: Option<Arc<DiskClaim>>,
}

/// Builds the transfer worker's reader for the two required string members.
pub(super) fn bulk_decoder(
    server: &SyncServer,
) -> impl FnOnce(BodySpool) -> Result<BulkDecoded, Unspooled> + Send + 'static {
    let vault = Arc::clone(server.vault());
    move |mut spool: BodySpool| {
        let mut memory = match spool.admit_string_decode_buffers() {
            Ok(memory) => memory,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let file = vault.archive_spool_file().map_err(create_failed)?;
        let mut sink = HexFileSink::new(file);
        let file = vault.archive_spool_file().map_err(create_failed)?;
        let mut reference = TextFileSink::new_admitted(file, &mut memory);
        let json = spool.string_object_admitted(
            &mut [
                BulkMember::required(DELTA_MEMBER, &mut sink),
                BulkMember::required("proposal_ref", &mut reference),
            ],
            &mut memory,
        );
        let decoded = DecodedFields {
            json,
            field: sink.into_field(),
            reference: reference.into_field(),
            room: spool.into_room(),
        };
        drop(memory);
        Ok(Ok(decoded))
    }
}

/// Joins a bulk decode: malformed JSON first, then the delta's refusal,
/// then the reference file. Reference shape stays in the native door.
fn join_bulk(decoded: Result<BulkDecoded, Unspooled>) -> Result<AcceptBulk, ApiError> {
    let decoded = decoded
        .map_err(Unspooled::refusal)?
        .map_err(decode_memory_refused)?;
    decoded.json.map_err(|_| invalid_json())?;
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
    let reference = decoded.reference.map_err(Unspooled::refusal)?;
    Ok(AcceptBulk {
        reference,
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
    let (reference, reference_len) = bulk.reference.file();
    let (file, len) = bulk.field.file();
    let receipt = server
        .vault()
        .accept_widen_readers(&owner, credential, reference, reference_len, file, len)
        .map_err(|error| widen_refusal(&error, "widen approval failed"))?;
    Ok(Json(CoreAcceptWidenResponse {
        decision_id: receipt.decision_id().to_hex(),
        grant_ref: receipt
            .grant_ref()
            .ok_or_else(|| ApiError::invalid_state(Some("consent_widen_receipt")))?,
    }))
}
