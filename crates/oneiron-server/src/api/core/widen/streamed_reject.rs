//! Large widen declines: the reference streamed under the body's disk room.

use std::sync::Arc;

use axum::Json;

use super::{CoreRejectWidenResponse, WidenHolder, widen_refusal};
use crate::api::body_spool::{
    BodySpool, BulkMember, SpooledField, TextFileSink, Unspooled, create_failed,
    decode_memory_refused, invalid_json,
};
use crate::api::clock_ingress;
use crate::error::{ApiError, EnvelopedApiError};
use crate::machine::{DiskClaim, MemoryRefusal};
use crate::server::SyncServer;

/// The reference file closes before the same raw body's stored-copy room.
struct RejectBulk {
    reference: SpooledField,
    _room: Option<Arc<DiskClaim>>,
}

pub(super) type BulkDecoded = Result<DecodedFields, MemoryRefusal>;

pub(super) struct DecodedFields {
    json: Result<(), crate::api::body_spool::JsonInvalid>,
    reference: Result<SpooledField, Unspooled>,
    room: Option<Arc<DiskClaim>>,
}

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
        let mut reference = TextFileSink::new_admitted(file, &mut memory);
        let json = spool.string_object_admitted(
            &mut [BulkMember::required("proposal_ref", &mut reference)],
            &mut memory,
        );
        let decoded = DecodedFields {
            json,
            reference: reference.into_field(),
            room: spool.into_room(),
        };
        drop(memory);
        Ok(Ok(decoded))
    }
}

pub(super) async fn answer_bulk(
    server: Arc<SyncServer>,
    holder: WidenHolder,
    decoded: Result<BulkDecoded, Unspooled>,
) -> Result<Json<CoreRejectWidenResponse>, EnvelopedApiError> {
    let decoded = decoded
        .map_err(Unspooled::refusal)?
        .map_err(decode_memory_refused)?;
    decoded.json.map_err(|_| invalid_json())?;
    let reference = decoded.reference.map_err(Unspooled::refusal)?;
    let bulk = RejectBulk {
        reference,
        _room: decoded.room,
    };
    clock_ingress::run_blocking(move || run_bulk(server, holder, bulk))
        .await
        .map_err(|_| ApiError::internal_server_error("widen decline failed"))?
}

/// Owns the complete file/room pair through the final native read, including
/// cancellation of the awaiting HTTP future.
fn run_bulk(
    server: Arc<SyncServer>,
    holder: WidenHolder,
    bulk: RejectBulk,
) -> Result<Json<CoreRejectWidenResponse>, EnvelopedApiError> {
    let (owner, credential) = holder.owner(&server)?;
    let (reference, len) = bulk.reference.file();
    let receipt = server
        .vault()
        .reject_widen_reader(&owner, credential, reference, len)
        .map_err(|error| widen_refusal(&error, "widen decline failed"))?;
    Ok(Json(CoreRejectWidenResponse {
        decision_id: receipt.decision_id().to_hex(),
    }))
}
