//! The transfer verbs over a kept export, and MCP's kept export (FIX 11176).
//! `vault.export.transfer.read` reads one byte range of an export a
//! `vault.export` kept with `delivery: "transfer"`, as base64, and
//! `vault.export.transfer.release` lets it go: the same kept spool, under
//! the same admission and lapse check, as `GET` and `DELETE
//! /v1/core/export-transfers/{transfer_ref}`, for a transport with no byte
//! route. An MCP `vault.export` whose `delivery` asks for a transfer keeps
//! its archive here as the facade keeps it ([`mcp_export_transfer`]).

use std::sync::Arc;

use base64::Engine as _;
use oneiron::EntityId;
use oneiron::authority::{ActSurface, HostActionAuthority};
use oneiron::memory::{
    EXPORT_TRANSFER_READ_BYTES, ExportOptions, ExportTransfer, ExportTransferPiece,
    ExportTransferReadRequest, ExportTransferReleaseRequest, ExportTransferReleased, MemoryError,
    MemoryResult,
};
use oneiron::settings::ReadDestination;

use super::{EXPORT_VERB, FacadeApiError, admitted_as, kept_transfer};
use crate::api::facade::host_doors::support::{Listed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The verb that reads a kept export.
const READ_VERB: &str = "vault.export.transfer.read";

/// `vault.export.transfer.read`: the bytes of the kept export
/// `transfer_ref` names from `offset`, `length` of them (the default piece
/// when it names none) up to its end, once its caller is admitted to it now
/// as the export admitted its exporter. Beside it, the rows the archive was
/// derived from.
pub(crate) async fn vault_export_transfer_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ExportTransferReadRequest,
) -> Listed<ExportTransferPiece> {
    let kept = match admitted_as(server, auth, None, &input.transfer_ref) {
        Ok(kept) => kept,
        Err(refused) => return (Err(refused.into_memory_error()), Vec::new()),
    };
    let rows = kept.rows.clone();
    let total = kept.receipt.bytes;
    let offset = input.offset;
    if offset > total {
        return (
            Err(MemoryError::bad_request(format!(
                "offset {offset} is past the archive's end at {total} bytes"
            ))),
            rows,
        );
    }
    let length = input
        .length
        .unwrap_or(EXPORT_TRANSFER_READ_BYTES)
        .min(total - offset);
    let digest = kept.receipt.digest.clone();
    let read =
        crate::api::facade::clock_ingress::run_blocking(move || kept.piece(offset, length)).await;
    let Ok(Ok(piece)) = read else {
        return (Err(internal(READ_VERB)), rows);
    };
    let piece = ExportTransferPiece {
        transfer_ref: input.transfer_ref,
        offset,
        bytes_base64: base64::engine::general_purpose::STANDARD.encode(&piece),
        length,
        total_bytes: total,
        digest,
        end: offset + length == total,
    };
    (Ok(piece), rows)
}

/// `vault.export.transfer.release`: lets the kept export `transfer_ref`
/// names go once its caller has it, admitted as a read is. Its answer
/// derives from no row.
pub(crate) async fn vault_export_transfer_release(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ExportTransferReleaseRequest,
) -> Listed<ExportTransferReleased> {
    let released = admitted_as(server, auth, None, &input.transfer_ref)
        .and_then(|_| server.export_transfers.release(&input.transfer_ref));
    match released {
        Ok(()) => (
            Ok(ExportTransferReleased {
                transfer_ref: input.transfer_ref,
                released: true,
            }),
            Vec::new(),
        ),
        Err(refused) => (Err(refused.into_memory_error()), Vec::new()),
    }
}

/// An MCP `vault.export` whose `delivery` asks for a transfer: its archive
/// kept here for `auth`'s caller and named by its transfer, beside the rows
/// its snapshot read past `destination`, as the facade keeps one. It runs
/// the facade's four owner paths: a host root's slip, an owner's slip, the
/// host `action` with no slip, and a managed vault's attested owner, with
/// where the owner spoke from as `surface` names it.
pub(crate) fn mcp_export_transfer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    destination: &ReadDestination,
    input: &ExportOptions,
    action: Option<HostActionAuthority>,
) -> MemoryResult<(ExportTransfer, Vec<EntityId>)> {
    let proof = auth.verified_slip();
    let owner = match (proof, &action) {
        (None, None) if auth.managed_owner().is_some() => {
            Some(owner_proof(auth, server, EXPORT_VERB)?)
        }
        _ => None,
    };
    kept_transfer(
        server,
        auth,
        surface,
        destination,
        input,
        (proof, action, owner),
    )
    .map_err(FacadeApiError::into_memory_error)
}
