//! Whole-vault exports kept on the server for their caller to read (FIX
//! 3676). `vault.export` with `delivery: "transfer"` writes its archive to a
//! spool file as it is built and answers with an [`ExportTransfer`] naming
//! it, so no reply, replay or hook holds the archive whole.
//! `GET /v1/core/export-transfers/{transfer_ref}` reads it whole or one byte
//! range at a time (`Range: bytes=`), and `DELETE` lets it go. One whose
//! reply the destination release withholds is dropped at once, since no
//! caller learns its handle (FIX 11178).
//!
//! Each read and release admits its caller again as the export admitted its
//! exporter: the scope, an unattenuated owner credential outside a room
//! turn, an owner proof that holds now, the exporter itself, every row the
//! archive was derived from (source admission), and no hold a world keeps
//! from the caller's destination. A kept export lives until its owner lets
//! it go or the server stops: nothing expires it while it is unread.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Mutex;

use axum::body::Bytes;
use axum::extract::Path;
use axum::http::header;
use axum::routing::get;
use oneiron::authority::{HostActionAuthority, VerifiedSlip};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{ExportDelivery, ExportOptions, ExportTransfer, MemoryExportReceipt};
use rand_core::RngCore as _;
use serde_json::Value;

use super::*;

/// The verb whose admission every transfer access runs again.
const EXPORT_VERB: &str = "vault.export";
/// Prefix of every transfer handle; the rest is 128 random bits in hex.
const TRANSFER_REF_PREFIX: &str = "export_transfer:";
/// The most bytes one piece of a transfer's body carries: a pacing quantum,
/// every byte asked for is sent.
const TRANSFER_PIECE_BYTES: u64 = 64 * 1024;

/// The exports this server keeps for their callers, by transfer handle.
#[derive(Default)]
pub(crate) struct ExportTransfers {
    kept: Mutex<BTreeMap<String, Arc<KeptExport>>>,
}

/// One kept export: who made it, the rows it was derived from, its receipt
/// and the spool file holding the archive.
struct KeptExport {
    exporter: String,
    rows: Vec<EntityId>,
    receipt: MemoryExportReceipt,
    spool: Mutex<File>,
}

impl ExportTransfers {
    /// Keeps `spool`, the archive `receipt` describes, for `auth`'s caller,
    /// and names it.
    fn keep(
        &self,
        auth: &CoreAuth,
        spool: File,
        receipt: MemoryExportReceipt,
        rows: Vec<EntityId>,
    ) -> Result<ExportTransfer, FacadeApiError> {
        let mut random = [0_u8; 16];
        rand_core::OsRng.fill_bytes(&mut random);
        let transfer_ref = format!(
            "{TRANSFER_REF_PREFIX}{}",
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let transfer = ExportTransfer {
            transfer_ref: transfer_ref.clone(),
            format: receipt.format.clone(),
            bytes: receipt.bytes,
            digest: receipt.digest.clone(),
        };
        let kept = KeptExport {
            exporter: exporter_of(auth),
            rows,
            receipt,
            spool: Mutex::new(spool),
        };
        self.kept
            .lock()
            .map_err(|_| transfers_unreadable())?
            .insert(transfer_ref, Arc::new(kept));
        Ok(transfer)
    }

    fn get(&self, transfer_ref: &str) -> Result<Option<Arc<KeptExport>>, FacadeApiError> {
        Ok(self
            .kept
            .lock()
            .map_err(|_| transfers_unreadable())?
            .get(transfer_ref)
            .cloned())
    }

    fn release(&self, transfer_ref: &str) -> Result<(), FacadeApiError> {
        self.kept
            .lock()
            .map_err(|_| transfers_unreadable())?
            .remove(transfer_ref);
        Ok(())
    }

    /// Drops the kept export `withheld` names, when it names one (FIX 11178):
    /// a transfer-delivered `vault.export` whose reply the destination
    /// release withholds leaves no spool behind, since no caller learns its
    /// handle. A value naming no transfer drops nothing.
    pub(super) fn drop_withheld(&self, withheld: &Value) {
        if let Some(transfer_ref) = withheld.get("transfer_ref").and_then(Value::as_str) {
            let _ = self.release(transfer_ref);
        }
    }
}

impl KeptExport {
    /// `len` bytes of the archive from `at`.
    fn piece(&self, at: u64, len: u64) -> std::io::Result<Bytes> {
        let mut piece = vec![0_u8; usize::try_from(len).unwrap_or(usize::MAX)];
        let mut spool = self
            .spool
            .lock()
            .map_err(|_| std::io::Error::other("export transfer spool is unreadable"))?;
        spool.seek(SeekFrom::Start(at))?;
        spool.read_exact(&mut piece)?;
        Ok(Bytes::from(piece))
    }
}

/// The answer one `vault.export` call gives, beside the rows its snapshot
/// read: the archive inline, or kept here and named by an [`ExportTransfer`],
/// as the caller's `delivery` asks (FIX 3676). Both run the same four owner
/// paths: a host root's slip, an owner's slip, a host action with no slip,
/// and a managed vault's attested owner. Each arm's receipt records the
/// owner's act, with where the owner spoke from as this request proved it
/// (audit only; FIX 4625, 4626).
pub(super) fn vault_export_answer(
    server: &Arc<SyncServer>,
    call: &FacadeCall<'_>,
    input: &ExportOptions,
    proof: Option<&VerifiedSlip>,
    action: Option<HostActionAuthority>,
    owner: Option<AuthenticatedOwner>,
) -> Result<(Value, Vec<EntityId>), FacadeApiError> {
    let auth = call.auth();
    let surface = call.surface();
    let vault = &server.vault;
    if input.delivery.unwrap_or_default() == ExportDelivery::Inline {
        let (output, rows) = match (proof, action, owner) {
            (Some(proof), _, _) if proof.claims().holder_ref == "host" => vault
                .export_with_verified_host_owner_listing(
                    input,
                    proof,
                    surface,
                    auth.destination(),
                )?,
            (Some(proof), _, _) => {
                let (actor, class) = super::identity::facade_actor(server, auth)?;
                let producers = oneiron::memory::ProducerRows::default();
                let output = vault
                    .memory(actor, class)
                    .for_destination(&auth.destination())
                    .listing_producers(&producers)
                    .export_with_verified_owner(input, proof, surface)?;
                (output, producers.take())
            }
            (None, Some(action), _) => vault.export_with_host_action_listing(
                input,
                &action,
                surface,
                auth.destination(),
            )?,
            (None, None, Some(owner)) => vault.export_with_authenticated_owner_listing(
                input,
                &owner,
                surface,
                auth.destination(),
            )?,
            (None, None, None) => return Err(no_owner_proof()),
        };
        return Ok((encoded(&output)?, rows));
    }
    let mut spool = vault.archive_spool_file().map_err(MemoryError::from)?;
    let (receipt, rows) = match (proof, action, owner) {
        (Some(proof), _, _) if proof.claims().holder_ref == "host" => vault
            .export_with_verified_host_owner_listing_to(
                input,
                proof,
                surface,
                auth.destination(),
                &mut spool,
            )?,
        (Some(proof), _, _) => {
            let (actor, class) = super::identity::facade_actor(server, auth)?;
            let producers = oneiron::memory::ProducerRows::default();
            let receipt = vault
                .memory(actor, class)
                .for_destination(&auth.destination())
                .listing_producers(&producers)
                .export_with_verified_owner_to(input, proof, surface, &mut spool)?;
            (receipt, producers.take())
        }
        (None, Some(action), _) => vault.export_with_host_action_listing_to(
            input,
            &action,
            surface,
            auth.destination(),
            &mut spool,
        )?,
        (None, None, Some(owner)) => vault.export_with_authenticated_owner_listing_to(
            input,
            &owner,
            surface,
            auth.destination(),
            &mut spool,
        )?,
        (None, None, None) => return Err(no_owner_proof()),
    };
    let transfer = server
        .export_transfers
        .keep(auth, spool, receipt, rows.clone())?;
    Ok((encoded(&transfer)?, rows))
}

/// The transfer routes.
pub(crate) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route(
        "/v1/core/export-transfers/{transfer_ref}",
        get(read_transfer).delete(release_transfer),
    )
}

/// `GET`: the kept archive, whole (200) or the one byte range a
/// `Range: bytes=` header asks (206), streamed a piece at a time.
async fn read_transfer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(transfer_ref): Path<String>,
    headers: HeaderMap,
    extensions: Extensions,
) -> Response {
    let call = FacadeCall::http(&server, &auth, &headers, &extensions);
    let kept = match admitted(&server, &call, &transfer_ref) {
        Ok(kept) => kept,
        Err(refused) => return refused.into_response(),
    };
    let len = kept.receipt.bytes;
    let (status, start, end) = match asked_range(&headers, len) {
        Ok(None) => (StatusCode::OK, 0, len),
        Ok(Some((start, last))) => (StatusCode::PARTIAL_CONTENT, start, last.saturating_add(1)),
        Err(()) => {
            return (
                StatusCode::RANGE_NOT_SATISFIABLE,
                [(header::CONTENT_RANGE, format!("bytes */{len}"))],
            )
                .into_response();
        }
    };
    let digest = format!("\"{}\"", kept.receipt.digest);
    let mut response = Response::new(kept_body(kept, start, end));
    *response.status_mut() = status;
    let reply = response.headers_mut();
    reply.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    reply.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    reply.insert(header::CONTENT_LENGTH, HeaderValue::from(end - start));
    if let Ok(tag) = HeaderValue::from_str(&digest) {
        reply.insert(header::ETAG, tag);
    }
    if status == StatusCode::PARTIAL_CONTENT
        && let Ok(range) = HeaderValue::from_str(&format!("bytes {start}-{}/{len}", end - 1))
    {
        reply.insert(header::CONTENT_RANGE, range);
    }
    response
}

/// `DELETE`: lets the kept archive go once its caller has it (204).
async fn release_transfer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(transfer_ref): Path<String>,
    headers: HeaderMap,
    extensions: Extensions,
) -> Response {
    let call = FacadeCall::http(&server, &auth, &headers, &extensions);
    match admitted(&server, &call, &transfer_ref)
        .and_then(|_| server.export_transfers.release(&transfer_ref))
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(refused) => refused.into_response(),
    }
}

/// The kept export `transfer_ref` names, once `call`'s caller is admitted
/// to it now as `vault.export` admitted its exporter.
fn admitted(
    server: &Arc<SyncServer>,
    call: &FacadeCall<'_>,
    transfer_ref: &str,
) -> Result<Arc<KeptExport>, FacadeApiError> {
    let auth = call.auth();
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    super::invoke::facade_outside_room_turn(call, EXPORT_VERB)?;
    if !auth.is_owner_grade() {
        return Err(FacadeApiError::forbidden(
            "full-vault export requires owner authority",
            ["Present a verified, unattenuated owner credential."],
        ));
    }
    let action = crate::api::host_action::facade_host_action(server, auth)?;
    match (auth.verified_slip(), action) {
        (Some(proof), _) if proof.claims().holder_ref == "host" => {
            server.vault.admit_host_owner_export(proof)?;
        }
        (Some(proof), _) => {
            let (actor, class) = super::identity::facade_actor(server, auth)?;
            server
                .vault
                .memory(actor, class)
                .admit_export(Some(proof))?;
        }
        (None, Some(action)) => server.vault.admit_host_action_export(&action)?,
        (None, None) if auth.managed_owner().is_some() => {
            let owner = super::host_doors::support::owner_proof(auth, server, EXPORT_VERB)?;
            server.vault.admit_authenticated_owner_export(&owner)?;
        }
        (None, None) => return Err(no_owner_proof()),
    }
    let kept = server
        .export_transfers
        .get(transfer_ref)?
        .filter(|kept| kept.exporter == exporter_of(auth))
        .ok_or_else(unknown_transfer)?;
    let vault = server.vault();
    let destination = auth.destination();
    if !super::release::rows_still_admitted(vault, auth, &kept.rows)
        || super::release::known_denied_rows(vault, &destination, &kept.rows, &Value::Null)
    {
        return Err(FacadeApiError::forbidden(
            "this export's rows are not released to this caller now",
            ["Export again from where its rows are released."],
        ));
    }
    Ok(kept)
}

/// The one byte range, first and last byte inclusive, a `Range: bytes=`
/// header asks of `len` bytes: `None` for no header, several ranges or a
/// header this reader does not parse (the whole is sent), `Err` for a range
/// that starts past the end.
fn asked_range(headers: &HeaderMap, len: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(spec) = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().strip_prefix("bytes="))
        .filter(|spec| !spec.contains(','))
    else {
        return Ok(None);
    };
    let Some((first, last)) = spec.trim().split_once('-') else {
        return Ok(None);
    };
    let range = match (first.trim(), last.trim()) {
        ("", "") => return Ok(None),
        ("", suffix) => match suffix.parse::<u64>() {
            Ok(0) | Err(_) => return Err(()),
            Ok(suffix) => (len.saturating_sub(suffix), len.saturating_sub(1)),
        },
        (first, "") => match first.parse::<u64>() {
            Ok(first) => (first, len.saturating_sub(1)),
            Err(_) => return Ok(None),
        },
        (first, last) => match (first.parse::<u64>(), last.parse::<u64>()) {
            (Ok(first), Ok(last)) if first <= last => (first, last.min(len.saturating_sub(1))),
            _ => return Ok(None),
        },
    };
    if len == 0 || range.0 >= len {
        return Err(());
    }
    Ok(Some(range))
}

/// Bytes `start..end` of `kept`, a piece at a time, each read off the async
/// runtime.
fn kept_body(kept: Arc<KeptExport>, start: u64, end: u64) -> Body {
    Body::from_stream(futures_util::stream::unfold(
        (kept, start),
        move |(kept, at)| async move {
            if at >= end {
                return None;
            }
            let len = (end - at).min(TRANSFER_PIECE_BYTES);
            let reader = Arc::clone(&kept);
            let piece = tokio::task::spawn_blocking(move || reader.piece(at, len))
                .await
                .unwrap_or_else(|_| Err(std::io::Error::other("export transfer read stopped")));
            match piece {
                Ok(piece) => Some((Ok(piece), (kept, at + len))),
                Err(error) => Some((Err(error), (kept, end))),
            }
        },
    ))
}

/// Who a kept export belongs to: the principal its exporting call was
/// attributed to.
fn exporter_of(auth: &CoreAuth) -> String {
    crate::api::call_receipt::call_actor(auth).0
}

fn encoded(value: &impl serde::Serialize) -> Result<Value, FacadeApiError> {
    serde_json::to_value(value).map_err(|_| {
        FacadeApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            MEMORY_CODE_INTERNAL,
            "export result encoding failed",
            ["Report this SDK response mismatch."],
        )
    })
}

fn no_owner_proof() -> FacadeApiError {
    FacadeApiError::forbidden(
        "full-vault export requires verified owner authority",
        ["Present a verified owner credential."],
    )
}

fn unknown_transfer() -> FacadeApiError {
    FacadeApiError::new(
        StatusCode::NOT_FOUND,
        MEMORY_CODE_NOT_FOUND,
        "no export is kept under this transfer_ref for this caller",
        ["Export again with delivery \"transfer\"."],
    )
}

fn transfers_unreadable() -> FacadeApiError {
    FacadeApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        MEMORY_CODE_INTERNAL,
        "the kept export list is unreadable",
        ["Retry the export."],
    )
}
