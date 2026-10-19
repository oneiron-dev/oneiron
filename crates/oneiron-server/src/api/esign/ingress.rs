//! Token-first ingress at the public signing doors (FIX 3808, Engine rulings
//! 10-18 and 10-19). Every ceremony POST carries its recipient link's
//! capability in the `x-oneiron-esign-capability` header, and the vault
//! admits it ([`oneiron::Vault::admit_esign_ingress`]) before a byte of the
//! body is read. A request with no such header, or one the vault does not
//! admit, is shed with its body unread. An admitted body spools whole to an
//! anonymous file the vault stages, under the server's one disk floor; its
//! size is the `[limits] esign_body_bytes` row, which asks the envelope's
//! sender past it and never refuses the body. The owner's editor POSTs
//! (FIX 5618) share this spool under their own admission and rows.
use super::*;
use crate::api::transfer::{self, BodyReader};
use crate::machine::{DiskClaim, DiskFloor};
use axum::body::Body;
use axum::extract::FromRequestParts;
use oneiron::blob_artifact::esign::{EsignCapability, EsignIngress, SigningAction};
use oneiron::limit_ask::EngineLimit;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use tokio::sync::mpsc;

/// The header a public signing door reads its capability from. The
/// invitation stays `/sign#<capability>`: the page reads the fragment, which
/// no request target holds, and sends it only here.
const CAPABILITY_HEADER: &str = "x-oneiron-esign-capability";

/// Bytes the spool reads at a time, and the largest piece the body is fed in.
const SPOOL_PIECE: usize = 64 * 1024;

/// Bytes a body of no declared length spools between looks at the disk
/// floor; each look claims the stretch to the next one.
const FLOOR_EVERY_BYTES: u64 = 8 * 1024 * 1024;

/// A signing link a public door admitted, and its capability for the act.
pub(super) struct SigningIngress {
    pub(super) token: EsignCapability,
    pub(super) admitted: EsignIngress,
}

impl FromRequestParts<Arc<SyncServer>> for SigningIngress {
    type Rejection = Response;

    /// Runs on the request's head alone, before the body extractor: no
    /// body, digest or decode precedes it. Admission only reads, so a door
    /// keeps its own turn and terminal answers. A recipient the vault
    /// admits is no longer a stranger to the listener.
    async fn from_request_parts(
        parts: &mut Parts,
        server: &Arc<SyncServer>,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(CAPABILITY_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|raw| EsignCapability::parse(raw).ok())
            .ok_or_else(refused)?;
        let admitted = server
            .vault
            .admit_esign_ingress(&token)
            .map_err(|_| refused())?;
        crate::http_listener::authenticated();
        Ok(Self { token, admitted })
    }
}

/// `POST /sign/action`'s body: the act alone, the capability in the header.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActionBody {
    pub(super) action: SigningAction,
}

/// `POST /sign/pdf`'s and `POST /sign/preview`'s body: the item, by position.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ItemBody {
    pub(super) item: usize,
}

/// `POST /sign/signature`'s body: the stored image to read back.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignatureBody {
    pub(super) image_ref: String,
}

/// An admitted door's JSON payload: its body spooled, then parsed from the
/// spool on the same worker. A body that is not the payload is malformed; a
/// token in it is not a fallback carrier, so it is malformed too.
pub(super) async fn payload<T: DeserializeOwned + Send + 'static>(
    server: &Arc<SyncServer>,
    admitted: EsignIngress,
    headers: &HeaderMap,
    body: Body,
) -> Result<T, Response> {
    spooled(server, admitted, headers, body, |file, _| {
        serde_json::from_reader::<_, T>(io::BufReader::new(file)).ok()
    })
    .await?
    .ok_or_else(malformed)
}

/// A spooled body read whole, for a door whose consumer takes a slice.
pub(super) fn whole_body(mut file: File, bytes: u64) -> Option<Vec<u8>> {
    let mut whole = Vec::with_capacity(usize::try_from(bytes).unwrap_or(0));
    file.read_to_end(&mut whole).ok()?;
    Some(whole)
}

/// How a body ended before its door read it.
enum Unspooled {
    /// The vault's disk reached its free-space reserve.
    Floored,
    /// The body failed, stalled past the idle limit or was cancelled, or its
    /// spool could not be written.
    Failed,
}

/// Spools an admitted door's `body` whole on a transfer worker, measures it
/// against `[limits] esign_body_bytes`, then hands the rewound spool and its
/// length to `read` on the same worker. The body's disk claim is held until
/// `read` returns. Only the disk floor or a body that never arrives whole
/// ends it unread; its size never does.
pub(super) async fn spooled<T: Send + 'static>(
    server: &Arc<SyncServer>,
    admitted: EsignIngress,
    headers: &HeaderMap,
    body: Body,
    read: impl FnOnce(File, u64) -> T + Send + 'static,
) -> Result<T, Response> {
    let vault = Arc::clone(&server.vault);
    spool_whole(
        server,
        headers,
        body,
        |_| {},
        move |file, bytes| {
            if let Err(error) = vault.measure_esign_body(&admitted, bytes) {
                tracing::warn!(
                    ?error,
                    "a signing body's esign_body_bytes crossing could not be kept"
                );
            }
            read(file, bytes)
        },
    )
    .await
}

/// An admitted editor POST's `body` (FIX 5618), spooled whole as a ceremony
/// body is and handed to `read` on the same worker. Its size is measured
/// against `row` as it spools: the first piece past the row's bound asks the
/// vault owner ([`oneiron::Vault::measure_limit`], once per request), and the
/// body keeps spooling. No envelope stands behind the editor's computation,
/// so no sender is asked and no document is charged.
pub(super) async fn editor_spooled<T: Send + 'static>(
    server: &Arc<SyncServer>,
    row: EngineLimit,
    headers: &HeaderMap,
    body: Body,
    read: impl FnOnce(File, u64) -> T + Send + 'static,
) -> Result<T, Response> {
    let vault = Arc::clone(&server.vault);
    let mut asked = false;
    let measure = move |bytes| {
        if !asked {
            asked = vault.measure_limit(row, bytes).is_some();
        }
    };
    spool_whole(server, headers, body, measure, read).await
}

/// The spool both admissions share: `body` whole on a transfer worker,
/// `progress` told the bytes copied after each piece, then the rewound
/// spool and its length handed to `read` on the same worker. The body's
/// disk claim is held until `read` returns.
async fn spool_whole<T: Send + 'static>(
    server: &Arc<SyncServer>,
    headers: &HeaderMap,
    body: Body,
    progress: impl FnMut(u64) + Send + 'static,
    read: impl FnOnce(File, u64) -> T + Send + 'static,
) -> Result<T, Response> {
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let floor = server.transfers.disk.clone();
    let claim = floor.claim();
    // A declared body claims its spool and the stored copy it may come to
    // before a byte of it is read.
    if let Some(size) = declared
        && !floor.hold(&claim, size.saturating_mul(2))
    {
        return Err(disk_floor());
    }
    let vault = Arc::clone(&server.vault);
    let (sender, receiver) = mpsc::channel(2);
    let mut worker = transfer::spawn_worker(move || -> Result<T, Unspooled> {
        let (file, bytes) = spool(
            &vault,
            BodyReader::new(receiver),
            &floor,
            &claim,
            declared,
            progress,
        )?;
        let answer = read(file, bytes);
        drop(claim);
        Ok(answer)
    });
    // The worker can end at the disk floor before the client sends its next
    // frame, so its answer is taken without waiting for the body to end.
    let early = tokio::select! {
        biased;
        joined = &mut worker => Some(joined),
        () = transfer::feed_body(body, sender, server.transfers.idle, SPOOL_PIECE) => None,
    };
    let joined = match early {
        Some(joined) => joined,
        None => worker.await,
    };
    match joined {
        Ok(Ok(answer)) => Ok(answer),
        Ok(Err(Unspooled::Floored)) => Err(disk_floor()),
        Ok(Err(Unspooled::Failed)) | Err(_) => Err(unread()),
    }
}

/// The body to its end in a vault-staged spool, judged against the disk
/// floor as it goes: each look moves the claim to what is still to be
/// written, the spool's rest and its stored copy, so no other upload counts
/// that room as free. At its end the spool is on the disk, and the claim is
/// its stored copy. `progress` hears the bytes copied after each piece.
fn spool(
    vault: &oneiron::Vault,
    mut body: BodyReader,
    floor: &DiskFloor,
    claim: &DiskClaim,
    declared: Option<u64>,
    mut progress: impl FnMut(u64),
) -> Result<(File, u64), Unspooled> {
    let mut file = vault.archive_spool_file().map_err(|_| Unspooled::Failed)?;
    let mut piece = vec![0; SPOOL_PIECE];
    let mut read = 0u64;
    let mut looked_at: Option<u64> = None;
    loop {
        let count = body.read(&mut piece).map_err(|_| Unspooled::Failed)?;
        if count == 0 {
            break;
        }
        let written = read;
        read = read.saturating_add(count as u64);
        if looked_at.is_none_or(|at| read.saturating_sub(at) >= FLOOR_EVERY_BYTES) {
            looked_at = Some(read);
            let needed = declared
                .map_or((count as u64).saturating_add(FLOOR_EVERY_BYTES), |size| {
                    size.saturating_sub(written).saturating_add(size.max(read))
                });
            if !floor.hold(claim, needed) {
                return Err(Unspooled::Floored);
            }
        }
        file.write_all(&piece[..count])
            .map_err(|_| Unspooled::Failed)?;
        progress(read);
    }
    if !floor.hold(claim, read) {
        return Err(Unspooled::Floored);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Unspooled::Failed)?;
    Ok((file, read))
}

/// The vault's disk is at its free-space reserve (`limits.disk_reserve_bytes`):
/// the only refusal an admitted body's size can meet.
fn disk_floor() -> Response {
    (
        StatusCode::INSUFFICIENT_STORAGE,
        Json(serde_json::json!({"error":{"code":"signing_disk_floor"}})),
    )
        .into_response()
}

/// An admitted body that did not arrive whole.
pub(super) fn unread() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error":{"code":"signing_body_unread"}})),
    )
        .into_response()
}

/// An admitted body that is not its door's payload.
pub(super) fn malformed() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error":{"code":"signing_body_malformed"}})),
    )
        .into_response()
}
