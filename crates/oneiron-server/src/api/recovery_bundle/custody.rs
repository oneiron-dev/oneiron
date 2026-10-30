//! The kit door to the key custody the residence home holds (FIX 5846): an
//! install that holds the recovery kit and no machine of the vault's reads
//! the sealed head and log frames of its custody lineage a page at a time,
//! to restore on a new host. Keyless, as the sealed-bundle doors are: each
//! request is signed with the owner anchor of the recovery root this home
//! pins for the vault (`oneiron::sync::residence::kit_custody_page`), and
//! the home serves only ciphertext, only to that root.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Uri};
use axum::response::Json;
use base64::Engine;
use oneiron::store::custody_protocol::Lineage;
use oneiron::sync::residence::{KitCustodyFetch, kit_custody_page, sealed_digest_hex};
use oneiron::world_keys::RecoveryRootId;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{kit_origins, kit_public_urls};
use crate::auth::{parse_signature, parse_slip_id};
use crate::error::{ApiError, ApiErrorEnvelope, EnvelopedApiError};
use crate::server::SyncServer;

/// One page the kit asks for: the vault, the kit's root, the custody
/// lineage, the head offset and the last log sequence number a page before
/// reached, signed at `timestamp` with a fresh `nonce`; each in lower-case
/// hex.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::api) struct KitCustodyPageRequest {
    /// The vault, 64 hex.
    vault_id: String,
    /// The kit's recovery root, 64 hex.
    root: String,
    /// The custody lineage's vault, 64 hex, as the backup's custody names it.
    custody_vault: String,
    /// The custody lineage's namespace, 32 hex.
    custody_namespace: String,
    /// The head's bytes the page starts at; 0 for the first page.
    head_offset: u64,
    /// The page holds the frames after this log sequence number; 0 for the
    /// first page.
    after_seq: u64,
    /// When the kit signed the request, in Unix seconds. The home takes it
    /// within 300 seconds of its own clock.
    timestamp: u64,
    /// 32 fresh random bytes, 64 hex. The home takes each nonce once.
    nonce: String,
    /// The root's owner anchor's Ed25519 signature over the request, 128 hex.
    signature: String,
}

/// One log frame of the lineage.
#[derive(Serialize, ToSchema)]
pub(in crate::api) struct KitCustodyFrame {
    /// The frame's log sequence number.
    seq: u64,
    /// The sealed frame, in standard base64.
    frame: String,
}

/// Where the next page starts.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct KitCustodyCursor {
    /// The head's bytes the next page starts at.
    head_offset: u64,
    /// The last log sequence number this page reached.
    after_seq: u64,
}

/// One page of the lineage's custody: a slice of its sealed head, then its
/// log frames once the head is whole, read as one pair under the lineage's
/// lock.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct KitCustodyPageResponse {
    /// The BLAKE3 of the whole head the page was read with, 64 hex. A page
    /// that names another head than the page before means the home switched
    /// its head: the scan starts over.
    head_object_id: String,
    /// The whole head's length in bytes.
    head_length: u64,
    /// The log sequence number the head's position names: the last frame
    /// the pages serve.
    head_seq: u64,
    /// Where the page's slice of the head starts.
    head_offset: u64,
    /// The head's bytes from `headOffset`, in standard base64; empty once the
    /// head is whole.
    head_part: String,
    /// The frames after the cursor's sequence number, in order, through the
    /// head's at most.
    frames: Vec<KitCustodyFrame>,
    /// The cursor to sign for the next page; absent on the last, and where
    /// the home lacks the next frame.
    #[schema(inline)]
    next_cursor: Option<KitCustodyCursor>,
}

/// `POST /v1/recovery/custody/page`: one page of the key custody the home
/// holds of a lineage, for the kit of the root the home pins for the vault
/// (FIX 5846). A request that does not verify, a vault or root the home does
/// not pin, a lineage it holds no head of and an offset past the head's end
/// all look missing.
#[utoipa::path(
    post,
    path = "/v1/recovery/custody/page",
    operation_id = "recovery_custody_page",
    request_body(
        content = KitCustodyPageRequest,
        description = "One signed page request. No bearer: the signature is the authentication. It is the owner anchor's, of the recovery root this home pins for the vault, over the vault, the root, the home's address (as a sealed-bundle part request signs it), the method, this path, the custody lineage's vault and namespace, the head offset, the sequence number, the time and the nonce.",
        content_type = "application/json"
    ),
    responses(
        (status = 200, description = "One page of the lineage's custody, and the next page's cursor when more follow.", body = KitCustodyPageResponse, content_type = "application/json"),
        (status = 400, description = "The body does not parse, a field is malformed, or neither the request nor any of the home's configured public URLs names a host.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "The request does not verify, the home pins no such root for the vault, it holds no head of the lineage, or the offset is past the head's end. All look the same.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "The custody read stopped.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(in crate::api) async fn custody_page(
    State(server): State<Arc<SyncServer>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<KitCustodyPageResponse>, EnvelopedApiError> {
    let input: KitCustodyPageRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad_request("the kit fetch does not parse", None))?;
    let bad = |field: &str| ApiError::bad_request("the kit fetch field is malformed", Some(field));
    let mut origins = kit_origins(kit_public_urls(&server), &uri, &headers).into_iter();
    let fetch = KitCustodyFetch {
        vault_id: parse_slip_id(&input.vault_id).map_err(|_| bad("vaultId"))?,
        root: RecoveryRootId(parse_slip_id(&input.root).map_err(|_| bad("root"))?),
        origin: origins
            .next()
            .ok_or_else(|| ApiError::bad_request("the request names no host", None))?,
        lineage: Lineage::from_hex(&input.custody_vault, &input.custody_namespace)
            .ok_or_else(|| bad("custodyVault"))?,
        head_offset: input.head_offset,
        after_seq: input.after_seq,
        timestamp: input.timestamp,
        nonce: parse_slip_id(&input.nonce).map_err(|_| bad("nonce"))?,
    };
    let signature: [u8; 64] = parse_signature(&input.signature)
        .ok()
        .and_then(|signature| signature.try_into().ok())
        .ok_or_else(|| bad("signature"))?;
    let vault = Arc::clone(server.vault());
    // As for a sealed-bundle part: each other address checks a request that
    // did not verify.
    let read = tokio::task::spawn_blocking(move || {
        let mut fetch = fetch;
        let mut read = kit_custody_page(&vault, &fetch, &signature);
        for origin in origins {
            if read.is_ok() {
                break;
            }
            fetch.origin = origin;
            read = kit_custody_page(&vault, &fetch, &signature);
        }
        read
    })
    .await
    .map_err(|_| ApiError::internal_server_error("the custody read stopped"))?;
    let Ok(page) = read else {
        return Err(ApiError::not_found("custody head", None).into());
    };
    let standard = base64::engine::general_purpose::STANDARD;
    Ok(Json(KitCustodyPageResponse {
        head_object_id: sealed_digest_hex(&page.head_object_id),
        head_length: page.head_len,
        head_seq: page.head_seq,
        head_offset: page.head_offset,
        head_part: standard.encode(&page.head_part),
        frames: page
            .frames
            .iter()
            .map(|(seq, frame)| KitCustodyFrame {
                seq: *seq,
                frame: standard.encode(frame),
            })
            .collect(),
        next_cursor: page.next.map(|next| KitCustodyCursor {
            head_offset: next.head_offset,
            after_seq: next.after_seq,
        }),
    }))
}
