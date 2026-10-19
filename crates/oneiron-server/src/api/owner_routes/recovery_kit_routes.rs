//! `/v1/owner/recovery-kit`: the world kit's public status on a running
//! server (OF-173). The direct ceremony (issue, confirm, restore) stays with
//! `oneiron recovery-kit` on a stopped vault. On a running server a root
//! change goes through the owner's request and its target
//! (`root_routes`, `recovery_kit_target_routes`; FIX 4530, 4736): a piece or
//! a passphrase crosses HTTP only in the target install's own call, for that
//! call alone, and never through a coordinating install's reply.
//!
//! `/v1/owner/custody-anchor` is the self-host custody anchor door (KS-4A1,
//! FIX 5685): the keyless read and compare-and-swap advance of a lineage's
//! anchor record in this server's custody anchor root (CALLS
//! CUSTODY_ANCHOR_ROOT), the store an install whose own disk would roll
//! back with its vault anchors its custody head on. A record carries a
//! position and a tag, never a key; the engine checks an advance extends
//! the anchored position, and the reader checks the tag.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::get;
use oneiron::recovery::checkpoint::CustodyAnchorRoot;
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, host, owner, owner_error};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::owner::recovery_kit::{self as view, KitStatusView};
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/recovery-kit", get(status))
        .route("/custody-anchor", get(read_anchor).post(advance_anchor))
}

/// `GET /v1/owner/recovery-kit`: the kits this vault issued, the current
/// one, and each private world's no-kit state here.
async fn status(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<KitStatusView> {
    owner(&auth, &server)?;
    let report = blocking(move || Ok(view::report(server.vault())?)).await?;
    Ok(Json(report))
}

/// One custody lineage: its vault id (64 hex) and namespace (32 hex).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorLineage {
    vault: String,
    namespace: String,
}

/// A compare-and-swap advance: the BLAKE3 (64 hex) of the record the caller
/// read, `null` when it read none, and the record (hex) to make current.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorAdvanceRequest {
    expected: Option<String>,
    record: String,
}

#[derive(Serialize)]
struct AnchorRecordView {
    /// The lineage's current record (hex); `null` while it has none.
    record: Option<String>,
}

#[derive(Serialize)]
struct AnchorAdvanceView {
    /// `false` when another writer moved the record first: nothing changed.
    advanced: bool,
}

/// This server's custody anchor root, refused while none is set up.
fn anchor_root(server: &SyncServer) -> Result<CustodyAnchorRoot, ApiError> {
    host(server)?
        .backups
        .custody_anchor
        .clone()
        .map(CustodyAnchorRoot::at)
        .ok_or_else(|| {
            owner_error(OwnerError::NotFound(
                "custody anchor root",
                "on this server (backup.custody_anchor_root)".to_owned(),
            ))
        })
}

fn unhex<const N: usize>(text: &str, what: &str) -> OwnerResult<[u8; N]> {
    unhex_vec(text, what)?
        .try_into()
        .map_err(|_| OwnerError::Invalid(format!("{what} is {} hex", N * 2)))
}

fn unhex_vec(text: &str, what: &str) -> OwnerResult<Vec<u8>> {
    let invalid = || OwnerError::Invalid(format!("{what} is not hex"));
    if !text.len().is_multiple_of(2) || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    (0..text.len())
        .step_by(2)
        .map(|at| {
            text.get(at..at + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(invalid)
        })
        .collect()
}

/// `GET /v1/owner/custody-anchor`: one lineage's current anchor record here.
async fn read_anchor(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<AnchorLineage>, QueryRejection>,
) -> OwnerReply<AnchorRecordView> {
    let owner = owner(&auth, &server)?;
    let lineage = query_params(query)?;
    let anchor = anchor_root(&server)?;
    let record = blocking(move || -> OwnerResult<Option<Vec<u8>>> {
        owner.actor_for_read(server.vault())?;
        let vault = unhex::<32>(&lineage.vault, "vault")?;
        let namespace = unhex::<16>(&lineage.namespace, "namespace")?;
        Ok(anchor.read(vault, namespace)?)
    })
    .await?;
    Ok(Json(AnchorRecordView {
        record: record.as_deref().map(crate::owner::vault_key::hex),
    }))
}

/// `POST /v1/owner/custody-anchor`: makes a record its lineage's current
/// one while the current one is still the one the caller read.
async fn advance_anchor(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<AnchorAdvanceRequest>, JsonRejection>,
) -> OwnerReply<AnchorAdvanceView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let anchor = anchor_root(&server)?;
    let advanced = blocking(move || -> OwnerResult<bool> {
        owner.revalidate_person(server.vault())?;
        let expected = request
            .expected
            .as_deref()
            .map(|expected| unhex::<32>(expected, "expected"))
            .transpose()?;
        let record = unhex_vec(&request.record, "record")?;
        Ok(anchor.advance(expected, &record)?)
    })
    .await?;
    Ok(Json(AnchorAdvanceView { advanced }))
}
