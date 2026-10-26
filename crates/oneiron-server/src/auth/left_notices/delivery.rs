//! `POST /v1/shared/removal-delivery` and `POST /v1/shared/removal-delivery/ack`
//! (FIX 3215, 3396): the host sends a removed holder's device the archives
//! export-first removals kept for it, and records its acknowledgement, on the
//! pull doors' proof: the revoked slip in `x-oneiron-left-slip` and a fresh
//! holder proof in `x-oneiron-binding`, its nonce spent once. Each request is
//! its own session, and it releases bytes only under the proof it carries.
//!
//! A session answers every archive the holder has not acknowledged at its
//! current delivery version, each as the pull door gives it. With none owed
//! it stays open until an execute or re-execute wakes it for that person, or
//! until [`REMOVAL_DELIVERY_HOLD`] passes, and then answers none, saying
//! whether it was woken: the device asks again at once, with a fresh proof.
//! The ack says the holder stores that version; an archive delivered anew
//! since stays owed. Neither door gives back membership or any other read.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::HeaderMap;
use oneiron::federation::RemovalExportCopy;
use serde::{Deserialize, Serialize};

use super::left_proof;
use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;

/// How long a delivery session with nothing owed stays open for a wake
/// (FIX 3396, a call): back to back, a device's sessions are its push
/// channel, each one proof and one spent nonce.
const REMOVAL_DELIVERY_HOLD: Duration = Duration::from_secs(50);

/// One archive a session sends, with the delivery version its ack names.
#[derive(Debug, Serialize)]
struct Delivery {
    version: u64,
    copy: RemovalExportCopy,
}

#[derive(Debug, Serialize)]
pub(super) struct Deliveries {
    deliveries: Vec<Delivery>,
    /// A wake for this person ended the session: ask again at once.
    woken: bool,
}

pub(super) async fn removal_delivery(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<Deliveries>, EnvelopedApiError> {
    let (slip, proof, signature) = left_proof(&headers)?;
    // Taken before the read, so a wake while it reads is not missed.
    let since = server.removal_deliveries.mark();
    let reading = Arc::clone(&server);
    let (person, owed) = tokio::task::spawn_blocking(move || {
        reading.vault().removal_deliveries(
            &slip,
            proof.timestamp,
            &signature,
            proof.nonce.as_bytes(),
        )
    })
    .await
    .map_err(|_| ApiError::unauthorized())?
    .map_err(|_| ApiError::unauthorized())?;
    if !owed.is_empty() {
        let deliveries = owed
            .into_iter()
            .map(|(version, copy)| Delivery { version, copy })
            .collect();
        return Ok(Json(Deliveries {
            deliveries,
            woken: false,
        }));
    }
    let woken = server
        .removal_deliveries
        .hold(person, since, REMOVAL_DELIVERY_HOLD)
        .await;
    Ok(Json(Deliveries {
        deliveries: Vec::new(),
        woken,
    }))
}

/// The version of one archive the holder now stores.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeliveryAck {
    receipt_id: String,
    version: u64,
}

/// Where the holder stands with that archive after its ack.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum DeliveryState {
    /// It stores the archive's current version.
    Acked,
    /// The archive was delivered anew since, or is gone: a session says
    /// which.
    Pending,
}

#[derive(Debug, Serialize)]
pub(super) struct Acknowledged {
    state: DeliveryState,
}

pub(super) async fn removal_delivery_ack(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<DeliveryAck>, JsonRejection>,
) -> Result<Json<Acknowledged>, EnvelopedApiError> {
    let ack = crate::api::json_payload(payload)?;
    // Refused before the nonce is spent.
    if oneiron::EntityId::from_hex(&ack.receipt_id).is_err() {
        return Err(ApiError::bad_request("receipt_id must be 32 hex", Some("receipt_id")).into());
    }
    let (slip, proof, signature) = left_proof(&headers)?;
    let acked = tokio::task::spawn_blocking(move || {
        server.vault().ack_removal_delivery(
            &slip,
            proof.timestamp,
            &signature,
            proof.nonce.as_bytes(),
            &ack.receipt_id,
            ack.version,
        )
    })
    .await
    .map_err(|_| ApiError::unauthorized())?
    .map_err(|_| ApiError::unauthorized())?;
    let state = if acked {
        DeliveryState::Acked
    } else {
        DeliveryState::Pending
    };
    Ok(Json(Acknowledged { state }))
}
