//! Existing-generation publication grants over the bundle-access RPC.
//! Old readers issue on the existing upkeep tick; the asked executor fetches
//! only a separately offered pair, never an outer key in the clear.

use std::collections::BTreeMap;

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::{PartSource, ResidenceRpc, fetch_generation, refused, storage};
use crate::authority::{AuthorityEntryHash, Destination, PeerMachine};
use crate::sync::residence::{
    sealed_digest_from_hex, sealed_digest_hex, sealed_generation_from_hex, sealed_generation_hex,
};
use crate::sync::transport::TransportError;
use crate::world_keys::{CapsuleRead, LatestRead, SealedBundleGeneration, SealedPublicationGrant};
use crate::{EntityId, Vault};

const ACCESS_RPC: &str = "residence.bundle.access";

#[derive(Deserialize)]
struct PendingReply {
    pending: Vec<PendingWire>,
}

#[derive(Deserialize)]
struct PendingWire {
    generation: String,
    request: String,
    executor: String,
}

#[derive(Deserialize)]
struct GrantReply {
    grant: Option<String>,
}

/// Every upkeep, an old reader opens both actual objects itself before it
/// signs a pair. No pending request or ciphertext presence supplies a key.
pub(super) async fn serve(vault: &Vault, rpc: &mut ResidenceRpc) -> Result<usize, TransportError> {
    let PeerMachine::Proven { machine: home, .. } = vault.peer_machine_stands(rpc.home) else {
        return Ok(0);
    };
    let reply = rpc
        .request(ACCESS_RPC, json!({"op": "publicationPending"}))
        .await?;
    let reply: PendingReply = serde_json::from_value(reply).map_err(|_| refused())?;
    let mut generations: BTreeMap<SealedBundleGeneration, Vec<_>> = BTreeMap::new();
    for row in reply.pending {
        let generation = sealed_generation_from_hex(&row.generation).ok_or_else(refused)?;
        let request = sealed_digest_from_hex(&row.request).ok_or_else(refused)?;
        let executor = EntityId::from_hex(&row.executor).map_err(|_| refused())?;
        generations
            .entry(generation)
            .or_default()
            .push((request, executor));
    }
    let mut offered = 0;
    for (generation, requests) in generations {
        let Some((bundle, pads)) =
            fetch_generation(&mut PartSource::Machine(rpc), Some(generation)).await?
        else {
            continue;
        };
        for (request, executor) in requests {
            let grant = match vault.seal_bundle_publication_grant(
                &bundle,
                &pads,
                Destination::Machine(home),
                request,
            ) {
                Ok(grant) if grant.executor() == executor => grant,
                Ok(_) => continue,
                Err(error) => {
                    tracing::debug!(kind = ?error.kind(), "publication grant not issued");
                    continue;
                }
            };
            let bytes = grant.to_bytes().map_err(storage)?;
            if rpc
                .call(
                    ACCESS_RPC,
                    json!({
                        "op": "publicationOffer",
                        "grant": base64::engine::general_purpose::STANDARD.encode(bytes),
                    }),
                )
                .await?
                .is_ok()
            {
                offered += 1;
            }
        }
    }
    Ok(offered)
}

/// Only a missing reader/in-object capsule needs the separate grant path.
pub(super) fn needs_grant(read: &LatestRead) -> bool {
    matches!(read, LatestRead::Read { bundle, pads, .. }
        if *bundle == CapsuleRead::NoCapsuleHere || *pads == CapsuleRead::NoCapsuleHere)
}

pub(super) fn opened(read: &LatestRead) -> bool {
    let usable =
        |value: &CapsuleRead| matches!(value, CapsuleRead::Opens | CapsuleRead::PublicationGrant);
    matches!(read, LatestRead::Read { bundle, pads, .. } if usable(bundle) && usable(pads))
}

pub(super) async fn get(
    rpc: &mut ResidenceRpc,
    generation: SealedBundleGeneration,
    request: AuthorityEntryHash,
) -> Result<Option<SealedPublicationGrant>, TransportError> {
    let reply = rpc
        .request(
            ACCESS_RPC,
            json!({
                "op": "publicationGet",
                "generation": sealed_generation_hex(&generation),
                "request": sealed_digest_hex(&request),
            }),
        )
        .await?;
    let reply: GrantReply = serde_json::from_value(reply).map_err(|_| refused())?;
    let Some(encoded) = reply.grant else {
        return Ok(None);
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| refused())?;
    let grant = SealedPublicationGrant::from_bytes(&bytes).map_err(|_| refused())?;
    if grant.generation() != generation || *grant.request() != request {
        return Err(refused());
    }
    Ok(Some(grant))
}

/// Resets only the offer the actual executor tried. The home checks its
/// current proof/request and compares exact bytes before deleting anything.
pub(super) async fn invalidate(
    rpc: &mut ResidenceRpc,
    grant: &SealedPublicationGrant,
) -> Result<(), TransportError> {
    let bytes = grant.to_bytes().map_err(storage)?;
    rpc.request(
        ACCESS_RPC,
        json!({
            "op": "publicationInvalidate",
            "grant": base64::engine::general_purpose::STANDARD.encode(bytes),
        }),
    )
    .await
    .map(drop)
}
