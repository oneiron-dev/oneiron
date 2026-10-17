//! Connect (ARCH-0043 #relationship-lifecycle, FIX 323): the owner offers a
//! pact to a peer vault and accepts the peer's signed half. Each half is
//! signed by its vault's host-root key, and each side's log pins the other's,
//! so the courtesy asks and answers those hosts sign verify (OF-273). The
//! owner carries each half to the other host; this host sends nothing.

use oneiron::authority::{AuthorityKey, ConnectOffer, FederationPactGesture};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::parse_hex;
use oneiron::federation::{FederationDirectionScope, FederationPactScope};
use serde::{Deserialize, Serialize};

use super::cooperative_deletion::with_issuer;
use super::vault_key::hex;
use super::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

/// `GET /v1/owner/federation/connect`: what a peer's owner names to offer
/// this vault a pact.
#[derive(Debug, Serialize)]
pub(crate) struct ConnectIdentity {
    /// This vault's id (its genesis hash), as 64 hex.
    pub(crate) vault: String,
    /// The host-root key this host signs its halves and courtesy asks with.
    pub(crate) host_key: String,
}

/// `POST /v1/owner/federation/connect/offer`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OfferConnect {
    /// The peer vault's id, as 64 hex.
    pub(crate) peer_vault: String,
    /// This vault's FEDERATION_GRANT the pact will govern, as 32 hex.
    pub(crate) grant: String,
    /// What this vault shares with the peer.
    pub(crate) outbound: FederationDirectionScope,
    /// What the peer shares with this vault.
    pub(crate) inbound: FederationDirectionScope,
}

/// One host's signed half of a Connect, as the owner carries it.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Offer {
    /// The pact id, as 64 hex.
    pub(crate) pact: String,
    /// The pact nonce, as 32 hex.
    pub(crate) nonce: String,
    /// The signing host's vault, as 64 hex.
    pub(crate) from: String,
    /// The vault the offer is for, as 64 hex.
    pub(crate) to: String,
    /// The scope pair, by vault id: `lo_to_hi` is what the smaller id shares.
    pub(crate) scope: FederationPactScope,
    /// The signing host's root key (Ed25519), as 64 hex.
    pub(crate) signer: String,
    /// Its signature over the pact transcript, as 128 hex.
    pub(crate) signature: String,
}

/// `POST /v1/owner/federation/connect/accept`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AcceptConnect {
    /// The peer host's half.
    pub(crate) offer: Offer,
    /// This vault's FEDERATION_GRANT the pact governs, as 32 hex.
    pub(crate) grant: String,
}

/// The pact as this vault's log now holds it.
#[derive(Debug, Serialize)]
pub(crate) struct Accepted {
    pub(crate) pact: String,
    pub(crate) status: String,
    /// The key this log pinned for the peer: its host-root key.
    pub(crate) peer_key: String,
    /// This host's half of the same pact, for the peer's owner to accept.
    pub(crate) counter: Offer,
}

fn hex_field<const N: usize>(field: &str, value: &str) -> OwnerResult<[u8; N]> {
    parse_hex(value).ok_or_else(|| OwnerError::Invalid(format!("{field} must be {} hex", N * 2)))
}

fn key_hex(key: &AuthorityKey) -> String {
    match key {
        AuthorityKey::Ed25519(bytes) => hex(bytes),
        AuthorityKey::P256(bytes) => hex(bytes),
    }
}

fn offer_json(offer: &ConnectOffer) -> Offer {
    Offer {
        pact: hex(&offer.pact_id),
        nonce: hex(&offer.pact_nonce),
        from: hex(&offer.from_vault),
        to: hex(&offer.to_vault),
        scope: offer.pact_scope.clone(),
        signer: key_hex(&offer.gesture.signer),
        signature: hex(&offer.gesture.signature),
    }
}

fn parse_offer(offer: &Offer) -> OwnerResult<ConnectOffer> {
    Ok(ConnectOffer {
        from_vault: hex_field("offer.from", &offer.from)?,
        to_vault: hex_field("offer.to", &offer.to)?,
        pact_id: hex_field("offer.pact", &offer.pact)?,
        pact_nonce: hex_field("offer.nonce", &offer.nonce)?,
        pact_scope: offer.scope.clone(),
        gesture: FederationPactGesture {
            signer: AuthorityKey::Ed25519(hex_field("offer.signer", &offer.signer)?),
            signature: hex_field::<64>("offer.signature", &offer.signature)?.to_vec(),
        },
    })
}

/// The engine's refusal, unless the owner's standing lapsed first.
fn refused(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    error: oneiron::Error,
) -> OwnerError {
    if let Err(refusal) = vault.recheck_owner(owner) {
        return OwnerError::from(refusal);
    }
    OwnerError::Invalid(error.to_string())
}

/// This vault's id and host key.
pub(crate) fn identity(server: &SyncServer) -> OwnerResult<ConnectIdentity> {
    let vault =
        server.vault().authority_fold()?.vault_id.ok_or_else(|| {
            OwnerError::Refused("this vault has no authority root yet".to_owned())
        })?;
    let host_key = with_issuer(server, |issuer| Ok(issuer.public_key()))?;
    Ok(ConnectIdentity {
        vault: hex(&vault),
        host_key: key_hex(&host_key),
    })
}

/// Signs this host's half of a new pact with a peer vault. Logs nothing.
pub(crate) fn offer(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    request: &OfferConnect,
) -> OwnerResult<Offer> {
    let vault = server.vault();
    let peer = hex_field("peer_vault", &request.peer_vault)?;
    let grant = entity_id("grant", &request.grant)?;
    let offered = with_issuer(server, |issuer| {
        Ok(vault.propose_connect_as(
            owner,
            issuer,
            grant,
            peer,
            request.outbound.clone(),
            request.inbound.clone(),
        ))
    })?
    .map_err(|error| refused(vault, owner, error))?;
    Ok(offer_json(&offered))
}

/// Logs the Connect the peer host's half signs, pinning its key, and answers
/// this host's half of the same pact.
pub(crate) fn accept(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    request: &AcceptConnect,
) -> OwnerResult<Accepted> {
    let vault = server.vault();
    let grant = entity_id("grant", &request.grant)?;
    let offer = parse_offer(&request.offer)?;
    let (pact, counter) = with_issuer(server, |issuer| {
        Ok(vault.accept_connect_as(owner, issuer, grant, &offer))
    })?
    .map_err(|error| refused(vault, owner, error))?;
    Ok(Accepted {
        pact: hex(&offer.pact_id),
        status: format!("{:?}", pact.status),
        peer_key: key_hex(&pact.peer_owner_key),
        counter: offer_json(&counter),
    })
}
