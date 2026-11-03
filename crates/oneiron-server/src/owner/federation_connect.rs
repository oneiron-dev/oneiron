//! Connect (ARCH-0043 #relationship-lifecycle, FIX 323): the owner offers a
//! pact to a peer vault and accepts the peer's signed half. Each half is
//! signed by its vault's host-root key, and each side's log pins the other's,
//! so the courtesy asks and answers those hosts sign verify (OF-273). The
//! owner carries each half to the other host; this host sends nothing.
//! Before offering or accepting, each owner mints the guest grant its side's
//! pact governs (FIX 3016).

use oneiron::authority::{AuthorityKey, ConnectOffer, FederationPactGesture, ScopeOpeningKey};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::parse_hex;
use oneiron::federation::{FederationDirectionScope, FederationPactScope};
use oneiron::policy_model::{
    ForeignWorldPrivacyDelivery, ForeignWorldPrivacyExportRequest, WorldPrivacyRequest,
};
pub(crate) use oneiron::task_verb::sdk::{
    AcceptConnect, ConnectAccepted as Accepted, ConnectGrant, ConnectIdentity, MintConnectGrant,
    Offer, OfferConnect,
};
use oneiron::task_verb::sdk::{
    AcceptRescopeConnect, ConnectDelivery, ConnectDisconnected, ConnectExportRequest,
    ConnectPactReceipt, ConnectPactRequest, ConnectRejoined, ConnectRescoped, NarrowConnect,
    RescopeConnect, RescopeOffer,
};

use super::courtesy_delete::with_issuer;
use super::vault_key::hex;
use super::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

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
        key: hex(offer.scope_key.expose()),
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
        scope_key: ScopeOpeningKey::from_bytes(hex_field("offer.key", &offer.key)?),
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

/// Mints the guest grant a Connect with the peer vault will govern. Inert
/// until both owners' Connect makes its pact Active.
pub(crate) fn mint_grant(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    request: &MintConnectGrant,
) -> OwnerResult<ConnectGrant> {
    let vault = server.vault();
    let peer = hex_field("peer_vault", &request.peer_vault)?;
    let minted = vault
        .mint_connect_grant(
            owner,
            peer,
            request.authority_scope.clone(),
            request.expires_at,
        )
        .map_err(|error| refused(vault, owner, error))?;
    Ok(ConnectGrant {
        grant: minted.grant.to_hex(),
        guest_actor: minted.guest_actor.to_hex(),
        resolved_scope: minted.resolved_scope,
        expires_at: minted.expires_at,
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

fn scope_pair(
    server: &SyncServer,
    pact: &str,
    outbound: FederationDirectionScope,
    inbound: FederationDirectionScope,
) -> OwnerResult<FederationPactScope> {
    let fold = server.vault().authority_fold()?;
    let state = fold
        .federation_pacts
        .get(&hex_field("pact", pact)?)
        .ok_or_else(|| OwnerError::NotFound("pact", pact.to_owned()))?;
    let local = fold
        .vault_id
        .ok_or_else(|| OwnerError::Refused("no authority root".into()))?;
    Ok(if local <= state.peer_vault_id {
        FederationPactScope {
            lo_to_hi: outbound,
            hi_to_lo: inbound,
        }
    } else {
        FederationPactScope {
            lo_to_hi: inbound,
            hi_to_lo: outbound,
        }
    })
}

fn pact_receipt(
    pact: String,
    state: oneiron::authority::FederationPactState,
) -> ConnectPactReceipt {
    ConnectPactReceipt {
        pact,
        status: state.status,
        epoch: state.pact_epoch,
        scope: state.pact_scope,
        effective_scope: state.effective_scope,
    }
}

fn rescope_json(offered: &oneiron::authority::ConnectRescopeOffer) -> RescopeOffer {
    let offer = offer_json(&offered.offer);
    RescopeOffer {
        pact: offer.pact,
        epoch: offered.epoch,
        nonce: offer.nonce,
        from: offer.from,
        to: offer.to,
        scope: offer.scope,
        signer: offer.signer,
        signature: offer.signature,
        key: offer.key,
    }
}

pub(crate) fn rescope_offer(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    request: &RescopeConnect,
) -> OwnerResult<RescopeOffer> {
    let scope = scope_pair(
        server,
        &request.pact,
        request.outbound.clone(),
        request.inbound.clone(),
    )?;
    let pact = hex_field("pact", &request.pact)?;
    let offered = with_issuer(server, |issuer| {
        Ok(server
            .vault()
            .propose_connect_rescope_as(owner, issuer, pact, request.epoch, scope))
    })?
    .map_err(|error| refused(server.vault(), owner, error))?;
    Ok(rescope_json(&offered))
}

pub(crate) fn rescope_accept(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    request: &AcceptRescopeConnect,
) -> OwnerResult<ConnectRescoped> {
    let offer = &request.offer;
    let offered = oneiron::authority::ConnectRescopeOffer {
        epoch: offer.epoch,
        offer: parse_offer(&Offer {
            pact: offer.pact.clone(),
            nonce: offer.nonce.clone(),
            from: offer.from.clone(),
            to: offer.to.clone(),
            scope: offer.scope.clone(),
            signer: offer.signer.clone(),
            signature: offer.signature.clone(),
            key: offer.key.clone(),
        })?,
    };
    let (state, counter) = with_issuer(server, |issuer| {
        Ok(server
            .vault()
            .accept_connect_rescope_as(owner, issuer, &offered))
    })?
    .map_err(|error| refused(server.vault(), owner, error))?;
    Ok(ConnectRescoped {
        receipt: pact_receipt(offer.pact.clone(), state),
        counter: rescope_json(&counter),
    })
}

pub(crate) fn narrow(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    request: &NarrowConnect,
) -> OwnerResult<ConnectPactReceipt> {
    let pact = hex_field("pact", &request.pact)?;
    let state = with_issuer(server, |issuer| {
        Ok(server.vault().narrow_connect_as(
            owner,
            issuer,
            pact,
            request.epoch,
            request.outbound.clone(),
        ))
    })?
    .map_err(|error| refused(server.vault(), owner, error))?;
    Ok(pact_receipt(request.pact.clone(), state))
}

pub(crate) fn disconnect(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    request: &ConnectPactRequest,
) -> OwnerResult<ConnectDisconnected> {
    let pact = hex_field("pact", &request.pact)?;
    let state = with_issuer(server, |issuer| {
        Ok(server.vault().disconnect_connect_as(owner, issuer, pact))
    })?
    .map_err(|error| refused(server.vault(), owner, error))?;
    Ok(ConnectDisconnected {
        receipt: pact_receipt(request.pact.clone(), state),
        outbound_access: false,
        inbound_access: false,
        sync_stopped: true,
        copied_bytes_recallable: false,
        recipient_copy_state: oneiron::receipt::GuestCopyState::Unknown,
    })
}

pub(crate) fn export(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    request: ConnectExportRequest,
) -> OwnerResult<ConnectDelivery> {
    with_issuer(server, |issuer| {
        Ok(oneiron::sync::SyncClient::export_connect_window_as(
            &server.reassert_manager,
            owner,
            issuer,
            request,
        ))
    })?
    .map_err(|error| refused(server.vault(), owner, error))
}

pub(crate) fn rejoin(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    request: ConnectDelivery,
) -> OwnerResult<ConnectRejoined> {
    oneiron::sync::SyncClient::rejoin_connect_as(&server.reassert_manager, owner, request)
        .map_err(|error| refused(server.vault(), owner, error))
}

/// The owner signs the world-settings leg a request owes its connected
/// vault, for the owner to carry there (FIX 4702): an agent's ask on a world
/// that vault owns, or this vault's holders' answer to one.
pub(crate) fn world_privacy_export(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    request: ForeignWorldPrivacyExportRequest,
) -> OwnerResult<ForeignWorldPrivacyDelivery> {
    let request = entity_id("request", &request.request)?;
    with_issuer(server, |issuer| {
        Ok(server
            .vault()
            .export_foreign_world_privacy(owner, issuer, request))
    })?
    .map_err(|error| refused(server.vault(), owner, error))
}

/// The owner hands in a world-settings leg a connected vault's host signed
/// (FIX 4702): an ask files for this vault's holders, an answer settles the
/// ask it answers.
pub(crate) fn world_privacy_receive(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    delivery: ForeignWorldPrivacyDelivery,
) -> OwnerResult<WorldPrivacyRequest> {
    server
        .vault()
        .receive_foreign_world_privacy(owner, delivery)
        .map_err(|error| refused(server.vault(), owner, error))
}
