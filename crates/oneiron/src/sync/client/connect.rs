//! Public Connect delivery/rejoin over the production guest admission path.
use std::sync::Arc;

use crate::authority::{
    AuthoritySignature, FederationPactStatus, HostSlipIssuer, verify_authority_signature,
};
use crate::consent::AuthenticatedOwner;
use crate::federation::{Ceiling, FederationDirectionScope, Position, ScopeAxis, ScopeId};
use crate::sync::federation_burst::FederationPeer;
use crate::sync::{
    FederationAdmissionRole, SyncClient, SyncClientConfig, SyncSelector, SyncSelectorWorld,
    WindowManager,
};
use crate::task_verb::sdk::{
    ConnectDelivery, ConnectExportRequest, ConnectRejoinStatus, ConnectRejoined, ConnectWindow,
};
use crate::{EntityId, Error, Result};

fn refused() -> Error {
    Error::InvalidConfig("Connect delivery does not match the live reciprocal pact".into())
}

fn grant(vault: &crate::Vault, id: EntityId) -> Result<crate::federation::FederationGrant> {
    let txn = vault.store.env.read_txn()?;
    let crate::vault::LiveEntityRow::Live {
        entity_type: crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
        body,
    } = crate::vault::live_entity_row_in_txn(&vault.store, &txn, &id)?
    else {
        return Err(Error::EntityNotFound);
    };
    crate::federation::decode_federation_grant_body(&body)
}

fn id(value: &str) -> Result<[u8; 32]> {
    crate::deletion::parse_hex(value).ok_or_else(refused)
}

/// The active pact and its own vault id, under this owner's live proof.
fn active(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    pact_id: &[u8; 32],
) -> Result<(
    crate::authority::AuthorityVaultId,
    crate::authority::FederationPactState,
)> {
    vault.recheck_owner(owner)?;
    let fold = vault.authority_fold()?;
    let state = fold
        .federation_pacts
        .get(pact_id)
        .filter(|state| state.status == FederationPactStatus::Active)
        .cloned()
        .ok_or_else(refused)?;
    Ok((fold.vault_id.ok_or_else(refused)?, state))
}

impl SyncClient {
    /// The source host exports one world through its live grant and signs the result.
    pub fn export_connect_window_as(
        manager: &Arc<WindowManager>,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        request: ConnectExportRequest,
    ) -> Result<ConnectDelivery> {
        let vault = manager.vault();
        let (local, state) = active(vault, owner, &id(&request.pact)?)?;
        let local_world = crate::entity_id::LocalWorldId::try_from(request.world_ref)?;
        let grant = grant(vault, state.grant_ref)?;
        let selector = SyncSelector::new(
            state.grant_ref,
            grant.member_ref,
            SyncSelectorWorld::World(local_world),
            request.facets.clone(),
            request.bands.clone(),
        );
        let key = crate::sync::WindowKey::try_new(&request.window_key).ok_or_else(refused)?;
        if key.world().is_some_and(|world| world != request.world_ref) {
            return Err(refused());
        }
        let window = manager.open_window(&key)?;
        let envelope = crate::sync::selector::guest_share_envelope_body(
            vault,
            &window.doc,
            &key,
            grant.scope,
            &selector,
        )?;
        let body = ConnectWindow {
            pact: request.pact,
            epoch: state.pact_epoch,
            source_vault: crate::entity_id::bytes_to_hex_lower(&local),
            recipient_vault: crate::entity_id::bytes_to_hex_lower(&state.peer_vault_id),
            world_ref: request.world_ref,
            facets: request.facets,
            bands: request.bands,
            window_key: request.window_key,
            update: envelope.update,
        };
        Ok(ConnectDelivery {
            signature: issuer.sign_connect_window(&body)?,
            body,
        })
    }

    /// Rejoins the recipient's intact vault, verifying the peer host before the
    /// production guest import remaps, grades and attributes its actual bytes.
    pub fn rejoin_connect_as(
        manager: &Arc<WindowManager>,
        owner: &AuthenticatedOwner,
        delivery: ConnectDelivery,
    ) -> Result<ConnectRejoined> {
        let (joined, burst) = Self::rejoin_connect_with_burst_as(manager, owner, delivery)?;
        if burst.state == crate::sync::federation_burst::FederationBurstWorkState::Rejected {
            return Err(Error::InvalidConfig(
                "the owner rejected this federation batch".into(),
            ));
        }
        Ok(joined)
    }

    /// The same signed Connect ingress, returning its typed burst receipt.
    pub fn rejoin_connect_with_burst_as(
        manager: &Arc<WindowManager>,
        owner: &AuthenticatedOwner,
        delivery: ConnectDelivery,
    ) -> Result<(
        ConnectRejoined,
        crate::sync::federation_burst::FederationBurstReceipt,
    )> {
        let vault = manager.vault();
        let body = delivery.body;
        let pact_id = id(&body.pact)?;
        let (local, state) = active(vault, owner, &pact_id)?;
        if id(&body.source_vault)? != state.peer_vault_id
            || id(&body.recipient_vault)? != local
            || body.epoch != state.pact_epoch
        {
            return Err(refused());
        }
        let signature = AuthoritySignature {
            suite: state.peer_owner_key.suite(),
            public_key: state.peer_owner_key.clone(),
            signature: crate::deletion::parse_hex::<64>(&delivery.signature)
                .ok_or_else(refused)?
                .to_vec(),
        };
        if !verify_authority_signature(&signature, &body.transcript()?) {
            return Err(refused());
        }
        let inbound = if local <= state.peer_vault_id {
            &state.pact_scope.hi_to_lo
        } else {
            &state.pact_scope.lo_to_hi
        };
        let requested = FederationDirectionScope {
            worlds: ScopeAxis::Some([ScopeId(body.world_ref)].into()),
            facets: if body.facets.is_empty() {
                inbound.facets.clone()
            } else {
                body.facets.iter().copied().map(ScopeId).collect()
            },
            bands: if body.bands.is_empty() {
                inbound.bands.clone()
            } else {
                body.bands.iter().copied().collect()
            },
        };
        requested.validate()?;
        if !Position::new(requested).is_narrowing_of(&Ceiling::new(inbound.clone())) {
            return Err(refused());
        }
        // The principal is authenticated by the pinned peer-host signature,
        // then resolved from the local grant, never from a caller's actor field.
        let grant = grant(vault, state.grant_ref)?;
        let ScopeAxis::Some(worlds) = &state.effective_scope.worlds else {
            return Err(refused());
        };
        let world = worlds.first().ok_or_else(refused)?.0;
        let selector = SyncSelector::new(
            state.grant_ref,
            grant.member_ref,
            SyncSelectorWorld::World(crate::entity_id::LocalWorldId::try_from(world)?),
            Vec::new(),
            Vec::new(),
        );
        let peer = FederationPeer::authorize(vault, grant.member_ref, grant.scope, &selector)?
            .with_owner(vault, owner)?;
        // Constructing this one call must not drain another pending delivery.
        let (mut client, _events) =
            SyncClient::new(Arc::clone(manager), SyncClientConfig::default())?;
        client.config.federation_peer = Some(peer);
        let burst = client
            .import_federated_window_update_with_disposition(
                &body.window_key,
                &body.update,
                FederationAdmissionRole::Guest,
            )
            .map_err(|error| match error {
                crate::sync::TransportError::AdmissionDenied(denial) => {
                    crate::error::GateError::GateWriteRejected {
                        outcome: denial.outcome().as_str(),
                        reason_codes: denial
                            .reason_codes()
                            .iter()
                            .map(|reason| reason.as_str())
                            .collect(),
                    }
                    .into()
                }
                other => Error::InvalidConfig(other.to_string()),
            })?;
        let request = (burst.state
            == crate::sync::federation_burst::FederationBurstWorkState::Pending)
            .then(|| burst.batch_ref.clone());
        let foreign = crate::federation::pact_foreign_world(
            &vault.authority_fold()?,
            &pact_id,
            body.world_ref,
        )?
        .ok_or_else(refused)?
        .entity_id();
        Ok((
            ConnectRejoined {
                pact: body.pact,
                epoch: body.epoch,
                world_ref: foreign,
                status: if request.is_some() {
                    ConnectRejoinStatus::Deferred
                } else {
                    ConnectRejoinStatus::Imported
                },
                request,
            },
            burst,
        ))
    }
}
