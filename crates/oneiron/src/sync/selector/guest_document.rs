//! The shared guest-document export door: owner sharing and recipient fetching.
use std::sync::Arc;

use crate::authority::{HostSlipIssuer, VerifiedSlip};
use crate::claim::CallerLocality;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, LocalWorldId, bytes_to_hex_lower};
use crate::federation::{
    FederationGrant, FederationGrantScope, ScopeId, decode_federation_grant_body,
};
use crate::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_WORLD};
use crate::sync::{SyncSelector, SyncSelectorWorld, WindowKey, WindowManager};
use crate::task_verb::sdk::{
    GuestDocumentContext, GuestDocumentEnvelope, GuestDocumentShareRequest,
};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{Error, Result, Vault};

fn refused() -> Error {
    crate::error::GateError::GateWriteRejected {
        outcome: "deny",
        reason_codes: vec!["guest_document_scope"],
    }
    .into()
}

/// Resolves a live guest's authority, never a member grant or an Ask disclosure.
fn context(
    vault: &Vault,
    input: &GuestDocumentShareRequest,
) -> Result<(FederationGrant, GuestDocumentContext)> {
    let txn = vault.store.env.read_txn()?;
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_FEDERATION_GRANT,
        body,
    } = live_entity_row_in_txn(&vault.store, &txn, &input.grant_ref)?
    else {
        return Err(Error::EntityNotFound);
    };
    let grant = decode_federation_grant_body(&body)?;
    if !grant.role.is_guest()
        || !matches!(grant.scope, FederationGrantScope::Connect { .. })
        || !grant.confers_at(vault.store.clock.now_recorded_at())
        || input.world_ref == crate::claim::base_world_id()
        || LocalWorldId::try_from(input.world_ref).is_err()
        || !grant.authority_scope.worlds.contains(&ScopeId(input.world_ref))
        || live_entity_row_in_txn(&vault.store, &txn, &input.world_ref)?.live_type()
            != Some(ENTITY_TYPE_WORLD)
    {
        return Err(refused());
    }
    let fold = vault.authority_fold_readonly_in_txn(&txn)?;
    if !crate::federation::pact_admits_grant(&fold, &input.grant_ref, &grant) {
        return Err(refused());
    }
    let (pact, epoch) = fold.active_pact_delivery_context(&input.grant_ref)?;
    // The six-axis grant remains the record ceiling. The effective pact overlay
    // is checked by the selector and carried in the signed disclosure as well.
    let state = fold.federation_pacts.get(&pact).ok_or_else(refused)?;
    let context = GuestDocumentContext {
        pact: bytes_to_hex_lower(&pact),
        epoch,
        ceiling: grant.authority_scope.clone(),
        effective_scope: state.effective_scope.clone(),
    };
    Ok((grant, context))
}

fn export(
    manager: &Arc<WindowManager>,
    issuer: &HostSlipIssuer,
    input: &GuestDocumentShareRequest,
    admit: impl Fn(&Vault, &FederationGrant) -> Result<()>,
    readable: impl Fn(&Vault, &[EntityId]) -> Result<bool>,
) -> Result<(GuestDocumentEnvelope, Vec<EntityId>)> {
    let vault = manager.vault();
    let (grant, before) = context(vault, input)?;
    admit(vault, &grant)?;
    let selector = SyncSelector::new(
        input.grant_ref,
        grant.member_ref,
        SyncSelectorWorld::World(LocalWorldId::try_from(input.world_ref)?),
        input.facets.clone(),
        input.bands.clone(),
    );
    // Refuse a bad selector before opening or creating its window.
    super::authorize_sync_selector(vault, grant.scope, &selector)?;
    let key = WindowKey::try_new(&input.window_key).ok_or_else(refused)?;
    if key.world().is_some_and(|world| world != input.world_ref) {
        return Err(refused());
    }
    let window = manager.open_window(&key)?;
    let (body, rows) = super::codec::guest_share_envelope_body_listing(
        vault,
        &window.doc,
        &key,
        grant.scope,
        &selector,
    )?;
    // A narrower credential never exports bytes around its own read lane.
    // If any selected row is withheld for this caller, the whole export refuses.
    if !readable(vault, &rows)? {
        return Err(refused());
    }
    let (current, after) = context(vault, input)?;
    admit(vault, &current)?;
    if current != grant || before != after {
        return Err(refused());
    }
    Ok((issuer.sign_guest_document_envelope(after, body)?, rows))
}

/// The owner's share and re-share paths use one local-world-only engine door.
/// A received foreign WORLD never becomes eligible by changing the recipient.
pub fn share_guest_document_as_owner(
    manager: &Arc<WindowManager>,
    owner: &AuthenticatedOwner,
    issuer: &HostSlipIssuer,
    input: &GuestDocumentShareRequest,
) -> Result<(GuestDocumentEnvelope, Vec<EntityId>)> {
    manager.vault().recheck_owner(owner)?;
    export(
        manager,
        issuer,
        input,
        |vault, _| vault.recheck_owner(owner),
        |_, _| Ok(true),
    )
}

/// The recipient fetches only the grant its own verified credential names.
/// HTTP and the held socket's verb RPC reach this same check and signed body.
pub fn export_guest_document_for_guest(
    manager: &Arc<WindowManager>,
    proof: &VerifiedSlip,
    locality: CallerLocality,
    issuer: &HostSlipIssuer,
    input: &GuestDocumentShareRequest,
) -> Result<(GuestDocumentEnvelope, Vec<EntityId>)> {
    export(
        manager,
        issuer,
        input,
        |vault, grant| {
            if proof.claims().grant_ref.as_deref() != Some(input.grant_ref.to_hex().as_str())
                || proof.claims().holder_ref != grant.member_ref.to_hex()
                || proof.is_transferred()
                || !proof.allows_verb("read")
                || !proof.claims().channels.is_empty()
                || !vault.capability_slip_is_live(proof)?
            {
                return Err(refused());
            }
            Ok(())
        },
        |vault, rows| {
            let key = vault.credential_read_key(proof)?.ok_or_else(refused)?;
            vault.scoped_read(key.at(locality)).all_refs_readable(rows)
        },
    )
}
