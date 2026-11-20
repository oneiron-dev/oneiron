//! The shared guest-document export door: owner sharing and recipient fetching.
use std::sync::Arc;

use crate::authority::{GuestDocumentContext, GuestDocumentEnvelope};
use crate::authority::{HostSlipIssuer, VerifiedSlip};
use crate::claim::CallerLocality;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, LocalWorldId, bytes_to_hex_lower};
use crate::federation::{
    FederationGrant, FederationGrantScope, ScopeId, decode_federation_grant_body,
};
pub use crate::guest_document_share::GuestDocumentShareRequest;
use crate::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_WORLD};
use crate::sync::{SyncSelector, SyncSelectorWorld, WindowKey, WindowManager};
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
    let grant = guest_connect_grant_in(vault, &txn, &input.grant_ref)?;
    if input.world_ref == crate::claim::base_world_id()
        || LocalWorldId::try_from(input.world_ref).is_err()
        || !grant
            .authority_scope
            .worlds
            .contains(&ScopeId(input.world_ref))
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

/// The live guest grant `grant_ref` names, under Connect scope and
/// conferring now; a missing row is not found and any other grant refuses.
fn guest_connect_grant_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant_ref: &EntityId,
) -> Result<FederationGrant> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_FEDERATION_GRANT,
        body,
    } = live_entity_row_in_txn(&vault.store, txn, grant_ref)?
    else {
        return Err(Error::EntityNotFound);
    };
    let grant = decode_federation_grant_body(&body)?;
    if !grant.role.is_guest()
        || !matches!(grant.scope, FederationGrantScope::Connect { .. })
        || !grant.confers_at(vault.store.clock.now_recorded_at())
    {
        return Err(refused());
    }
    Ok(grant)
}

/// Whether `proof` is a live, untransferred read credential its member
/// holds for the guest grant `grant_ref` names, bound to no channel.
fn holds_guest_grant(
    vault: &Vault,
    proof: &VerifiedSlip,
    grant_ref: &EntityId,
    grant: &FederationGrant,
) -> Result<bool> {
    Ok(
        proof.claims().grant_ref.as_deref() == Some(grant_ref.to_hex().as_str())
            && proof.claims().holder_ref == grant.member_ref.to_hex()
            && !proof.is_transferred()
            && proof.allows_verb("read")
            && proof.claims().channels.is_empty()
            && vault.capability_slip_is_live(proof)?,
    )
}

/// The read key the recipient's fetch judges its rows with: the credential's
/// own key, its conversation home cleared up to the Connect grant's ceiling
/// (ANSWER FED-CONNECT-STAMPED-HOME = A), every other check it makes kept.
fn guest_fetch_read_key(
    vault: &Vault,
    proof: &VerifiedSlip,
    grant: &FederationGrant,
) -> Result<crate::claim::ScopedReadActorKey> {
    Ok(vault
        .credential_read_key(proof)?
        .ok_or_else(refused)?
        .home_cleared_to_connect_ceiling(grant.authority_scope.sensitivity))
}

fn export(
    manager: &Arc<WindowManager>,
    issuer: &HostSlipIssuer,
    input: &GuestDocumentShareRequest,
    admit: impl Fn(&Vault, &FederationGrant) -> Result<EntityId>,
    readable: impl Fn(&Vault, &FederationGrant, &[EntityId]) -> Result<bool>,
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
    let (body, rows, travelled) = super::codec::guest_share_envelope_body_listing(
        vault,
        &window.doc,
        &key,
        grant.scope,
        &selector,
    )?;
    // A narrower credential never exports bytes around its own read lane.
    // If any selected row is withheld for this caller, the whole export refuses.
    if !readable(vault, &grant, &rows)? {
        return Err(refused());
    }
    let (current, after) = context(vault, input)?;
    let by = admit(vault, &current)?;
    if current != grant || before != after {
        return Err(refused());
    }
    let mut envelope = issuer.sign_guest_document_envelope(after, body)?;
    envelope.travel_receipt = Some(vault.record_guest_window_travel(
        &input.grant_ref,
        &current.member_ref,
        current.scope,
        key.as_str(),
        &input.world_ref,
        &rows,
        &envelope.envelope.body.update,
        &by,
        travelled,
    ));
    Ok((envelope, rows))
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
        |vault, _| {
            vault.recheck_owner(owner)?;
            owner.actor_for_read(vault)
        },
        |_, _, _| Ok(true),
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
            if !holds_guest_grant(vault, proof, &input.grant_ref, grant)? {
                return Err(refused());
            }
            Ok(grant.member_ref)
        },
        |vault, grant, rows| {
            // The fetch reads what the export selected under this Connect
            // grant: its stamped claims up to the grant's own ceiling, which
            // the credential's conversation home alone would withhold,
            // refusing the fetch.
            let key = guest_fetch_read_key(vault, proof, grant)?;
            vault.scoped_read(key.at(locality)).all_refs_readable(rows)
        },
    )
}

/// The recipient's fetch answered again (an HTTP invocation replay, FIX
/// 8212): whether `proof` still reads every one of `rows`, the rows its
/// first answer listed, through the fetch's own check
/// ([`export_guest_document_for_guest`]). The grant its credential names
/// must still be a live Connect guest grant its pact admits and the
/// credential holds, and the fetch's read key, met with `destination`, must
/// read each row. Anything else, a fault included, reads nothing: the
/// replay then keeps its details on the device.
pub fn guest_document_rows_still_readable(
    vault: &Vault,
    proof: &VerifiedSlip,
    destination: &crate::settings::ReadDestination,
    rows: &[EntityId],
) -> bool {
    let readable = || -> Result<bool> {
        let Some(grant_ref) = proof
            .claims()
            .grant_ref
            .as_deref()
            .and_then(|grant_ref| EntityId::from_hex(grant_ref).ok())
        else {
            return Ok(false);
        };
        let grant = {
            let txn = vault.store.env.read_txn()?;
            let grant = guest_connect_grant_in(vault, &txn, &grant_ref)?;
            let fold = vault.authority_fold_readonly_in_txn(&txn)?;
            if !crate::federation::pact_admits_grant(&fold, &grant_ref, &grant) {
                return Ok(false);
            }
            grant
        };
        if !holds_guest_grant(vault, proof, &grant_ref, &grant)? {
            return Ok(false);
        }
        let key = guest_fetch_read_key(vault, proof, &grant)?;
        vault
            .scoped_read(key.for_destination(destination))
            .all_refs_readable(rows)
    };
    readable().unwrap_or(false)
}
