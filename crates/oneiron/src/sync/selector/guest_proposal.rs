//! A Connect guest's proposals (FIX 3684; L02 04:5x): the guest's `propose`
//! door, beside its document fetch, and the owner's review of the inbox.
//!
//! A guest's proposal never writes the vault. It is the write of one
//! record's text a peer's document frame would carry, which document
//! admission refuses a guest. Here it is judged as that write is, against
//! the guest's live grant and its own credential with `propose` in place of
//! `write`, in the writer that lands one row in the pact's inbox
//! (`federation::connect_proposal`); a record outside what the grant could
//! write is refused as that write is. The owner lists the pending
//! proposals, accepts one, which joins its update to the record's text as
//! the owner's own act in one writer, or rejects one, which writes nothing.

use std::sync::Arc;

use crate::authority::VerifiedSlip;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, LocalWorldId};
use crate::federation::decode_federation_grant_body;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::sync::{SyncSelector, SyncSelectorWorld, WindowManager};
use crate::task_verb::sdk::{
    ConnectProposal, ConnectProposalLanded, ConnectProposalRef, ConnectProposeRequest,
};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{Error, Result, Vault};

/// Today's typed refusal of a peer's document write.
fn denied() -> Error {
    Error::sync_protocol(crate::error::SyncProtocolValidation::DocumentAdmissionDenied)
}

/// A Connect guest proposes one write of a record's text under `proof`, its
/// own live grant-bound credential, over HTTP or the held socket's verb RPC.
/// The credential, the grant, the record's selection under it and the
/// inbox's bound are all read in the writer that lands the proposal.
pub fn propose_as_connect_guest(
    vault: &Vault,
    proof: &VerifiedSlip,
    input: &ConnectProposeRequest,
) -> Result<ConnectProposalLanded> {
    let claims = proof.claims();
    let entity = input.entity_ref.to_hex();
    if claims.grant_ref.as_deref() != Some(input.grant_ref.to_hex().as_str())
        || proof.is_transferred()
        || !claims.channels.is_empty()
        || !(claims.records.is_empty() || claims.records.contains(&entity))
    {
        return Err(denied());
    }
    let world = LocalWorldId::try_from(input.world_ref).map_err(|_| denied())?;
    vault.with_write_txn_grouped(|txn| {
        if !vault.capability_slip_is_live_in_txn(txn, proof)? {
            return Err(denied());
        }
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&vault.store, txn, &input.grant_ref)?
        else {
            return Err(denied());
        };
        let grant = decode_federation_grant_body(&body)?;
        let selector = SyncSelector::new(
            input.grant_ref,
            grant.member_ref,
            SyncSelectorWorld::World(world),
            Vec::new(),
            Vec::new(),
        );
        super::document_admission::admit_document_proposal_in_txn(
            vault,
            txn,
            input.entity_ref,
            grant.scope,
            &selector,
            proof,
        )?;
        crate::federation::land_connect_proposal_in_txn(
            vault,
            txn,
            input.grant_ref,
            grant.member_ref,
            input.world_ref,
            input.entity_ref,
            &input.update,
        )
    })
}

/// Every pending proposal Connect guests sent this vault, for the owner,
/// each with its record's text as accepting it would leave it.
pub fn connect_proposals_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> Result<Vec<ConnectProposal>> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    crate::federation::pending_connect_proposals_in_txn(vault, &txn, |entity, update| {
        preview_in_txn(vault, &txn, entity, update)
    })
}

/// `entity`'s text with `update` joined, read in `txn`: `None` when it holds
/// no text here yet or the update does not join cleanly.
fn preview_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: EntityId,
    update: &[u8],
) -> Option<String> {
    let text = crate::entity_doc::sync_text_in(vault, txn, &entity).ok()??;
    let doc = text.doc.fork();
    crate::sync::documents::storage::import_complete(&doc, update).ok()?;
    Some(doc.get_text("body").to_string())
}

/// The owner accepts a pending proposal: its update joins the record's text
/// as the owner's own act, and the proposal's record names the proposer,
/// its grant, and whether that grant still stood; the accept applies either
/// way. The decision and the join commit in one writer, so a revoke that
/// lands first leaves nothing to accept.
pub fn accept_connect_proposal_as_owner(
    manager: &Arc<WindowManager>,
    owner: &AuthenticatedOwner,
    input: &ConnectProposalRef,
) -> Result<ConnectProposal> {
    let vault = manager.vault();
    let (entity, update) = {
        let txn = vault.store.env.read_txn()?;
        owner.revalidate_in_txn(vault, &txn)?;
        crate::federation::pending_connect_proposal_in_txn(
            vault,
            &txn,
            input.grant_ref,
            input.proposal_ref,
        )?
    };
    let document = manager.documents().open(entity)?;
    let mut settled = None;
    document.import_accepted_proposal(&update, |txn| {
        let by = owner.revalidate_in_txn(vault, txn)?;
        settled = Some(crate::federation::settle_connect_proposal_in_txn(
            vault,
            txn,
            input.grant_ref,
            input.proposal_ref,
            by,
            true,
        )?);
        Ok(())
    })?;
    settled.ok_or(Error::InvariantViolation(
        "an accepted Connect proposal settled no row",
    ))
}

/// The owner rejects a pending proposal: nothing is written to the vault,
/// and the proposal's record names the proposer and its grant.
pub fn reject_connect_proposal_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &ConnectProposalRef,
) -> Result<ConnectProposal> {
    vault.with_write_txn_grouped(|txn| {
        let by = owner.revalidate_in_txn(vault, txn)?;
        crate::federation::settle_connect_proposal_in_txn(
            vault,
            txn,
            input.grant_ref,
            input.proposal_ref,
            by,
            false,
        )
    })
}
