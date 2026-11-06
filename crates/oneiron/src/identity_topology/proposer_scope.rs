//! The proposer axis of the ARCH-0055 r7 ramp scope (FIX 9870 + FIX 10189):
//! op kind x target class x the proposing skill or agent.
//!
//! A decision's core is actorless, and its author lives only in an erasable
//! carrier, so the scope never names an actor ref. Each proposing actor gets
//! one opaque random handle on this vault, kept in a local actor-to-handle
//! map that never replicates. A merge or split proposal's seal signs the
//! handle (admission v4), and its resolution copies it into the scope its
//! receipts and ramp counters group by. Erasing the actor drops only the map
//! row: the signed handle stays, names no one, and its outcomes stay apart
//! from unknown authors'. A seal signed before v4 binds no handle, and its
//! proposal reads unattributed.

use std::fmt::Write as _;

use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::store::Store;
use crate::vault::Vault;

use super::admission_disposition::{SealTrust, trusted_proposer_scope_for_store_in_txn};
use super::stored_event::StoredIdentityOpEvent;
use super::transition_table::ProposalScope;
use super::wire_keys::PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED;

/// The spelling every handle starts with; 64 lowercase hex digits follow.
const HANDLE_PREFIX: &str = "proposer:";

/// Each proposing actor's handle on this vault: 32 random bytes. Local and
/// erasable; never replicated, never restored from an image. Key: hex32
/// (actor entity id).
const PROPOSER_SCOPE: SideTable<HexId, [u8; 32], Raw> =
    SideTable::new(&side_table::IDENTITY_TOPOLOGY_PROPOSER_SCOPE);

/// `actor`'s handle, minted at its first proposal and reused after.
///
/// # Errors
/// A store failure.
pub(super) fn handle_for_actor_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    actor: EntityId,
) -> Result<String> {
    let key = HexId(actor);
    let token = match PROPOSER_SCOPE.get(store, wtxn, &key)? {
        Some(token) => token,
        None => {
            use rand_core::{OsRng, RngCore};
            let mut token = [0; 32];
            OsRng.fill_bytes(&mut token);
            PROPOSER_SCOPE.put(store, wtxn, &key, &token)?;
            token
        }
    };
    let mut handle = String::with_capacity(HANDLE_PREFIX.len() + 64);
    handle.push_str(HANDLE_PREFIX);
    for byte in token {
        let _ = write!(handle, "{byte:02x}");
    }
    Ok(handle)
}

/// Forgets `actor`'s handle, in the erasure writer: the handle its signed
/// proposals and resolutions hold no longer resolves to anyone.
///
/// # Errors
/// A store failure.
pub(super) fn forget_actor_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    actor: EntityId,
) -> Result<()> {
    PROPOSER_SCOPE.delete(store, wtxn, &HexId(actor))?;
    Ok(())
}

/// Whether `actor` is a scope's proposer in its one spelling: a handle, or
/// the unattributed scope.
pub(super) fn is_scope_actor_spelling(actor: &str) -> bool {
    actor == PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED
        || actor.strip_prefix(HANDLE_PREFIX).is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// The one scope derivation every reader shares: the proposal's action
/// kind, the registry class of its primary target, and `actor`, the handle
/// the caller's authority names. It never reads the core's actor.
pub(super) fn derive_proposal_scope(
    record: &StoredIdentityOpEvent,
    target_class: &str,
    actor: &str,
) -> ProposalScope {
    ProposalScope {
        op_kind: record.action.kind_str(),
        target_class: target_class.to_owned(),
        actor: actor.to_owned(),
    }
}

/// The handle a resolution settled here stamps for `proposal`, its core
/// `record`: the one its validated seal binds, when a seal this vault counts
/// binds one; else this vault's own handle for the author its own carrier
/// names; else unattributed. A peer's unsigned carrier never names one.
///
/// # Errors
/// A store failure, a seal that does not verify, or conflicting handles.
pub(super) fn settled_proposer_scope_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    proposal: EntityId,
    record: &StoredIdentityOpEvent,
) -> Result<String> {
    let mut trust = SealTrust::default();
    if let Some(actor) =
        trusted_proposer_scope_for_store_in_txn(&vault.store, wtxn, &proposal, record, &mut trust)?
    {
        return Ok(actor);
    }
    match super::admitted_author_in_txn(&vault.store, wtxn, proposal)? {
        Some(author) => handle_for_actor_in_txn(&vault.store, wtxn, author.entity_ref()),
        None => Ok(PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED.to_owned()),
    }
}

/// The handle a proposal written now signs in its seal: `actor`'s, or
/// unattributed for a proposal no actor wrote.
///
/// # Errors
/// A store failure.
pub(super) fn proposal_seal_scope_actor_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    actor: Option<EntityId>,
) -> Result<String> {
    match actor {
        Some(actor) => handle_for_actor_in_txn(store, wtxn, actor),
        None => Ok(PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED.to_owned()),
    }
}
