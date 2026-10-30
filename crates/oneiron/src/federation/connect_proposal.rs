//! A Connect pact's proposal inbox (FIX 3684; L02 04:5x): where a Connect
//! guest's `propose` lands, since a guest never writes the vault.
//!
//! One row per proposal, keyed by the guest's Connect grant: a grant
//! confers through exactly one Active pact, so a grant's rows are its pact's
//! inbox. A row holds the proposer (the grant's guest actor), the world and
//! record it names, and the text update as the guest sent it, until the
//! owner decides. Past [`CONNECT_PROPOSALS_PER_PACT`] pending rows, or
//! [`CONNECT_PROPOSAL_BYTES_PER_PACT`] pending update bytes, the guest is
//! told so, typed, and nothing is dropped.
//!
//! The owner's accept or reject is the row's decision: it keeps who decided,
//! when, and whether the guest's grant still stood at an accept, and drops
//! the update's bytes, keeping their length and BLAKE3. A decided row stays
//! as the owner's record. The rows are this host's own and ride no carrier,
//! so they never leave it. Revoking the guest drops its grant's pending
//! rows; erasing the guest actor drops every row that names it.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
#[cfg(feature = "sync")]
use crate::task_verb::sdk::{ConnectProposal, ConnectProposalDecision, ConnectProposalLanded};

/// Pending proposals one Connect pact's inbox holds (L02 04:5x).
#[cfg(feature = "sync")]
const CONNECT_PROPOSALS_PER_PACT: usize = 256;

/// Pending update bytes one Connect pact's inbox holds, together (L02 04:5x).
#[cfg(feature = "sync")]
const CONNECT_PROPOSAL_BYTES_PER_PACT: usize = 16 * 1024 * 1024;

/// Key: id16(grant) + id16(proposal).
const PROPOSALS: SideTable<(EntityId, EntityId), ProposalRow, Named> =
    SideTable::new(&side_table::FEDERATION_CONNECT_PROPOSAL);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposalRow {
    proposer: EntityId,
    world: EntityId,
    entity: EntityId,
    proposed_at: u64,
    update_len: u64,
    /// BLAKE3 of the update, 64 hex.
    update_digest: String,
    /// The update as the guest sent it; empty once decided.
    update: Vec<u8>,
    decision: Option<Decision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    accepted: bool,
    by: EntityId,
    at: u64,
    grant_lapsed: bool,
}

#[cfg(feature = "sync")]
fn view(
    (grant, proposal): (EntityId, EntityId),
    row: ProposalRow,
    preview: Option<String>,
) -> ConnectProposal {
    ConnectProposal {
        proposal_ref: proposal,
        grant_ref: grant,
        proposer_ref: row.proposer,
        world_ref: row.world,
        entity_ref: row.entity,
        proposed_at: row.proposed_at,
        update_len: row.update_len,
        update_digest: row.update_digest,
        preview,
        decision: row.decision.map(|decision| ConnectProposalDecision {
            accepted: decision.accepted,
            by: decision.by,
            at: decision.at,
            grant_lapsed: decision.grant_lapsed,
        }),
    }
}

/// Lands one proposal in `grant`'s inbox, in the caller's writer, which has
/// judged it against the guest's live grant. Past the inbox's bound it is
/// refused, naming the bound; nothing already there is dropped.
#[cfg(feature = "sync")]
pub(crate) fn land_connect_proposal_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    grant: EntityId,
    proposer: EntityId,
    world: EntityId,
    entity: EntityId,
    update: &[u8],
) -> Result<ConnectProposalLanded> {
    let (mut pending, mut bytes) = (0_usize, 0_usize);
    for row in PROPOSALS.iter_from(&vault.store, txn, grant.as_bytes())? {
        let (_, row) = row?;
        if row.decision.is_none() {
            pending += 1;
            bytes = bytes.saturating_add(row.update.len());
        }
    }
    if pending >= CONNECT_PROPOSALS_PER_PACT
        || bytes.saturating_add(update.len()) > CONNECT_PROPOSAL_BYTES_PER_PACT
    {
        return Err(crate::Error::Refused(format!(
            "this Connect's proposal inbox is full: it holds {pending} pending proposals of \
             {CONNECT_PROPOSALS_PER_PACT} and {bytes} pending update bytes of \
             {CONNECT_PROPOSAL_BYTES_PER_PACT}; propose again once the owner has decided some"
        )));
    }
    let proposal = vault.store.clock.entity_id()?;
    let proposed_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let row = ProposalRow {
        proposer,
        world,
        entity,
        proposed_at,
        update_len: u64::try_from(update.len()).unwrap_or(u64::MAX),
        update_digest: blake3::hash(update).to_hex().to_string(),
        update: update.to_vec(),
        decision: None,
    };
    PROPOSALS.put(&vault.store, txn, &(grant, proposal), &row)?;
    Ok(ConnectProposalLanded {
        proposal_ref: proposal,
        grant_ref: grant,
        entity_ref: entity,
        proposed_at,
    })
}

/// The record a pending proposal names and its update, read in `txn`; not
/// found when it is decided or gone.
#[cfg(feature = "sync")]
pub(crate) fn pending_connect_proposal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant: EntityId,
    proposal: EntityId,
) -> Result<(EntityId, Vec<u8>)> {
    match PROPOSALS.get(&vault.store, txn, &(grant, proposal))? {
        Some(row) if row.decision.is_none() => Ok((row.entity, row.update)),
        _ => Err(crate::Error::EntityNotFound),
    }
}

/// Every pending proposal, read in `txn`, each with `preview`'s text for its
/// record and update.
#[cfg(feature = "sync")]
pub(crate) fn pending_connect_proposals_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    preview: impl Fn(EntityId, &[u8]) -> Option<String>,
) -> Result<Vec<ConnectProposal>> {
    let mut pending = Vec::new();
    for row in PROPOSALS.iter_from(&vault.store, txn, &[])? {
        let (key, row) = row?;
        if row.decision.is_none() {
            let text = preview(row.entity, &row.update);
            pending.push(view(key, row, text));
        }
    }
    Ok(pending)
}

/// The owner's decision on a pending proposal, in the caller's writer: `by`
/// accepted or rejected it now. An accept records whether the guest's grant
/// still stood; the accept stands either way. Not found when the proposal is
/// decided or gone.
#[cfg(feature = "sync")]
pub(crate) fn settle_connect_proposal_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    grant: EntityId,
    proposal: EntityId,
    by: EntityId,
    accepted: bool,
) -> Result<ConnectProposal> {
    let key = (grant, proposal);
    let mut row = PROPOSALS
        .get(&vault.store, txn, &key)?
        .filter(|row| row.decision.is_none())
        .ok_or(crate::Error::EntityNotFound)?;
    let grant_lapsed =
        accepted && !super::connect_grant_stands_in_txn(vault, txn, &grant, &row.proposer)?;
    row.decision = Some(Decision {
        accepted,
        by,
        at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
        grant_lapsed,
    });
    row.update = Vec::new();
    PROPOSALS.put(&vault.store, txn, &key, &row)?;
    Ok(view(key, row, None))
}

/// Drops `grant`'s pending proposals in the caller's writer: revoking the
/// guest takes them (L02 04:5x). Decided ones stay as the owner's record.
pub(crate) fn drop_pending_connect_proposals_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    grant: &EntityId,
) -> Result<()> {
    let mut pending = Vec::new();
    for row in PROPOSALS.iter_from(&vault.store, txn, grant.as_bytes())? {
        let (key, row) = row?;
        if row.decision.is_none() {
            pending.push(key);
        }
    }
    for key in &pending {
        PROPOSALS.delete(&vault.store, txn, key)?;
    }
    Ok(())
}

/// The inbox's actor scrub (FIX 3520): an erased actor's proposals, and the
/// decisions it made, leave with it.
pub(crate) fn erase_connect_proposer_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let mut named = Vec::new();
    for row in PROPOSALS.iter_from(&vault.store, txn, &[])? {
        let (key, row) = row?;
        if row.proposer == *actor || row.decision.is_some_and(|decision| decision.by == *actor) {
            named.push(key);
        }
    }
    for key in &named {
        PROPOSALS.delete(&vault.store, txn, key)?;
    }
    Ok(())
}
