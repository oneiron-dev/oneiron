//! The new home's doors for a home handoff (FIX 5661 C2a): the target end of
//! `residence.home_handoff.status`, `.part` and `.commit` on the residence
//! RPC lane. Only a machine of the owner's that proved itself on its socket
//! is heard, and a commit lands only when the sealed handoff names that
//! machine as its source; the target is this node, as its own machine and
//! node. Status reads the durable staged position or the saved ack. A part
//! stores durable progress: the same part again resumes, other bytes
//! conflict. A commit joins the staged parts, checks them against the digest
//! it names, opens and verifies the whole manifest, and adopts every
//! registered table in one transaction, answering the saved ack; nothing
//! partial lands. Sealed bytes and signed acks only: the carrier's tables
//! and keys stay behind these doors.

use super::bundle::denied;
use crate::Vault;
use crate::authority::PeerMachine;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::sync::home_handoff::{self, AdoptOutcome, HOME_HANDOFF_PART_BYTES, HomeAck};

/// Where one home handoff stands on this node as its target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeHandoffStanding {
    /// Not adopted here: how many of its parts are staged, in order from the
    /// first.
    Staged { parts: u32 },
    /// Adopted here: the ack this node signed, as named MessagePack.
    Adopted { ack: Vec<u8> },
}

/// Admits a machine of the owner's, as its socket proved it, and names it.
fn owner_machine(vault: &Vault, peer: PeerMachine) -> Result<EntityId> {
    let PeerMachine::Proven { machine, key } = peer else {
        return Err(denied());
    };
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_fold_readonly_in_txn(&txn)?;
    fold.trusted_machine(machine)
        .filter(|_| fold.machine_proof_key(machine) == Some(key))
        .map(|_| machine)
        .ok_or_else(denied)
}

/// The saved ack, when it is the one for these sealed bytes.
fn saved_ack(ack: &HomeAck, digest: &[u8; 32]) -> Result<Vec<u8>> {
    if ack.digest != *digest {
        return Err(denied());
    }
    home_handoff::encode_ack(ack)
}

/// Where handoff `id`, sealed to the bytes `digest` names, stands here.
///
/// # Errors
///
/// A refused peer; an adopted handoff with other bytes; a handoff this node
/// froze; storage errors.
pub fn home_handoff_status(
    vault: &Vault,
    peer: PeerMachine,
    id: [u8; 32],
    digest: [u8; 32],
) -> Result<HomeHandoffStanding> {
    owner_machine(vault, peer)?;
    if let Some(ack) = home_handoff::target_receipt(vault, &id)? {
        return Ok(HomeHandoffStanding::Adopted {
            ack: saved_ack(&ack, &digest)?,
        });
    }
    Ok(HomeHandoffStanding::Staged {
        parts: home_handoff::staged_position(vault, &id)?,
    })
}

/// Stages part `index` of `count` of handoff `id`; returns the staged
/// position after it. A handoff adopted here already answers `count`.
///
/// # Errors
///
/// A refused peer; an empty or oversized part, or an index past `count`; a
/// part past the staged position, or other bytes than the part staged; an
/// adopted handoff with other bytes; storage errors.
pub fn home_handoff_part(
    vault: &Vault,
    peer: PeerMachine,
    id: [u8; 32],
    digest: [u8; 32],
    index: u32,
    count: u32,
    part: &[u8],
) -> Result<u32> {
    owner_machine(vault, peer)?;
    if part.is_empty() || part.len() > HOME_HANDOFF_PART_BYTES || index >= count {
        return Err(denied());
    }
    if let Some(ack) = home_handoff::target_receipt(vault, &id)? {
        saved_ack(&ack, &digest)?;
        return Ok(count);
    }
    home_handoff::stage_part(vault, &id, index, part)
}

/// Commits handoff `id`: its staged parts, joined, must be the bytes
/// `digest` names and open here as a handoff from the calling machine; every
/// registered table then adopts in one transaction. Returns the ack this
/// node signed and saved, as named MessagePack; a commit sent again after a
/// lost reply answers the same ack.
///
/// # Errors
///
/// A refused peer; staged bytes other than the ones the commit names, or a
/// handoff that does not open or verify here or names another source; a
/// move this node does not adopt now (not yet its home, stale, or in
/// conflict with rows here); storage errors.
pub fn home_handoff_commit(
    vault: &Vault,
    peer: PeerMachine,
    id: [u8; 32],
    digest: [u8; 32],
) -> Result<Vec<u8>> {
    let source = owner_machine(vault, peer)?;
    if let Some(ack) = home_handoff::target_receipt(vault, &id)? {
        return saved_ack(&ack, &digest);
    }
    let sealed = home_handoff::staged_sealed(vault, &id)?;
    if *blake3::hash(&sealed).as_bytes() != digest {
        return Err(denied());
    }
    let verified = home_handoff::open_handoff(vault, id, &sealed)?;
    if verified.movement().source.machine != source {
        return Err(denied());
    }
    let ack = match home_handoff::adopt(vault, verified, &home_handoff::home_tables())? {
        AdoptOutcome::Adopted(ack) | AdoptOutcome::AlreadyAdopted(ack) => ack,
        AdoptOutcome::Pending | AdoptOutcome::Stale | AdoptOutcome::Conflict => {
            return Err(denied());
        }
    };
    // The receipt stands for the staged parts now.
    if let Err(error) = home_handoff::drop_staged(vault, &id) {
        tracing::debug!(kind = ?error.kind(), "an adopted home handoff kept its staged parts");
    }
    home_handoff::encode_ack(&ack)
}
