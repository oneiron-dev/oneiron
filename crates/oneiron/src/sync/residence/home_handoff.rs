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
//!
//! FIX 5661 C2b: `.cancel` fences a handoff its source takes back (FIX
//! 5931), and the host's driver readies a new home before its first
//! free-time pass ([`prepare_home_handoff`]) and arms the free-time tries
//! this node admits, the old home's drain among them
//! ([`free_time_arming`]).

use std::collections::HashSet;

use super::bundle::denied;
use crate::Vault;
use crate::attempt_queue::AttemptId;
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

/// The free-time tries the host timer arms on this node (FIX 5661 C2b, FIX
/// 6212), each by the claim's own readiness, placement and the operator's
/// pauses, never by MACRO consolidation's bucket rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FreeTimeArming {
    /// Every free-time try this node's admission takes now; one that never
    /// started only while this node takes new free-time work.
    pub tries: HashSet<AttemptId>,
    /// The started ones this node drains as the home its election left,
    /// armed without the home gate so each runs to its own end here before
    /// the node freezes its state for the move.
    pub drain: HashSet<AttemptId>,
}

/// What this node answers its source's cancel of a home handoff (FIX 5931).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeHandoffCancel {
    /// Never adopted here, and fenced now: no commit lands it after.
    Fenced,
    /// Adopted here first, and it stays adopted: the ack this node signed,
    /// as named MessagePack.
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
    let source = owner_machine(vault, peer)?;
    if part.is_empty() || part.len() > HOME_HANDOFF_PART_BYTES || index >= count {
        return Err(denied());
    }
    if let Some(ack) = home_handoff::target_receipt(vault, &id)? {
        saved_ack(&ack, &digest)?;
        return Ok(count);
    }
    home_handoff::stage_part(vault, &id, &digest, count, source, index, part)
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

/// FIX 5931: cancels handoff `id`, sealed to the bytes `digest` names, at
/// its source's word, in the writer that adopts. Never adopted here, it is
/// fenced for good: its staged parts go and no commit lands it after.
/// Adopted here first, it stays adopted and the answer is the saved ack.
/// The source takes its state back only on [`HomeHandoffCancel::Fenced`].
///
/// # Errors
///
/// A refused peer; a handoff adopted here with other bytes, staged here by
/// another machine, or one this node froze; storage errors.
pub fn home_handoff_cancel(
    vault: &Vault,
    peer: PeerMachine,
    id: [u8; 32],
    digest: [u8; 32],
) -> Result<HomeHandoffCancel> {
    let source = owner_machine(vault, peer)?;
    Ok(
        match home_handoff::fence_handoff(vault, &id, &digest, source)? {
            Some(ack) => HomeHandoffCancel::Adopted {
                ack: home_handoff::encode_ack(&ack)?,
            },
            None => HomeHandoffCancel::Fenced,
        },
    )
}

/// FIX 5661 C2b (FIX 6211): readies this node as the vault's new MACRO home,
/// called by the host before its deadline read arms any free-time cadence
/// and before each wake pass. While this node's own election names it home,
/// a handoff staged here in full adopts, with the commit door's checks; with
/// none that adopts, a move that came here records Incomplete, so its local
/// opening never travels as the lineage's state. Nothing waits or refuses:
/// today's opening goes on. Elsewhere, and once done, it writes nothing.
///
/// # Errors
///
/// Storage errors reading the carrier's head or recording the outcome.
pub fn prepare_home_handoff(vault: &Vault) -> Result<()> {
    home_handoff::prepare_arrival(vault)
}

/// FIX 5661 C2b (FIX 6212): the free-time tries the host timer arms on this
/// node ([`FreeTimeArming`]): every one its admission takes now, and the
/// started ones it drains as the home its election left, which run here to
/// their own end before it freezes its state for the move.
///
/// # Errors
///
/// Storage errors; a retry chain past its bound.
pub fn free_time_arming(vault: &Vault) -> Result<FreeTimeArming> {
    let (tries, drain) = home_handoff::free_time_arming(vault)?;
    Ok(FreeTimeArming { tries, drain })
}
