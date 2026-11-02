//! The residence home's door for the key custody of the owner's machines
//! (KS-4A2, FIX 5685): the residence target. A machine of the owner's that
//! proved itself on its socket reads what this home holds of its custody
//! lineage, ships the log frames the home lacks, stages its sealed head in
//! parts and commits it. The home switches its head in one step (never over
//! a newer position), removes every superseded head and stale stage, lists
//! the lineage again and persists its ack before it answers. Any other peer
//! is refused. Sealed bytes only: the home never opens a head or a frame.

use super::bundle::denied;
use crate::Vault;
use crate::authority::PeerMachine;
use crate::error::Result;
use crate::store::custody_protocol::{
    AckRecord, CustodyPosition, DrainAck, DrainTicket, Lineage, ResidenceCommit,
};

/// Admits a machine of the owner's, as its socket proved it.
fn owner_machine(vault: &Vault, peer: PeerMachine) -> Result<()> {
    let PeerMachine::Proven { machine, key } = peer else {
        return Err(denied());
    };
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_fold_readonly_in_txn(&txn)?;
    fold.trusted_machine(machine)
        .filter(|_| fold.machine_proof_key(machine) == Some(key))
        .map(|_| ())
        .ok_or_else(denied)
}

/// The position of the head this home holds of `lineage`, if any.
///
/// # Errors
///
/// A refused peer; storage errors.
pub fn custody_residence_held(
    vault: &Vault,
    peer: PeerMachine,
    lineage: Lineage,
) -> Result<Option<CustodyPosition>> {
    owner_machine(vault, peer)?;
    vault.store.residence_custody_held(lineage)
}

/// Keeps `frames` (log sequence number, sealed frame) of `lineage` here. A
/// frame the home holds already must be the same bytes.
///
/// # Errors
///
/// A refused peer; a frame of another lineage or sequence number, or other
/// bytes than the ones held; storage errors.
pub fn custody_residence_frames(
    vault: &Vault,
    peer: PeerMachine,
    lineage: Lineage,
    frames: &[(u64, Vec<u8>)],
) -> Result<()> {
    owner_machine(vault, peer)?;
    for (seq, frame) in frames {
        vault.store.residence_custody_frame(lineage, *seq, frame)?;
    }
    Ok(())
}

/// Stages one part of the head the operation `operation` publishes, at
/// `offset`; a part sent again after a lost reply is taken when its bytes
/// are there. Returns the stage's length.
///
/// # Errors
///
/// A refused peer; a part at another offset than the stage's end; storage
/// errors.
pub fn custody_residence_stage(
    vault: &Vault,
    peer: PeerMachine,
    lineage: Lineage,
    operation: [u8; 32],
    offset: u64,
    part: &[u8],
) -> Result<u64> {
    owner_machine(vault, peer)?;
    vault
        .store
        .residence_custody_stage(lineage, operation, offset, part)
}

/// Commits the staged head `commit` names and returns the ack this home
/// persisted for it, attested as this home's machine. A commit sent again
/// after a lost reply answers the same ack.
///
/// # Errors
///
/// A refused peer; a home with no machine id; staged bytes other than the
/// ones the commit names; a newer head here; storage errors.
pub fn custody_residence_commit(
    vault: &Vault,
    peer: PeerMachine,
    commit: &ResidenceCommit,
) -> Result<AckRecord> {
    owner_machine(vault, peer)?;
    let home = vault.local_machine()?.ok_or_else(denied)?.id;
    vault.store.residence_custody_commit(commit, home)
}

/// Drains the lineage `ticket` names and returns this home's sweep ack for
/// it, as `residence:<home hex>`. A drain sent again after a lost reply
/// answers the same ack.
///
/// # Errors
///
/// A refused peer; a home with no machine id; storage errors.
pub fn custody_residence_drain(
    vault: &Vault,
    peer: PeerMachine,
    ticket: &DrainTicket,
) -> Result<DrainAck> {
    owner_machine(vault, peer)?;
    let home = vault.local_machine()?.ok_or_else(denied)?.id;
    vault.store.residence_custody_drain(ticket, home)
}
