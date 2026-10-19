//! The home-state lineage (CALLS: home handoff lineage). Only the node that
//! holds the state advances the generation; a target admits a generation
//! only where it chains.

use heed::RoTxn;

use super::envelope::VerifiedHandoff;
use super::store::HandoffHead;
use super::{HomeGeneration, HomeMove, refused};
use crate::Vault;
use crate::error::Result;

/// The move starts at this install and node, names another as its target,
/// and takes the next generation of the state this node holds: 0 with no
/// predecessor before it took part in any move, else one past the handoff
/// it last adopted, naming it.
pub(super) fn check_source(
    vault: &Vault,
    txn: &RoTxn<'_>,
    head: &HandoffHead,
    movement: &HomeMove,
) -> Result<()> {
    let machine = crate::identity::read_machine_id_in_txn(vault, txn)?;
    let node = crate::identity::read_client_id_in_txn(vault, txn)?;
    if machine != Some(movement.source.machine) || node != Some(movement.source.node_id) {
        return Err(refused("the move does not start at this node"));
    }
    if movement.target.machine == movement.source.machine
        || movement.target.node_id == movement.source.node_id
    {
        return Err(refused("the move names this node as its target"));
    }
    let next = match head.floor {
        None => HomeGeneration {
            serial: 0,
            predecessor: None,
        },
        Some(floor) => HomeGeneration {
            serial: floor
                .serial
                .checked_add(1)
                .ok_or_else(|| refused("the lineage has no next generation"))?,
            predecessor: Some(floor.handoff),
        },
    };
    if movement.generation != next {
        return Err(refused(
            "the move does not take the next generation of this node's state",
        ));
    }
    Ok(())
}

/// CALLS home handoff lineage: a target takes generation 0, with no
/// predecessor, only while it has taken part in no move; that the source is
/// one of the owner's machines ([`super::open_handoff`]) and that this
/// node's election names it home ([`super::adopt`]) are checked beside
/// this. A later generation chains through its predecessor's signed header,
/// which the handoff carries: it moved the state to this move's source, one
/// generation before.
pub(super) fn lineage_admits(head: &HandoffHead, handoff: &VerifiedHandoff) -> bool {
    let movement = handoff.movement();
    let Some(predecessor) = movement.generation.predecessor else {
        return movement.generation.serial == 0 && head.floor.is_none();
    };
    handoff.lineage.as_ref().is_some_and(|(id, prior)| {
        *id == predecessor
            && prior.movement.target == movement.source
            && prior.movement.generation.serial.checked_add(1) == Some(movement.generation.serial)
    })
}
