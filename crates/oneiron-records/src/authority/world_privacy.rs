//! Moved from `crates/oneiron/src/authority/world_privacy.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::*;
pub use oneiron_base::machine_destination::Destination;
pub use oneiron_base::machine_destination::EffectiveRead;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::authority::world_privacy::EffectiveModelOrder;
use std::collections::BTreeSet;

/// How a machine stands toward a world, judged on the world's read: whether
/// it holds the world, contends for it, or may re-pick an orphan. Holder
/// execution and diagnostics only: who edits a world is the owner's
/// authenticated say-so, carried by any live linked machine (mesh contract
/// §3), never this standing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorldEditStanding {
    /// The world is readable on the machine.
    Holds,
    /// The machine is one of a conflict's contenders.
    Contends,
    /// No machine the world's read names is still the owner's.
    RepicksOrphan,
}

/// `read` is the roster rule's. `is_mine` judges the machine, `named_mine`
/// the machines the read names.
pub fn edit_standing(
    read: &EffectiveRead,
    machine: EntityId,
    is_mine: impl Fn(EntityId) -> bool,
    named_mine: impl Fn(EntityId) -> bool,
) -> Option<WorldEditStanding> {
    if !is_mine(machine) {
        return None;
    }
    if readable(read, Destination::Machine(machine), &is_mine) {
        return Some(WorldEditStanding::Holds);
    }
    match read {
        EffectiveRead::Conflicted { contenders } if contenders.contains(&machine) => {
            Some(WorldEditStanding::Contends)
        }
        _ if !orphaned_from(read, named_mine).is_empty() => Some(WorldEditStanding::RepicksOrphan),
        _ => None,
    }
}

/// The machines `read` names when none of them is still the owner's; empty
/// when the world is not orphaned.
pub fn orphaned_from(
    read: &EffectiveRead,
    is_mine: impl Fn(EntityId) -> bool,
) -> BTreeSet<EntityId> {
    let named = match read {
        EffectiveRead::OneMachine(machine) => BTreeSet::from([*machine]),
        EffectiveRead::Conflicted { contenders } => contenders.clone(),
        EffectiveRead::Everywhere | EffectiveRead::MyMachines => return BTreeSet::new(),
    };
    if named.iter().any(|machine| is_mine(*machine)) {
        BTreeSet::new()
    } else {
        named
    }
}

pub fn readable(
    read: &EffectiveRead,
    destination: Destination,
    is_mine: impl Fn(EntityId) -> bool,
) -> bool {
    let machine = match destination {
        Destination::Machine(machine) if is_mine(machine) => Some(machine),
        _ => None,
    };
    match read {
        EffectiveRead::Everywhere => true,
        EffectiveRead::MyMachines => machine.is_some(),
        EffectiveRead::OneMachine(only) => machine == Some(*only),
        EffectiveRead::Conflicted { .. } => false,
    }
}

/// The world a per-world side entry belongs to; `None` for a main-log entry.
/// Only a world's key records ride a side branch, recipient-filtered, with
/// the joins a carrier stages over the branch's leaves (FIX 11868). Its
/// settings edits are main-log metadata every linked machine folds (the
/// Engine call "OwnerAct world metadata to every linked machine"), so the
/// main-log heads, sequence scopes, refold, retired-signer walk, import order
/// and every transport filter that read this see them as main-log rows.
pub fn side_world(op: &AuthorityOp) -> Option<EntityId> {
    match op {
        AuthorityOp::WorldKeyWraps(record) => Some(record.key.world),
        AuthorityOp::FrontierJoin(FrontierJoin {
            scope: FrontierJoinScope::World(world),
            ..
        }) => Some(*world),
        _ => None,
    }
}
