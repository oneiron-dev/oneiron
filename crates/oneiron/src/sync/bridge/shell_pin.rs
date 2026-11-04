//! A withdrawn Shell's topology pin from the structural ids its window
//! carries (FIX 11803, L09 01:22, 01:42). A machine that never held a
//! withdrawn reply's body receives its Shell header alone, so no withdrawal
//! here pinned where the reply stood, and its ChildOf, Parent and RepliesTo
//! wait in their window (FIX 931). The ids they name pin the Shell
//! content-free ([`crate::conversation_dag::pin_shell_record_in_txn`]):
//! - its ChildOf names its room, and its RepliesTo the room its target
//!   stands in here; either pins the Shell there, with the Parent the same
//!   window carries for it and the session this store records for it;
//! - a Parent that lands once the pin stands fills the parent it lacks.
//!
//! The edges themselves still wait.

use loro::{LoroMap, LoroValue, ValueOrContainer};

use super::companion_identity::parse_edge_key;
use crate::edge::{EdgeKind, decode_edge_value_for_kind};
use crate::error::{Error, RecordError};
use crate::sync::withdrawn_cutoffs::withdrawn_shell_in;
use crate::{EntityId, Result, Vault};

/// A `kind` edge of `src` to `tgt` met a withdrawn Shell: when it is the
/// Shell's own ChildOf or RepliesTo and names a room, the Shell is pinned
/// there, with the one admissible Parent `edges` carries for it and its
/// recorded session. A Shell keeps no body to mark it a thread record, so it
/// is pinned as an ordinary record. Observer B and the forward pass's edge
/// gate both pin through it.
pub(in crate::sync) fn pin_from_edge(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    edges: &LoroMap,
    kind: EdgeKind,
    src: &EntityId,
    tgt: &EntityId,
) -> Result<()> {
    if !matches!(kind, EdgeKind::ChildOf | EdgeKind::RepliesTo)
        || !withdrawn_shell_in(&vault.store, wtxn, src)?
    {
        return Ok(());
    }
    let Some(room) = named_room(vault, wtxn, kind, tgt)? else {
        return Ok(());
    };
    let parent = carried_parent(edges, src);
    let session = crate::compaction::turn_session_membership_in_txn(&vault.store, wtxn, src)?;
    crate::conversation_dag::pin_shell_record_in_txn(
        &vault.store,
        wtxn,
        src,
        room,
        parent,
        session,
        false,
    )
}

/// An admitted Parent of `source` to `target` met a withdrawn Shell: when
/// `source` is the Shell and its pin stands, `target` fills the parent the
/// pin lacks (L09 01:42). With no pin yet, the ChildOf or RepliesTo that
/// pins it reads this Parent from its window.
pub(super) fn pin_parent(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    source: &EntityId,
    target: &EntityId,
) -> Result<()> {
    if !withdrawn_shell_in(&vault.store, wtxn, source)? {
        return Ok(());
    }
    let Some(pin) = crate::conversation_dag::redacted_record_pin(&vault.store, wtxn, source)?
    else {
        return Ok(());
    };
    let session = crate::compaction::turn_session_membership_in_txn(&vault.store, wtxn, source)?;
    crate::conversation_dag::pin_shell_record_in_txn(
        &vault.store,
        wtxn,
        source,
        pin.room,
        Some(*target),
        session,
        pin.thread,
    )
}

/// The room a `kind` edge to `tgt` names for its Shell: a ChildOf's target,
/// or the room a RepliesTo's target stands in here, read through its own
/// `conversation_of`; `None` for a target that stands in no room here yet.
fn named_room(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    kind: EdgeKind,
    tgt: &EntityId,
) -> Result<Option<EntityId>> {
    if kind == EdgeKind::ChildOf {
        return Ok(Some(*tgt));
    }
    match crate::conversation_dag::conversation_of(&vault.store, txn, tgt) {
        Ok(room) => Ok(Some(room)),
        Err(Error::EntityNotFound | Error::Record(RecordError::InvalidConversationDag(_))) => {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// The one Parent `edges` carries out of `src` whose value the Parent door
/// admits, as `parent_retry::submit` judges it; `None` with none or more
/// than one.
fn carried_parent(edges: &LoroMap, src: &EntityId) -> Option<EntityId> {
    let mut parents = Vec::new();
    edges.for_each(|key, value| {
        let Some((source, EdgeKind::Parent, target)) = parse_edge_key(key) else {
            return;
        };
        let ValueOrContainer::Value(LoroValue::Binary(buf)) = value else {
            return;
        };
        if source == *src
            && decode_edge_value_for_kind(EdgeKind::Parent, buf.as_slice()).is_ok_and(|decoded| {
                crate::conversation_dag::validate_received_parent_value(source, target, decoded)
                    .is_ok()
            })
        {
            parents.push(target);
        }
    });
    match parents.as_slice() {
        [parent] => Some(*parent),
        _ => None,
    }
}
