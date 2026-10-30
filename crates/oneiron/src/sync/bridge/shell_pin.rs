//! A withdrawn Shell's topology pin from the structural ids its window
//! carries (FIX 11803). A machine that never held a withdrawn reply's body
//! receives its Shell header alone, so no withdrawal here pinned where the
//! reply stood, and its ChildOf and Parent wait in their window (FIX 931).
//! As each of them meets the Shell here, the ids it names pin the Shell
//! content-free ([`crate::conversation_dag::pin_received_shell_in_txn`]):
//! its ChildOf, with the Parent the same window carries for it, and a Parent
//! that lands after the pin. The edges themselves still wait.

use loro::{LoroMap, LoroValue, ValueOrContainer};

use super::companion_identity::parse_edge_key;
use crate::edge::{EdgeKind, decode_edge_value_for_kind};
use crate::sync::withdrawn_cutoffs::withdrawn_shell_in;
use crate::{EntityId, Result, Vault};

/// A `kind` edge of `src` to `tgt` met a withdrawn Shell: when it is the
/// Shell's own ChildOf, the Shell is pinned in room `tgt`, with the one
/// admissible Parent `edges` carries for it.
pub(super) fn pin_child_of(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    edges: &LoroMap,
    kind: EdgeKind,
    src: &EntityId,
    tgt: &EntityId,
) -> Result<()> {
    if kind != EdgeKind::ChildOf || !withdrawn_shell_in(&vault.store, wtxn, src)? {
        return Ok(());
    }
    let parent = carried_parent(edges, src);
    crate::conversation_dag::pin_received_shell_in_txn(&vault.store, wtxn, src, Some(*tgt), parent)
}

/// An admitted Parent of `source` to `target` met a withdrawn Shell: when
/// `source` is the Shell, `target` fills the parent of the pin its ChildOf
/// made.
pub(super) fn pin_parent(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    source: &EntityId,
    target: &EntityId,
) -> Result<()> {
    if !withdrawn_shell_in(&vault.store, wtxn, source)? {
        return Ok(());
    }
    crate::conversation_dag::pin_received_shell_in_txn(
        &vault.store,
        wtxn,
        source,
        None,
        Some(*target),
    )
}

/// The one Parent `edges` carries out of `src` whose value admission takes,
/// as `parent_retry::submit` judges it; `None` with none or more than one.
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
