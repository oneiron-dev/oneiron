//! An erased actor out of the symbol manifests' producing-operation chains
//! (FIX 4476). Each operation keeps its place in its chain and names no one;
//! symbol ids and the revision index never hash the actor.

use std::borrow::Cow;
use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::keys::MANIFEST;
use super::types::{CodeProducingOperation, CodeSymbolManifest};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{CodeError, Error, Result};
use crate::store::Store;

/// One producing operation as it stands apart from who made it.
type OperationIdentity = (EntityId, EntityId, EntityId, EntityId);

fn identity(op: &CodeProducingOperation) -> OperationIdentity {
    (op.operation, op.turn, op.activity, op.intent)
}

/// Every producing operation in `manifest`'s chunk and symbol chains.
fn operations(manifest: &CodeSymbolManifest) -> impl Iterator<Item = &CodeProducingOperation> {
    let chunks = manifest.chunks.iter().flat_map(|c| &c.producing_operations);
    let symbols = manifest
        .symbols
        .iter()
        .flat_map(|s| &s.producing_operations);
    chunks.chain(symbols)
}

/// [`operations`], to rewrite.
fn operations_mut(
    manifest: &mut CodeSymbolManifest,
) -> impl Iterator<Item = &mut CodeProducingOperation> {
    let chunks = manifest
        .chunks
        .iter_mut()
        .flat_map(|c| &mut c.producing_operations);
    let symbols = manifest
        .symbols
        .iter_mut()
        .flat_map(|s| &mut s.producing_operations);
    chunks.chain(symbols)
}

/// `manifest` as it replaces `id`'s held manifest (FIX 4476): an operation
/// the held copy names no one for names no one in the new copy too, so a
/// replacement never brings an erased actor back (erased wins, as
/// `ACTOR_ERASE_CARRIER_MERGE` says). A held row that does not decode holds
/// no erasure, as its delete treats it.
pub(super) fn keep_erased_actors<'a>(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    manifest: &'a CodeSymbolManifest,
) -> Result<Cow<'a, CodeSymbolManifest>> {
    let held = match MANIFEST.get(store, txn, id) {
        Ok(Some(held)) => held,
        Ok(None) | Err(Error::Code(CodeError::InvalidCodeSymbolManifestBody(_))) => {
            return Ok(Cow::Borrowed(manifest));
        }
        Err(other) => return Err(other),
    };
    let erased: BTreeSet<OperationIdentity> = operations(&held)
        .filter(|op| op.actor.is_none())
        .map(identity)
        .collect();
    if !operations(manifest).any(|op| op.actor.is_some() && erased.contains(&identity(op))) {
        return Ok(Cow::Borrowed(manifest));
    }
    let mut merged = manifest.clone();
    for op in operations_mut(&mut merged) {
        if erased.contains(&identity(op)) {
            op.actor = None;
        }
    }
    Ok(Cow::Owned(merged))
}

/// Erasing `actor` from the symbol manifests (FIX 4476): each operation it
/// made, in every chunk's and symbol's chain, keeps its place, operation,
/// turn, activity and intent and names no one, so blame still shows the
/// chain. One-way, in the erase's own transaction. An id whose entity is no
/// actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a manifest row that cannot be read.
pub(crate) fn erase_manifest_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::typed_body::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut manifests = Vec::new();
    for (id, mut manifest) in MANIFEST.scan(&vault.store, wtxn)? {
        let mut named = false;
        for op in operations_mut(&mut manifest) {
            if op.actor == Some(*actor) {
                op.actor = None;
                named = true;
            }
        }
        if named {
            manifests.push((id, manifest));
        }
    }
    for (id, manifest) in manifests {
        MANIFEST.put(&vault.store, wtxn, &id, &manifest)?;
    }
    Ok(())
}
