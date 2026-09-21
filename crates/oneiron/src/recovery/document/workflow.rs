//! Durable NOTE workflow capture and reference validation without CRDT op IDs.

use crate::recovery::canonical::{CanonicalSnapshot, invalid, pack};
use crate::{
    Vault,
    error::Result,
    note::{NoteFork, NoteReviewBundle, NoteVerdict},
};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn fork_key(fork: &NoteFork) -> Vec<u8> {
    [b"note_fork:v1:".as_slice(), fork.fork.as_bytes()].concat()
}
pub(super) fn bundle_key(bundle: &NoteReviewBundle) -> Vec<u8> {
    [b"note_proposal:v1:".as_slice(), bundle.id.as_bytes()].concat()
}
pub(super) fn decode<T: DeserializeOwned + Serialize>(raw: &[u8]) -> Result<T> {
    let value: T = rmp_serde::from_slice(raw).map_err(|_| invalid("NOTE workflow encoding"))?;
    if pack(&value)? != raw {
        return Err(invalid("noncanonical NOTE workflow"));
    }
    Ok(value)
}
pub(super) fn bundle_notes(bundle: &NoteReviewBundle) -> BTreeSet<[u8; 16]> {
    bundle
        .waiting
        .iter()
        .map(|fork| *fork.note.as_bytes())
        .chain(bundle.landed.iter().map(|receipt| *receipt.note.as_bytes()))
        .collect()
}

/// Resolve the old history while it still exists. The artifact carries values,
/// not frontiers that could refer to unrelated peers after reconstruction.
pub(super) fn normalize(vault: &Vault, txn: &heed::RoTxn<'_>, fork: &NoteFork) -> Result<NoteFork> {
    let _ = (vault, txn);
    if fork.parent != fork.note
        || !fork.frontier.is_empty()
        || ((!fork.decided && !fork.rewrite) != fork.recovery_merge.is_some())
    {
        return Err(invalid("proposal requires canonical value basis"));
    }
    Ok(fork.clone())
}

pub(super) fn capture(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    snapshot: &mut CanonicalSnapshot,
    ids: &BTreeSet<[u8; 16]>,
) -> Result<()> {
    let mut originals = BTreeMap::new();
    for row in vault.store.vault_meta.prefix_iter(txn, b"note_fork:v1:")? {
        let (key, raw) = row?;
        let fork: NoteFork = decode(&raw)?;
        if !ids.contains(fork.note.as_bytes()) {
            continue;
        }
        if key != fork_key(&fork) {
            return Err(invalid("stored fork key"));
        }
        snapshot.note_forks.push(normalize(vault, txn, &fork)?);
        originals.insert(fork.fork, fork);
    }
    for row in vault
        .store
        .vault_meta
        .prefix_iter(txn, b"note_proposal:v1:")?
    {
        let (key, raw) = row?;
        let mut bundle: NoteReviewBundle = decode(&raw)?;
        let mut notes = bundle_notes(&bundle);
        for fork_id in bundle
            .waiting
            .iter()
            .map(|fork| fork.fork)
            .chain(bundle.landed.iter().map(|receipt| receipt.fork))
        {
            if let Some(fork) = originals.get(&fork_id) {
                notes.insert(*fork.note.as_bytes());
            }
        }
        if notes.is_disjoint(ids) {
            continue;
        }
        if !notes.is_subset(ids) {
            return Err(invalid("proposal crosses recovery scope"));
        }
        if key != bundle_key(&bundle) {
            return Err(invalid("stored proposal key"));
        }
        for fork in &mut bundle.waiting {
            if originals.get(&fork.fork) != Some(fork) {
                return Err(invalid("proposal fork divergence"));
            }
            *fork = normalize(vault, txn, fork)?;
        }
        snapshot.note_proposals.push(bundle);
    }
    snapshot.note_forks.sort_by_key(|fork| fork.fork);
    snapshot.note_proposals.sort_by_key(|bundle| bundle.id);
    Ok(())
}

pub(super) fn validate(snapshot: &CanonicalSnapshot) -> Result<()> {
    crate::recovery::validation::strict(snapshot.note_forks.iter().map(|fork| fork.fork))?;
    crate::recovery::validation::strict(snapshot.note_proposals.iter().map(|bundle| bundle.id))?;
    let docs: BTreeMap<_, _> = snapshot
        .doc_snapshots
        .iter()
        .map(|row| ((row.entity_id, row.head), row.text.as_str()))
        .collect();
    let forks: BTreeMap<_, _> = snapshot
        .note_forks
        .iter()
        .map(|fork| (fork.fork, fork))
        .collect();
    let receipts: BTreeMap<_, _> = snapshot
        .head_move_receipts
        .iter()
        .map(|row| row.decode().map(|receipt| (receipt.id, receipt)))
        .collect::<Result<_>>()?;
    let mut receipt_forks = BTreeSet::new();
    for receipt in receipts.values() {
        let fork = forks
            .get(&receipt.fork)
            .ok_or(invalid("receipt fork absent"))?;
        if !fork.decided
            || fork.note != receipt.note
            || !receipt_forks.insert(fork.fork)
            || (fork.rewrite && receipt.verdict == NoteVerdict::Merge)
        {
            return Err(invalid("receipt fork binding"));
        }
        if receipt.verdict == NoteVerdict::Reject
            && docs.contains_key(&(*fork.note.as_bytes(), *fork.fork.as_bytes()))
        {
            return Err(invalid("rejected fork retains document"));
        }
    }
    let mut membership = BTreeMap::new();
    for bundle in &snapshot.note_proposals {
        let count = bundle.waiting.len() + bundle.landed.len();
        if !(1..=256).contains(&count) || bundle.explainer.trim().is_empty() {
            return Err(invalid("proposal shape"));
        }
        for fork in &bundle.waiting {
            if forks.get(&fork.fork).copied() != Some(fork)
                || fork.decided
                || membership.insert(fork.fork, bundle.id).is_some()
            {
                return Err(invalid("proposal waiting membership"));
            }
        }
        for receipt in &bundle.landed {
            if receipts.get(&receipt.id) != Some(receipt)
                || membership.insert(receipt.fork, bundle.id).is_some()
            {
                return Err(invalid("proposal landed membership"));
            }
        }
    }
    for fork in &snapshot.note_forks {
        if !fork.frontier.is_empty()
            || fork.parent != fork.note
            || fork.fork == fork.parent
            || (!fork.decided && !fork.rewrite) != fork.recovery_merge.is_some()
        {
            return Err(invalid("canonical fork basis"));
        }
        if !docs.contains_key(&(*fork.note.as_bytes(), *fork.parent.as_bytes()))
            || (!fork.decided
                && !docs.contains_key(&(*fork.note.as_bytes(), *fork.fork.as_bytes())))
        {
            return Err(invalid("fork document reference"));
        }
        if let Some((_, target)) = &fork.recovery_merge
            && docs
                .get(&(*fork.note.as_bytes(), *fork.fork.as_bytes()))
                .copied()
                != Some(target.as_str())
        {
            return Err(invalid("fork merge target differs from proposal value"));
        }
        if fork.proposal != membership.get(&fork.fork).copied()
            || fork.decided != receipt_forks.contains(&fork.fork)
        {
            return Err(invalid("fork proposal binding"));
        }
    }
    for row in &snapshot.doc_snapshots {
        if row.head != row.entity_id
            && forks
                .get(&crate::EntityId::from_bytes(row.head)?)
                .is_none_or(|fork| fork.note.as_bytes() != &row.entity_id || fork.decided)
        {
            return Err(invalid("proposal value has no pending fork"));
        }
    }
    Ok(())
}
