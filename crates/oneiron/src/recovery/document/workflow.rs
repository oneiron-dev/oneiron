//! Durable NOTE workflow capture and reference validation without CRDT op IDs.

#[cfg(feature = "sync")]
use crate::recovery::canonical::pack;
use crate::recovery::canonical::{ByteBudget, CanonicalSnapshot, invalid};
use crate::{
    Vault,
    error::Result,
    note::{NoteFork, NoteReviewBundle, NoteVerdict},
};
#[cfg(feature = "sync")]
use serde::{Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "sync")]
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

/// The bytes one fork holds: its ids, frontier and recovery texts.
fn fork_bytes(fork: &NoteFork) -> usize {
    4 * 16
        + fork.frontier.len()
        + fork
            .recovery_merge
            .as_ref()
            .map_or(0, |(parent, merged)| parent.len() + merged.len())
}

/// The frontier a fork opened at: empty, or a Loro frontier encoding.
fn frontier_decodes(fork: &NoteFork) -> bool {
    fork.frontier.is_empty() || loro::Frontiers::decode(&fork.frontier).is_ok()
}

/// Resolve the old history while it still exists. The artifact merges by
/// values: the fork's opening frontier rides along byte for byte, never as a
/// basis, since it may name peers a reconstruction no longer has.
pub(super) fn normalize(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fork: &NoteFork,
    retained: &BTreeSet<super::retained::Place>,
) -> Result<NoteFork> {
    // A pending fork's basis is the live head, or a head a later switch
    // replaced that the artifact retains for it (FIX 8829); a decided one's
    // may be any head a later switch replaced.
    let head = crate::note::documents::head_in(&vault.store, txn, fork.note)?.0;
    if (fork.parent != fork.note
        && !fork.decided
        && fork.parent != head
        && !retained.contains(&(fork.note, fork.parent)))
        || !frontier_decodes(fork)
        || ((!fork.decided && !fork.rewrite) != fork.recovery_merge.is_some())
    {
        return Err(invalid("proposal requires canonical value basis"));
    }
    // The artifact names no one this vault erased (FIX 3878).
    fork.clone().erased_here(vault, txn)
}

pub(super) fn capture(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    snapshot: &mut CanonicalSnapshot,
    ids: &BTreeSet<[u8; 16]>,
    retained: &BTreeSet<super::retained::Place>,
    budget: &mut ByteBudget,
) -> Result<()> {
    let mut originals = BTreeMap::new();
    for row in super::NOTE_FORK.iter_from(&vault.store, txn, &[])? {
        let (fork_id, fork) = row?;
        if !ids.contains(fork.note.as_bytes()) {
            continue;
        }
        if fork_id != fork.fork {
            return Err(invalid("stored fork key"));
        }
        // The captured fork and the original kept to check bundles against.
        budget.take(2 * fork_bytes(&fork))?;
        snapshot
            .note_forks
            .push(normalize(vault, txn, &fork, retained)?);
        originals.insert(fork.fork, fork);
    }
    for row in super::NOTE_PROPOSAL_BUNDLE.iter_from(&vault.store, txn, &[])? {
        let (bundle_id, mut bundle) = row?;
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
        if bundle_id != bundle.id {
            return Err(invalid("stored proposal key"));
        }
        for fork in &mut bundle.waiting {
            if originals.get(&fork.fork) != Some(fork) {
                return Err(invalid("proposal fork divergence"));
            }
            *fork = normalize(vault, txn, fork, retained)?;
        }
        for receipt in &mut bundle.landed {
            receipt.actor = receipt.actor.erased_here(vault, txn)?;
        }
        budget.take(
            16 + bundle.explainer.len()
                + bundle.waiting.iter().map(fork_bytes).sum::<usize>()
                + bundle.landed.len() * 6 * 16,
        )?;
        snapshot.note_proposals.push(bundle);
    }
    snapshot.note_forks.sort_by_key(|fork| fork.fork);
    snapshot.note_proposals.sort_by_key(|bundle| bundle.id);
    Ok(())
}

/// An artifact's NOTE workflow rows as this vault recovers them (FIX 3878):
/// each actor this vault erased reads as no one, and a fork no one decided
/// goes with its erase, with its proposal value and its place in a bundle,
/// as the erase takes them out of this vault's own rows. Recovery checks and
/// installs only this form, so an older artifact never writes the actor back.
#[cfg(feature = "sync")]
pub(super) fn erase_actors_here(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    snapshot: &mut CanonicalSnapshot,
) -> Result<()> {
    let mut gone = BTreeSet::new();
    let needed = super::retained::carried(snapshot)?;
    for fork in std::mem::take(&mut snapshot.note_forks) {
        let place = (*fork.note.as_bytes(), *fork.fork.as_bytes());
        match fork.carried_here(vault, txn)? {
            Some(fork) => snapshot.note_forks.push(fork),
            None => {
                gone.insert(place);
            }
        }
    }
    if !gone.is_empty() {
        // A retained parent goes with the last pending fork that needed it
        // (FIX 8829).
        let still = super::retained::carried(snapshot)?;
        let unneeded: BTreeSet<_> = needed
            .difference(&still)
            .map(|(note, head)| (*note.as_bytes(), *head.as_bytes()))
            .collect();
        snapshot.doc_snapshots.retain(|row| {
            !gone.contains(&(row.entity_id, row.head))
                && !unneeded.contains(&(row.entity_id, row.head))
        });
        snapshot.refresh_containers();
    }
    for bundle in std::mem::take(&mut snapshot.note_proposals) {
        snapshot
            .note_proposals
            .extend(bundle.carried_here(vault, txn)?);
    }
    for row in &mut snapshot.head_move_receipts {
        let mut receipt = row.decode()?;
        let actor = receipt.actor.erased_here(vault, txn)?;
        if actor != receipt.actor {
            receipt.actor = actor;
            row.receipt = pack(&receipt)?;
        }
    }
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
    let heads: BTreeMap<_, _> = snapshot
        .document_heads
        .iter()
        .map(|row| (row.entity_id, row.head))
        .collect();
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
    // No count bounds a bundle (Rule 5, FIX 8828): it holds a fork and an
    // explainer.
    for bundle in &snapshot.note_proposals {
        if (bundle.waiting.is_empty() && bundle.landed.is_empty())
            || bundle.explainer.trim().is_empty()
        {
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
    let switched: BTreeSet<_> = receipts
        .values()
        .filter(|receipt| receipt.verdict == NoteVerdict::Switch)
        .map(|receipt| (receipt.note, receipt.head))
        .collect();
    for fork in &snapshot.note_forks {
        if !frontier_decodes(fork)
            || (fork.parent != fork.note && !switched.contains(&(fork.note, fork.parent)))
            || fork.fork == fork.parent
            || (!fork.decided && !fork.rewrite) != fork.recovery_merge.is_some()
        {
            return Err(invalid("canonical fork basis"));
        }
        // A decided fork's parent may be a head a later switch replaced.
        if !fork.decided
            && (!docs.contains_key(&(*fork.note.as_bytes(), *fork.parent.as_bytes()))
                || !docs.contains_key(&(*fork.note.as_bytes(), *fork.fork.as_bytes())))
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
    // A value that is neither a head nor a pending fork's own is a retained
    // parent a pending fork needs (FIX 8829), or it has no place here.
    let retained = super::retained::carried(snapshot)?;
    for row in &snapshot.doc_snapshots {
        if row.head != row.entity_id
            && heads.get(&row.entity_id) != Some(&row.head)
            && !retained.contains(&(
                crate::EntityId::from_bytes(row.entity_id)?,
                crate::EntityId::from_bytes(row.head)?,
            ))
            && forks
                .get(&crate::EntityId::from_bytes(row.head)?)
                .is_none_or(|fork| fork.note.as_bytes() != &row.entity_id || fork.decided)
        {
            return Err(invalid("proposal value has no pending fork"));
        }
    }
    Ok(())
}
