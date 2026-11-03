//! Which generations a store keeps once a capture's pad objects install over
//! its own (PAD-1, FIX 11294): before an install writes the objects of the
//! generations both keep, each generation only the capture keeps is adopted,
//! entry, bundle, pad object and grants, and each only the store keeps is
//! retired where the capture's own rows prove it retired. Nothing else
//! changes: a generation neither adopted nor retired keeps what it holds,
//! and the restore names it owed.

use super::super::{
    GENERATIONS, PARTS, SealedBundleEntry, SealedBundleObject, object_prefix, order, part_key,
    sealed_generation_hex,
};
use super::{
    ACCESS, CapturedObject, CapturedPadObjects, CurrentPadObjects, Family, PadObjectMeta,
    QUEUED_PREFIX, current_pad_objects_in_txn, generation_prefix, put_access,
    read_back_captured_in_txn, txn_rows, whole,
};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::world_keys::SealedBundleGeneration;

/// What an install does with the generations a store and a capture do not
/// both keep (CALLS: PAD-1 generation membership).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PadObjectMembership {
    /// A source's capture over a restored copy or an activated archive: each
    /// generation only the source keeps is adopted when the capture carries
    /// its bundle and its pad object whole, else it stays not carried. Each
    /// generation only the copy keeps is retired, bundle, pad object and
    /// grants, only when the source's own keep and age rule, run over the
    /// generations its same read keeps with that one placed among them by
    /// commit order, retires it; else it keeps its bytes.
    SourceKeepRuleProvesRetired,
    /// A store's own objects put back over an install that did not read
    /// back: every generation they keep comes back as they held it, whole or
    /// not, its grants and the admission outbox too (FIX 12142), and each
    /// the install brought that they do not keep goes.
    StoreOwnPutBack,
}

/// What an install changes of the generations a store keeps, past the
/// objects of the ones it keeps with the capture.
pub(super) struct MembershipChange {
    /// Each adopted generation, by its index in the capture.
    adopted: Vec<usize>,
    /// Each generation the store keeps that goes.
    retired: Vec<SealedBundleGeneration>,
}

/// What installing `captured` over `held`, the store's current objects,
/// changes of the generations it keeps under `membership`. Reads nothing
/// and writes nothing: every check comes before the install's first write.
pub(super) fn membership_change(
    held: &CurrentPadObjects,
    captured: &CapturedPadObjects,
    membership: PadObjectMembership,
) -> MembershipChange {
    let kept_here = |generation: &SealedBundleGeneration| {
        held.entries
            .iter()
            .any(|meta| meta.entry.generation == *generation)
    };
    let adopted = captured
        .index
        .entries
        .iter()
        .zip(&captured.objects)
        .enumerate()
        .filter(|(_, (meta, object))| {
            !kept_here(&meta.entry.generation)
                && match membership {
                    PadObjectMembership::SourceKeepRuleProvesRetired => {
                        carried_whole(&meta.entry, object)
                    }
                    PadObjectMembership::StoreOwnPutBack => true,
                }
        })
        .map(|(index, _)| index)
        .collect();
    let retired = held
        .entries
        .iter()
        .filter(|meta| captured.object(&meta.entry.generation).is_none())
        .filter(|meta| match membership {
            PadObjectMembership::SourceKeepRuleProvesRetired => {
                source_rule_retires(&captured.index.entries, &meta.entry)
            }
            PadObjectMembership::StoreOwnPutBack => true,
        })
        .map(|meta| meta.entry.generation)
        .collect();
    MembershipChange { adopted, retired }
}

/// The generations an install of `captured` under `membership` would retire
/// from the store's objects in `txn`, named for `expected`'s vault and home:
/// the ones whose bundles a capture of the store's own carries, to put back
/// should the install not read back.
///
/// # Errors
///
/// An entry that does not decode; storage errors.
pub(crate) fn generations_an_install_retires_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    expected: &CurrentPadObjects,
    captured: &CapturedPadObjects,
    membership: PadObjectMembership,
) -> Result<Vec<SealedBundleGeneration>> {
    let held = current_pad_objects_in_txn(store, txn, expected.vault_id, expected.home)?;
    Ok(membership_change(&held, captured, membership).retired)
}

/// Writes `change` in `wtxn`: each retired generation goes, its entry, both
/// objects' parts and its grants, as the home's retire drops them; each
/// adopted one lands as the capture carries it, its entry last.
///
/// # Errors
///
/// Storage errors.
pub(super) fn write_membership_change_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    captured: &CapturedPadObjects,
    change: &MembershipChange,
) -> Result<()> {
    for generation in &change.retired {
        let key = sealed_generation_hex(generation);
        GENERATIONS.delete(store, wtxn, &key)?;
        PARTS.delete_from(store, wtxn, format!("{key}:").as_bytes())?;
        // Its late joiners' grants go with it (FIX 4271).
        ACCESS.delete_from(store, wtxn, generation_prefix(generation).as_bytes())?;
    }
    for index in &change.adopted {
        let (Some(meta), Some(object)) = (
            captured.index.entries.get(*index),
            captured.objects.get(*index),
        ) else {
            continue;
        };
        adopt_in_txn(store, wtxn, meta, object)?;
    }
    Ok(())
}

/// Lands one generation `meta` names, as `object` carries it: each stored
/// part of its bundle and its pad object at its offset, its grant rows, then
/// its entry, in place of anything left under its name.
fn adopt_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    meta: &PadObjectMeta,
    object: &CapturedObject,
) -> Result<()> {
    let generation = &meta.entry.generation;
    let key = sealed_generation_hex(generation);
    PARTS.delete_from(store, wtxn, format!("{key}:").as_bytes())?;
    for (kind, parts) in [
        (SealedBundleObject::Bundle, &object.bundle),
        (SealedBundleObject::Pads, &object.parts),
    ] {
        for (offset, part) in parts {
            PARTS.put(store, wtxn, &part_key(generation, kind, *offset), part)?;
        }
    }
    ACCESS.delete_from(store, wtxn, generation_prefix(generation).as_bytes())?;
    for (grant, raw) in &object.grants {
        put_access(store, wtxn, grant, raw)?;
    }
    GENERATIONS.put(store, wtxn, &key, &meta.entry.encode())
}

/// Puts `entry`'s pad object back as a store held it: `parts` at their
/// offsets, whole or not, under `digest`, its entry last (FIX 11825). What a
/// store's own objects put back hold, never cut again nor required whole.
///
/// # Errors
///
/// Storage errors.
pub(super) fn put_pads_as_held(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    mut entry: SealedBundleEntry,
    digest: [u8; 32],
    parts: &[(u64, Vec<u8>)],
) -> Result<()> {
    let generation = entry.generation;
    let prefix = object_prefix(&generation, SealedBundleObject::Pads);
    PARTS.delete_from(store, wtxn, prefix.as_bytes())?;
    for (offset, part) in parts {
        let key = part_key(&generation, SealedBundleObject::Pads, *offset);
        PARTS.put(store, wtxn, &key, part)?;
    }
    entry.pads_digest = digest;
    let key = sealed_generation_hex(&generation);
    GENERATIONS.put(store, wtxn, &key, &entry.encode())
}

impl CapturedPadObjects {
    /// This capture, a store's own read before `installing` lands over it,
    /// with each outbox key `installing` carries that it does not hold
    /// noted (FIX 12142): the rows that install adds, which a put-back of
    /// this capture takes out again.
    pub(crate) fn noting_outbox_added_by(mut self, installing: &Self) -> Self {
        let added = installing
            .queued
            .iter()
            .map(|(key, _)| key)
            .filter(|key| !self.queued.iter().any(|(held, _)| held == *key))
            .cloned()
            .collect();
        self.outbox_added = added;
        self
    }
}

/// Puts `rows`, a generation's grant rows a store held under `prefix`, back
/// as it held them, through their table (FIX 12142): every row under
/// `prefix` goes first, so none an install added there stays. The
/// install's own revision covers these rows, so no other writer changed
/// them since.
///
/// # Errors
///
/// Storage errors.
pub(super) fn put_access_as_held(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    prefix: &[u8],
    rows: &[(Vec<u8>, Vec<u8>)],
) -> Result<()> {
    ACCESS.delete_from(store, wtxn, prefix)?;
    for (key, raw) in rows {
        put_access(store, wtxn, key, raw)?;
    }
    Ok(())
}

/// Puts the admission outbox back as `baseline`, a store's own capture,
/// held it, through its table (FIX 12142): each key the install over it
/// added goes ([`CapturedPadObjects::noting_outbox_added_by`]), then each
/// row it held lands as it held it. No revision covers the outbox, so a row
/// another writer queued since the install stays.
///
/// # Errors
///
/// A key that is not text; storage errors.
pub(super) fn put_outbox_as_held(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    baseline: &CapturedPadObjects,
) -> Result<()> {
    for key in &baseline.outbox_added {
        let key = std::str::from_utf8(key).map_err(|_| Error::InvalidKey)?;
        ACCESS.delete(store, wtxn, &key.to_owned())?;
    }
    for (key, raw) in &baseline.queued {
        put_access(store, wtxn, key, raw)?;
    }
    Ok(())
}

/// Whether the store holds, in `txn`, its own objects put back as
/// `baseline`, their capture before the install, holds them (FIX 12142):
/// the revision that capture names, so each kept generation's entry and
/// grant rows as the store held them, each pad object as
/// [`read_back_captured_in_txn`] reads it, and each admission outbox row as
/// the store held it, with none the install added left. It is never judged
/// against the put-back's own revision, which holds whatever the put-back
/// wrote.
///
/// # Errors
///
/// An entry or a part key that does not decode; storage errors.
pub(crate) fn read_back_put_back_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    baseline: &CapturedPadObjects,
) -> Result<bool> {
    if !read_back_captured_in_txn(store, txn, &baseline.index, baseline)? {
        return Ok(false);
    }
    let outbox = txn_rows(store, txn, Family::Access, QUEUED_PREFIX)?;
    Ok(baseline.queued.iter().all(|row| outbox.contains(row))
        && baseline
            .outbox_added
            .iter()
            .all(|added| outbox.iter().all(|(key, _)| key != added)))
}

/// Whether `object` carries both of `entry`'s objects whole: its pad object
/// ([`whole`]), and its bundle contiguous from offset 0, its length and its
/// digest.
fn carried_whole(entry: &SealedBundleEntry, object: &CapturedObject) -> bool {
    if whole(entry, &object.parts).is_err() {
        return false;
    }
    let mut hasher = blake3::Hasher::new();
    let mut held = 0_u64;
    for (offset, part) in &object.bundle {
        if *offset != held {
            return false;
        }
        hasher.update(part);
        held = held.saturating_add(part.len() as u64);
    }
    held == entry.bundle_len && *hasher.finalize().as_bytes() == entry.bundle_digest
}

/// Whether the source's keep and age rule retires `held`, a generation the
/// store keeps and the source's read does not ([`order`]): run over the
/// generations that read keeps with `held` placed among them by its commit
/// order, in the slot of the newest of them. A home commits no generation of
/// a slot past its clock, so its clock is at least there, and the rule only
/// retires more as the clock moves on. A commit order the source also names
/// proves nothing, nor does a source that keeps none.
fn source_rule_retires(source: &[PadObjectMeta], held: &SealedBundleEntry) -> bool {
    if source
        .iter()
        .any(|meta| meta.entry.commit_order == held.commit_order)
    {
        return false;
    }
    let Some(now_slot) = source.iter().map(|meta| meta.entry.generation.slot).max() else {
        return false;
    };
    let mut kept: Vec<SealedBundleEntry> = source.iter().map(|meta| meta.entry).collect();
    kept.push(*held);
    kept.sort_by_key(|entry| entry.commit_order);
    order::retired_in_commit_order(now_slot, &kept).contains(&held.generation)
}
