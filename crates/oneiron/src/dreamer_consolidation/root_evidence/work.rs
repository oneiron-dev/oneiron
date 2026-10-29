//! A root's pins and frontiers as fair work (FIX 8698): every bucket,
//! reference and child is taken, however many, and none is refused for a
//! count. The reads run in one snapshot outside the vault's writer, so a
//! large root never holds other writes; the writer only stores what they
//! settled. A pin keeps one frozen evidence revision: the snapshot's, or,
//! when a commit raced its opening, the writer's own.
use std::collections::{BTreeMap, BTreeSet};

use super::{
    ROOTS, Root, account_bucket, held_root, owned_root, pin_in_txn, pinned_buckets_in_txn,
    put_root_in_txn, reference,
};
use crate::claim::ScopedRead;
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::memory::consolidation_frontier::{
    ConsolidationChildReceipt, ConsolidationFrontierRequest, ConsolidationPinRequest,
    ConsolidationRootAccounting,
};
use crate::{EntityId, Error, Result, Vault};

/// Pins `input` for the owner `owner` resolves in each transaction: every
/// reference read in one snapshot at the revision it opened on, then the
/// root stored in a short write. A snapshot a commit raced as it opened has
/// no one revision, so the pins are read in the writer instead.
pub(crate) fn pin_frozen<E: From<Error>>(
    vault: &Vault,
    read: &ScopedRead<'_>,
    input: &ConsolidationPinRequest,
    owner: impl Fn(&heed::RoTxn<'_>) -> std::result::Result<EntityId, E>,
) -> std::result::Result<ConsolidationRootAccounting, E> {
    let revision = vault.store.env.info().last_txn_id;
    let pinned = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        if vault.store.env.info().last_txn_id == revision {
            owner(&txn)?;
            Some(pinned_buckets_in_txn(vault, read, &txn, input)?)
        } else {
            None
        }
    };
    vault.try_with_write_txn(|txn| {
        let actor = owner(txn)?;
        Ok(match pinned {
            Some(buckets) => put_root_in_txn(vault, txn, actor, buckets, revision as u64)?,
            None => pin_in_txn(vault, read, txn, actor, input)?,
        })
    })
}

/// Adds `input`'s children to the owner's root: read authority over every
/// pinned source and each child's checks against the root's immutable pins
/// run in a snapshot; the writer reads the root again and lands them, so a
/// frontier landed meanwhile is never lost.
pub(crate) fn frontier_frozen<E: From<Error>>(
    vault: &Vault,
    read: &ScopedRead<'_>,
    input: &ConsolidationFrontierRequest,
    owner: impl Fn(&heed::RoTxn<'_>) -> std::result::Result<EntityId, E>,
) -> std::result::Result<ConsolidationRootAccounting, E> {
    let receipts = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let actor = owner(&txn)?;
        let (_, root) = held_root(vault, read, &txn, actor, &input.root_ref)?;
        child_receipts(&root, input)?
    };
    vault.try_with_write_txn(|txn| {
        let actor = owner(txn)?;
        let (id, mut root) = owned_root(vault, txn, actor, &input.root_ref)?;
        apply_receipts(&mut root, receipts)?;
        ROOTS.put(&vault.store, txn, &id, &root)?;
        Ok(root.accounting)
    })
}

/// Each child of `input` checked against `root`'s pins, with the index of
/// the bucket it names. Every citation is looked up once, never scanned for.
fn child_receipts(
    root: &Root,
    input: &ConsolidationFrontierRequest,
) -> Result<Vec<(usize, ConsolidationChildReceipt)>> {
    let pinned: Vec<BTreeSet<_>> = root
        .accounting
        .buckets
        .iter()
        .map(|bucket| bucket.pinned.iter().map(|row| &row.reference).collect())
        .collect();
    let mut receipts = Vec::with_capacity(input.children.len());
    for child in &input.children {
        EntityId::from_hex(&child.child_ref)?;
        if !child.judgement.confidence.is_finite()
            || !(0.0..=1.0).contains(&child.judgement.confidence)
            || child.evidence.is_empty()
        {
            return Err(invalid_consolidation(
                "invalid child judgement or empty frontier",
            ));
        }
        let index = root
            .accounting
            .buckets
            .iter()
            .position(|bucket| bucket.bucket_hash == child.bucket_hash)
            .ok_or_else(|| invalid_consolidation("child names an unpinned bucket"))?;
        crate::claim::validate_predicate(&child.judgement.predicate, false)?;
        if crate::claim::predicate_root(&child.judgement.predicate)
            != root.accounting.buckets[index].bucket.predicate_root
        {
            return Err(invalid_consolidation("child judgement crossed its bucket"));
        }
        let mut evidence = child.evidence.clone();
        evidence.sort();
        evidence.dedup();
        for entry in &evidence {
            reference(entry)?;
            if !pinned[index].contains(entry) {
                return Err(invalid_consolidation(
                    "child citation was not pinned by the root",
                ));
            }
        }
        let encoded = serde_json::to_vec(&child.judgement)
            .map_err(|_| invalid_consolidation("child judgement does not encode"))?;
        receipts.push((
            index,
            ConsolidationChildReceipt {
                child_ref: child.child_ref.clone(),
                judgement_hash: *blake3::hash(&encoded).as_bytes(),
                evidence,
            },
        ));
    }
    Ok(receipts)
}

/// Lands `receipts` on `root`. A child identity stays in its one bucket,
/// counting the children landed here, and a child landed before must be the
/// same; each bucket a child landed on is accounted once.
fn apply_receipts(
    root: &mut Root,
    receipts: Vec<(usize, ConsolidationChildReceipt)>,
) -> Result<()> {
    // Each child identity's bucket and place in it, as the root holds it.
    let mut homes: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for (index, bucket) in root.accounting.buckets.iter().enumerate() {
        for (at, row) in bucket.children.iter().enumerate() {
            homes.insert(row.child_ref.clone(), (index, at));
        }
    }
    let mut touched = BTreeSet::new();
    for (index, receipt) in receipts {
        let bucket = root
            .accounting
            .buckets
            .get_mut(index)
            .ok_or_else(|| invalid_consolidation("child names an unpinned bucket"))?;
        match homes.get(&receipt.child_ref) {
            Some((home, _)) if *home != index => {
                return Err(invalid_consolidation("child identity crossed its bucket"));
            }
            Some((_, at)) => {
                let old = &bucket.children[*at];
                if old.judgement_hash != receipt.judgement_hash || old.evidence != receipt.evidence
                {
                    return Err(invalid_consolidation(
                        "child frontier changed after submission",
                    ));
                }
            }
            None => {
                homes.insert(receipt.child_ref.clone(), (index, bucket.children.len()));
                bucket.children.push(receipt);
                touched.insert(index);
            }
        }
    }
    for index in touched {
        let bucket = &mut root.accounting.buckets[index];
        bucket
            .children
            .sort_by(|left, right| left.child_ref.cmp(&right.child_ref));
        account_bucket(bucket)?;
    }
    Ok(())
}
