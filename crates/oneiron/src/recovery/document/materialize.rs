//! Scoped NOTE replacement and immutable-workflow preflight in one transaction.

use super::{receipt_key, workflow};
use crate::recovery::canonical::{CanonicalSnapshot, id, invalid, pack, parse_id};
use crate::{
    Vault,
    error::Result,
    note::{NoteFork, NoteReviewBundle},
};
use loro::LoroDoc;
use std::collections::{BTreeMap, BTreeSet};

type Scope = BTreeSet<[u8; 16]>;
struct Cleanup {
    docs: Vec<String>,
    metadata: Vec<Vec<u8>>,
}
fn same_fork(previous: &NoteFork, expected: &NoteFork) -> bool {
    let mut previous = previous.clone();
    if previous.recovery_merge.is_some() && !previous.frontier.is_empty() {
        return false;
    }
    if previous.recovery_merge.is_none()
        && !previous.decided
        && !previous.rewrite
        && loro::Frontiers::decode(&previous.frontier).is_err()
    {
        return false;
    }
    previous.frontier.clear();
    // A native fork's merge basis is resolved at capture, not persisted in its
    // original row. Already recovered bases are immutable source values.
    if previous.recovery_merge.is_none() && !previous.decided && !previous.rewrite {
        previous.recovery_merge = expected.recovery_merge.clone();
    }
    previous == *expected
}

fn plan(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    snapshot: &CanonicalSnapshot,
    admitted: &Scope,
) -> Result<Cleanup> {
    let mut cleanup = Cleanup {
        docs: Vec::new(),
        metadata: Vec::new(),
    };
    if admitted.is_empty() && snapshot.note_proposals.is_empty() {
        return Ok(cleanup);
    }
    let live: BTreeSet<_> = snapshot
        .document_heads
        .iter()
        .map(|row| (row.entity_id, row.head))
        .collect();
    let expected_docs: BTreeSet<_> = snapshot
        .doc_snapshots
        .iter()
        .filter(|row| !live.contains(&(row.entity_id, row.head)))
        .map(|row| {
            Ok(crate::note::documents::doc_key(
                id(row.entity_id)?,
                id(row.head)?,
            ))
        })
        .collect::<Result<_>>()?;
    for owner in admitted {
        let note = id(*owner)?;
        crate::note::recovery::guard(vault, txn, note)?;
        let prefix = format!("note_proposal_doc:v1:{}:", note.to_hex());
        for row in vault.store.sync_state.prefix_iter(txn, &prefix)? {
            let (key, _) = row?;
            parse_id(&key[prefix.len()..])?;
            if !expected_docs.contains(key.as_ref()) {
                cleanup.docs.push(key.to_string());
            }
        }
    }
    let receipts: BTreeMap<_, _> = snapshot
        .head_move_receipts
        .iter()
        .map(|row| (row.id, row))
        .collect();
    let mut stored_receipts = BTreeMap::new();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(txn, b"note_receipt:v1:")?
    {
        let (key, raw) = row?;
        let receipt: crate::note::NoteLandingReceipt = workflow::decode(&raw)?;
        stored_receipts.insert(receipt.id, receipt.clone());
        if !admitted.contains(receipt.note.as_bytes())
            && !receipts.contains_key(receipt.id.as_bytes())
        {
            continue;
        }
        if key != receipt_key(*receipt.id.as_bytes()) {
            return Err(invalid("stored receipt key"));
        }
        match receipts.get(receipt.id.as_bytes()) {
            Some(expected) if expected.receipt.as_slice() != raw.as_ref() => {
                return Err(invalid("immutable head receipt divergence"));
            }
            Some(_) => {}
            None => cleanup.metadata.push(key.to_vec()),
        }
    }
    let expected_forks: BTreeMap<_, _> = snapshot
        .note_forks
        .iter()
        .map(|fork| (fork.fork, fork))
        .collect();
    let mut stored_forks = BTreeMap::new();
    for row in vault.store.vault_meta.prefix_iter(txn, b"note_fork:v1:")? {
        let (key, raw) = row?;
        let fork: NoteFork = workflow::decode(&raw)?;
        // Even an out-of-scope row cannot alias an admitted immutable id.
        if admitted.contains(fork.note.as_bytes()) || expected_forks.contains_key(&fork.fork) {
            if key != workflow::fork_key(&fork) {
                return Err(invalid("stored fork key"));
            }
            match expected_forks.get(&fork.fork) {
                Some(expected) if !same_fork(&fork, expected) => {
                    return Err(invalid("immutable fork divergence"));
                }
                Some(_) => {}
                None => cleanup.metadata.push(key.to_vec()),
            }
        }
        stored_forks.insert(fork.fork, fork);
    }
    let expected_bundles: BTreeMap<_, _> = snapshot
        .note_proposals
        .iter()
        .map(|bundle| (bundle.id, bundle))
        .collect();
    for bundle in &snapshot.note_proposals {
        if !workflow::bundle_notes(bundle).is_subset(admitted) {
            return Err(invalid("proposal was only partially admitted"));
        }
    }
    for row in vault
        .store
        .vault_meta
        .prefix_iter(txn, b"note_proposal:v1:")?
    {
        let (key, raw) = row?;
        let mut bundle: NoteReviewBundle = workflow::decode(&raw)?;
        let mut notes = workflow::bundle_notes(&bundle);
        for fork_id in bundle
            .waiting
            .iter()
            .map(|fork| fork.fork)
            .chain(bundle.landed.iter().map(|receipt| receipt.fork))
        {
            if let Some(fork) = stored_forks.get(&fork_id) {
                notes.insert(*fork.note.as_bytes());
            }
        }
        if notes.is_disjoint(admitted) && !expected_bundles.contains_key(&bundle.id) {
            continue;
        }
        if !notes.is_subset(admitted) {
            return Err(invalid("stored proposal crosses recovery scope"));
        }
        if key != workflow::bundle_key(&bundle) {
            return Err(invalid("stored proposal key"));
        }
        if !(1..=256).contains(&(bundle.waiting.len() + bundle.landed.len()))
            || bundle.explainer.trim().is_empty()
        {
            return Err(invalid("stored proposal shape"));
        }
        let mut members = BTreeSet::new();
        for fork in &bundle.waiting {
            if fork.proposal != Some(bundle.id)
                || fork.decided
                || !members.insert(fork.fork)
                || stored_forks.get(&fork.fork) != Some(fork)
            {
                return Err(invalid("stored proposal fork divergence"));
            }
        }
        for receipt in &bundle.landed {
            let fork = stored_forks
                .get(&receipt.fork)
                .ok_or(invalid("stored landed fork absent"))?;
            if fork.proposal != Some(bundle.id)
                || !fork.decided
                || fork.note != receipt.note
                || !members.insert(fork.fork)
                || stored_receipts.get(&receipt.id) != Some(receipt)
            {
                return Err(invalid("stored landed fork binding"));
            }
        }
        match expected_bundles.get(&bundle.id) {
            Some(expected) => {
                for fork in &mut bundle.waiting {
                    if let Some(expected) = expected_forks.get(&fork.fork) {
                        if !same_fork(fork, expected) {
                            return Err(invalid("immutable proposal fork divergence"));
                        }
                        *fork = (*expected).clone();
                    }
                }
                if bundle != **expected {
                    return Err(invalid("immutable proposal divergence"));
                }
            }
            None => cleanup.metadata.push(key.to_vec()),
        }
    }
    Ok(cleanup)
}

impl CanonicalSnapshot {
    /// Run before manifest quarantine or any durable forward pass. Malformed or
    /// cross-window workflows must not leave even the entity pass half applied.
    pub(crate) fn preflight_note_recovery(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<()> {
        let scope = self
            .entity_blobs
            .iter()
            .filter(|row| {
                row.blob.len() > crate::batch::ENTITY_METADATA_HEADER_LEN
                    && crate::batch::EntityMetadataHeader::parse(&row.blob).is_some_and(|header| {
                        header.entity_type == crate::registry::ENTITY_TYPE_NOTE
                    })
            })
            .map(|row| row.id)
            .collect();
        plan(vault, txn, self, &scope).map(|_| ())
    }
}

pub(super) fn run(vault: &Vault, doc: &LoroDoc, snapshot: &CanonicalSnapshot) -> Result<()> {
    vault.with_write_txn(|txn| run_in_txn(vault, txn, doc, snapshot))
}

pub(crate) fn run_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    doc: &LoroDoc,
    snapshot: &CanonicalSnapshot,
) -> Result<()> {
    let mut admitted = BTreeSet::new();
    for head in &snapshot.document_heads {
        let owner = id(head.entity_id)?;
        if crate::sync::loro_support::tombstone_map_contains_id(&doc.get_map("tombstones"), &owner)
            || vault.local_hard_delete_marker_exists_in_txn(txn, &owner)?
        {
            return Err(invalid("recovery NOTE was deleted"));
        }
        let entity = snapshot
            .entity_blobs
            .iter()
            .find(|entity| entity.id == head.entity_id)
            .ok_or(invalid("NOTE recovery owner absent"))?;
        if vault.store.entities.get(txn, owner.as_bytes())?.as_deref()
            != Some(entity.blob.as_slice())
        {
            return Err(invalid("document core was not admitted"));
        }
        admitted.insert(head.entity_id);
    }
    let cleanup = plan(vault, txn, snapshot, &admitted)?;
    for key in cleanup.docs {
        vault.store.sync_state.delete(txn, &key)?;
    }
    for key in cleanup.metadata {
        vault.store.vault_meta.delete(txn, &key)?;
    }
    let heads: BTreeMap<_, _> = snapshot
        .document_heads
        .iter()
        .map(|row| (row.entity_id, row.head))
        .collect();
    for row in &snapshot.doc_snapshots {
        let note = id(row.entity_id)?;
        if !admitted.contains(&row.entity_id) {
            return Err(invalid("NOTE recovery scope incomplete"));
        }
        if heads.get(&row.entity_id) == Some(&row.head) {
            let head = id(row.head)?;
            if crate::note::documents::head_in(&vault.store, txn, note)?.0 != head {
                // Each switch raised the head sequence by one.
                let seq = snapshot
                    .head_move_receipts
                    .iter()
                    .filter(|receipt| receipt.entity_id == row.entity_id)
                    .map(|receipt| receipt.decode())
                    .collect::<Result<Vec<_>>>()?
                    .iter()
                    .filter(|receipt| receipt.verdict == crate::note::NoteVerdict::Switch)
                    .count();
                crate::note::recovery::restore_head(
                    vault,
                    txn,
                    note,
                    head,
                    u64::try_from(seq).map_err(|_| invalid("NOTE head sequence"))?,
                    &row.text,
                    &row.authorship,
                )?;
            } else {
                crate::note::recovery::restore(vault, txn, note, &row.text, &row.authorship)?;
            }
        } else {
            let key = crate::note::documents::doc_key(note, id(row.head)?);
            // Proposal equality is a text-value claim, never proof that a
            // nested Loro snapshot has no erased history. Rebuild even when
            // the current text matches; live value-equal docs remain untouched.
            let doc = crate::note::documents::proposal_value(note, &row.text)?;
            vault
                .store
                .sync_state
                .put(txn, &key, &crate::note::documents::snapshot(&doc)?)?;
        }
    }
    for receipt in &snapshot.head_move_receipts {
        vault
            .store
            .vault_meta
            .put(txn, &receipt_key(receipt.id), &receipt.receipt)?;
    }
    for fork in &snapshot.note_forks {
        vault
            .store
            .vault_meta
            .put(txn, &workflow::fork_key(fork), &pack(fork)?)?;
    }
    for bundle in &snapshot.note_proposals {
        vault
            .store
            .vault_meta
            .put(txn, &workflow::bundle_key(bundle), &pack(bundle)?)?;
    }
    Ok(())
}
