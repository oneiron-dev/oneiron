//! Scoped NOTE replacement and immutable-workflow preflight in one transaction.

use super::{from_doc, head_key, receipt_key, workflow};
use crate::recovery::canonical::{CanonicalSnapshot, id, invalid, pack, parse_id};
use crate::{
    Vault,
    error::Result,
    note::{NoteFork, NoteReviewBundle},
};
use loro::{ExportMode, LoroDoc};
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
    let expected_docs: BTreeSet<_> = snapshot
        .doc_snapshots
        .iter()
        .map(super::CanonicalDocument::key)
        .collect();
    let heads: BTreeSet<_> = snapshot
        .document_heads
        .iter()
        .map(|row| row.entity_id)
        .collect();
    for owner in admitted {
        let prefix = format!("note_doc:v1:{}:", id(*owner)?.to_hex());
        for row in vault.store.sync_state.prefix_iter(txn, &prefix)? {
            let (key, _) = row?;
            parse_id(&key[prefix.len()..])?;
            if !expected_docs.contains(key.as_ref()) {
                cleanup.docs.push(key.to_string());
            }
        }
        if !heads.contains(owner) {
            cleanup.metadata.push(head_key(*owner));
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
            .filter(|row| row.blob.len() > crate::batch::ENTITY_METADATA_HEADER_LEN)
            .map(|row| row.id)
            .collect();
        plan(vault, txn, self, &scope).map(|_| ())
    }
}

pub(super) fn run(vault: &Vault, doc: &LoroDoc, snapshot: &CanonicalSnapshot) -> Result<()> {
    if snapshot.entity_blobs.is_empty() {
        return Ok(());
    }
    let exports = snapshot
        .doc_snapshots
        .iter()
        .map(|row| {
            Ok((
                row,
                row.rebuild()?
                    .export(ExportMode::Snapshot)
                    .map_err(|_| invalid("document export"))?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    vault.with_write_txn(|txn| {
        let mut admitted = BTreeSet::new();
        for entity in &snapshot.entity_blobs {
            let owner = id(entity.id)?;
            if crate::sync::loro_support::tombstone_map_contains_id(
                &doc.get_map("tombstones"),
                &owner,
            ) || vault.local_hard_delete_marker_exists_in_txn(txn, &owner)?
            {
                continue;
            }
            let Some(raw) = vault.store.entities.get(txn, owner.as_bytes())? else {
                continue;
            };
            if raw.as_ref() != entity.blob.as_slice() {
                return Err(invalid("document core was not admitted"));
            }
            admitted.insert(entity.id);
        }
        let cleanup = plan(vault, txn, snapshot, &admitted)?;
        for key in cleanup.docs {
            vault.store.sync_state.delete(txn, &key)?;
        }
        for key in cleanup.metadata {
            vault.store.vault_meta.delete(txn, &key)?;
        }
        for (row, bytes) in &exports {
            if !admitted.contains(&row.entity_id) {
                continue;
            }
            let same = vault
                .store
                .sync_state
                .get(txn, &row.key())?
                .is_some_and(|current| {
                    LoroDoc::from_snapshot(&current)
                        .ok()
                        .and_then(|old| from_doc(row.entity_id, row.head, &old).ok())
                        .as_ref()
                        == Some(*row)
                });
            if !same {
                vault.store.sync_state.put(txn, &row.key(), bytes)?;
            }
        }
        for head in &snapshot.document_heads {
            if !admitted.contains(&head.entity_id) {
                continue;
            }
            vault
                .store
                .vault_meta
                .put(txn, &head_key(head.entity_id), &head.head)?;
            let text = &snapshot
                .doc_snapshots
                .iter()
                .find(|row| row.entity_id == head.entity_id && row.head == head.head)
                .ok_or(invalid("missing head document"))?
                .text;
            vault
                .batch_in()
                .text(&id(head.entity_id)?, &[("markdown", text.as_str())])
                .apply(txn)?;
        }
        for receipt in &snapshot.head_move_receipts {
            if admitted.contains(&receipt.entity_id) {
                vault
                    .store
                    .vault_meta
                    .put(txn, &receipt_key(receipt.id), &receipt.receipt)?;
            }
        }
        for fork in &snapshot.note_forks {
            if admitted.contains(fork.note.as_bytes()) {
                vault
                    .store
                    .vault_meta
                    .put(txn, &workflow::fork_key(fork), &pack(fork)?)?;
            }
        }
        for bundle in &snapshot.note_proposals {
            vault
                .store
                .vault_meta
                .put(txn, &workflow::bundle_key(bundle), &pack(bundle)?)?;
        }
        Ok(())
    })
}
