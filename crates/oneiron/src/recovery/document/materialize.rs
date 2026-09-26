//! Scoped NOTE replacement and immutable-workflow preflight in one transaction.

use super::{DocKey, NOTE_FORK, NOTE_PROPOSAL_BUNDLE, NOTE_PROPOSAL_DOC, NOTE_RECEIPT, workflow};
use crate::entity_id::EntityId;
use crate::recovery::canonical::{CanonicalSnapshot, id, invalid};
use crate::{Vault, error::Result, note::NoteFork};
use loro::LoroDoc;
use std::collections::{BTreeMap, BTreeSet};

type Scope = BTreeSet<[u8; 16]>;

/// One stale row this pass drops: a proposal document, or a receipt/fork/
/// bundle row addressed by its typed table.
enum StaleMetadata {
    Receipt(EntityId),
    Fork(EntityId),
    Proposal(EntityId),
}

struct Cleanup {
    docs: Vec<DocKey>,
    metadata: Vec<StaleMetadata>,
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
    let expected_docs: BTreeSet<(EntityId, EntityId)> = snapshot
        .doc_snapshots
        .iter()
        .filter(|row| !live.contains(&(row.entity_id, row.head)))
        .map(|row| Ok((id(row.entity_id)?, id(row.head)?)))
        .collect::<Result<_>>()?;
    for owner in admitted {
        let note = id(*owner)?;
        crate::note::recovery::guard(vault, txn, note)?;
        let note_prefix = [note.to_hex().as_bytes(), b":".as_slice()].concat();
        for key in NOTE_PROPOSAL_DOC.scan_keys(&vault.store, txn, &note_prefix)? {
            let DocKey(_, head) = key;
            if !expected_docs.contains(&(note, head)) {
                cleanup.docs.push(key);
            }
        }
    }
    let receipts: BTreeMap<_, _> = snapshot
        .head_move_receipts
        .iter()
        .map(|row| (row.id, row))
        .collect();
    let mut stored_receipts = BTreeMap::new();
    for (receipt_id, receipt) in NOTE_RECEIPT.scan(&vault.store, txn)? {
        stored_receipts.insert(receipt.id, receipt.clone());
        if !admitted.contains(receipt.note.as_bytes())
            && !receipts.contains_key(receipt.id.as_bytes())
        {
            continue;
        }
        if receipt_id != receipt.id {
            return Err(invalid("stored receipt key"));
        }
        match receipts.get(receipt.id.as_bytes()) {
            Some(expected) if expected.receipt != NOTE_RECEIPT.encode_value(&receipt)? => {
                return Err(invalid("immutable head receipt divergence"));
            }
            Some(_) => {}
            None => cleanup.metadata.push(StaleMetadata::Receipt(receipt_id)),
        }
    }
    let expected_forks: BTreeMap<_, _> = snapshot
        .note_forks
        .iter()
        .map(|fork| (fork.fork, fork))
        .collect();
    let mut stored_forks = BTreeMap::new();
    for (fork_id, fork) in NOTE_FORK.scan(&vault.store, txn)? {
        // Even an out-of-scope row cannot alias an admitted immutable id.
        if admitted.contains(fork.note.as_bytes()) || expected_forks.contains_key(&fork.fork) {
            if fork_id != fork.fork {
                return Err(invalid("stored fork key"));
            }
            match expected_forks.get(&fork.fork) {
                Some(expected) if !same_fork(&fork, expected) => {
                    return Err(invalid("immutable fork divergence"));
                }
                Some(_) => {}
                None => cleanup.metadata.push(StaleMetadata::Fork(fork_id)),
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
    for (bundle_id, mut bundle) in NOTE_PROPOSAL_BUNDLE.scan(&vault.store, txn)? {
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
        if bundle_id != bundle.id {
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
            None => cleanup.metadata.push(StaleMetadata::Proposal(bundle_id)),
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
        NOTE_PROPOSAL_DOC.delete(&vault.store, txn, &key)?;
    }
    for key in cleanup.metadata {
        match key {
            StaleMetadata::Receipt(id) => {
                NOTE_RECEIPT.delete(&vault.store, txn, &id)?;
            }
            StaleMetadata::Fork(id) => {
                NOTE_FORK.delete(&vault.store, txn, &id)?;
            }
            StaleMetadata::Proposal(id) => {
                NOTE_PROPOSAL_BUNDLE.delete(&vault.store, txn, &id)?;
            }
        }
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
                    .map(super::CanonicalHeadMove::decode)
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
            let key = DocKey(note, id(row.head)?);
            // Proposal equality is a text-value claim, never proof that a
            // nested Loro snapshot has no erased history. Rebuild even when
            // the current text matches; live value-equal docs remain untouched.
            let doc = crate::note::documents::proposal_value(note, &row.text)?;
            NOTE_PROPOSAL_DOC.put(
                &vault.store,
                txn,
                &key,
                &crate::note::documents::snapshot(&doc)?,
            )?;
        }
    }
    for receipt in &snapshot.head_move_receipts {
        let value: crate::note::NoteLandingReceipt =
            rmp_serde::from_slice(&receipt.receipt).map_err(|_| invalid("head receipt"))?;
        NOTE_RECEIPT.put(&vault.store, txn, &value.id, &value)?;
    }
    for fork in &snapshot.note_forks {
        NOTE_FORK.put(&vault.store, txn, &fork.fork, fork)?;
    }
    for bundle in &snapshot.note_proposals {
        NOTE_PROPOSAL_BUNDLE.put(&vault.store, txn, &bundle.id, bundle)?;
    }
    Ok(())
}
