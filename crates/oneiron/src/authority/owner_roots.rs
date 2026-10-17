//! The owner roots this vault stores, as this install sees them (world privacy
//! P6b, R1).
//!
//! The fold keeps only each valid root's anchor and id. A root's full record
//! is read from its stored entry, in one snapshot with the fold that judged it
//! valid. The fold never caps roots: a host can always add bulk, up to the
//! bound the store gate gives every anchor this install does not pin (r23),
//! so the view pages and counts, and no root ever drops out of admission.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};

use ed25519_dalek::{Signer, SigningKey};

use super::*;
use crate::Vault;
use crate::error::Result;
use crate::store::Store;

/// The roots this install sees: the one it pins, and every other valid root,
/// which it never trusts (`ForeignRoot`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerRootView {
    pub pinned: Option<RecoveryRootId>,
    /// One page of the foreign roots whose anchor admits a live machine, by
    /// id, with how many machines each admits.
    pub foreign: BTreeMap<RecoveryRootId, usize>,
    /// Every foreign root that admits a machine, across all pages.
    pub foreign_total: u64,
    /// Foreign roots that admit no machine.
    pub inert_foreign: u64,
    /// The owner item a pin door left: the root it awaits, once it can
    /// finish.
    pub awaiting: Option<AwaitedRoot>,
}

/// A root `pin_owner_root` awaits (Astra #1422e F1; the Engine, r23): one
/// the owner pinned by its fingerprint before this install stored it, or
/// the pin, while this machine is not mine under it yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AwaitedRoot {
    pub root: RecoveryRootId,
    /// The root's row is stored now, and under the pin this machine is mine:
    /// pinning it again finishes.
    pub arrived: bool,
}

impl Vault {
    /// The stored, valid root records, read in one snapshot. Two entries of
    /// one root carry the same keys, so the seed's holder made both; the
    /// smaller entry hash stands for it.
    pub fn owner_root_records(
        &self,
    ) -> Result<BTreeMap<RecoveryRootId, (AuthorityEntryHash, OwnerRootRecord)>> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        owner_root_records_in_txn(&self.store, &txn, &fold)
    }

    /// The roots as this install sees them, one page of foreign roots after
    /// `after`. Built from the fold's roots and machine chains, never from a
    /// capped set: one machine can be admitted by many roots.
    pub fn owner_root_view(
        &self,
        after: Option<RecoveryRootId>,
        limit: usize,
    ) -> Result<OwnerRootView> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let pinned = fold.pinned_root.map(|pin| pin.id);
        let mut admitting: BTreeMap<[u8; 32], usize> = BTreeMap::new();
        for machine in fold.machines.values() {
            for anchor in machine.anchored.keys() {
                if machine.admits(&MachineAdmitter::Anchor(*anchor)) {
                    *admitting.entry(*anchor).or_default() += 1;
                }
            }
        }
        let awaiting = match super::pinned_root::read_pin_row_in_txn(&self.store, &txn)?.awaiting {
            Some(root) if pinned == Some(root) => {
                let me = crate::identity::read_machine_id_in_txn(self, &txn)?;
                let arrived = me.is_some_and(|me| fold.trusted_machine(me).is_some());
                Some(AwaitedRoot { root, arrived })
            }
            Some(root) => Some(AwaitedRoot {
                root,
                arrived: fold.root_anchors().values().any(|ids| ids.contains(&root)),
            }),
            None => None,
        };
        let mut view = OwnerRootView {
            pinned,
            foreign: BTreeMap::new(),
            foreign_total: 0,
            inert_foreign: 0,
            awaiting,
        };
        let roots = fold
            .root_anchors()
            .iter()
            .flat_map(|(anchor, ids)| ids.iter().map(move |id| (*id, anchor)));
        for (id, anchor) in roots.filter(|(id, _)| Some(*id) != pinned) {
            let Some(&machines) = admitting.get(anchor) else {
                view.inert_foreign += 1;
                continue;
            };
            view.foreign_total += 1;
            if after.is_none_or(|after| id > after) {
                view.foreign.insert(id, machines);
            }
        }
        // Several anchors interleave ids, so the page is cut after the walk.
        while view.foreign.len() > limit {
            view.foreign.pop_last();
        }
        Ok(view)
    }
}

/// [`Vault::owner_root_records`] in the caller's snapshot, against the fold
/// read in it. On a vault that adopted a checkpoint image, the root records
/// the image carries and the vault does not store count as stored ones do
/// (OF-469, slice E).
pub(super) fn owner_root_records_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
) -> Result<BTreeMap<RecoveryRootId, (AuthorityEntryHash, OwnerRootRecord)>> {
    let mut records = BTreeMap::new();
    let mut stored = BTreeSet::new();
    for (_, body) in authority_log_rows_in_txn(store, txn)? {
        let entry = decode_authority_log_entry_body(&body)?;
        let hash = authority_entry_hash(&entry)?;
        let AuthorityOp::OwnerRoot(record) = entry.op else {
            continue;
        };
        stored.insert(hash);
        if !fold.valid_entries.contains(&hash) {
            continue;
        }
        keep_smallest(&mut records, hash, record);
    }
    if let Some(evidence) = super::adopted_evidence::adopted_evidence_in_txn(store, txn)? {
        for (hash, entry) in evidence.carried_past(&stored) {
            if let AuthorityOp::OwnerRoot(record) = &entry.op
                && fold.valid_entries.contains(hash)
            {
                keep_smallest(&mut records, *hash, record.clone());
            }
        }
    }
    Ok(records)
}

/// Keeps `record` for its root unless a smaller entry hash already stands
/// for that root.
fn keep_smallest(
    records: &mut BTreeMap<RecoveryRootId, (AuthorityEntryHash, OwnerRootRecord)>,
    hash: AuthorityEntryHash,
    record: OwnerRootRecord,
) {
    match records.entry(record.root) {
        Entry::Vacant(slot) => {
            slot.insert((hash, record));
        }
        Entry::Occupied(mut slot) if hash < slot.get().0 => {
            slot.insert((hash, record));
        }
        Entry::Occupied(_) => {}
    }
}

/// The next entry `signer`, a key outside the roster, signs on `fold`'s
/// heads: an owner root's anchor signing its root, or a mark in its own chain.
pub(crate) fn anchor_signed_entry(
    fold: &AuthorityFold,
    signer: &SigningKey,
    op: AuthorityOp,
    now: u64,
) -> Result<AuthorityLogEntry> {
    let public_key = AuthorityKey::Ed25519(signer.verifying_key().to_bytes());
    let seq = fold
        .append_sequences
        .get(&public_key)
        .map(|seq| seq.checked_add(1).ok_or_else(invalid_authority))
        .transpose()?
        .unwrap_or(0);
    // The main log's heads, and this anchor's own: no door names another
    // anchor's rows (Astra S2-R2 A2-F4).
    let parents: BTreeSet<_> = fold
        .append_heads
        .iter()
        .chain(
            fold.anchor_heads
                .get(&signer.verifying_key().to_bytes())
                .into_iter()
                .flatten(),
        )
        .copied()
        .collect();
    if fold.vault_id.is_none() || parents.is_empty() {
        return Err(invalid_authority());
    }
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: fold.vault_id,
        seq,
        parent_hashes: parents.into_iter().collect(),
        op,
        signer: AuthoritySignature {
            suite: AuthoritySignatureSuite::Ed25519,
            public_key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: now,
    };
    entry.signer.signature = signer
        .sign(&authority_transcript(&entry)?)
        .to_bytes()
        .to_vec();
    Ok(entry)
}
