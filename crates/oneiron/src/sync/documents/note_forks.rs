//! A NOTE's pending forks and proposal membership for its owner lane
//! (FIX 7787): the canonical workflow section an owner frame carries
//! beside its head, and the floor that lets an unchanged update omit it.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::Result;
use crate::note::documents::invalid;
use crate::note::owner_workflows::{BundleProjection, OwnerNoteWorkflows};
use crate::note::{NoteFork, NoteLandingReceipt, NoteReviewBundle};
use crate::side_table::{self, HexId, Named, Raw, SideKey, SideTable};
use crate::{EntityId, Vault};

/// Recorded NOTE forks (owned by `note::proposals`; this binds the same
/// declaration for the owner export's read-only scan).
const NOTE_FORK: SideTable<EntityId, NoteFork, Named> = SideTable::new(&side_table::NOTE_FORK);
/// Durable head-move receipts (owned by `note::proposals`; see [`NOTE_FORK`]).
const NOTE_RECEIPT: SideTable<EntityId, NoteLandingReceipt, Named> =
    SideTable::new(&side_table::NOTE_RECEIPT);
/// Review bundles (owned by `note::proposals`; see [`NOTE_FORK`]).
const NOTE_PROPOSAL_BUNDLE: SideTable<EntityId, NoteReviewBundle, Named> =
    SideTable::new(&side_table::NOTE_PROPOSAL_BUNDLE);
/// Proposal snapshot bytes by (note, fork) (owned by `note::documents`).
const NOTE_PROPOSAL_DOC: SideTable<NoteForkKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::NOTE_PROPOSAL_DOC);
/// The workflow floor: the section hash last sent per admission (FIX 7787).
const AD_NF: SideTable<Vec<u8>, Vec<u8>, Raw> = SideTable::new(&side_table::SYNC_AD_NF);

/// `hex32(note) ":" hex32(fork)` — the [`NOTE_PROPOSAL_DOC`] key shape
/// (mirrors `note::side_keys::HexPair`, not visible from this module tree).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NoteForkKey(HexId, HexId);

impl SideKey for NoteForkKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
        out.push(b':');
        self.1.encode_into(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (a, rest) = bytes.split_at_checked(32)?;
        let b = rest.strip_prefix(b":")?;
        Some(Self(HexId::decode_key(a)?, HexId::decode_key(b)?))
    }
}

/// `fork` in proposal-only shape (FIX 8879): no recovery merge basis rides
/// an owner frame, as a replica never lands one.
fn proposal_only(fork: NoteFork) -> NoteFork {
    NoteFork {
        recovery_merge: None,
        ..fork
    }
}

fn build_in(vault: &Vault, txn: &heed::RoTxn<'_>, note: EntityId) -> Result<Vec<u8>> {
    let mut fork_rows = BTreeMap::new();
    for (key, row) in NOTE_FORK.scan(&vault.store, txn)? {
        if row.note == note {
            if key != row.fork {
                return Err(invalid("NOTE stored fork key"));
            }
            fork_rows.insert(row.fork, row);
        }
    }
    let mut forks = Vec::with_capacity(fork_rows.len());
    let mut values = BTreeMap::new();
    for row in fork_rows.values() {
        if !row.decided {
            let key = NoteForkKey(HexId(note), HexId(row.fork));
            let raw = NOTE_PROPOSAL_DOC
                .get(&vault.store, txn, &key)?
                .ok_or_else(|| invalid("NOTE stored fork value"))?;
            crate::note::documents::proposal_text(note, &raw)?;
            values.insert(row.fork, raw);
        }
        forks.push(proposal_only(row.clone()).erased_here(vault, txn)?);
    }
    let mut receipts = Vec::new();
    for (key, row) in NOTE_RECEIPT.scan(&vault.store, txn)? {
        if row.note == note {
            if key != row.id {
                return Err(invalid("NOTE stored receipt key"));
            }
            receipts.push(row.erased_here(vault, txn)?);
        }
    }
    let mut bundles = Vec::new();
    for (key, bundle) in NOTE_PROPOSAL_BUNDLE.scan(&vault.store, txn)? {
        let notes: BTreeSet<EntityId> = bundle
            .waiting
            .iter()
            .map(|fork| fork.note)
            .chain(bundle.landed.iter().map(|receipt| receipt.note))
            .collect();
        if !notes.contains(&note) {
            continue;
        }
        if key != bundle.id {
            return Err(invalid("NOTE stored proposal key"));
        }
        let complete = notes.len() == 1;
        let mut waiting = Vec::new();
        for fork in bundle.waiting.iter().filter(|fork| fork.note == note) {
            waiting.push(proposal_only(fork.clone()).erased_here(vault, txn)?);
        }
        let mut landed = Vec::new();
        for receipt in bundle.landed.iter().filter(|receipt| receipt.note == note) {
            landed.push(receipt.clone().erased_here(vault, txn)?);
        }
        if waiting.is_empty() && landed.is_empty() {
            continue;
        }
        bundles.push(BundleProjection {
            id: bundle.id,
            waiting,
            landed,
            explainer: if complete {
                bundle.explainer.clone()
            } else {
                "redacted".to_owned()
            },
            complete,
        });
    }
    rmp_serde::to_vec_named(&OwnerNoteWorkflows {
        forks,
        values,
        receipts,
        bundles,
    })
    .map_err(|_| invalid("NOTE workflows encode"))
}

/// `note`'s workflow section for this owner export: the canonical bytes
/// when this is a state copy or the workflow state changed since the last
/// section sent under `admission_key`, empty when an update may omit it.
/// The floor moves in the export's own write.
pub(super) fn section_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    admission_key: &[u8],
    state_copy: bool,
) -> Result<Vec<u8>> {
    let bytes = build_in(vault, txn, note)?;
    let hash = blake3::hash(&bytes);
    let key = format!("{}:{}", note.to_hex(), blake3::hash(admission_key).to_hex()).into_bytes();
    if !state_copy && AD_NF.get(&vault.store, txn, &key)?.as_deref() == Some(&hash.as_bytes()[..]) {
        return Ok(Vec::new());
    }
    AD_NF.put(&vault.store, txn, &key, &hash.as_bytes().to_vec())?;
    Ok(bytes)
}
