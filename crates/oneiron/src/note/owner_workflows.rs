//! A NOTE's pending forks and proposal membership as the owner lane
//! carries them (FIX 7787): the payload an owner frame holds beside its
//! head, its install on a subscribed own device, and the marks that keep
//! a fork born on that device out of the authority sweep.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::documents::{NOTE_PROPOSAL_DOC, invalid};
use super::proposals::{NOTE_FORK, NOTE_PROPOSAL_BUNDLE, NOTE_RECEIPT};
use super::side_keys::HexPair;
use super::{NoteFork, NoteLandingReceipt, NoteReviewBundle, NoteVerdict};
use crate::error::Result;
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::{EntityId, Vault};

/// Replica-local NOTE forks: born on this subscribed device, never part of
/// authority state (FIX 7787).
pub(super) const NOTE_FORK_LOCAL: SideTable<HexPair, (), Raw> =
    SideTable::new(&side_table::NOTE_FORK_LOCAL);

const REDACTED: &str = "redacted";

/// One NOTE's workflow state as its owner lane carries it: every fork row
/// of the note in proposal-only shape, each pending fork's proposal
/// snapshot bytes, its landing receipts, and each bundle holding a member
/// of it, projected onto this note alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerNoteWorkflows {
    pub(crate) forks: Vec<NoteFork>,
    pub(crate) values: BTreeMap<EntityId, Vec<u8>>,
    pub(crate) receipts: Vec<NoteLandingReceipt>,
    pub(crate) bundles: Vec<BundleProjection>,
}

/// One review bundle as one member NOTE's lane carries it: that note's
/// members alone. `complete` only when the bundle holds no other NOTE;
/// a projection's explainer is redacted, as it can quote what left.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BundleProjection {
    #[serde(with = "crate::entity_id::serde_hex")]
    pub(crate) id: EntityId,
    pub(crate) waiting: Vec<NoteFork>,
    pub(crate) landed: Vec<NoteLandingReceipt>,
    pub(crate) explainer: String,
    pub(crate) complete: bool,
}

pub(super) fn mark_local_fork_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    fork: EntityId,
) -> Result<()> {
    NOTE_FORK_LOCAL.put(&vault.store, txn, &HexPair(HexId(note), HexId(fork)), &())
}

pub(super) fn unmark_local_fork_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    fork: EntityId,
) -> Result<()> {
    NOTE_FORK_LOCAL.delete(&vault.store, txn, &HexPair(HexId(note), HexId(fork)))?;
    Ok(())
}

fn local_forks(vault: &Vault, txn: &heed::RoTxn<'_>, note: EntityId) -> Result<BTreeSet<EntityId>> {
    let prefix = format!("{}:", note.to_hex()).into_bytes();
    Ok(NOTE_FORK_LOCAL
        .scan_keys(&vault.store, txn, &prefix)?
        .into_iter()
        .map(|HexPair(_, HexId(fork))| fork)
        .collect())
}

fn decode(bytes: &[u8]) -> Result<OwnerNoteWorkflows> {
    let carried: OwnerNoteWorkflows =
        rmp_serde::from_slice(bytes).map_err(|_| invalid("NOTE workflows frame"))?;
    let canonical =
        rmp_serde::to_vec_named(&carried).map_err(|_| invalid("NOTE workflows frame"))?;
    if canonical != bytes {
        return Err(invalid("NOTE workflows frame"));
    }
    Ok(carried)
}

fn validate_value(note: EntityId, bytes: &[u8]) -> Result<()> {
    let view = super::document::NoteDocument::load(note, bytes)?.view()?;
    if !view.pins.is_empty() || !view.authorship.is_empty() {
        return Err(invalid("proposal cannot carry authority or citations"));
    }
    super::validate_markdown(&view.markdown)
}

fn validate(note: EntityId, carried: &OwnerNoteWorkflows) -> Result<()> {
    let mut forks = BTreeMap::new();
    for fork in &carried.forks {
        if fork.note != note
            || fork.recovery_merge.is_some()
            || (!fork.frontier.is_empty() && loro::Frontiers::decode(&fork.frontier).is_err())
            || forks.insert(fork.fork, fork).is_some()
        {
            return Err(invalid("NOTE workflow fork"));
        }
    }
    let mut receipts = BTreeMap::new();
    for receipt in &carried.receipts {
        let Some(fork) = forks.get(&receipt.fork) else {
            return Err(invalid("NOTE workflow receipt fork"));
        };
        if receipt.note != note || !fork.decided || receipts.insert(receipt.id, receipt).is_some() {
            return Err(invalid("NOTE workflow receipt"));
        }
        match receipt.verdict {
            NoteVerdict::Switch if receipt.head == receipt.fork => {}
            NoteVerdict::Merge if !fork.rewrite && receipt.head == receipt.previous_head => {}
            NoteVerdict::Reject
                if receipt.head == receipt.previous_head
                    && !carried.values.contains_key(&receipt.fork) => {}
            _ => return Err(invalid("NOTE workflow receipt verdict")),
        }
    }
    let mut membership = BTreeMap::new();
    let mut bundles = BTreeSet::new();
    for bundle in &carried.bundles {
        if !bundles.insert(bundle.id)
            || bundle.explainer.trim().is_empty()
            || (bundle.waiting.is_empty() && bundle.landed.is_empty())
            || (!bundle.complete && bundle.explainer != REDACTED)
        {
            return Err(invalid("NOTE workflow bundle"));
        }
        for fork in &bundle.waiting {
            match forks.get(&fork.fork) {
                Some(carried_fork) if *carried_fork == fork && !fork.decided => {}
                _ => return Err(invalid("NOTE workflow waiting fork")),
            }
            if membership.insert(fork.fork, bundle.id).is_some() {
                return Err(invalid("NOTE workflow membership"));
            }
        }
        for receipt in &bundle.landed {
            match receipts.get(&receipt.id) {
                Some(carried_receipt) if *carried_receipt == receipt => {}
                _ => return Err(invalid("NOTE workflow landed receipt")),
            }
            if membership.insert(receipt.fork, bundle.id).is_some() {
                return Err(invalid("NOTE workflow membership"));
            }
        }
    }
    for fork in &carried.forks {
        if fork.proposal != membership.get(&fork.fork).copied() {
            return Err(invalid("NOTE workflow proposal binding"));
        }
        if !fork.decided && !carried.values.contains_key(&fork.fork) {
            return Err(invalid("NOTE workflow value absent"));
        }
    }
    for (fork, bytes) in &carried.values {
        match forks.get(fork) {
            Some(row) if !row.decided => validate_value(note, bytes)?,
            _ => return Err(invalid("NOTE workflow value fork")),
        }
    }
    Ok(())
}

fn merge_bundle(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    carried: &BundleProjection,
    local: &BTreeSet<EntityId>,
) -> Result<()> {
    let (mut waiting, mut landed) =
        match NOTE_PROPOSAL_BUNDLE.get(&vault.store, txn, &carried.id)? {
            Some(held) => (held.waiting, held.landed),
            None => (Vec::new(), Vec::new()),
        };
    waiting.retain(|fork| fork.note != note || local.contains(&fork.fork));
    landed.retain(|receipt| receipt.note != note || local.contains(&receipt.fork));
    waiting.extend(carried.waiting.iter().cloned());
    landed.extend(carried.landed.iter().cloned());
    if waiting.is_empty() && landed.is_empty() {
        NOTE_PROPOSAL_BUNDLE.delete(&vault.store, txn, &carried.id)?;
        return Ok(());
    }
    let explainer = if carried.complete {
        carried.explainer.clone()
    } else {
        REDACTED.to_owned()
    };
    NOTE_PROPOSAL_BUNDLE.put(
        &vault.store,
        txn,
        &carried.id,
        &NoteReviewBundle {
            id: carried.id,
            waiting,
            landed,
            explainer,
        },
    )
}

/// Installs one owner frame's workflow section for `note` in the head's
/// own write: the carried rows stand, bundles keep their other notes'
/// slices, and authority rows the section no longer names go. A fork this
/// device born itself is never swept (FIX 7787). An empty section carries
/// nothing and installs nothing.
pub(crate) fn install_frame_workflows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    bytes: &[u8],
) -> Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    let carried = decode(bytes)?;
    validate(note, &carried)?;
    let local = local_forks(vault, txn, note)?;
    for fork in &carried.forks {
        NOTE_FORK.put(&vault.store, txn, &fork.fork, fork)?;
        if fork.decided {
            NOTE_PROPOSAL_DOC.delete(&vault.store, txn, &HexPair(HexId(note), HexId(fork.fork)))?;
        }
    }
    for (fork, raw) in &carried.values {
        NOTE_PROPOSAL_DOC.put(&vault.store, txn, &HexPair(HexId(note), HexId(*fork)), raw)?;
    }
    for receipt in &carried.receipts {
        NOTE_RECEIPT.put(&vault.store, txn, &receipt.id, receipt)?;
        if local.contains(&receipt.fork) {
            continue;
        }
        if let Some(mut held) = NOTE_FORK.get(&vault.store, txn, &receipt.fork)? {
            if held.note == note && !held.decided {
                held.decided = true;
                held.recovery_merge = None;
                NOTE_FORK.put(&vault.store, txn, &receipt.fork, &held)?;
                NOTE_PROPOSAL_DOC.delete(
                    &vault.store,
                    txn,
                    &HexPair(HexId(note), HexId(receipt.fork)),
                )?;
            }
        }
    }
    let carried_bundles: BTreeSet<EntityId> =
        carried.bundles.iter().map(|bundle| bundle.id).collect();
    for bundle in &carried.bundles {
        merge_bundle(vault, txn, note, bundle, &local)?;
    }
    for (key, mut held) in NOTE_PROPOSAL_BUNDLE.scan(&vault.store, txn)? {
        if carried_bundles.contains(&key) {
            continue;
        }
        let before = held.waiting.len() + held.landed.len();
        held.waiting
            .retain(|fork| fork.note != note || local.contains(&fork.fork));
        held.landed
            .retain(|receipt| receipt.note != note || local.contains(&receipt.fork));
        if held.waiting.len() + held.landed.len() == before {
            continue;
        }
        if held.waiting.is_empty() && held.landed.is_empty() {
            NOTE_PROPOSAL_BUNDLE.delete(&vault.store, txn, &key)?;
        } else {
            held.explainer = REDACTED.to_owned();
            NOTE_PROPOSAL_BUNDLE.put(&vault.store, txn, &key, &held)?;
        }
    }
    let carried_forks: BTreeSet<EntityId> = carried.forks.iter().map(|fork| fork.fork).collect();
    for (key, held) in NOTE_FORK.scan(&vault.store, txn)? {
        if held.note == note && !carried_forks.contains(&key) && !local.contains(&key) {
            NOTE_FORK.delete(&vault.store, txn, &key)?;
            NOTE_PROPOSAL_DOC.delete(&vault.store, txn, &HexPair(HexId(note), HexId(key)))?;
        }
    }
    Ok(())
}
