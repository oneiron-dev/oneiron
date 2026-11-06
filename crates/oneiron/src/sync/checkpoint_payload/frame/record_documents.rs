//! The independent native source bank's binary frame.
//!
//! Only final slot uses, copy locators and actor field names cross this
//! boundary. Original heads, native part digests and payloads do not.

use std::collections::{BTreeMap, BTreeSet};

use loro::checkpoint::{AtomId, Skeleton, SlotKind, placeholder_atom};
use loro::{Lamport, PeerID};
use serde::{Deserialize, Serialize};

use super::{FrameCopy, read_copies, write_copies};
use crate::error::Result;
use crate::store::checkpoint_payload::rows::bad_part;
use crate::sync::checkpoint_payload::AtomHome;
use crate::sync::checkpoint_payload::record_documents::{JoinedRecordDocument, RecordDocumentSlot};
use crate::sync::skill_docs::SKILL_DOCS_MAP;

/// This bank has one spelling; no earlier source-bank format exists.
const FRAME: u8 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    frame: u8,
    sources: Vec<Source>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    entity_key: String,
    slots: crate::sync::checkpoint_payload::record_documents::RecordDocumentSlots,
    copies: Vec<FrameCopy>,
    holes: Vec<String>,
}

/// Spells every source independently, including repeated descriptor positions
/// and shared writes. The supplied skeleton is the FINAL outer capture.
pub(crate) fn encode(skeleton: &Skeleton, sources: &[JoinedRecordDocument]) -> Result<Vec<u8>> {
    validate(skeleton, sources)?;
    let sources = sources
        .iter()
        .map(|source| {
            Ok(Source {
                entity_key: source.entity_key.clone(),
                slots: source.slots.clone(),
                copies: write_copies(&source.copies)?,
                holes: source.holes.clone(),
            })
        })
        .collect::<Result<_>>()?;
    rmp_serde::to_vec_named(&Frame {
        frame: FRAME,
        sources,
    })
    .map_err(|_| bad_part())
}

/// Reads the bank against the supplied final outer skeleton. Copy authentication
/// and native history opening still belong to the source owner's `open`.
pub(crate) fn decode(skeleton: &Skeleton, bytes: &[u8]) -> Result<Vec<JoinedRecordDocument>> {
    let frame: Frame = rmp_serde::from_slice(bytes).map_err(|_| bad_part())?;
    if frame.frame != FRAME {
        return Err(bad_part());
    }
    let sources = frame
        .sources
        .into_iter()
        .map(|source| {
            Ok(JoinedRecordDocument {
                entity_key: source.entity_key,
                slots: source.slots,
                copies: read_copies(source.copies)?,
                holes: source.holes,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if encode(skeleton, &sources)? != bytes {
        return Err(bad_part());
    }
    Ok(sources)
}

/// Checks references, never grants native operation authority. A value must
/// name its real retained write or nonretained shallow winner, not merely a
/// current-map entry. A shallow alias of a retained write keeps its witness.
pub(crate) fn validate(skeleton: &Skeleton, sources: &[JoinedRecordDocument]) -> Result<()> {
    let mut sites = BTreeMap::new();
    let mut retained = BTreeSet::new();
    for change in &skeleton.changes {
        for (offset, op) in change.ops.iter().enumerate() {
            let Some(value) = op.value else { continue };
            if !retained.insert(value) {
                return Err(bad_part());
            }
            let offset = Lamport::try_from(offset).map_err(|_| bad_part())?;
            let lamport = change.lamport.checked_add(offset).ok_or_else(bad_part)?;
            site(
                skeleton,
                &mut sites,
                value,
                op.root,
                &op.key,
                change.peer,
                lamport,
            )?;
        }
    }
    for winner in skeleton.shallow.iter().flat_map(|root| &root.winners) {
        if let Some(value) = winner.value {
            site(
                skeleton,
                &mut sites,
                value,
                winner.root,
                &winner.key,
                winner.peer,
                winner.lamport,
            )?;
        }
    }
    for source in sources {
        let holes: BTreeSet<_> = source.holes.iter().collect();
        if holes.len() != source.holes.len()
            || source.copies.is_empty()
            || source
                .copies
                .iter()
                .any(|copy| !matches!(copy.home, AtomHome::Owner(_)))
        {
            return Err(bad_part());
        }
        check(
            skeleton,
            &sites,
            &source.slots.head,
            SKILL_DOCS_MAP,
            Some(&source.entity_key),
        )?;
        if source.slots.rows.is_empty() || source.slots.snapshot.is_empty() {
            return Err(bad_part());
        }
        for row in &source.slots.rows {
            check(skeleton, &sites, row, "entities", Some(&source.entity_key))?;
        }
        for leg in std::iter::once(&source.slots.snapshot).chain(source.slots.refinement.iter()) {
            if leg.is_empty() {
                return Err(bad_part());
            }
            for position in leg {
                if position.is_empty() {
                    return Err(bad_part());
                }
                for slot in position {
                    check(skeleton, &sites, slot, SKILL_DOCS_MAP, None)?;
                }
            }
        }
    }
    Ok(())
}

// A final value slot's native witness. Latest-state references are not sites.
type Sites<'s> = BTreeMap<AtomId, (&'s str, &'s str, PeerID, Lamport)>;

fn site<'s>(
    skeleton: &'s Skeleton,
    sites: &mut Sites<'s>,
    value: AtomId,
    root: u32,
    key: &'s str,
    peer: PeerID,
    lamport: Lamport,
) -> Result<()> {
    let root = usize::try_from(root)
        .ok()
        .and_then(|root| skeleton.roots.get(root))
        .ok_or_else(bad_part)?;
    let witness = (root.as_str(), key, peer, lamport);
    if sites
        .insert(value, witness)
        .is_some_and(|known| known != witness)
    {
        return Err(bad_part());
    }
    Ok(())
}

fn shape(skeleton: &Skeleton, id: AtomId, kind: SlotKind) -> Result<()> {
    let shape = usize::try_from(id)
        .ok()
        .and_then(|id| skeleton.slots.get(id))
        .ok_or_else(bad_part)?;
    if shape.kind != kind || shape.holders.is_empty() {
        return Err(bad_part());
    }
    Ok(())
}

fn check(
    skeleton: &Skeleton,
    sites: &Sites<'_>,
    slot: &RecordDocumentSlot,
    expected_root: &str,
    expected_key: Option<&str>,
) -> Result<()> {
    shape(skeleton, slot.value, SlotKind::Value)?;
    let &(root, key, _, _) = sites.get(&slot.value).ok_or_else(bad_part)?;
    if root != expected_root {
        return Err(bad_part());
    }
    match (placeholder_atom(key), slot.key, expected_key) {
        (None, None, Some(expected)) if key == expected => Ok(()),
        (Some(Some(actual)), Some(id), None) if actual == id => shape(skeleton, id, SlotKind::Key),
        _ => Err(bad_part()),
    }
}
