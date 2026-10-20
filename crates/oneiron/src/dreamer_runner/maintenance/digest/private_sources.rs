//! The proactivity digest's screen of private thread words (FIX 6411; FIX
//! 6381 and 6383: "never the words"). A proposal's words come from its claim
//! and, transitively, from each claim's typed consolidation refs and the
//! sources its writes registered (the MESSAGEs its evidence cites). Each
//! record reached meets the private thread walk every audience read meets
//! ([`crate::conversation::private_threads_readable_with_read_in`]): a viewer
//! reads the item only while it stands in each private thread those words
//! sit in, each turn under the CONTENT rule, so a viewer outside the thread,
//! or added after the turn, does not.
//!
//! The turns found when a digest is assembled are pinned on the item, so a
//! later public rewrite of its claim cannot relabel words a digest already
//! keeps; a read checks the pins and the ancestry as it stands. A declared
//! private source that does not resolve withholds that item alone. A record
//! off every private thread, or a claim with no consolidation evidence, is
//! never refused here, and nothing else in a digest narrows.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::DigestProposal;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::{EntityId, Error, Result, Vault};

/// One private thread turn a proposal's words were drawn from when its
/// digest was assembled (FIX 6411).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestPrivateSource {
    /// The thread's root TURN.
    #[serde(with = "crate::serialize::entity_ref")]
    pub root: EntityId,
    /// The turn the words were read from.
    #[serde(with = "crate::serialize::entity_ref")]
    pub turn: EntityId,
}

/// The private thread turns the words of the proposal `claim` are drawn
/// from, to pin on it as its digest is assembled; empty for words off every
/// private thread. `None` when a source its ancestry declares does not
/// resolve, or the walk does not read: no view carries that item.
pub(super) fn digest_private_sources_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: EntityId,
) -> Option<Vec<DigestPrivateSource>> {
    let turns = word_turns_in(vault, txn, claim).ok().flatten()?;
    Some(
        turns
            .into_iter()
            .map(|(root, turn)| DigestPrivateSource { root, turn })
            .collect(),
    )
}

/// Whether `viewer` reads the words of `item`: each turn pinned on it under
/// the CONTENT rule as the thread's audience stands now, and every record
/// its claim's words come from now, by the private thread walk. An item a
/// declared source left unresolved, or whose walk does not read, is
/// withheld; no other item is.
pub(super) fn digest_item_readable_by_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    item: &DigestProposal,
    viewer: EntityId,
) -> bool {
    !item.unverified && readable_in(vault, txn, item, viewer).unwrap_or(false)
}

/// [`digest_item_readable_by_in`] past the unverified mark.
fn readable_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    item: &DigestProposal,
    viewer: EntityId,
) -> Result<bool> {
    let dbs = vault.store.read();
    let viewers = [viewer];
    for source in &item.private_sources {
        if !crate::workspace_roster::thread_turn_readable_with_read_in(
            vault,
            &dbs,
            txn,
            source.root,
            source.turn,
            &viewers,
        )? {
            return Ok(false);
        }
    }
    for (id, raw) in word_records_in(vault, txn, item.claim_ref)? {
        if !crate::conversation::private_threads_readable_with_read_in(
            vault, &dbs, txn, id, &raw, &viewers, false,
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Every private thread turn, by its root, the records of `claim`'s words
/// are read from; `None` where the walk of one denies every viewer.
fn word_turns_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: EntityId,
) -> Result<Option<BTreeSet<(EntityId, EntityId)>>> {
    let mut turns = BTreeSet::new();
    for (id, raw) in word_records_in(vault, txn, claim)? {
        match crate::conversation::private_thread_word_turns_in(vault, txn, id, &raw)? {
            Some(found) => turns.extend(found),
            None => return Ok(None),
        }
    }
    Ok(Some(turns))
}

/// The records a proposal's words are drawn from, each as its row stands:
/// its claim, then, transitively, each claim's typed consolidation refs and
/// every record's registered dependency sources. A record that is gone names
/// nothing here, as a gone ancestor names nothing in the thread walk; the
/// walk ends where it has seen every record, and nothing is capped (Rule 5).
fn word_records_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: EntityId,
) -> Result<Vec<(EntityId, Vec<u8>)>> {
    let mut pending = vec![claim];
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
        else {
            continue;
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("digest word source header"))?;
        if header.entity_type == ENTITY_TYPE_CLAIM
            && let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..)
            && let Ok(claim) = crate::claim::decode_claim_body(body, true)
        {
            pending.extend(consolidation_refs(&claim));
        }
        pending.extend(crate::ports::dependency_sources_in(&vault.store, txn, &id)?);
        records.push((id, raw));
    }
    Ok(records)
}

/// The typed consolidation refs `claim`'s evidence names: its envelope's
/// `refs`, kept under `candidate_evidence` or as the whole evidence. None
/// for a claim with no envelope, or one that does not decode, which the
/// thread walk reads as it reads any record.
fn consolidation_refs(claim: &crate::ClaimBody) -> Vec<EntityId> {
    let Some(evidence) = claim.evidence.as_ref() else {
        return Vec::new();
    };
    let stored = evidence
        .as_map()
        .and_then(|fields| {
            fields
                .iter()
                .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
                .map(|(_, value)| value)
        })
        .unwrap_or(evidence);
    crate::dreamer_consolidation::decode_consolidation_evidence(stored)
        .ok()
        .flatten()
        .map(|envelope| envelope.refs)
        .unwrap_or_default()
}
