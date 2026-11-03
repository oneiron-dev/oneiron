//! What an erase reaches in identity maintenance (FIX 8707), and what a
//! revert checks before it puts anything back.
//!
//! The kept copies of a mention's bytes are the open asks, the saved hints'
//! contributions and the Dreamer's identity inverses. An erase of a turn or
//! a message drops each copy it fed: an ask on a mention in it goes, a
//! hint's contribution from it goes, and an inverse loses its copy of the
//! ask's text or a provisional entity's name while its content-free anchor
//! (ids, span and revision) stays, so the rest of that inverse still
//! reverts and its receipt stays. An erased entity leaves every ask and
//! inverse it was a candidate of, and its hints go. The same scrub runs at
//! both delete doors, for an erased actor and for a restored image's replay.
//!
//! A revert puts a copy back only while its mention still reads as it did:
//! its turn and message stand undeleted and the span's text is the copy's.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{ASKS, IdentityAsk, ProvisionalInverse, hints, index};
use crate::ports::TombstoneStoreRead;
use crate::store::Store;
use crate::vault::entity_revision::{ReadMode, RevisionRef, revision_for_mode_in_txn};
use crate::{EntityId, Result, Vault};

/// Where a kept copy's text came from, without the text: a saved span and
/// its message's live revision when the copy was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceAnchor {
    pub(super) turn: EntityId,
    pub(super) message: EntityId,
    pub(super) start: usize,
    pub(super) end: usize,
    /// The message's live revision then; none while it kept no document.
    pub(super) revision: Option<RevisionRef>,
}

impl SourceAnchor {
    /// Whether the span is in `id`, its turn or its message.
    pub(super) fn names(&self, id: &EntityId) -> bool {
        self.turn == *id || self.message == *id
    }

    /// Whether it anchors the same span as `other`.
    pub(super) fn same_span(&self, other: &Self) -> bool {
        (self.turn, self.message, self.start, self.end)
            == (other.turn, other.message, other.start, other.end)
    }
}

/// The anchor of the span of `turn` at `message`, `start`..`end`, at the
/// message's live revision now.
pub(super) fn anchor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (turn, message, start, end): (EntityId, EntityId, usize, usize),
) -> Result<SourceAnchor> {
    Ok(SourceAnchor {
        turn,
        message,
        start,
        end,
        revision: revision_for_mode_in_txn(&vault.store, txn, &message, ReadMode::Live)?,
    })
}

/// The anchor of `ask`'s mention.
pub(super) fn ask_anchor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ask: &IdentityAsk,
) -> Result<SourceAnchor> {
    anchor_in_txn(vault, txn, (ask.turn, ask.message, ask.start, ask.end))
}

/// Whether `id` stands: no delete, erase or archive marks it.
pub(super) fn stands_in_txn(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(!TombstoneStoreRead::port_deletion_state(store, txn, id)?.deleted)
}

/// Whether the text of the span of `turn` at `message`, `start`..`end`,
/// reads `name` now, both trimmed.
pub(super) fn span_reads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (turn, message, start, end): (EntityId, EntityId, usize, usize),
    name: &str,
) -> Result<bool> {
    let Some(text) = crate::tagging::message_text_in_txn(vault, txn, &turn, &message)? else {
        return Ok(false);
    };
    Ok(text.get(start..end).map(str::trim) == Some(name.trim()))
}

/// Whether the span `anchor` still reads as a copy of `name` made there:
/// its turn and message stand, and the span's text is `name`. A message
/// edited since whose span still reads `name` passes; the recorded revision
/// is a record, not a check.
pub(super) fn anchor_reads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    anchor: &SourceAnchor,
    name: &str,
) -> Result<bool> {
    if !stands_in_txn(&vault.store, txn, &anchor.turn)?
        || !stands_in_txn(&vault.store, txn, &anchor.message)?
    {
        return Ok(false);
    }
    span_reads_in_txn(
        vault,
        txn,
        (anchor.turn, anchor.message, anchor.start, anchor.end),
        name,
    )
}

/// Takes the erased `id` out of `ask`: none when the ask's own mention is
/// in it or no option is left (no candidate and no provisional entity of
/// its own), else whether it changed.
fn erase_from_ask(ask: &mut IdentityAsk, id: &EntityId) -> Option<bool> {
    if ask.turn == *id || ask.message == *id {
        return None;
    }
    let before = ask.candidates.len();
    ask.candidates.retain(|each| each != id);
    let mut changed = ask.candidates.len() != before;
    if ask.provisional == Some(*id) {
        ask.provisional = None;
        changed = true;
    }
    if ask.candidates.is_empty() && ask.provisional.is_none() {
        return None;
    }
    Some(changed)
}

/// Takes the erased `id` out of a kept copy of an ask: the copy is none
/// once its mention is in `id` or no option is left. True when it changed.
pub(super) fn erase_snapshot(ask: &mut Option<IdentityAsk>, id: &EntityId) -> bool {
    let outcome = match ask.as_mut() {
        Some(held) => erase_from_ask(held, id),
        None => return false,
    };
    match outcome {
        Some(changed) => changed,
        None => {
            *ask = None;
            true
        }
    }
}

impl ProvisionalInverse {
    /// Takes the erased `id` out of the kept prior ask; its anchor stays.
    /// True when it changed.
    pub(in crate::dreamer_runner::maintenance) fn erase_source(&mut self, id: &EntityId) -> bool {
        erase_snapshot(&mut self.prior, id)
    }
}

/// Drops what of the open asks depends on the erased `id`: an ask on a
/// mention in it goes, and one it was a candidate of keeps its other
/// options, or goes when none is left.
fn erase_asks_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<()> {
    for (_, key) in index::ASK_BY_SOURCE.scan_keys(store, txn, id.as_bytes())? {
        // A stale membership row names no ask: an extra read, never a scrub.
        let Some(mut ask) = ASKS.get(store, txn, &key)? else {
            continue;
        };
        let old = index::ask_ids(&ask);
        match erase_from_ask(&mut ask, id) {
            Some(false) => {}
            Some(true) => {
                ASKS.put(store, txn, &key, &ask)?;
                index::sync_ask_sets(store, txn, &key, &old, &index::ask_ids(&ask))?;
            }
            None => {
                ASKS.delete(store, txn, &key)?;
                index::sync_ask_sets(store, txn, &key, &old, &BTreeSet::new())?;
            }
        }
    }
    Ok(())
}

/// Drops every copy identity maintenance keeps of the erased `id`'s bytes,
/// in the erase's own transaction: the open asks, the saved hints and the
/// Dreamer's identity inverses, reverted ones too. A no-op for an id none
/// names.
pub(crate) fn erase_sources_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    erase_asks_in_txn(store, txn, id)?;
    hints::erase_in_txn(store, txn, id)?;
    super::super::applied::erase_identity_inverses_in_txn(store, txn, id)
}

/// The identity ask table's actor scrub (FIX 3520): an actor's erase, and a
/// restored image's replay of every erased id, run [`erase_sources_in_txn`].
pub(crate) fn erase_actor_sources_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    erase_sources_in_txn(&vault.store, txn, id)
}
