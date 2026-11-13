//! Whether a saved tag set still reads its turn as published (FIX 10169).
//!
//! A published edit of a turn's text only queues its retag marker; until
//! that marker settles, the turn's saved tags, their mood and the
//! provisional names they hold were read from the text before. They stay
//! readable to every caller who could read them, and are said to be stale:
//! no read door withholds them for it and no new hold waits on the retag.
//! Freshness is derived at read from what the set saved (its envelope's
//! digests) and the turn's text now, never kept in a second table.

use serde::{Deserialize, Serialize};

use super::input::{TurnInput, turn_input_in_txn};
use super::marker::{TAGGING_MARKER_KIND, dedupe_key};
use super::tags::TurnTags;
use crate::attempt_queue::AttemptQueue;
use crate::error::Result;
use crate::{EntityId, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::tagging::freshness::{TaggingFreshness, TaggingMoodPartView};

/// How current `tags`, the set saved for `turn`, is in `txn`: stale unless
/// its envelope names the input the turn reads now (with or without its live
/// window) or, for a conversation register's set, the turn's text now; a
/// turn that reads gone or empty leaves its set stale. Pending while the
/// turn's marker is owed.
pub(crate) fn tagging_freshness_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    tags: &TurnTags,
) -> Result<TaggingFreshness> {
    let current = match turn_input_in_txn(vault, txn, turn)? {
        TurnInput::Ready {
            hash, text_hash, ..
        } => {
            let read = &tags.envelope.content_hash;
            *read == hash
                || *read == text_hash
                || tags.envelope.text_hash.as_deref() == Some(text_hash.as_str())
        }
        TurnInput::Gone | TurnInput::Empty => false,
    };
    let pending_retag = match vault.tagging_marker_config() {
        Some(config) => AttemptQueue::from_store(&vault.store)
            .pending_dedupe_in_txn(txn, TAGGING_MARKER_KIND, &dedupe_key(turn, &config))?
            .is_some(),
        None => false,
    };
    Ok(TaggingFreshness {
        stale: !current,
        pending_retag,
    })
}

/// [`tagging_freshness_in_txn`] for the set's mood: stale too when the mood
/// is an earlier set's, kept because the last answer read the turn in
/// windows and measured no mood of the whole of it.
pub(crate) fn mood_freshness(freshness: TaggingFreshness, tags: &TurnTags) -> TaggingFreshness {
    TaggingFreshness {
        stale: freshness.stale || tags.mood_carried,
        pending_retag: freshness.pending_retag,
    }
}

/// `tags`' window moods, their messages named by ref; a part whose message
/// the set does not list is left out.
pub(crate) fn mood_part_views(tags: &TurnTags) -> Vec<TaggingMoodPartView> {
    tags.mood_parts
        .iter()
        .filter_map(|part| {
            Some(TaggingMoodPartView {
                message_ref: tags.messages.get(part.message)?.to_hex(),
                start: part.start,
                end_message_ref: tags.messages.get(part.end_message)?.to_hex(),
                end: part.end,
                valence: part.vad.valence,
                arousal: part.vad.arousal,
                dominance: part.vad.dominance,
            })
        })
        .collect()
}

impl Vault {
    /// How current the tags saved for `turn` are, in one read; `None` while
    /// no set reads for it.
    pub fn tagging_freshness(&self, turn: &EntityId) -> Result<Option<TaggingFreshness>> {
        let txn = self.store.env.read_txn()?;
        let Some(tags) = super::tags::readable_view_in_txn(&self.store, &txn, turn)? else {
            return Ok(None);
        };
        tagging_freshness_in_txn(self, &txn, turn, &tags).map(Some)
    }

    /// How current the name of the provisional entity `id` is: its origin
    /// turn's tags' freshness. A name read from text since edited stays
    /// readable, said to be stale; `None` while it is no provisional entity
    /// whose text reads.
    pub fn provisional_entity_freshness(&self, id: &EntityId) -> Result<Option<TaggingFreshness>> {
        let Some(entity) = self.provisional_entity(id)? else {
            return Ok(None);
        };
        self.tagging_freshness(&entity.origin)
    }
}
