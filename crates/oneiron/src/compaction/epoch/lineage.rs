//! An epoch's lineage: its scope, its durable prior and its boundary.
//!
//! FIX 5029: a lineage is a SESSION's own log, or one conversation's turns
//! within a SESSION. Two conversations witnessed into one sitting each keep
//! their own epochs, so neither takes the other's epoch as its prior. The
//! durable rows are the counter in each lineage, and a removed epoch keeps
//! its place there through the floor it left.

use rmpv::Value;

use super::codec::{
    AT_TURN_END, EPOCH_SUMMARY_BODY_KEYS, KEY_EPOCH_CONVERSATION, KEY_EPOCH_SESSION,
    decode_epoch_summary_body,
};
use crate::compaction::driver::CompactionWindowMessage;
use crate::compaction::withdrawn::WithdrawnKeyframe;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SUMMARY;
use crate::side_table::SideKey;
use crate::store::Store;

/// The lineage an epoch counts in (FIX 5029): a SESSION's own log, or one
/// conversation's turns within a SESSION. A lineage's epochs number from 1
/// and its turn ranges continue one another; another lineage's epochs are
/// never its prior, in the same SESSION or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EpochScope {
    pub(crate) session: EntityId,
    pub(crate) conversation: Option<EntityId>,
}

impl EpochScope {
    /// The SESSION's own log.
    pub(crate) const fn of_session(session: EntityId) -> Self {
        Self {
            session,
            conversation: None,
        }
    }

    /// `conversation`'s turns within `session`.
    pub(crate) const fn of_conversation(session: EntityId, conversation: EntityId) -> Self {
        Self {
            session,
            conversation: Some(conversation),
        }
    }
}

/// A floor row's key: the SESSION's 16 bytes, then the conversation's for a
/// conversation's lineage.
impl SideKey for EpochScope {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.session.encode_into(out);
        if let Some(conversation) = &self.conversation {
            conversation.encode_into(out);
        }
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (session, rest) = bytes.split_at_checked(16)?;
        let conversation = if rest.is_empty() {
            None
        } else {
            Some(EntityId::decode_key(rest)?)
        };
        Some(Self {
            session: EntityId::decode_key(session)?,
            conversation,
        })
    }
}

/// Recognizes a lineage's epoch-shaped map even when strict decoding fails.
///
/// Identity requires the pinned version/session/conversation/epoch/turn-range
/// keys, or the full pinned key set with just one key missing. A lone shared
/// application field is not epoch identity. Read top-level keys in order so
/// a damaged suffix cannot hide identity already read. Apart from the
/// session match, strict decoding owns value validation; the codec permits
/// any key order. A row is another lineage's only when it readably names
/// exactly one conversation that is not `scope`'s; a conversation it does not
/// name readably may be this one.
fn is_epoch_candidate_for_scope(bytes: &[u8], scope: &EpochScope) -> bool {
    let (pairs, mut cursor) = match bytes {
        [marker @ 0x80..=0x8f, rest @ ..] => (u32::from(*marker & 0x0f), rest),
        [0xde, a, b, rest @ ..] => (u32::from(u16::from_be_bytes([*a, *b])), rest),
        [0xdf, a, b, c, d, rest @ ..] => (u32::from_be_bytes([*a, *b, *c, *d]), rest),
        _ => return false,
    };
    let mut matching_session = false;
    let mut named: Vec<Option<Option<EntityId>>> = Vec::new();
    let mut seen = [false; EPOCH_SUMMARY_BODY_KEYS.len()];
    for _ in 0..pairs {
        let Ok(key) = rmpv::decode::read_value(&mut cursor) else {
            break;
        };
        if let Some(index) = EPOCH_SUMMARY_BODY_KEYS
            .iter()
            .position(|known| Some(*known) == key.as_str())
        {
            seen[index] = true;
        }
        let Ok(value) = rmpv::decode::read_value(&mut cursor) else {
            break;
        };
        match key.as_str() {
            Some(KEY_EPOCH_SESSION) => {
                matching_session |= value
                    .as_str()
                    .and_then(|text| EntityId::from_hex(text).ok())
                    .is_some_and(|id| id == scope.session);
            }
            Some(KEY_EPOCH_CONVERSATION) => named.push(conversation_named(&value)),
            _ => {}
        }
    }
    let other_lineage =
        matches!(named.as_slice(), [Some(conversation)] if *conversation != scope.conversation);
    // The pinned keys through `turn_end` carry codec and lineage identity.
    // Count distinct keys, not occurrences: duplicates cannot supply identity.
    let identity_keys = seen[..=AT_TURN_END].iter().all(|&present| present);
    let one_missing_key = seen.iter().filter(|&&present| !present).count() == 1;
    matching_session && !other_lineage && (identity_keys || one_missing_key)
}

/// The conversation a stored `conversation` value names: `Some(None)` for
/// nil, `Some(Some(id))` for a 32-hex ref, `None` for anything else.
fn conversation_named(value: &Value) -> Option<Option<EntityId>> {
    if value.is_nil() {
        return Some(None);
    }
    value
        .as_str()
        .and_then(|text| EntityId::from_hex(text).ok())
        .map(Some)
}

/// One durable prior epoch of a lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PriorEpoch {
    epoch: u64,
    turn_end: u64,
}

impl PriorEpoch {
    pub(crate) const fn new(epoch: u64, turn_end: u64) -> Self {
        Self { epoch, turn_end }
    }
}

/// The claimed range must cover every distinct turn, in message-log order.
pub(in crate::compaction) fn validate_window_span(
    window: &[CompactionWindowMessage],
) -> Result<(u64, u64)> {
    let Some(first) = window.first() else {
        return Err(Error::InvariantViolation(
            "compaction window carries no messages",
        ));
    };
    let mut last = first.turn;
    for message in &window[1..] {
        if message.turn != last && last.checked_add(1) != Some(message.turn) {
            return Err(Error::InvariantViolation(
                "compaction window turns must be ordered and contiguous",
            ));
        }
        last = message.turn;
    }
    Ok((first.turn, last))
}

/// Checked both at request issuance and under the mint's write transaction.
pub(in crate::compaction) fn validate_epoch_boundary(
    prior: Option<PriorEpoch>,
    turn_start: u64,
) -> Result<()> {
    if let Some(prior) = prior {
        let next = prior
            .turn_end
            .checked_add(1)
            .ok_or(Error::InvariantViolation(
                "compaction turn boundary is exhausted",
            ))?;
        if turn_start != next {
            return Err(Error::InvariantViolation(
                "compaction window does not start at the next durable turn boundary",
            ));
        }
    }
    Ok(())
}

/// Reads the highest durable epoch summary of `scope`'s lineage.
///
/// The DURABLE entities are the counter: a crash between two compactions can
/// never desynchronize an epoch number from the rows that justify it, because
/// the only other input, the floor a removed epoch leaves, is written in the
/// transaction that removes it.
///
/// Rows whose body is not an epoch-summary record are SKIPPED, not refused: an
/// ordinary witness SUMMARY is a different kind of row that happens to share
/// the type byte, and it carries no epoch to compare. An identifiable malformed
/// epoch candidate for this lineage is refused rather than losing its lineage.
/// A withdrawn epoch counts by the keyframe it keeps, and a purged or demoted
/// one by the lineage's epoch floor, so numbering never restarts under either.
/// Only `scope`'s own epochs count (FIX 5029): a SESSION's log reads its
/// session epochs, a conversation its own epochs within that SESSION.
pub(in crate::compaction) fn prior_epoch_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    scope: &EpochScope,
) -> Result<Option<PriorEpoch>> {
    let mut best: Option<(WithdrawnKeyframe, Option<String>)> = None;
    let mut conflicting = false;
    for row in store.port_entity_records(rtxn)? {
        let (_, row) = row?;
        if row.entity_type != ENTITY_TYPE_SUMMARY || row.body.is_empty() {
            continue;
        }
        let bytes = &row.body;
        let (keyframe, text) = match decode_epoch_summary_body(bytes) {
            Ok(body) => (WithdrawnKeyframe::of_body(&body)?, Some(body.text)),
            Err(error) => match WithdrawnKeyframe::decode(bytes) {
                Ok(keyframe) => (keyframe, None),
                Err(_) if is_epoch_candidate_for_scope(bytes, scope) => return Err(error),
                Err(_) => continue,
            },
        };
        if keyframe.scope() != *scope {
            continue;
        }
        match best.as_ref() {
            Some((prior, _)) if keyframe.epoch < prior.epoch => {}
            Some((prior, prior_text)) if keyframe.epoch == prior.epoch => {
                // Lineages and epoch numbers already match; actor IDs
                // compare as IDs, not as the codec spells them. Different
                // keyframes at the highest epoch remain conflicts, and so do
                // words beside none: a withdrawn one keeps nothing to compare.
                conflicting |= keyframe != *prior || text != *prior_text;
            }
            _ => {
                best = Some((keyframe, text));
                conflicting = false;
            }
        }
    }
    // Wait until the maximum is known: a lower tied epoch must not make the
    // answer depend on which entity ID the store iterated first.
    if conflicting {
        return Err(Error::InvariantViolation(
            "conflicting summaries at the highest compaction epoch",
        ));
    }
    // A removed epoch keeps its place through the floor it left (OF-013).
    let row = best.map(|(keyframe, _)| (keyframe.epoch, keyframe.turn_end));
    let floor = crate::compaction::epoch_floor::epoch_floor_in_txn(store, rtxn, scope)?;
    Ok(row
        .max(floor)
        .map(|(epoch, turn_end)| PriorEpoch { epoch, turn_end }))
}

/// The epoch after `prior`, or the first.
pub(super) fn next_epoch(prior: Option<PriorEpoch>) -> Result<u64> {
    match prior {
        Some(prior) => prior.epoch.checked_add(1).ok_or(Error::InvariantViolation(
            "compaction epoch counter is exhausted",
        )),
        None => Ok(1),
    }
}
