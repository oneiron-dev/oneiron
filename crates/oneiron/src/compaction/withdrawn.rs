//! What a withdrawn epoch summary keeps: its keyframe, without its words.
//!
//! The public epoch codec stays strict and nonblank. A withdrawn row has its
//! own internal form, every pinned key but `text`, with no pointer and no
//! digest of what it said, so the durable counter still reads it.

use rmpv::Value;

use super::epoch::KEY_EPOCH_TEXT;
use super::stored_epoch::{StoredEpoch, stored_epoch_in};
use super::{EPOCH_SUMMARY_BODY_KEYS, EPOCH_SUMMARY_BODY_VERSION, EpochSummaryBody};
use crate::deletion::WithdrawnReplacement;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EntityStoreMaintenance, EntityStoreRead, ScrubbedRecord};
use crate::registry::ENTITY_TYPE_SUMMARY;
use crate::store::Store;

const KEY_V: &str = EPOCH_SUMMARY_BODY_KEYS[0];
const KEY_SESSION: &str = EPOCH_SUMMARY_BODY_KEYS[1];
const KEY_EPOCH: &str = EPOCH_SUMMARY_BODY_KEYS[2];
const KEY_TURN_START: &str = EPOCH_SUMMARY_BODY_KEYS[3];
const KEY_TURN_END: &str = EPOCH_SUMMARY_BODY_KEYS[4];
const KEY_LEVEL: &str = EPOCH_SUMMARY_BODY_KEYS[5];
const KEY_ACTOR: &str = EPOCH_SUMMARY_BODY_KEYS[7];

/// A withdrawn epoch summary's stored body: the pinned keys less `text`, so
/// `v`, `session`, `epoch`, `turn_start`, `turn_end`, `level` and `actor`.
/// The codec version is always [`EPOCH_SUMMARY_BODY_VERSION`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WithdrawnKeyframe {
    pub(super) session: EntityId,
    pub(super) epoch: u64,
    pub(super) turn_start: u64,
    pub(super) turn_end: u64,
    level: u64,
    actor: EntityId,
}

impl WithdrawnKeyframe {
    /// The keyframe of a strictly decoded epoch body.
    pub(super) fn of_body(body: &EpochSummaryBody) -> Result<Self> {
        Ok(Self {
            session: EntityId::from_hex(&body.session)?,
            epoch: body.epoch,
            turn_start: body.turn_start,
            turn_end: body.turn_end,
            level: body.level,
            actor: EntityId::from_hex(&body.actor)?,
        })
    }

    /// Strictly decodes a withdrawn keyframe: exactly its seven keys, once
    /// each, and no trailing bytes.
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = bytes;
        let Ok(Value::Map(fields)) = rmpv::decode::read_value(&mut cursor) else {
            return Err(refused());
        };
        if !cursor.is_empty() {
            return Err(refused());
        }
        Self::read(&fields, true)
    }

    /// The keyframe kept in the stored epoch body `body`, inline or beside a
    /// pointer; `None` when its keyframe keys do not hold one.
    fn of_stored(body: &[u8]) -> Option<Self> {
        let mut cursor = body;
        let Ok(Value::Map(fields)) = rmpv::decode::read_value(&mut cursor) else {
            return None;
        };
        Self::read(&fields, false).ok()
    }

    /// Reads the keyframe keys of `fields`. `strict` refuses any other key;
    /// otherwise the text, the pointer and any other key are passed by.
    fn read(fields: &[(Value, Value)], strict: bool) -> Result<Self> {
        let mut held: [Option<&Value>; EPOCH_SUMMARY_BODY_KEYS.len()] =
            [None; EPOCH_SUMMARY_BODY_KEYS.len()];
        for (key, value) in fields {
            let index = key
                .as_str()
                .filter(|key| *key != KEY_EPOCH_TEXT)
                .and_then(|key| {
                    EPOCH_SUMMARY_BODY_KEYS
                        .iter()
                        .position(|known| *known == key)
                });
            match index {
                Some(index) => {
                    if held[index].replace(value).is_some() {
                        return Err(refused());
                    }
                }
                None if strict => return Err(refused()),
                None => {}
            }
        }
        let number = |index: usize| held[index].and_then(Value::as_u64).ok_or_else(refused);
        let id = |index: usize| {
            held[index]
                .and_then(Value::as_str)
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or_else(refused)
        };
        if number(0)? != EPOCH_SUMMARY_BODY_VERSION {
            return Err(refused());
        }
        let keyframe = Self {
            session: id(1)?,
            epoch: number(2)?,
            turn_start: number(3)?,
            turn_end: number(4)?,
            level: number(5)?,
            actor: id(7)?,
        };
        if keyframe.turn_end < keyframe.turn_start {
            return Err(refused());
        }
        Ok(keyframe)
    }

    /// The keyframe's stored bytes, in pinned key order.
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let value = Value::Map(vec![
            (Value::from(KEY_V), Value::from(EPOCH_SUMMARY_BODY_VERSION)),
            (Value::from(KEY_SESSION), Value::from(self.session.to_hex())),
            (Value::from(KEY_EPOCH), Value::from(self.epoch)),
            (Value::from(KEY_TURN_START), Value::from(self.turn_start)),
            (Value::from(KEY_TURN_END), Value::from(self.turn_end)),
            (Value::from(KEY_LEVEL), Value::from(self.level)),
            (Value::from(KEY_ACTOR), Value::from(self.actor.to_hex())),
        ]);
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &value)
            .map_err(|_| Error::InvariantViolation("MessagePack encode failed"))?;
        Ok(out)
    }
}

fn refused() -> Error {
    Error::InvariantViolation("not a withdrawn epoch keyframe")
}

/// Whether `body` is a withdrawn epoch keyframe, the content-free form a
/// withdrawn generation keeps.
#[cfg(feature = "sync")]
pub(crate) fn is_withdrawn_keyframe(body: &[u8]) -> bool {
    WithdrawnKeyframe::decode(body).is_ok()
}

/// The content-free stand-in for epoch summary carrier `envelope` (its
/// header, then its stored body): the same header, then the keyframe the body
/// keeps, as [`ScrubbedRecord::WithdrawnEpoch`] leaves the row. `None` when
/// the carrier is no SUMMARY or its body keeps no keyframe.
#[cfg(feature = "sync")]
pub(crate) fn withdrawn_keyframe_envelope(envelope: &[u8]) -> Result<Option<Vec<u8>>> {
    let header_len = crate::batch::ENTITY_METADATA_HEADER_LEN;
    let Some(header) = crate::batch::EntityMetadataHeader::parse(envelope) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_SUMMARY {
        return Ok(None);
    }
    let Some(keyframe) = WithdrawnKeyframe::of_stored(&envelope[header_len..]) else {
        return Ok(None);
    };
    let mut out = envelope[..header_len].to_vec();
    out.extend(keyframe.encode()?);
    Ok(Some(out))
}

/// What erasure leaves of stored row `envelope` (its header, then its body):
/// an epoch summary keeps its keyframe, as a withdrawn one does, so epoch
/// numbering never restarts under an erased epoch; any other row keeps its
/// header only.
pub(crate) fn erased_form(envelope: &[u8]) -> ScrubbedRecord {
    crate::batch::EntityMetadataHeader::parse(envelope)
        .filter(|header| header.entity_type == ENTITY_TYPE_SUMMARY)
        .and_then(|_| envelope.get(crate::batch::ENTITY_METADATA_HEADER_LEN..))
        .and_then(WithdrawnKeyframe::of_stored)
        .map_or(ScrubbedRecord::Shell, ScrubbedRecord::WithdrawnEpoch)
}

/// Takes withdrawn epoch summary `id`'s words from its row and from the
/// carriers beside it on this device: its document, its row revisions, its
/// short-id rows and the L2 cache. The row keeps its header and keyframe, or
/// only its header when its keyframe keys do not decode.
///
/// The caller has marked `id` stale, recorded its worlds and walked every
/// epoch written from it; the keyframe still reads as an epoch for any walk
/// after. The historical sweep's obligation for this generation is staged
/// first, ids only; window history and queued sends are that sweep's. Any
/// other row, a live one or one already scrubbed, is left as it is.
pub(crate) fn scrub_withdrawn_epoch_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(row) = store.port_entity_record(txn, id)? else {
        return Ok(());
    };
    if row.entity_type != ENTITY_TYPE_SUMMARY
        || WithdrawnKeyframe::decode(&row.body).is_ok()
        || !crate::ports::stale_in_txn(store, txn, id)?
    {
        return Ok(());
    }
    let form = stored_epoch_in(store, txn, id, &row.body)?;
    if !form.may_be() {
        return Ok(());
    }
    // A pointer no head stands for may carry any world's words; its record
    // keeps that before the pointer goes.
    if form == StoredEpoch::Unresolved {
        crate::ports::keep_deleted_worlds_in_txn(store, txn, id)?;
    }
    let keyframe = WithdrawnKeyframe::of_stored(&row.body);
    let at = crate::ports::recorded_at_in_txn(store, txn)?;
    crate::deletion::enqueue_withdrawn_generation_in_txn(
        store,
        txn,
        id,
        row.learned_at,
        WithdrawnReplacement::EpochKeyframe,
        at,
    )?;
    #[cfg(feature = "sync")]
    crate::entity_doc::erase_in_txn(store, txn, id)?;
    crate::vault::entity_revision::remove_entity_revisions(store, txn, id)?;
    crate::batch::delete_short_id_rows_for_id(store, txn, id)?;
    store
        .l2_base_cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .erase(id, store.env.info().last_txn_id);
    let scrubbed = keyframe.map_or(ScrubbedRecord::Shell, ScrubbedRecord::WithdrawnEpoch);
    store.port_entity_scrub(txn, id, scrubbed, at)?;
    Ok(())
}
