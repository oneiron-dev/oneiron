//! The epoch-summary body codec: pinned keys, strict encode and decode.
//!
//! FIX 5029: a body names its lineage, the SESSION and, for a chat epoch,
//! the conversation whose turns it counts over within that SESSION. The
//! `conversation` key is always present: MessagePack nil for an epoch of
//! the SESSION's own log, so the key set stays pinned.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Pinned body keys for an epoch summary, in encode order.
///
/// `actor` is LAST: the dreamer/loom byline is persisted as the final key, so
/// authorship closes the record rather than opening it.
pub const EPOCH_SUMMARY_BODY_KEYS: [&str; 9] = [
    "v",
    "session",
    "conversation",
    "epoch",
    "turn_start",
    "turn_end",
    "level",
    "text",
    "actor",
];

/// Current epoch-summary body codec version.
pub const EPOCH_SUMMARY_BODY_VERSION: u64 = 1;

/// `SUMMARY.level` an epoch summary mints at.
///
/// Storage truth is an UNBOUNDED integer (owner comment `9d06995b`). There is
/// no tier ladder here and no tier vocabulary anywhere in this module: names
/// for grains are display-layer property owned elsewhere.
pub const EPOCH_SUMMARY_LEVEL: u64 = 0;

/// Where each pinned key sits in [`EPOCH_SUMMARY_BODY_KEYS`].
pub(in crate::compaction) const AT_V: usize = 0;
pub(in crate::compaction) const AT_SESSION: usize = 1;
pub(in crate::compaction) const AT_CONVERSATION: usize = 2;
pub(in crate::compaction) const AT_EPOCH: usize = 3;
pub(in crate::compaction) const AT_TURN_START: usize = 4;
pub(in crate::compaction) const AT_TURN_END: usize = 5;
pub(in crate::compaction) const AT_LEVEL: usize = 6;
pub(in crate::compaction) const AT_TEXT: usize = 7;
pub(in crate::compaction) const AT_ACTOR: usize = 8;

const KEY_EPOCH_V: &str = EPOCH_SUMMARY_BODY_KEYS[AT_V];
pub(super) const KEY_EPOCH_SESSION: &str = EPOCH_SUMMARY_BODY_KEYS[AT_SESSION];
pub(super) const KEY_EPOCH_CONVERSATION: &str = EPOCH_SUMMARY_BODY_KEYS[AT_CONVERSATION];
const KEY_EPOCH_EPOCH: &str = EPOCH_SUMMARY_BODY_KEYS[AT_EPOCH];
const KEY_EPOCH_TURN_START: &str = EPOCH_SUMMARY_BODY_KEYS[AT_TURN_START];
const KEY_EPOCH_TURN_END: &str = EPOCH_SUMMARY_BODY_KEYS[AT_TURN_END];
const KEY_EPOCH_LEVEL: &str = EPOCH_SUMMARY_BODY_KEYS[AT_LEVEL];
pub(in crate::compaction) const KEY_EPOCH_TEXT: &str = EPOCH_SUMMARY_BODY_KEYS[AT_TEXT];
const KEY_EPOCH_ACTOR: &str = EPOCH_SUMMARY_BODY_KEYS[AT_ACTOR];

/// The typed epoch-summary body — the CB-A render contract.
///
/// CB-A (ONE-1701 keyframe render, ONE-1797 board tail) decodes an epoch
/// summary by calling the re-exported [`decode_epoch_summary_body`]. The body
/// deliberately does NOT ride `serialize.rs` SUMMARY field profiles
/// (`txt`/`lvl`/`at`/`src`): the typed codec IS the contract, so a render
/// cannot drift with a field-profile table it does not own.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EpochSummaryBody {
    /// Codec version, currently [`EPOCH_SUMMARY_BODY_VERSION`].
    pub v: u64,
    /// 32-hex ref of the SESSION this epoch belongs to.
    pub session: String,
    /// 32-hex ref of the conversation whose turns this epoch counts over
    /// within its SESSION (FIX 5029); `None` for an epoch of the SESSION's
    /// own log. The SESSION and this conversation are the epoch's lineage.
    pub conversation: Option<String>,
    /// 1-based. The next epoch number derives from the lineage's existing
    /// epoch summaries — durable entities ARE the counter, crash-safe by
    /// append-only lineage — never from a mutable session row.
    pub epoch: u64,
    pub turn_start: u64,
    pub turn_end: u64,
    /// Storage-truth ladder integer, unbounded and never named.
    pub level: u64,
    pub text: String,
    /// 32-hex ref of the host-stamped [`crate::WriteActor`] passed to
    /// [`crate::compaction::CompactionDriver::integrate`]. Guest-supplied authorship is
    /// unrepresentable: the writer stamps this, never the body's author.
    pub actor: String,
}

/// Encodes an epoch-summary body into its pinned-key MessagePack form.
///
/// The encoder enforces the SAME axes [`decode_epoch_summary_body`] refuses,
/// so this module cannot emit bytes it would itself reject on the way back
/// in: an unsupported codec version, an inverted turn range, a `session`,
/// `conversation` or `actor` that is not a 32-hex entity ref, or blank text
/// is a refusal here — at the moment the value is still in hand — rather
/// than a durable row whose consumers discover the problem at render time.
pub fn encode_epoch_summary_body(body: &EpochSummaryBody) -> Result<Vec<u8>> {
    if body.v != EPOCH_SUMMARY_BODY_VERSION {
        return Err(Error::InvariantViolation(
            "unsupported epoch summary codec version",
        ));
    }
    if body.turn_end < body.turn_start {
        return Err(Error::InvariantViolation("turn_end precedes turn_start"));
    }
    for hex in [body.session.as_str(), body.actor.as_str()]
        .into_iter()
        .chain(body.conversation.as_deref())
    {
        EntityId::from_hex(hex)
            .map_err(|_| Error::InvariantViolation("entity refs must be 32-hex strings"))?;
    }
    if body.text.trim().is_empty() {
        return Err(Error::InvariantViolation("epoch summary text is empty"));
    }
    let value = Value::Map(vec![
        (Value::from(KEY_EPOCH_V), Value::from(body.v)),
        (
            Value::from(KEY_EPOCH_SESSION),
            Value::from(body.session.as_str()),
        ),
        (
            Value::from(KEY_EPOCH_CONVERSATION),
            body.conversation.as_deref().map_or(Value::Nil, Value::from),
        ),
        (Value::from(KEY_EPOCH_EPOCH), Value::from(body.epoch)),
        (
            Value::from(KEY_EPOCH_TURN_START),
            Value::from(body.turn_start),
        ),
        (Value::from(KEY_EPOCH_TURN_END), Value::from(body.turn_end)),
        (Value::from(KEY_EPOCH_LEVEL), Value::from(body.level)),
        (Value::from(KEY_EPOCH_TEXT), Value::from(body.text.as_str())),
        (
            Value::from(KEY_EPOCH_ACTOR),
            Value::from(body.actor.as_str()),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("MessagePack encode failed"))?;
    Ok(out)
}

/// Strictly decodes an epoch-summary body.
///
/// Trailing bytes, non-map values, non-string keys, unknown keys and
/// duplicate keys are all refused — the same discipline the AGENT_DEF and
/// SKILL codecs enforce, so a host cannot smuggle a field into the keyframe.
pub fn decode_epoch_summary_body(bytes: &[u8]) -> Result<EpochSummaryBody> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvariantViolation("body is not valid MessagePack"))?;
    if !cursor.is_empty() {
        return Err(Error::InvariantViolation("trailing bytes after body map"));
    }
    let Value::Map(entries) = value else {
        return Err(Error::InvariantViolation("body must be a MessagePack map"));
    };

    let mut integers: [Option<u64>; EPOCH_SUMMARY_BODY_KEYS.len()] =
        [None; EPOCH_SUMMARY_BODY_KEYS.len()];
    let mut session = None;
    let mut conversation = None;
    let mut text = None;
    let mut actor = None;
    let mut seen = [false; EPOCH_SUMMARY_BODY_KEYS.len()];

    for (key, value) in &entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvariantViolation("body keys must be strings"));
        };
        let Some(index) = EPOCH_SUMMARY_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvariantViolation(
                "body key is not in the pinned EPOCH_SUMMARY_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvariantViolation("duplicate body key"));
        }
        seen[index] = true;
        match EPOCH_SUMMARY_BODY_KEYS[index] {
            KEY_EPOCH_SESSION => session = Some(epoch_summary_hex_ref(value)?),
            KEY_EPOCH_CONVERSATION => {
                conversation = Some(if value.is_nil() {
                    None
                } else {
                    Some(epoch_summary_hex_ref(value)?)
                });
            }
            KEY_EPOCH_ACTOR => actor = Some(epoch_summary_hex_ref(value)?),
            KEY_EPOCH_TEXT => {
                text = Some(
                    value
                        .as_str()
                        .ok_or(Error::InvariantViolation("text must be a UTF-8 string"))?
                        .to_owned(),
                );
            }
            _ => {
                integers[index] = Some(value.as_u64().ok_or(Error::InvariantViolation(
                    "numeric body keys must be unsigned integers",
                ))?);
            }
        }
    }

    let missing = || Error::InvariantViolation("missing required body key");
    let body = EpochSummaryBody {
        v: integers[AT_V].ok_or_else(missing)?,
        session: session.ok_or_else(missing)?,
        conversation: conversation.ok_or_else(missing)?,
        epoch: integers[AT_EPOCH].ok_or_else(missing)?,
        turn_start: integers[AT_TURN_START].ok_or_else(missing)?,
        turn_end: integers[AT_TURN_END].ok_or_else(missing)?,
        level: integers[AT_LEVEL].ok_or_else(missing)?,
        text: text.ok_or_else(missing)?,
        actor: actor.ok_or_else(missing)?,
    };
    if body.v != EPOCH_SUMMARY_BODY_VERSION {
        return Err(Error::InvariantViolation(
            "unsupported epoch summary codec version",
        ));
    }
    if body.turn_end < body.turn_start {
        return Err(Error::InvariantViolation("turn_end precedes turn_start"));
    }
    // Symmetric with the encoder: a keyframe whose whole point is prose the
    // render and the embedder consume cannot carry no prose at all, so the
    // codec refuses in both directions rather than round-tripping a body its
    // consumers would have to special-case.
    if body.text.trim().is_empty() {
        return Err(Error::InvariantViolation("epoch summary text is empty"));
    }
    Ok(body)
}

/// A 32-hex entity ref, validated as one rather than accepted as any string.
fn epoch_summary_hex_ref(value: &Value) -> Result<String> {
    let text = value.as_str().ok_or(Error::InvariantViolation(
        "entity refs must be 32-hex strings",
    ))?;
    EntityId::from_hex(text)
        .map_err(|_| Error::InvariantViolation("entity refs must be 32-hex strings"))?;
    Ok(text.to_owned())
}
