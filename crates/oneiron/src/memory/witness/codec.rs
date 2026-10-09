//! Turn-speaker and message-envelope codec plus session alias formatting.

use super::super::support::*;
use super::super::*;

use rmpv::{Value, ValueRef};

use crate::gate::WitnessMessageEnvelope;

/// Renders a session-local alias in the same `short_id:content_hash` shape the
/// base resolver produces, so a client formats one kind of ref.
///
/// The alias itself is what keeps the namespaces apart: session ids carry the
/// `s` sigil, which is not a legal base prefix, so an in-room ref can neither
/// shadow a durable entity nor resolve at a base door.
pub(super) fn session_short_ref_string((short_id, content_hash): &(String, u8)) -> String {
    format!("{short_id}:{content_hash:02x}")
}

/// The one additive TURN-body key the witness door stamps. A turn's speaker
/// is a turn-level grouping fact, not a per-message one: the content stays
/// on the MESSAGE children.
const WITNESS_TURN_SPEAKER_KEY: &str = "speaker";

/// The canonical TURN speaker string for one author bucket; `None` for the
/// `System` bucket, which is interleave and never a grouping speaker.
///
/// These are the ROLE strings the consolidation scanner reads
/// (`dreamer_turn_role`), not the MESSAGE-body `author` vocabulary: a turn
/// stamped `companion` would score `Unknown` and never reach extraction
/// unless the host lists that name in `VaultConfig::assistant_display_names`.
const fn canonical_turn_speaker(author: WitnessAuthor) -> Option<&'static str> {
    match author {
        WitnessAuthor::User => Some("user"),
        WitnessAuthor::Companion => Some("assistant"),
        WitnessAuthor::System => None,
    }
}

/// The call's unique non-system speaker.
///
/// `None` means this call contains only permitted system/tooling/REPL
/// interleave. More than one distinct non-system speaker is a bad request:
/// a TURN is the maximal consecutive run of ONE speaker.
pub(super) fn incoming_turn_speaker(
    messages: &[WitnessMessage],
) -> MemoryResult<Option<&'static str>> {
    let mut speaker: Option<&'static str> = None;
    for message in messages {
        let Some(candidate) = canonical_turn_speaker(message.author) else {
            continue;
        };
        match speaker {
            Some(existing) if existing != candidate => {
                return Err(MemoryError::bad_request_with(
                    "a witnessed turn carries one non-system speaker",
                    &["Witness each speaker's consecutive run as its own turn."],
                ));
            }
            _ => speaker = Some(candidate),
        }
    }
    Ok(speaker)
}

/// Strict writer-side TURN-speaker decoder: the body must carry exactly one
/// `speaker` entry holding a non-empty string.
///
/// It deliberately does not inspect MESSAGE children, follow `AuthoredBy`,
/// read the scanner's `spkr` alias, or accept a missing key. An append that
/// cannot read the grouping fact must refuse, not invent one — a synthesized
/// speaker would let a second speaker's messages join a turn that already
/// belongs to someone else.
pub(in crate::memory) fn decode_witness_turn_speaker(body: &[u8]) -> MemoryResult<&str> {
    let unstamped = || {
        MemoryError::bad_request_with(
            "the witnessed turn carries no speaker",
            &["Witness a new turn instead of appending to an unstamped one."],
        )
    };
    let mut cursor = body;
    let Ok(ValueRef::Map(entries)) = rmpv::decode::read_value_ref(&mut cursor) else {
        return Err(unstamped());
    };
    let mut speaker: Option<&str> = None;
    for (key, value) in entries {
        let ValueRef::String(key) = key else {
            continue;
        };
        if key.as_str() != Some(WITNESS_TURN_SPEAKER_KEY) {
            continue;
        }
        if speaker.is_some() {
            return Err(unstamped());
        }
        let ValueRef::String(text) = value else {
            return Err(unstamped());
        };
        speaker = match text.into_str() {
            Some(text) if !text.is_empty() => Some(text),
            _ => return Err(unstamped()),
        };
    }
    speaker.ok_or_else(unstamped)
}

/// A PERSON author is an immutable identity stamp, not a speaker label.
/// Non-PERSON writer actors leave the author unknown.
pub(super) fn encode_witness_turn_body(
    speaker: &str,
    person: Option<crate::EntityId>,
) -> MemoryResult<Vec<u8>> {
    let mut fields = vec![(Value::from(WITNESS_TURN_SPEAKER_KEY), Value::from(speaker))];
    if let Some(person) = person {
        fields.push((Value::from("actor"), Value::from(person.to_hex())));
    }
    encode_rmpv(&Value::Map(fields))
}

/// The TURN and CONVERSATION body key naming the source an imported transcript
/// came from (ARCH-0027). Its presence is what makes a turn imported evidence:
/// the Dreamer classifies such a turn `Imported` whatever its speaker.
pub(crate) const IMPORTED_SOURCE_KEY: &str = "import_source";

/// An imported TURN's body: the grouping speaker and the source. No PERSON
/// byline — the source's speaker wrote these words, not whoever imported them.
pub(super) fn encode_imported_turn_body(speaker: &str, source: &str) -> MemoryResult<Vec<u8>> {
    encode_rmpv(&Value::Map(vec![
        (Value::from(WITNESS_TURN_SPEAKER_KEY), Value::from(speaker)),
        (Value::from(IMPORTED_SOURCE_KEY), Value::from(source)),
    ]))
}

/// An imported TURN's or CONVERSATION's source is a birth fact (ARCH-0040):
/// no later put adds, changes or removes it, so imported evidence is never
/// relabelled the owner's live words, nor the reverse, and an import's
/// container never becomes a live one. Every put door runs this, replay
/// included. A tombstoned shell has no body to compare and is not a birth.
pub(crate) fn guard_import_stamp(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: crate::EntityId,
    body: &[u8],
) -> crate::Result<()> {
    use crate::ports::EntityStoreRead;
    let refused = |reason| Err(crate::error::RecordError::InvalidConversationBody(reason).into());
    let stamp = import_stamp(body);
    if stamp == ImportStamp::Malformed {
        return refused("an import source must be one non-empty string");
    }
    let Some(previous) = store.port_entity_record(txn, &id)? else {
        return Ok(());
    };
    if !previous.body.is_empty() && import_stamp(&previous.body) != stamp {
        return refused("an import source is a birth fact");
    }
    Ok(())
}

/// What a TURN or CONVERSATION body says about where its words came from.
/// The Dreamer reads any `import_source` key as imported evidence, so a body
/// whose stamp is present but not one non-empty string is its own state:
/// neither live nor of any source, and no write door accepts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ImportStamp {
    Live,
    Imported(String),
    Malformed,
}

pub(super) fn import_stamp(body: &[u8]) -> ImportStamp {
    let mut cursor = body;
    // An opaque or non-map body carries no stamp.
    let Ok(ValueRef::Map(entries)) = rmpv::decode::read_value_ref(&mut cursor) else {
        return ImportStamp::Live;
    };
    let mut stamp = ImportStamp::Live;
    for (key, value) in entries {
        if !matches!(key, ValueRef::String(ref key) if key.as_str() == Some(IMPORTED_SOURCE_KEY)) {
            continue;
        }
        stamp = match (stamp, value) {
            (ImportStamp::Live, ValueRef::String(source)) => match source.into_str() {
                Some(source) if !source.is_empty() => ImportStamp::Imported(source.to_owned()),
                _ => ImportStamp::Malformed,
            },
            _ => ImportStamp::Malformed,
        };
    }
    stamp
}

pub(super) fn decode_witness_turn_person(body: &[u8]) -> MemoryResult<Option<crate::EntityId>> {
    let mut cursor = body;
    let ValueRef::Map(entries) = rmpv::decode::read_value_ref(&mut cursor)
        .map_err(|_| MemoryError::bad_request("invalid witnessed turn body"))?
    else {
        return Err(MemoryError::bad_request("invalid witnessed turn body"));
    };
    if !cursor.is_empty() {
        return Err(MemoryError::bad_request("invalid witnessed turn body"));
    }
    let mut person = None;
    for (key, value) in entries {
        let ValueRef::String(key) = key else {
            continue;
        };
        if key.as_str() != Some("actor") {
            continue;
        }
        if person.is_some() {
            return Err(MemoryError::bad_request("duplicate witnessed turn author"));
        }
        let ValueRef::String(value) = value else {
            return Err(MemoryError::bad_request("invalid witnessed turn author"));
        };
        let id = value
            .as_str()
            .and_then(|text| crate::EntityId::from_hex(text).ok())
            .ok_or_else(|| MemoryError::bad_request("invalid witnessed turn author"))?;
        person = Some(id);
    }
    Ok(person)
}

/// The gate-side view of one message: the six envelope axes exactly as the
/// MESSAGE body will carry them, with the caller's JSON metadata already
/// converted to the MessagePack value that gets written.
///
/// This is the ONE construction site that pairs a `WitnessMessage` with the
/// envelope the ceiling door authorizes, so the axes the door reads and the
/// bytes [`encode_witness_message_body`] produces cannot diverge.
pub(super) fn witness_message_envelope(message: &WitnessMessage) -> WitnessMessageEnvelope<'_> {
    WitnessMessageEnvelope {
        author: message.author.as_str(),
        message_type: message.message_type.as_str(),
        content: message.content.as_str(),
        metadata: message.metadata.as_ref().map(json_to_rmpv),
        is_visible: message.is_visible,
        order: message.order,
    }
}

/// The MESSAGE body bytes the write door would stage for `message`, for a
/// planner that predicts what that door refuses.
pub(crate) fn witness_message_body(message: &WitnessMessage) -> MemoryResult<Vec<u8>> {
    Ok(witness_message_envelope(message).encode_body()?)
}

/// The MESSAGE body bytes for one message.
///
/// The encoding itself lives in `gate::witness_message`, which is also what the
/// ceiling door re-runs to prove the staged bytes are the authorized envelope:
/// one encoder, so "what was checked" and "what is written" are the same
/// function of the same axes. Both write doors reach it through
/// [`witness_message_envelope`] so the envelope they authorize and the bytes
/// they stage come from ONE value; this wrapper is the shape tests pin.
#[cfg(test)]
pub(in crate::memory) fn encode_witness_message_body(
    message: &WitnessMessage,
) -> MemoryResult<Vec<u8>> {
    Ok(witness_message_envelope(message).encode_body()?)
}
