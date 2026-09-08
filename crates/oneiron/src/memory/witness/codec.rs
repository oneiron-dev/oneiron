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
/// stamped `companion` would score `Unknown` and never reach extraction.
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
pub(crate) fn decode_witness_turn_speaker(body: &[u8]) -> MemoryResult<&str> {
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

/// The minted TURN body: one additive `speaker` entry, nothing else.
pub(super) fn encode_witness_turn_body(speaker: &str) -> MemoryResult<Vec<u8>> {
    encode_rmpv(&Value::Map(vec![(
        Value::from(WITNESS_TURN_SPEAKER_KEY),
        Value::from(speaker),
    )]))
}

/// The gate-side view of one message: the six envelope axes exactly as the
/// MESSAGE body will carry them, with the caller's JSON metadata already
/// converted to the MessagePack value that gets written.
///
/// This is the ONE construction site that pairs a `WitnessMessage` with the
/// envelope the ceiling door authorizes, so the axes the door reads and the
/// bytes [`encode_witness_message_body`] produces cannot diverge.
pub(crate) fn witness_message_envelope(message: &WitnessMessage) -> WitnessMessageEnvelope<'_> {
    WitnessMessageEnvelope {
        author: message.author.as_str(),
        message_type: message.message_type.as_str(),
        content: message.content.as_str(),
        metadata: message.metadata.as_ref().map(json_to_rmpv),
        is_visible: message.is_visible,
        order: message.order,
    }
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
pub(crate) fn encode_witness_message_body(message: &WitnessMessage) -> MemoryResult<Vec<u8>> {
    Ok(witness_message_envelope(message).encode_body()?)
}
