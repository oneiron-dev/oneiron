//! How a standing outbound grant's bound spells a part too long for a
//! consent bound's caps: the part by its digest, with the grant's whole
//! principal and dial carried beside it as a record the grant reads back.
//!
//! An effect's candidate bounds spell each part the same way, so a digest
//! spelling covers exactly the effects its value covers. A value that itself
//! starts with the digest mark is spelled by its digest too, which keeps the
//! spelling one-to-one.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::bound::{
    DIAL_ARTIFACT_PUBLISH, DIAL_BOOKING_PAGE_INVITES, DIAL_BRIEF_VERB_CLASS, DIAL_CHANNEL,
    DIAL_CONTACT, DIAL_SCOPED_MCP, DIAL_VERB_CLASS, StandingOutboundGrantScope,
};
use crate::consent::MAX_CONSENT_REF_LEN;
use crate::entity_id::EntityId;
use crate::outbound_consent::DataClass;
use crate::outbound_consent::tool_call::ToolGrantDataClass;

/// The mark a part spelled by its digest starts with.
const DIGEST_MARK: &str = "blake3#";

/// The key prefix of each chunk of a grant's record: `dial.<index>`, the
/// index four digits wide so the chunks sort in order.
pub(super) const SELECTOR_DIAL_RECORD: &str = "dial.";

/// The selector a scoped-MCP grant's endpoint selectors collapse into when
/// they alone pass the selector cap; its record carries the endpoints.
const SELECTOR_ENDPOINT_SET: &str = "endpoint_set";

/// The base64 characters one record chunk carries, inside the cap with its
/// `dial.<index>:` key.
const RECORD_CHUNK_LEN: usize = 500;

/// Whether `value`, trimmed, is spelled as itself within `room` bytes.
fn fits(value: &str, room: usize) -> bool {
    let value = value.trim();
    value.len() <= room && !value.starts_with(DIGEST_MARK)
}

/// `value`, trimmed, when it fits in `room` bytes, else its digest.
fn spell(value: &str, room: usize) -> String {
    let value = value.trim();
    if fits(value, room) {
        value.to_owned()
    } else {
        format!("{DIGEST_MARK}{}", blake3::hash(value.as_bytes()).to_hex())
    }
}

/// The room one selector's value has beside its `key:`.
fn selector_room(key: &str) -> usize {
    MAX_CONSENT_REF_LEN.saturating_sub(key.len() + 1)
}

/// Whether an actor, class or target reference is spelled as itself.
pub(super) fn ref_fits(value: &str) -> bool {
    fits(value, MAX_CONSENT_REF_LEN)
}

/// An actor, class or target reference as a bound spells it.
pub(super) fn spell_ref(value: &str) -> String {
    spell(value, MAX_CONSENT_REF_LEN)
}

/// Whether a `key:value` selector's value is spelled as itself.
pub(super) fn selector_fits(selector: &str) -> bool {
    match selector.split_once(':') {
        Some((key, value)) => fits(value, selector_room(key)),
        None => ref_fits(selector),
    }
}

/// A `key:value` selector as a bound spells it.
pub(super) fn spell_selector(selector: &str) -> String {
    match selector.split_once(':') {
        Some((key, value)) => format!("{key}:{}", spell(value, selector_room(key))),
        None => spell_ref(selector),
    }
}

/// One selector for a scoped-MCP grant's whole endpoint list.
pub(super) fn endpoint_set_selector(endpoints: &[String]) -> String {
    let mut hasher = blake3::Hasher::new();
    for endpoint in endpoints {
        hasher.update(&(endpoint.len() as u64).to_le_bytes());
        hasher.update(endpoint.as_bytes());
    }
    format!(
        "{SELECTOR_ENDPOINT_SET}:{DIGEST_MARK}{}",
        hasher.finalize().to_hex()
    )
}

/// The selectors that carry `principal_ref` and `dial` whole: their fields,
/// each length-prefixed, in base64 chunks.
pub(super) fn record_selectors(
    principal_ref: &str,
    dial: &StandingOutboundGrantScope,
) -> Vec<String> {
    let mut bytes = Vec::new();
    for field in record_fields(principal_ref, dial) {
        bytes.extend_from_slice(&(field.len() as u64).to_le_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    URL_SAFE_NO_PAD
        .encode(bytes)
        .as_bytes()
        .chunks(RECORD_CHUNK_LEN)
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "{SELECTOR_DIAL_RECORD}{index:04}:{}",
                String::from_utf8_lossy(chunk)
            )
        })
        .collect()
}

/// The principal, the dial's label, then the dial's values in its own order.
fn record_fields(principal_ref: &str, dial: &StandingOutboundGrantScope) -> Vec<String> {
    let mut fields = vec![
        principal_ref.trim().to_owned(),
        dial.dial_label().to_owned(),
    ];
    match dial {
        StandingOutboundGrantScope::Contact { contact_ref: value }
        | StandingOutboundGrantScope::VerbClass { verb_class: value }
        | StandingOutboundGrantScope::Channel { channel: value }
        | StandingOutboundGrantScope::ArtifactPublish { artifact: value } => {
            fields.push(value.clone());
        }
        StandingOutboundGrantScope::BriefVerbClass {
            brief_ref,
            verb_class,
        } => fields.extend([brief_ref.clone(), verb_class.clone()]),
        StandingOutboundGrantScope::ScopedMcp {
            server,
            tool,
            data_class_ceiling,
            tool_data_classes,
            endpoint_allowlist,
        } => {
            fields.extend([
                server.clone(),
                tool.clone(),
                data_class_ceiling.as_str().to_owned(),
                tool_data_classes.len().to_string(),
            ]);
            fields.extend(
                tool_data_classes
                    .iter()
                    .map(|class| class.as_str().to_owned()),
            );
            fields.extend(endpoint_allowlist.iter().cloned());
        }
        StandingOutboundGrantScope::BookingPageInvites { page_ref } => {
            fields.push(page_ref.to_hex());
        }
    }
    fields
}

/// The principal and dial a grant's record chunks carry, from their
/// `(index, chunk)` pairs. `None`: the chunks spell no record.
pub(super) fn decode_record(
    mut chunks: Vec<(usize, &str)>,
) -> Option<(String, StandingOutboundGrantScope)> {
    chunks.sort_unstable_by_key(|(index, _)| *index);
    let mut encoded = String::new();
    for (position, (index, chunk)) in chunks.iter().enumerate() {
        if *index != position {
            return None;
        }
        encoded.push_str(chunk);
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let mut fields = Vec::new();
    let mut rest = bytes.as_slice();
    while !rest.is_empty() {
        let (len, tail) = rest.split_first_chunk::<8>()?;
        let len = usize::try_from(u64::from_le_bytes(*len)).ok()?;
        if tail.len() < len {
            return None;
        }
        let (field, tail) = tail.split_at(len);
        fields.push(std::str::from_utf8(field).ok()?);
        rest = tail;
    }
    let [principal, label, values @ ..] = fields.as_slice() else {
        return None;
    };
    let dial = match (*label, values) {
        (DIAL_CONTACT, [contact]) => StandingOutboundGrantScope::Contact {
            contact_ref: owned(contact),
        },
        (DIAL_VERB_CLASS, [verb_class]) => StandingOutboundGrantScope::VerbClass {
            verb_class: owned(verb_class),
        },
        (DIAL_CHANNEL, [channel]) => StandingOutboundGrantScope::Channel {
            channel: owned(channel),
        },
        (DIAL_BRIEF_VERB_CLASS, [brief_ref, verb_class]) => {
            StandingOutboundGrantScope::BriefVerbClass {
                brief_ref: owned(brief_ref),
                verb_class: owned(verb_class),
            }
        }
        (DIAL_ARTIFACT_PUBLISH, [artifact]) => StandingOutboundGrantScope::ArtifactPublish {
            artifact: owned(artifact),
        },
        (DIAL_SCOPED_MCP, [server, tool, ceiling, count, rest @ ..]) => {
            let count = count.parse::<usize>().ok()?;
            if rest.len() < count {
                return None;
            }
            let (classes, endpoints) = rest.split_at(count);
            StandingOutboundGrantScope::ScopedMcp {
                server: owned(server),
                tool: owned(tool),
                data_class_ceiling: DataClass::parse(ceiling),
                tool_data_classes: classes
                    .iter()
                    .copied()
                    .map(ToolGrantDataClass::parse)
                    .collect::<Option<Vec<_>>>()?,
                endpoint_allowlist: endpoints.iter().copied().map(owned).collect(),
            }
        }
        (DIAL_BOOKING_PAGE_INVITES, [page]) => StandingOutboundGrantScope::BookingPageInvites {
            page_ref: EntityId::from_hex(page).ok()?,
        },
        _ => return None,
    };
    Some((owned(principal), dial))
}

/// One record field as the dial's owned value.
fn owned(value: &str) -> String {
    value.to_owned()
}
