//! The provenance a converted record carries: the pinned keys, the map builder, the
//! source-linkage reader, and the content-named version.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::skill::{SkillContentHash, SkillRecord};

use super::types::ConvertUtterance;

/// Provenance key carrying the source message/turn ids a converted skill was
/// derived from, as an array of 32-char entity-id hex strings.
///
/// STRUCTURED on purpose, and this ticket mints the convention: ONE-1447 marks
/// a skill `stale` when its sources are deleted, which needs the linkage to be
/// READABLE rather than narrated in prose. [`source_message_refs`] is the
/// matching reader.
pub const PROVENANCE_SOURCE_MESSAGES_KEY: &str = "source_messages";

/// Provenance key naming the birth path, so a record says which of the three
/// roads it came in on without inference from flag combinations.
pub const PROVENANCE_BIRTH_KEY: &str = "birth";

/// [`PROVENANCE_BIRTH_KEY`] value for this door (the string the `skill.rs`
/// lifecycle comment already calls "conversation convert").
pub const CONVERT_BIRTH_PATH: &str = "conversation_convert";

/// Provenance key carrying the refiner's dedup rationale: why these bytes are a
/// NEW skill, or why they are an edit of an existing one.
///
/// One key for both verdicts because it answers one question. Which verdict was
/// reached is said by the presence of [`PROVENANCE_MERGE_OF_KEY`], never by a
/// second rationale key that could disagree with the first.
pub const PROVENANCE_DEDUP_RATIONALE_KEY: &str = "dedup_rationale";

/// Provenance key on a merge PROPOSAL: the hex id of the existing skill entity
/// this revision proposes to supersede.
pub const PROVENANCE_MERGE_OF_KEY: &str = "merge_of";

/// Version prefix for a conversion-minted revision.
const CONVERT_VERSION_PREFIX: &str = "convert-";

/// Hex characters of the content hash carried in the version string.
const CONVERT_VERSION_HASH_HEX: usize = 16;

/// The source message/turn ids a converted skill cites, or empty when the
/// record came in on another road.
///
/// Strict on the shape it wrote: a present-but-malformed linkage is corruption,
/// not an absent linkage, and ONE-1447's deletion sweep must not read it as
/// "this skill cites nothing".
pub fn source_message_refs(record: &SkillRecord) -> Result<Vec<EntityId>> {
    const CONTEXT: &str = "source_messages must be an array of 32-char entity id hex strings";
    let Value::Map(entries) = &record.provenance else {
        return Ok(Vec::new());
    };
    let Some((_, value)) = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(PROVENANCE_SOURCE_MESSAGES_KEY))
    else {
        return Ok(Vec::new());
    };
    let Value::Array(refs) = value else {
        return Err(Error::InvalidSkillBody(CONTEXT));
    };
    refs.iter()
        .map(|entry| {
            entry
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or(Error::InvalidSkillBody(CONTEXT))
        })
        .collect()
}

/// The provenance map: birth path, structured source linkage, and the receipted
/// dedup rationale.
pub(super) fn provenance(
    said: &[ConvertUtterance],
    rationale: &str,
    merge_of: Option<&EntityId>,
) -> Value {
    let mut sources: Vec<Value> = Vec::with_capacity(said.len());
    let mut seen = BTreeSet::new();
    for utterance in said {
        // A turn contributes once even when several of its messages were read:
        // the linkage is a citation SET, and ONE-1447 asks it "was this source
        // deleted", a question a repeat cannot answer twice.
        if seen.insert(utterance.source) {
            sources.push(Value::from(utterance.source.to_hex()));
        }
    }
    let mut entries = vec![
        (
            Value::from(PROVENANCE_BIRTH_KEY),
            Value::from(CONVERT_BIRTH_PATH),
        ),
        (
            Value::from(PROVENANCE_SOURCE_MESSAGES_KEY),
            Value::Array(sources),
        ),
        (
            Value::from(PROVENANCE_DEDUP_RATIONALE_KEY),
            Value::from(rationale),
        ),
    ];
    if let Some(existing) = merge_of {
        entries.push((
            Value::from(PROVENANCE_MERGE_OF_KEY),
            Value::from(existing.to_hex()),
        ));
    }
    Value::Map(entries)
}

/// The revision's version string.
///
/// A revision's identity IS its content in this engine (ARCH-0053 §7), so the
/// version NAMES the content instead of counting behind it. That also settles
/// the merge-proposal case for free: the proposal's version differs from the
/// target's because their bytes differ — no counter to read, no collision to
/// resolve.
pub(super) fn convert_version(content_hash: SkillContentHash) -> String {
    let hex = content_hash.to_hex();
    format!(
        "{CONVERT_VERSION_PREFIX}{}",
        &hex[..CONVERT_VERSION_HASH_HEX]
    )
}
