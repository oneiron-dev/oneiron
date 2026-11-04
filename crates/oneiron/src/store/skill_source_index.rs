//! Converted-skill source linkage and reverse-index maintenance.

use std::collections::HashSet;
use rmpv::Value;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::write_envelope::skill_record::SkillRecord;

/// Provenance key carrying the source message/turn ids a converted skill was
/// derived from, as an array of 32-char entity-id hex strings.
///
/// STRUCTURED on purpose, and this ticket mints the convention: ONE-1447 marks
/// a skill `stale` when its sources are deleted, which needs the linkage to be
/// READABLE rather than narrated in prose. [`source_message_refs`] is the
/// matching reader.
pub const PROVENANCE_SOURCE_MESSAGES_KEY: &str = "source_messages";

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
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(CONTEXT)));
    };
    refs.iter()
        .map(|entry| {
            entry
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or(Error::Artifact(ArtifactError::InvalidSkillBody(CONTEXT)))
        })
        .collect()
}

/// The reverse source index: skills citing a source. Key: id16(source) + id16(skill), empty
/// value.
///
/// Asking "which skills cite this id" by scanning every skill's provenance is
/// O(library) on EVERY entity delete; this makes it one prefix seek. The index
/// is a CACHE with an authority — the records themselves — and
/// [`rebuild_skill_source_index`] reconstructs it from them, so a missing or
/// drifted row costs a rebuild, never truth.
pub(crate) const SOURCE_INDEX: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::SKILL_SOURCE_INDEX);

/// Maintains the reverse index as a SKILL body lands, at the batch put
/// chokepoint every road funnels through — the typed doors, hub import, and
/// sync rematerialization alike. `previous` is the record this put replaces.
///
/// STRICT on the incoming linkage and lenient on the outgoing one: a malformed
/// `source_messages` in the new body is refused here, where the corruption
/// would enter, so the deletion sweep can never read a broken linkage as "this
/// skill cites nothing"; an unreadable PRIOR body is already on disk and only
/// costs unindexed rows, which the rebuild door clears.
pub(crate) fn maintain_skill_source_index_for_put(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    previous: Option<&SkillRecord>,
    record: &SkillRecord,
) -> Result<()> {
    let next = source_message_refs(record)?;
    // One set from the new refs keeps the dropped test linear inside the writer
    // txn (FIX 5969); the rows and their order are unchanged.
    let kept: HashSet<EntityId> = next.iter().copied().collect();
    let dropped = previous
        .and_then(|previous| source_message_refs(previous).ok())
        .unwrap_or_default();
    for source in dropped.iter().filter(|source| !kept.contains(*source)) {
        SOURCE_INDEX.delete(store, wtxn, &(*source, *skill))?;
    }
    for source in &next {
        SOURCE_INDEX.put(store, wtxn, &(*source, *skill), &())?;
    }
    Ok(())
}

