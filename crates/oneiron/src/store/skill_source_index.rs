//! Core half of `store::skill_source_index`: its store-layer items live in `oneiron_store::skill_source_index` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::skill_source_index::*;

use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::write_envelope::skill_record::SkillRecord;
use rmpv::Value;
use std::collections::HashSet;

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
