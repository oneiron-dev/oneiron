//! The composition lists one definition's put reads (FIX 9555). Every entry
//! is kept, however many (rule 5): past its row (the count of 64 it once
//! refused past) a list raises one check per family and agent id, and the
//! put goes on.

use crate::agent_def::{AGENT_MAX_LIST_ENTRIES, AgentDefinition};
use crate::entity_id::EntityId;
use crate::scan_check::{EngineScan, ScanCount};
use crate::store::Store;

/// Counts each of `def`'s six composition lists against the scan row,
/// scoped to the list's family and `id`. Evidence only: it never refuses and
/// never fails the put that reads it; a threshold row that does not read
/// asks at the old count.
pub(super) fn observe_list_entries(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    def: &AgentDefinition,
) {
    let profile = def.memory_profile.as_ref();
    let lists: [(&[u8], usize); 6] = [
        (b"skills", def.skills.len()),
        (b"connectors", def.connectors.len()),
        (b"codeModeMcps", def.code_mode_mcps.len()),
        (b"models", def.models.len()),
        (
            b"verbatim_pins",
            profile.map_or(0, |profile| profile.verbatim_pins.len()),
        ),
        (
            b"optional_memory",
            profile
                .and_then(|profile| profile.optional_memory.as_ref())
                .map_or(0, |optional| optional.families.len()),
        ),
    ];
    for (family, entries) in lists {
        let scope = [family, id.as_bytes()].concat();
        let mut count =
            ScanCount::start(store, txn, EngineScan::AgentDefinitionListEntries, &scope)
                .unwrap_or_else(|_| {
                    ScanCount::start_at(
                        EngineScan::AgentDefinitionListEntries,
                        &scope,
                        u64::try_from(AGENT_MAX_LIST_ENTRIES).unwrap_or(u64::MAX),
                    )
                });
        count.rows(entries);
        count.defer(store);
    }
}
