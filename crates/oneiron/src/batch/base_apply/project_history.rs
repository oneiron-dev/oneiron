use super::*;
use crate::temporal::TimeRange;

/// The revisions a PROJECT put or tear captured (decision 8), as engine puts
/// of the revision kind at each revision's own times.
pub(super) fn revision_puts(
    store: &Store,
    captured: impl IntoIterator<Item = (EntityId, Vec<u8>, TimeRange, u64)>,
) -> Result<Vec<BatchOp>> {
    let mut puts = Vec::new();
    for (id, data, occurred, learned_at) in captured {
        let entity_type = crate::workspace_roster::project_revision_type(store)
            .ok_or(Error::InvariantViolation("project revision kind missing"))?;
        puts.push(BatchOp::Put {
            id,
            entity_type,
            occurred,
            learned_at,
            data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        });
    }
    Ok(puts)
}
