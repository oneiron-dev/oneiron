//! Board row references kept for read checks and complete model-input lineage.

use oneiron::EntityId;

/// Keeps every valid row for the board's existing read checks. A missing
/// identity makes its complete source witness unknown, without dropping text.
pub(super) fn extend_source_rows<'a>(
    rows: &mut Vec<EntityId>,
    complete: &mut bool,
    references: impl IntoIterator<Item = &'a str>,
) {
    for reference in references {
        match EntityId::from_hex(reference) {
            Ok(row) => rows.push(row),
            Err(_) => *complete = false,
        }
    }
}
