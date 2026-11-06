//! Explicit task ids kept open by their actor's layout.

use super::projection::{TasksSection, TasksSectionRows};
use super::render::{bare_job_row, intent_row};
use crate::EntityId;

impl TasksSection {
    /// Restores kept rows from the SAME admitted source the projection used.
    /// No by-id fetch, alias lookup or admission bypass. Acknowledged failures
    /// stay off; missing or withheld ids add neither a row nor a count.
    pub fn keep_rows_open(&mut self, source: &TasksSectionRows, keep: &[EntityId]) {
        for id in keep {
            let id = id.to_hex();
            if self.rows.iter().any(|row| row.id == id) {
                continue;
            }
            let row = source
                .intents
                .iter()
                .find(|intent| intent.id == id && !intent.is_acked_failure())
                .map(intent_row)
                .or_else(|| {
                    source
                        .bare_jobs
                        .iter()
                        .find(|job| job.id == id)
                        .map(bare_job_row)
                });
            let Some(row) = row else {
                continue;
            };
            self.rows.push(row);
            if let Some(overflow) = &mut self.overflow {
                overflow.known_omitted_rows = overflow.known_omitted_rows.saturating_sub(1);
            }
        }
        if self
            .overflow
            .is_some_and(|overflow| overflow.known_omitted_rows == 0 && overflow.source_exhausted)
        {
            self.overflow = None;
        }
    }
}
