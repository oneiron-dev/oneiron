//! The structured failure corpus, read through the actor's scoped door.
use super::{PointRead, ReadRow, ScopedRead, ScopedReadResult};
use crate::self_heal::DiagnosticEvent;
use crate::{EntityId, Result};

impl ScopedRead<'_> {
    /// Every diagnostic event this actor may read, in one snapshot. The
    /// receipt counts the stored events withheld from this actor.
    pub fn diagnostic_events(&self) -> Result<ScopedReadResult<Vec<(EntityId, DiagnosticEvent)>>> {
        let ids = self
            .vault
            .entities_by_type(crate::registry::ENTITY_TYPE_DIAGNOSTIC)?;
        let reads: Vec<_> = ids.into_iter().map(PointRead::id).collect();
        let rows = self.read(&reads, None)?;
        let mut events = Vec::with_capacity(rows.value.len());
        for row in rows.value.iter().flatten() {
            if let ReadRow {
                id,
                body: Some(body),
                ..
            } = row
            {
                events.push((*id, crate::self_heal::decode_diagnostic_event_body(body)?));
            }
        }
        Ok(ScopedReadResult {
            value: events,
            receipt: rows.receipt,
        })
    }
}
