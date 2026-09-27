use super::*;

impl ScopedRead<'_> {
    /// Structured failure corpus, read through this actor's existing scoped door.
    pub fn diagnostic_events(&self) -> Result<Vec<(EntityId, crate::self_heal::DiagnosticEvent)>> {
        let mut events = Vec::new();
        for id in self
            .vault
            .entities_by_type(crate::registry::ENTITY_TYPE_DIAGNOSTIC)?
        {
            let ScopedReadResult {
                value,
                receipt: _receipt,
            } = self.get_entity_parts_with_receipt(&id, None)?;
            if let Some((_, _, body)) = value {
                events.push((id, crate::self_heal::decode_diagnostic_event_body(&body)?));
            }
        }
        Ok(events)
    }
}
