//! A structural put's one content write: owner and marker checks, then body, birth, edges, text.

use super::inputs::ResolvedEdge;
use super::*;

/// What a structural put lands, resolved before its write opens.
pub(super) struct StructuralWrite {
    pub(super) id: crate::EntityId,
    pub(super) type_byte: u8,
    pub(super) occurred: TimeRange,
    pub(super) learned_at: u64,
    pub(super) data: Vec<u8>,
    pub(super) sources: Vec<(crate::EntityId, f32)>,
    pub(super) resolved_edges: Vec<ResolvedEdge>,
    pub(super) text_fields: Vec<(String, String)>,
    pub(super) birth: Option<RowBirth>,
}

impl Memory<'_> {
    /// Inside the put's write transaction; `true` means a hard-delete marker
    /// refused the id.
    pub(super) fn write_structural_in_txn(
        &self,
        content: &mut crate::federation::ActorContentTxn<'_, '_, '_>,
        guard: impl FnOnce(&heed::RoTxn<'_>) -> MemoryResult<()>,
        write: StructuralWrite,
    ) -> MemoryResult<bool> {
        let StructuralWrite {
            id,
            type_byte,
            occurred,
            learned_at,
            data,
            sources,
            resolved_edges,
            text_fields,
            birth,
        } = write;
        // An actor-capable PERSON is still an owner verb; the content
        // transaction does not substitute for that domain authority.
        if type_byte == ENTITY_TYPE_PERSON {
            verify_owner_actor_binding_in_txn(self.vault, content.read(), self.actor)?;
        }
        if self
            .vault
            .local_hard_delete_marker_exists_in_txn(content.read(), &id)?
        {
            return Ok(true);
        }
        ensure_structural_create_in_txn(self.vault, content.read(), &id)?;
        guard(content.read())?;
        let mut batch = if sources.is_empty() {
            self.vault
                .batch_in()
                .put(&id, type_byte, occurred, learned_at, &data)
        } else {
            self.vault
                .batch_in()
                .asset_text_birth(&id, occurred, learned_at, &data, &sources)
        };
        batch = batch.made_by(&id, birth);
        for (kind, target, weight) in &resolved_edges {
            batch = batch.edge(&id, *kind, target, *weight);
        }
        if !text_fields.is_empty() {
            let fields: Vec<(&str, &str)> = text_fields
                .iter()
                .map(|(field, value)| (field.as_str(), value.as_str()))
                .collect();
            batch = batch.text(&id, &fields);
        }
        content.apply_batch(batch)?;
        Ok(false)
    }
}
