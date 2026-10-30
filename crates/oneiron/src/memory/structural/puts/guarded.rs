//! The guarded structural put: kind checks, then body, edges and text fields in one content write.
//! `Memory::put_structural_guarded` is its call surface.
//! `memory::structural` defines `StructuralPutInput` and `EntityRefReceipt`.

use super::*;

mod admission;
mod content_write;
mod inputs;

use self::content_write::StructuralWrite;
use self::inputs::split_asset_text_sources;

impl Memory<'_> {
    pub(crate) fn put_structural_guarded(
        &self,
        input: &StructuralPutInput,
        guard: impl FnOnce(&heed::RoTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<EntityRefReceipt> {
        let type_byte = type_byte_for_kind(&input.kind)?;
        self.admit_structural_kind(type_byte, input)?;
        let id = id_from_optional_hex(self.vault, input.id.as_deref())?;
        let occurred = TimeRange {
            start: input.occurred_at,
            end: input.occurred_at,
        };
        let learned_at = input.learned_at.unwrap_or(input.occurred_at);
        // A TURN's learned time feeds the consolidation watermark: this door
        // holds it to the witness door's clock ceiling (F30).
        if type_byte == ENTITY_TYPE_TURN {
            let now = self.vault.store.clock.now_recorded_at();
            crate::memory::witness::validate_witness_occurrence(now, learned_at)?;
        }
        let data = encode_rmpv(&json_to_rmpv(&input.body))?;
        let resolved_edges = self.resolve_structural_edges(input)?;
        // A text written from ASSETs is born under their one facet, with its
        // `DerivedFrom` edges (facet rule C); sources in two facets refuse it.
        let (sources, resolved_edges) = split_asset_text_sources(type_byte, resolved_edges);
        let text_fields = self.structural_text_fields(input)?;
        let birth = self.asset_text_birth(type_byte, &sources, learned_at);

        // Marker check and put share ONE write transaction (A1): a
        // concurrent hard delete either commits first (refused here) or
        // after this txn (its purge then erases what we wrote).
        let write = StructuralWrite {
            id,
            type_byte,
            occurred,
            learned_at,
            data,
            sources,
            resolved_edges,
            text_fields,
            birth,
        };
        let refused = self.with_actor_content_write_txn(|content| {
            self.write_structural_in_txn(content, guard, write)
        })?;
        if refused {
            return Err(hard_deleted_refusal(&id));
        }
        self.entity_ref_receipt_of(&id, type_byte)
    }
}