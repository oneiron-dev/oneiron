//! A structural put's resolved inputs: edges, an ASSET_TEXT's sources and birth, text fields.

use super::*;

/// A resolved outgoing edge: kind, target and weight.
pub(super) type ResolvedEdge = (EdgeKind, crate::EntityId, f32);

/// Splits an ASSET_TEXT's `DerivedFrom` edges out as its sources; every
/// other edge stays an edge.
pub(super) fn split_asset_text_sources(
    type_byte: u8,
    resolved_edges: Vec<ResolvedEdge>,
) -> (Vec<(crate::EntityId, f32)>, Vec<ResolvedEdge>) {
    let (sources, resolved_edges): (Vec<_>, Vec<_>) =
        resolved_edges.into_iter().partition(|(kind, _, _)| {
            type_byte == ENTITY_TYPE_ASSET_TEXT && *kind == EdgeKind::DerivedFrom
        });
    let sources: Vec<_> = sources
        .into_iter()
        .map(|(_, source, weight)| (source, weight))
        .collect();
    (sources, resolved_edges)
}

impl Memory<'_> {
    pub(super) fn resolve_structural_edges(
        &self,
        input: &StructuralPutInput,
    ) -> MemoryResult<Vec<ResolvedEdge>> {
        let mut resolved_edges = Vec::new();
        if let Some(edges) = &input.edges {
            for spec in edges {
                let kind = EdgeKind::from_name(&spec.edge_kind).ok_or_else(|| {
                    MemoryError::bad_request_with(
                        format!("unknown edge kind {:?}", spec.edge_kind),
                        &["Use a snake_case EdgeKind name such as belongs_to or attached."],
                    )
                })?;
                // ONE-1414: `same_as` asserts cross-vault identity, and the
                // assertion is only meaningful together with the status Claim
                // and per-pact consent surface that
                // `federation::put_coreference_link` writes in ONE actor-gated
                // transaction. A raw link minted here would be an identity
                // claim with no status, no consent, and no attributed actor —
                // and the export filter reads the link's consent to decide
                // what crosses a grant, so a forgeable link is a disclosure
                // surface. The federation helper is the owning write door.
                if kind == EdgeKind::SameAs {
                    return Err(MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        "same_as edges cannot be written through the structural door",
                        &[
                            "same_as is a cross-vault identity link carrying status and per-pact share consent.",
                            "Use the federation coreference door so the link and its status claim land atomically.",
                        ],
                    ));
                }
                let target = self.resolve_ref(&spec.target_ref)?;
                let weight = spec.weight.or_else(|| kind.default_weight()).unwrap_or(1.0);
                resolved_edges.push((kind, target, weight));
            }
        }
        Ok(resolved_edges)
    }

    /// The text fields to index, after the text index is proven trusted.
    pub(super) fn structural_text_fields(
        &self,
        input: &StructuralPutInput,
    ) -> MemoryResult<Vec<(String, String)>> {
        let text_fields: Vec<(String, String)> = input
            .text_fields
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|field| (field.field.clone(), field.value.clone()))
            .collect();
        if !text_fields.is_empty() {
            self.vault.ensure_text_index_trusted()?;
        }
        Ok(text_fields)
    }

    /// Rule A: an ASSET_TEXT is born in its writer's class from the ASSETs
    /// it derives from, every one of them; a non-person's
    /// text that derives from none names no input, so it has no birth.
    pub(super) fn asset_text_birth(
        &self,
        type_byte: u8,
        sources: &[(crate::EntityId, f32)],
        learned_at: u64,
    ) -> Option<RowBirth> {
        if type_byte == ENTITY_TYPE_ASSET_TEXT {
            let inputs: Vec<_> = sources.iter().map(|(source, _)| *source).collect();
            RowBirth::written(
                WriteActor::new(self.actor, self.actor_class),
                MadeByClass::of_writer(self.actor_class),
                "structural.asset_text",
                &inputs,
                &[],
                learned_at,
            )
        } else {
            None
        }
    }
}
