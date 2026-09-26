//! Builds typed recall items from the exact selected entity revision.
use super::*;

impl Memory<'_> {
    /// Builds one S6 memory item from an entity id. Returns `Ok(None)` for
    /// missing entities and non-surfaceable claims (D19 admission).
    pub(super) fn memory_item_for(
        &self,
        id: &EntityId,
        facet_hint: Option<EntityId>,
        mode: crate::vault::ReadMode,
        scoped_read: Option<&crate::claim::ScopedRead<'_>>,
    ) -> MemoryResult<Option<MemoryItem>> {
        let Some(entity_type) = self.vault.get_entity_type(id)? else {
            return Ok(None);
        };
        // The scored pack has already been filtered, but raw vault edges
        // would reintroduce denied targets through provenance and facet hints.
        let edges = match scoped_read {
            Some(read) => read.edges_out(id)?.value.unwrap_or_default(),
            None => self.vault.edges_out(id)?,
        };
        let mut source_revision_ids = vec![id.to_hex()];
        source_revision_ids.extend(
            edges
                .iter()
                .filter(|edge| edge.kind == EdgeKind::Supersedes)
                .map(|edge| edge.target.to_hex()),
        );
        let facet = facet_hint.map(|facet| facet.to_hex()).or_else(|| {
            edges
                .iter()
                .find(|edge| edge.kind == EdgeKind::HasFacet)
                .map(|edge| edge.target.to_hex())
        });
        let Some(view) = self.entity_view_with_mode(id, mode)? else {
            return Ok(None);
        };
        let short_id = view.short_ref.clone().unwrap_or_else(|| id.to_hex());
        let kind = kind_string_for_type(entity_type);

        if entity_type == ENTITY_TYPE_CLAIM {
            let Some(live_body) = self.vault.get_claim(id)? else {
                return Ok(None);
            };
            if !claim_surfaceable(&live_body) {
                return Ok(None);
            }
            let body = if mode == crate::vault::ReadMode::Live {
                live_body
            } else {
                let Some(raw) = self.vault.get_raw_with_mode(id, mode)? else {
                    return Ok(None);
                };
                crate::claim::decode_claim_body(
                    &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                    true,
                )?
            };
            if !claim_surfaceable(&body) {
                return Ok(None);
            }
            let value_json = companion_value_to_json(&body.value);
            Ok(Some(MemoryItem {
                short_id,
                kind,
                predicate: Some(body.predicate.clone()),
                value_text: truncate_text(&value_text_of(&value_json), DEFAULT_MAX_FIELD_CHARS),
                confidence: body.confidence,
                hedge_bucket: hedge_bucket_for(body.confidence).to_owned(),
                provenance: MemoryProvenance {
                    source: body
                        .source
                        .map_or_else(|| "unattributed".to_owned(), |s| s.as_str().to_owned()),
                    source_revision_ids,
                    evidence_turn_ids: Vec::new(),
                },
                world: body.world.map(|world| world.to_hex()),
                facet,
                salience: body.salience,
            }))
        } else {
            let value_text = view
                .body
                .as_ref()
                .and_then(|body| body.get("content"))
                .and_then(serde_json::Value::as_str)
                .map_or_else(
                    || {
                        view.body
                            .as_ref()
                            .map(|body| serde_json::to_string(body).unwrap_or_default())
                            .unwrap_or_default()
                    },
                    str::to_owned,
                );
            let evidence_turn_ids = if entity_type == ENTITY_TYPE_MESSAGE {
                edges
                    .iter()
                    .filter(|edge| edge.kind == EdgeKind::PartOf)
                    .map(|edge| edge.target.to_hex())
                    .collect()
            } else {
                Vec::new()
            };
            Ok(Some(MemoryItem {
                short_id,
                kind,
                predicate: None,
                value_text: truncate_text(&value_text, DEFAULT_MAX_FIELD_CHARS),
                confidence: 1.0,
                hedge_bucket: hedge_bucket_for(1.0).to_owned(),
                provenance: MemoryProvenance {
                    source: "record".to_owned(),
                    source_revision_ids,
                    evidence_turn_ids,
                },
                world: None,
                facet,
                salience: None,
            }))
        }
    }
}
