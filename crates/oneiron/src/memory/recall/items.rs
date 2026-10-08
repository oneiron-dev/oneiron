//! Builds typed recall items from actor-admitted rows at the selected revision.
use super::*;
use crate::claim::{PointRead, ScopedRead, ScopedReadReceipt, ScopedReadResult};

impl Memory<'_> {
    /// No item or its provenance may be assembled before the actor's scoped read.
    pub(super) fn memory_item_for(
        &self,
        lane: &ScopedRead<'_>,
        id: &EntityId,
        facet_hint: Option<EntityId>,
        mode: crate::vault::ReadMode,
        cited: &[EntityId],
        receipt: &mut ScopedReadReceipt,
    ) -> MemoryResult<Option<MemoryItem>> {
        let ScopedReadResult {
            value: admitted,
            receipt: read,
        } = lane.read_projected(&[PointRead::id(*id).at(mode)], None, |txn, rows| {
            let Some(row) = rows.into_iter().next().flatten() else {
                return Ok::<_, MemoryError>(None);
            };
            let entity_type = row.entity_type;
            let body = row.body.clone();
            // A TURN's text is its messages', which its own body does not
            // hold: those this actor may read.
            let turn_text = if entity_type == ENTITY_TYPE_TURN {
                crate::embed::readable_turn_text_in_txn(self.vault, txn, id, |message| {
                    lane.is_entity_readable_in(txn, message)
                })?
            } else {
                None
            };
            let view = self.entity_view_of_in_txn(txn, row, mode)?;
            Ok(Some((entity_type, body, view, turn_text)))
        })?;
        receipt.restrict_with(&read);
        let Some((entity_type, Some(body), Some(view), turn_text)) = admitted else {
            return Ok(None);
        };
        let ScopedReadResult {
            value: edges,
            receipt: graph,
        } = lane.edges_out(id)?;
        receipt.restrict_with(&graph);
        let edges = edges.unwrap_or_default();

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
        // The view qualifies a pinned short ref with its revision; the item
        // carries the two apart, so its short id matches a witness receipt.
        let short_id = view.short_ref.as_deref().map_or_else(
            || id.to_hex(),
            |short| {
                short
                    .rsplit_once('@')
                    .map_or(short, |(bare, _)| bare)
                    .to_owned()
            },
        );
        let source_revision_ref = match mode {
            crate::vault::ReadMode::Pinned(revision) => Some(revision.to_hex()),
            crate::vault::ReadMode::Live | crate::vault::ReadMode::Indexed => None,
        };
        let kind = kind_string_for_type(entity_type);

        if entity_type == ENTITY_TYPE_CLAIM {
            let body = crate::claim::decode_claim_body(&body, true)?;
            if !claim_surfaceable(&body) {
                return Ok(None);
            }
            let value_json = companion_value_to_json(&body.value);
            Ok(Some(MemoryItem {
                short_id,
                source_revision_ref,
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
                reactions: Vec::new(),
                cited_messages: Vec::new(),
            }))
        } else {
            let value_text = turn_text
                .as_deref()
                .or_else(|| {
                    view.body
                        .as_ref()
                        .and_then(|body| body.get("content"))
                        .and_then(serde_json::Value::as_str)
                })
                .map_or_else(
                    || {
                        view.body
                            .as_ref()
                            .map(|body| serde_json::to_string(body).unwrap_or_default())
                            .unwrap_or_default()
                    },
                    str::to_owned,
                );
            let mut reactions = if matches!(entity_type, ENTITY_TYPE_MESSAGE | ENTITY_TYPE_TURN) {
                lane.reaction_lines(id)?
            } else {
                Vec::new()
            };
            let evidence_turn_ids = if entity_type == ENTITY_TYPE_MESSAGE {
                edges
                    .iter()
                    .filter(|edge| edge.kind == EdgeKind::PartOf)
                    .map(|edge| edge.target.to_hex())
                    .collect()
            } else {
                Vec::new()
            };
            // Each message a TURN took in is read through the same lane, so a
            // quote is one the actor may read. Its reactions ride on the turn
            // that returns it.
            let mut cited_messages = Vec::with_capacity(cited.len());
            for message in cited {
                if let Some(item) = self.memory_item_for(
                    lane,
                    message,
                    None,
                    crate::vault::ReadMode::Indexed,
                    &[],
                    receipt,
                )? {
                    reactions.extend(item.reactions);
                    cited_messages.push(CitedMessage {
                        short_id: item.short_id,
                        value_text: item.value_text,
                    });
                }
            }
            Ok(Some(MemoryItem {
                short_id,
                source_revision_ref,
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
                reactions,
                cited_messages,
            }))
        }
    }
}
