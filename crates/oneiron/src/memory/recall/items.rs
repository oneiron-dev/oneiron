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
            // hold: those this actor may read, under the text revision that
            // pins them, both read in this snapshot. A pin at a text revision
            // reads the words it was served with.
            let turn = if entity_type == ENTITY_TYPE_TURN {
                // Every message the turn reads its text from, a hidden or
                // empty one too, which may show text after its next change.
                let mut members = Vec::new();
                for (message, _) in
                    crate::tagging::turn_members_in_txn(self.vault, txn, id)?.unwrap_or_default()
                {
                    if lane.is_entity_readable_in(txn, &message)? {
                        members.push(message);
                    }
                }
                match crate::vault::entity_revision::served_turn_text_in_txn(
                    self.vault, txn, id, mode,
                )? {
                    Some(text) => {
                        let revision = text.revision;
                        let messages =
                            text.readable(|message| lane.is_entity_readable_in(txn, message))?;
                        Some((messages, Some(revision), members))
                    }
                    None => Some((Vec::new(), None, members)),
                }
            } else {
                None
            };
            let view = self.entity_view_of_in_txn(txn, row, mode)?;
            Ok(Some((entity_type, body, view, turn)))
        })?;
        receipt.restrict_with(&read);
        let Some((entity_type, Some(body), Some(view), turn)) = admitted else {
            return Ok(None);
        };
        let (turn_messages, turn_revision, turn_members) = turn.unwrap_or_default();
        let turn_text = crate::embed::joined_turn_text(&turn_messages);
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
        // A TURN's words are its messages', so each message it reads them
        // from, or quotes, is a source too: an edit, erase, archive or
        // disclosure change of one changes the item. A live view depends on
        // every source an item names.
        let mut named = std::collections::HashSet::from([*id]);
        named.extend(
            edges
                .iter()
                .filter(|edge| edge.kind == EdgeKind::Supersedes)
                .map(|edge| edge.target),
        );
        for message in turn_members
            .iter()
            .chain(turn_messages.iter().map(|(message, _)| message))
        {
            if named.insert(*message) {
                source_revision_ids.push(message.to_hex());
            }
        }
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
        // A TURN names the text revision of the words it serves, not the
        // revision of its row, which holds none of them.
        let source_revision_ref = match mode {
            crate::vault::ReadMode::Pinned(revision) => {
                Some(turn_revision.unwrap_or(revision).to_hex())
            }
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
            // quote is one the actor may read. Its words are the ones the
            // turn's text joined in the turn's own snapshot, which the turn's
            // text revision pins; a message that text left out is not quoted.
            // Its reactions ride on the turn that returns it.
            let mut cited_messages = Vec::with_capacity(cited.len());
            for message in cited {
                let Some((_, text)) = turn_messages.iter().find(|(id, _)| id == message) else {
                    continue;
                };
                if let Some(item) = self.memory_item_for(
                    lane,
                    message,
                    None,
                    crate::vault::ReadMode::Live,
                    &[],
                    receipt,
                )? {
                    reactions.extend(item.reactions);
                    cited_messages.push(CitedMessage {
                        short_id: item.short_id,
                        value_text: truncate_text(text, DEFAULT_MAX_FIELD_CHARS),
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
