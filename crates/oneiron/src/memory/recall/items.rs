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
    ) -> MemoryResult<Option<MemoryItem>> {
        let Some(entity_type) = self.vault.get_entity_type(id)? else {
            return Ok(None);
        };
        let edges = self.vault.edges_out(id)?;
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
        let Some(view) = self.recall_record_view(id, mode)? else {
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

    /// Recall's own record projection, apart from the read verbs' lane.
    ///
    /// Recall's candidates, candidate counts and rendered pack all come from
    /// the unscoped retrieval pack, so its item read still admits as recall
    /// always has: the revision read, the keyed-memory refusal and NOTE
    /// privacy. Moving only this read onto the actor's lane would narrow the
    /// items under a pack that still carries them, with no receipt to say so.
    /// The recall follow-on moves the whole of recall onto `ScopedRead` and
    /// gives `MemoryPack` its receipt.
    fn recall_record_view(
        &self,
        id: &EntityId,
        mode: crate::vault::ReadMode,
    ) -> MemoryResult<Option<EntityView>> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        let Some(raw) =
            crate::vault::entity_revision::read_entity_revision_in_txn(self.vault, &txn, id, mode)?
        else {
            return Ok(None);
        };
        let header = crate::batch::EntityMetadataHeader::parse(&raw).ok_or_else(|| {
            MemoryError::from(crate::error::Error::CorruptedIndex("entity header"))
        })?;
        if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
            return Err(crate::secret_custody::reject_secret_custody_byte().into());
        }
        if header.entity_type == ENTITY_TYPE_CLAIM {
            let Some(body) = raw
                .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                .and_then(|bytes| crate::claim::decode_claim_body(bytes, true).ok())
            else {
                return Ok(None);
            };
            if !crate::claim::claim_generic_readable(&body) {
                return Ok(None);
            }
        }
        if header.entity_type == crate::registry::ENTITY_TYPE_NOTE {
            super::super::verify_actor_binding_in_txn(
                self.vault,
                &txn,
                self.actor,
                self.actor_class,
            )?;
            if !crate::note::note_body_readable(
                &self.vault.store,
                &txn,
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                Some(&self.actor),
            )? {
                return Ok(None);
            }
        }
        let projected = crate::note::live_body_in_txn(
            &self.vault.store,
            &txn,
            id,
            header.entity_type,
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        )?;
        let short_ref = self.short_ref_of_in_txn(&txn, id)?.map(|reference| {
            let short = reference.split(':').next().unwrap_or(&reference);
            let hash =
                (xxhash_rust::xxh32::xxh32(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], 0)
                    % 256) as u8;
            match mode {
                crate::vault::ReadMode::Pinned(revision) => {
                    format!("{short}:{hash:02x}@{}", revision.to_hex())
                }
                _ => format!("{short}:{hash:02x}"),
            }
        });
        Ok(Some(EntityView {
            id_hex: id.to_hex(),
            short_ref,
            kind: kind_string_for_type(header.entity_type),
            occurred_start: header.occurred_start,
            occurred_end: header.occurred_end,
            learned_at: header.learned_at,
            body: super::super::support::decode_body_json(&projected),
        }))
    }
}
