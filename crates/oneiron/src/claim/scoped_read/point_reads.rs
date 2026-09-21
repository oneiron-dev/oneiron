//! Same-snapshot, receipted point and short-reference hydration doors.
use super::{RetrievalFilter, ScopedRead, ScopedReadResult};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::vault::ReadMode;
use crate::{EntityId, Error, Result};
type EntityParts = (u8, u64, Vec<u8>);

impl ScopedRead<'_> {
    pub fn get(&self, id: &EntityId) -> Result<ScopedReadResult<Option<Vec<u8>>>> {
        let result = self.get_entity_parts_with_receipt(id, None)?;
        Ok(ScopedReadResult {
            value: result.value.map(|(_, _, body)| body),
            receipt: result.receipt,
        })
    }

    /// Internal convenience. Consumer projections use the receipted door.
    pub fn get_entity_parts(&self, id: &EntityId) -> Result<Option<EntityParts>> {
        Ok(self.get_entity_parts_with_receipt(id, None)?.value)
    }

    pub fn get_entity_parts_with_receipt(
        &self,
        id: &EntityId,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Option<EntityParts>>> {
        self.get_entity_parts_with_mode_with_receipt(id, ReadMode::Live, requested)
    }

    pub fn get_entity_parts_with_mode_with_receipt(
        &self,
        id: &EntityId,
        mode: ReadMode,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Option<EntityParts>>> {
        let result = self.get_entities_parts_with_modes_with_receipt(&[(*id, mode)], requested)?;
        Ok(ScopedReadResult {
            value: result.value.into_iter().next().flatten(),
            receipt: result.receipt,
        })
    }

    pub fn get_entities_parts_with_receipt(
        &self,
        ids: &[EntityId],
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<Option<EntityParts>>>> {
        let reads: Vec<_> = ids.iter().map(|id| (*id, ReadMode::Live)).collect();
        self.get_entities_parts_with_modes_with_receipt(&reads, requested)
    }

    /// Mixed source revisions and all page authority checks share one snapshot.
    pub fn get_entities_parts_with_modes_with_receipt(
        &self,
        reads: &[(EntityId, ReadMode)],
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<Option<EntityParts>>>> {
        let txn = self.vault.store.env.read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, requested)?;
        let mut value = Vec::with_capacity(reads.len());
        let mut suppressed = 0;
        for (id, mode) in reads {
            let raw = self.entity_raw_with_mode_in(&txn, &policy, &filter, id, *mode)?;
            let parts = if let Some(raw) = raw {
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("entity header"))?;
                Some((
                    header.entity_type,
                    header.learned_at,
                    raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
                ))
            } else {
                suppressed += usize::from(self.entity_record_in(&txn, id)?.is_some());
                None
            };
            value.push(parts);
        }
        Ok(ScopedReadResult {
            value,
            receipt: self.receipt_for(requested, &policy, &filter, suppressed),
        })
    }

    pub fn hydrate_short_id(
        &self,
        short_id: &str,
        content_hash: u8,
    ) -> Result<ScopedReadResult<Option<crate::HydratedShortId>>> {
        self.hydrate_short_id_with_mode_with_receipt(short_id, content_hash, ReadMode::Live)
    }

    pub fn hydrate_short_id_with_mode_with_receipt(
        &self,
        short_id: &str,
        content_hash: u8,
        mode: ReadMode,
    ) -> Result<ScopedReadResult<Option<crate::HydratedShortId>>> {
        let result = self.hydrate_short_ids_with_modes(&[(short_id, content_hash, mode)])?;
        Ok(ScopedReadResult {
            value: result.value.into_iter().next().flatten(),
            receipt: result.receipt,
        })
    }

    pub fn hydrate_short_ids(
        &self,
        refs: &[(&str, u8)],
    ) -> Result<ScopedReadResult<Vec<Option<crate::HydratedShortId>>>> {
        let reads: Vec<_> = refs
            .iter()
            .map(|(short, hash)| (*short, *hash, ReadMode::Live))
            .collect();
        self.hydrate_short_ids_with_modes(&reads)
    }

    /// Missing refs are not policy exclusions. Resolved, withheld rows are counted.
    pub fn hydrate_short_ids_with_modes(
        &self,
        refs: &[(&str, u8, ReadMode)],
    ) -> Result<ScopedReadResult<Vec<Option<crate::HydratedShortId>>>> {
        let txn = self.vault.store.env.read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, None)?;
        let mut value = Vec::with_capacity(refs.len());
        let mut suppressed = 0;
        for (short_id, content_hash, mode) in refs {
            let mut hydrated = match *mode {
                ReadMode::Pinned(revision) => {
                    let id = self.vault.resolve_pinned_entity_reference_in(
                        &txn,
                        &format!("{short_id}:{content_hash:02x}"),
                        revision,
                    )?;
                    match id {
                        Some(id) => {
                            let raw =
                                self.entity_raw_with_mode_in(&txn, &policy, &filter, &id, *mode)?;
                            if let Some(raw) = raw {
                                let header = EntityMetadataHeader::parse(&raw)
                                    .ok_or(Error::CorruptedIndex("entity header"))?;
                                Some(crate::HydratedShortId {
                                    id,
                                    entity_type: header.entity_type,
                                    learned_at: header.learned_at,
                                    deletion: None,
                                    body: Some(raw[ENTITY_METADATA_HEADER_LEN..].to_vec()),
                                })
                            } else {
                                suppressed +=
                                    usize::from(self.entity_record_in(&txn, &id)?.is_some());
                                None
                            }
                        }
                        None => None,
                    }
                }
                ReadMode::Live | ReadMode::Indexed => {
                    self.vault
                        .hydrate_short_id_in(&txn, short_id, *content_hash)?
                }
            };
            if let Some(row) = &mut hydrated {
                let allowed = if row.body.is_some() {
                    // Resolve the requested frontier in this same transaction.
                    if let Some(raw) =
                        self.entity_raw_with_mode_in(&txn, &policy, &filter, &row.id, *mode)?
                    {
                        let header = EntityMetadataHeader::parse(&raw)
                            .ok_or(Error::CorruptedIndex("entity header"))?;
                        row.entity_type = header.entity_type;
                        row.learned_at = header.learned_at;
                        row.body = Some(raw[ENTITY_METADATA_HEADER_LEN..].to_vec());
                        true
                    } else {
                        false
                    }
                } else {
                    // Erased relationship/private bodies cannot prove a scope.
                    row.deletion.is_some()
                        && self.audience_readable_in(&txn, &row.id)?
                        && row.entity_type != crate::registry::ENTITY_TYPE_NOTE
                        && !(self.actor_key.enforce_access_grants
                            && matches!(
                                row.entity_type,
                                crate::registry::ENTITY_TYPE_CLAIM
                                    | crate::registry::ENTITY_TYPE_MESSAGE
                                    | crate::registry::ENTITY_TYPE_SUMMARY
                            ))
                        && !filter.deny_all
                        && filter
                            .entity_types
                            .as_ref()
                            .is_none_or(|types| types.contains(&row.entity_type))
                };
                if !allowed {
                    suppressed += usize::from(self.entity_record_in(&txn, &row.id)?.is_some());
                    hydrated = None;
                }
            }
            value.push(hydrated);
        }
        Ok(ScopedReadResult {
            value,
            receipt: self.receipt_for(None, &policy, &filter, suppressed),
        })
    }
}
