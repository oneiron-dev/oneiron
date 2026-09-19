//! Same-snapshot, receipted point and short-reference hydration doors.
use super::{RetrievalFilter, ScopedRead, ScopedReadResult};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
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

    /// Internal body lookup. Consumer projections must use the receipted door.
    pub(crate) fn get_entity_parts(&self, id: &EntityId) -> Result<Option<EntityParts>> {
        Ok(self.get_entity_parts_with_receipt(id, None)?.value)
    }

    /// Reads bytes and authority in one snapshot. A preceding search's applied
    /// filter can be supplied to ensure projection never widens its plan.
    pub fn get_entity_parts_with_receipt(
        &self,
        id: &EntityId,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Option<EntityParts>>> {
        let result = self.get_entities_parts_with_receipt(&[*id], requested)?;
        Ok(ScopedReadResult {
            value: result.value.into_iter().next().flatten(),
            receipt: result.receipt,
        })
    }

    /// Point projections share one final authority snapshot across the page.
    pub fn get_entities_parts_with_receipt(
        &self,
        ids: &[EntityId],
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<Option<EntityParts>>>> {
        let txn = self.vault.store.env.read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, requested)?;
        let mut value = Vec::with_capacity(ids.len());
        let mut suppressed = 0;
        for id in ids {
            let mut parts = None;
            if let Some(raw) = self.entities().get(&txn, id.as_bytes())? {
                if self.is_entity_retrievable_with_policy_in(&txn, &policy, &filter, id)? {
                    let header = EntityMetadataHeader::parse(&raw)
                        .ok_or(Error::CorruptedIndex("entity header"))?;
                    parts = Some((
                        header.entity_type,
                        header.learned_at,
                        raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
                    ));
                } else {
                    suppressed += 1;
                }
            }
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
        let result = self.hydrate_short_ids(&[(short_id, content_hash)])?;
        Ok(ScopedReadResult {
            value: result.value.into_iter().next().flatten(),
            receipt: result.receipt,
        })
    }

    /// Batch lookup and all authority checks share one snapshot. Missing refs
    /// are not policy exclusions; only resolved rows can add to suppression.
    pub fn hydrate_short_ids(
        &self,
        refs: &[(&str, u8)],
    ) -> Result<ScopedReadResult<Vec<Option<crate::HydratedShortId>>>> {
        let txn = self.vault.store.env.read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, None)?;
        let mut value = Vec::with_capacity(refs.len());
        let mut suppressed = 0;
        for (short_id, content_hash) in refs {
            let mut hydrated = self
                .vault
                .hydrate_short_id_in(&txn, short_id, *content_hash)?;
            if let Some(row) = &hydrated {
                // Deletion metadata remains available only under the type ceiling.
                // Archived rows (no deletion receipt) are withheld, not empty live rows.
                let allowed = if row.body.is_some() {
                    self.is_entity_retrievable_with_policy_in(&txn, &policy, &filter, &row.id)?
                } else {
                    row.deletion.is_some()
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
                    hydrated = None;
                    suppressed += 1;
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
