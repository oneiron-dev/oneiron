//! Explicit memory pins bypass query relevance and render shedding, never read authority.
use super::memories::{MemoriesSection, MemoryRow, MemorySource, MemoryTier};
use super::memories_projection::{finish_projection, foreign_row, memory_asset_ref, memory_slot};
use crate::claim::{PointRead, ScopedRead, ScopedReadReceipt, decode_claim_body};
use crate::{EntityId, Result};
impl MemoriesSection {
    /// Pins are engine-issued short references already selected by the caller.
    /// Each read still resolves the actor ceiling and returns its mandatory receipt.
    /// No pin selection is inferred from retrieved prose.
    pub fn include_pinned_refs(
        &mut self,
        reader: &ScopedRead<'_>,
        references: &[String],
    ) -> Result<Vec<ScopedReadReceipt>> {
        self.include_pinned_refs_with_disclosure(reader, references, None)
    }

    /// Board callers apply their audience disclosure clamp as well as the
    /// actor's read ceiling. Pins bypass query relevance, never either authority.
    pub fn include_pinned_refs_with_disclosure(
        &mut self,
        reader: &ScopedRead<'_>,
        references: &[String],
        disclosure: Option<&crate::disclosure::DisclosureContext>,
    ) -> Result<Vec<ScopedReadReceipt>> {
        let mut receipts = Vec::with_capacity(references.len());
        let mut pins = std::collections::BTreeSet::<EntityId>::new();
        for reference in references {
            let (short_id, hash) =
                reference
                    .rsplit_once(':')
                    .ok_or(crate::Error::InvalidConfig(
                        "invalid memory pin reference".into(),
                    ))?;
            if hash.len() != 2 {
                return Err(crate::Error::InvalidConfig(
                    "invalid memory pin hash".into(),
                ));
            }
            let hash = u8::from_str_radix(hash, 16)
                .map_err(|_| crate::Error::InvalidConfig("invalid memory pin hash".into()))?;
            let hydrated = reader
                .read(&[PointRead::short(short_id, hash)], None)?
                .single();
            let mut receipt = hydrated.receipt;
            let Some(hydrated) = hydrated.value else {
                receipts.push(receipt);
                continue;
            };
            let Some(body) = hydrated.body else {
                receipts.push(receipt);
                continue;
            };
            if !pins.insert(hydrated.id) {
                receipts.push(receipt);
                continue;
            }
            let claim = if hydrated.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
                Some(decode_claim_body(&body, true)?)
            } else {
                None
            };
            if let Some(disclosure) = disclosure {
                let txn = reader.vault().store.env.read_txn()?;
                if !disclosure.admits(
                    &reader.vault().store,
                    &txn,
                    &hydrated.id,
                    hydrated.entity_type,
                    claim.as_ref(),
                )? {
                    receipt.add_suppressed(1);
                    receipts.push(receipt);
                    continue;
                }
            }
            receipts.push(receipt);
            let mut row = MemoryRow {
                row_index: 0,
                slot: memory_slot(hydrated.entity_type),
                source: MemorySource::Result,
                id: hydrated.id.to_hex(),
                short_id: short_id.to_owned(),
                content_hash: format!("{hash:02x}"),
                entity_type: hydrated.entity_type,
                asset_ref: memory_asset_ref(hydrated.entity_type, short_id, hash),
                score: 0.0,
                claim_source: claim.as_ref().and_then(|c| c.source),
                world: claim.as_ref().and_then(|c| c.world).map(|id| id.to_hex()),
                tier: MemoryTier::Pinned,
                snippet: None,
            };
            if !foreign_row(&row)
                && let Some(claim) = claim
            {
                let mut value = crate::companion::companion_value_to_json(&claim.value);
                crate::batch::export::redact_credentials(&mut value);
                row.snippet = Some(value.to_string());
            }
            self.rows.retain(|old| old.id != row.id);
            self.rows.push(row);
        }
        *self = finish_projection(
            std::mem::take(&mut self.rows),
            self.budget,
            self.companion.clone(),
            self.disclosure.clone(),
        );
        Ok(receipts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context_board::{MEMORIES_SECTION_VERSION_V4, MemoriesBudget};
    #[test]
    fn authorized_pins_survive_empty_query_scope_and_zero_shared_budget() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let id = EntityId::now();
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::TimeRange { start: 1, end: 1 },
            1,
            b"pinned person",
        )?;
        let txn = vault.store.env.read_txn()?;
        let encoded = vault
            .store
            .short_ids_reverse
            .get(&txn, id.as_bytes())?
            .unwrap();
        let (short, hash) = crate::batch::parse_short_id_value(&encoded)?;
        let reference = format!("{short}:{hash:02x}");
        drop(encoded);
        drop(txn);
        let mut section = MemoriesSection {
            version: MEMORIES_SECTION_VERSION_V4.into(),
            budget: MemoriesBudget::default().with_shared_total(0),
            rows: Vec::new(),
            companion: None,
            disclosure: None,
        };
        crate::test_util::authorize_readers(&vault, &["reader"]);
        let reader = vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").unwrap());
        let receipts = section.include_pinned_refs(&reader, &[reference])?;
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].suppressed_count, 0);
        assert_eq!(section.rows.len(), 1);
        assert_eq!(section.rows[0].id, id.to_hex());
        assert_eq!(section.rows[0].tier, MemoryTier::Pinned);
        Ok(())
    }
}
