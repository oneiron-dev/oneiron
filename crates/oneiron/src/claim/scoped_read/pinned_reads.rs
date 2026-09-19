//! Manifest-derived safety pins bypass query relevance, never actor authority.
use super::{ScopedRead, ScopedReadResult};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::decode_claim_body;
use crate::{EntityId, Error, Result};

impl ScopedRead<'_> {
    /// Current engine-issued refs for live claims in declared critical classes.
    /// Policy, row admission and reference binding share one read snapshot.
    pub fn manifest_pinned_refs(&self) -> Result<ScopedReadResult<Vec<String>>> {
        let txn = self.vault.store.env.read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, None)?;
        let mut value = Vec::new();
        let mut suppressed = 0;
        for entry in self.entities().iter(&txn)? {
            let (key, raw) = entry?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("pin entity header"))?;
            if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
                || raw.len() == ENTITY_METADATA_HEADER_LEN
            {
                continue;
            }
            let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if !policy.pins_predicate(&body.predicate) {
                continue;
            }
            let id = EntityId::from_bytes(
                key[..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("pin entity id"))?,
            )?;
            if !self.is_entity_retrievable_with_policy_in(&txn, &policy, &filter, &id)? {
                suppressed += 1;
                continue;
            }
            let Some(encoded) = self
                .vault
                .store
                .short_ids_reverse
                .get(&txn, id.as_bytes())?
            else {
                continue;
            };
            let (short_id, hash) = crate::batch::parse_short_id_value(&encoded)?;
            value.push(format!("{short_id}:{hash:02x}"));
        }
        Ok(ScopedReadResult {
            value,
            receipt: self.receipt_for(None, &policy, &filter, suppressed),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::{ClaimBody, ClaimSource, ClaimSubject, ScopedReadActorKey};
    #[test]
    fn manifest_critical_claims_are_pinned_without_query_selection() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let subject = EntityId::now();
        let id = EntityId::now();
        let when = crate::TimeRange { start: 1, end: 1 };
        vault.put_entity(
            &subject,
            crate::registry::ENTITY_TYPE_PERSON,
            when,
            1,
            b"person",
        )?;
        let mut claim = ClaimBody::new(
            "profile.name",
            ClaimSubject::Entity(subject),
            rmpv::Value::from("stored safety fact"),
            1.0,
            crate::ClaimApprovalStatus::Auto,
            crate::ClaimLifecycleStatus::Active,
        );
        claim.source = Some(ClaimSource::UserStated);
        vault.put_claim(&id, &claim, when, 1)?;
        let reader = vault.scoped_read(ScopedReadActorKey::new("pin-reader").unwrap());
        assert!(reader.manifest_pinned_refs()?.value.is_empty());
        let mut policy = rmpv::decode::read_value(&mut std::io::Cursor::new(
            crate::gate::default_policy_manifest(),
        ))
        .unwrap();
        // Remove the normal-prefix rules: the declared critical default now
        // classifies this existing approved row without rewriting its bytes.
        let rmpv::Value::Map(fields) = &mut policy else {
            unreachable!()
        };
        let rules = fields
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("rules"))
            .unwrap();
        rules.1 = rmpv::Value::Array(Vec::new());
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &policy).unwrap();
        crate::test_util::put_policy_manifest_bytes(
            &vault,
            crate::gate::default_policy_manifest_id()?,
            &bytes,
        )?;
        let pins = reader.manifest_pinned_refs()?;
        assert_eq!(pins.value.len(), 1);
        assert_eq!(pins.receipt.suppressed_count, 0);
        let mut section = crate::context_board::project_memories_section(
            &vault.context_pack().run()?,
            crate::MemoriesBudget::default().with_shared_total(0),
            None,
            None,
        );
        section.include_pinned_refs(&reader, &pins.value)?;
        assert_eq!(section.rows.len(), 1);
        assert_eq!(section.rows[0].id, id.to_hex());
        assert_eq!(
            section.rows[0].tier,
            crate::context_board::MemoryTier::Pinned
        );
        Ok(())
    }
}
