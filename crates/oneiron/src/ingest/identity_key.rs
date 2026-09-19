//! Per-kind identity hints and the lookup-before-mint entity-resolution door.
//! Index hits never prove sameness: only the evidence waterfall selects a link.

use super::resolution::{
    EntityResolutionCandidate, EntityResolutionRoute, EntityResolutionWaterfallDecision,
    evaluate_entity_resolution_waterfall_in_txn,
};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON, ENTITY_TYPE_PLACE};
use crate::store::ManifestDbs;
use crate::{EntityId, TimeRange, Vault};
use std::collections::BTreeSet;

/// Declared hints for kinds with human-facing identities. None is unique.
pub fn identity_fields_for_kind(kind: u8) -> &'static [&'static str] {
    match kind {
        ENTITY_TYPE_PERSON => &["name", "aliases", "phonetic", "contact_handle"],
        ENTITY_TYPE_ORG | ENTITY_TYPE_PLACE => &["name", "aliases", "phonetic"],
        _ => &[],
    }
}

fn hints(kind: u8, bytes: &[u8]) -> BTreeSet<String> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value = if let Ok(value) = rmpv::decode::read_value(&mut cursor)
        && cursor.position() == bytes.len() as u64
    {
        crate::companion::companion_value_to_json(&value)
    } else if let Ok(value) = serde_json::from_slice(bytes) {
        value
    } else {
        return BTreeSet::new();
    };
    let mut hints = BTreeSet::new();
    for field in identity_fields_for_kind(kind) {
        let Some(value) = value.get(*field) else {
            continue;
        };
        let values: Vec<_> = match value {
            serde_json::Value::Array(values) => values.iter().collect(),
            value => vec![value],
        };
        for value in values {
            if let Some(value) = value.as_str() {
                let value = value.trim().to_lowercase();
                if !value.is_empty() {
                    hints.insert(value);
                }
            }
        }
    }
    hints
}

fn prefix(kind: u8, hint: &str) -> Vec<u8> {
    let mut key = b"identity-hint:v1:".to_vec();
    key.push(kind);
    key.extend_from_slice(blake3::hash(hint.trim().to_lowercase().as_bytes()).as_bytes());
    key
}
fn index_key(kind: u8, hint: &str, id: &EntityId) -> Vec<u8> {
    let mut key = prefix(kind, hint);
    key.extend_from_slice(id.as_bytes());
    key
}

pub(crate) fn reindex_identity_hints(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    replacement: Option<(u8, &[u8])>,
) -> Result<()> {
    if let Some(raw) = store.entities().get(txn, id.as_bytes())?
        && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
    {
        for hint in hints(
            header.entity_type,
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        ) {
            store
                .vault_meta()
                .delete(txn, &index_key(header.entity_type, &hint, id))?;
        }
    }
    if let Some((kind, body)) = replacement {
        for hint in hints(kind, body) {
            store
                .vault_meta()
                .put(txn, &index_key(kind, &hint, id), &[])?;
        }
    }
    Ok(())
}

pub(super) struct MentionResolution<'a> {
    pub(super) kind: u8,
    pub(super) mention: &'a str,
    pub(super) body: &'a [u8],
    pub(super) occurred: TimeRange,
    pub(super) learned_at: u64,
    pub(super) found: &'a [EntityId],
    pub(super) candidates: &'a [EntityResolutionCandidate],
}

impl Vault {
    /// N candidates for a mention; reading this index never links or merges.
    pub fn lookup_identity_key(&self, kind: u8, mention: &str) -> Result<Vec<EntityId>> {
        if identity_fields_for_kind(kind).is_empty() {
            return Ok(Vec::new());
        }
        let txn = self.store.env.read_txn()?;
        self.lookup_identity_key_in_txn(&txn, kind, mention)
    }
    pub(super) fn lookup_identity_key_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        kind: u8,
        mention: &str,
    ) -> Result<Vec<EntityId>> {
        let prefix = prefix(kind, mention);
        let mut candidates = BTreeSet::new();
        for entry in self.store.vault_meta.prefix_iter(txn, &prefix)? {
            let (key, _) = entry?;
            let bytes: [u8; 16] = key[prefix.len()..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("identity hint key"))?;
            let id = EntityId::from_bytes(bytes)?;
            // Verify indexed evidence at read too; a stale/corrupt shortcut
            // can never create a candidate absent from the stored record.
            if let Some(raw) = self.store.entities.get(txn, id.as_bytes())?
                && crate::batch::EntityMetadataHeader::parse(&raw)
                    .is_some_and(|h| h.entity_type == kind)
                && hints(kind, &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                    .contains(&mention.trim().to_lowercase())
            {
                candidates.insert(id);
            }
        }
        Ok(candidates.into_iter().collect())
    }

    /// Resolves evidence ONLY over index candidates, then mints on the
    /// provisional route. No topology merge is performed, so distinct pairs
    /// cannot be joined by a matching name. `score` is an evidence producer,
    /// not a decision: the ARCH-0024 waterfall validates its stored claims.
    pub fn resolve_imported_mention(
        &self,
        kind: u8,
        mention: &str,
        body: &[u8],
        occurred: TimeRange,
        learned_at: u64,
        score: impl FnOnce(&[EntityId]) -> Result<Vec<EntityResolutionCandidate>>,
    ) -> Result<(EntityId, EntityResolutionWaterfallDecision)> {
        if identity_fields_for_kind(kind).is_empty()
            || !hints(kind, body).contains(&mention.trim().to_lowercase())
        {
            return Err(Error::InvalidClaimBody(
                "mention lacks a declared identity hint",
            ));
        }
        let found = self.lookup_identity_key(kind, mention)?;
        let candidates = score(&found)?;
        self.with_write_txn(|txn| {
            self.resolve_prepared_mention_in_txn(
                txn,
                &MentionResolution {
                    kind,
                    mention,
                    body,
                    occurred,
                    learned_at,
                    found: &found,
                    candidates: &candidates,
                },
            )
        })
    }
    pub(super) fn resolve_prepared_mention_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: &MentionResolution<'_>,
    ) -> Result<(EntityId, EntityResolutionWaterfallDecision)> {
        let MentionResolution {
            kind,
            mention,
            body,
            occurred,
            learned_at,
            found,
            candidates,
        } = input;
        if identity_fields_for_kind(*kind).is_empty()
            || !hints(*kind, body).contains(&mention.trim().to_lowercase())
        {
            return Err(Error::InvalidClaimBody(
                "mention lacks a declared identity hint",
            ));
        }
        if self
            .lookup_identity_key_in_txn(txn, *kind, mention)?
            .as_slice()
            != *found
        {
            return Err(Error::InvalidConfig(
                "identity candidates changed during scoring; retry".into(),
            ));
        }
        if candidates
            .iter()
            .any(|candidate| !found.contains(&candidate.subject))
        {
            return Err(Error::InvalidClaimBody(
                "resolution candidate is outside identity lookup",
            ));
        }
        let decision =
            evaluate_entity_resolution_waterfall_in_txn(self, txn, candidates, found.len() > 1)?;
        if let Some(id) = decision.selected {
            return Ok((id, decision));
        }
        if decision.route != EntityResolutionRoute::ProvisionalEntity {
            return Err(Error::InvariantViolation(
                "nonprovisional resolution lacks subject",
            ));
        }
        let id = EntityId::now();
        self.batch_in()
            .put(&id, *kind, *occurred, *learned_at, body)
            .apply(txn)?;
        Ok((id, decision))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_key_lookup_returns_every_candidate_and_never_links() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let body = rmp_serde::to_vec_named(&serde_json::json!({"name":"Yamada Tarou"})).unwrap();
        let occurred = TimeRange { start: 1, end: 1 };
        let (a, _) = vault.resolve_imported_mention(
            ENTITY_TYPE_PERSON,
            "Yamada Tarou",
            &body,
            occurred,
            1,
            |found| {
                assert!(found.is_empty());
                Ok(vec![])
            },
        )?;
        let (b, _) = vault.resolve_imported_mention(
            ENTITY_TYPE_PERSON,
            "Yamada Tarou",
            &body,
            occurred,
            1,
            |found| {
                assert_eq!(found, &[a]);
                Ok(vec![])
            },
        )?;
        assert_ne!(a, b);
        let found = vault.lookup_identity_key(ENTITY_TYPE_PERSON, "Yamada Tarou")?;
        assert_eq!(found.len(), 2);
        assert_eq!(vault.resolve_entity(&a)?, vec![a]);
        assert_eq!(vault.resolve_entity(&b)?, vec![b]);
        Ok(())
    }
    #[test]
    fn evidence_remention_reuses_ids_without_merging_a_distinct_pair() -> Result<()> {
        use crate::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
        use rmpv::Value;
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let body = rmp_serde::to_vec_named(&serde_json::json!({"name":"Yamada Tarou"})).unwrap();
        let time = TimeRange { start: 1, end: 1 };
        let a = vault
            .resolve_imported_mention(ENTITY_TYPE_PERSON, "Yamada Tarou", &body, time, 1, |_| {
                Ok(vec![])
            })?
            .0;
        let b = vault
            .resolve_imported_mention(ENTITY_TYPE_PERSON, "Yamada Tarou", &body, time, 1, |_| {
                Ok(vec![])
            })?
            .0;
        let (first, second) = if a < b { (a, b) } else { (b, a) };
        let distinct = ClaimBody::new(
            "entity.distinct_from",
            ClaimSubject::Entity(first),
            Value::Map(vec![
                (Value::from("a"), Value::Binary(first.as_bytes().to_vec())),
                (Value::from("b"), Value::Binary(second.as_bytes().to_vec())),
            ]),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        vault.put_claim(&EntityId::now(), &distinct, time, 1)?;
        for subject in [a, b] {
            let evidence = EntityId::now();
            let evidence_body = ClaimBody::new(
                "provider.enrichment",
                ClaimSubject::Entity(subject),
                Value::Map(vec![(
                    Value::from("provider"),
                    Value::from("fixture.identity"),
                )]),
                0.99,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            );
            vault.put_claim(&evidence, &evidence_body, time, 1)?;
            let (selected, decision) = vault.resolve_imported_mention(
                ENTITY_TYPE_PERSON,
                "Yamada Tarou",
                &body,
                time,
                2,
                |found| {
                    assert_eq!(found.len(), 2);
                    Ok(vec![EntityResolutionCandidate {
                        subject,
                        confidence_claim_ref: evidence,
                    }])
                },
            )?;
            assert_eq!(selected, subject);
            assert_ne!(decision.route, EntityResolutionRoute::ProvisionalEntity);
            assert_eq!(
                vault
                    .lookup_identity_key(ENTITY_TYPE_PERSON, "Yamada Tarou")?
                    .len(),
                2
            );
        }
        assert_eq!(vault.resolve_entity(&a)?, vec![a]);
        assert_eq!(vault.resolve_entity(&b)?, vec![b]);
        assert_eq!(vault.distinct_claims_for_pair(&a, &b)?.len(), 1);
        Ok(())
    }
    #[test]
    fn legacy_uuidv7_row_hydrates_and_resolves_after_reopen() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config = crate::test_util::embedding_test_config();
        let legacy = EntityId::from_bytes(*uuid::Uuid::now_v7().as_bytes())?;
        let body = rmp_serde::to_vec_named(&serde_json::json!({"name":"Legacy Person"})).unwrap();
        {
            let vault = Vault::open(dir.path(), config.clone())?;
            vault.put_entity(
                &legacy,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                &body,
            )?;
        }
        let vault = Vault::open(dir.path(), config)?;
        assert_eq!(
            vault.lookup_identity_key(ENTITY_TYPE_PERSON, "Legacy Person")?,
            vec![legacy]
        );
        assert!(vault.get_entity(&legacy)?.is_some());
        assert_eq!(vault.resolve_entity(&legacy)?, vec![legacy]);
        Ok(())
    }

    #[test]
    fn refused_import_rolls_back_provisional_person_too() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let actor = EntityId::now();
        let time = TimeRange { start: 1, end: 1 };
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, time, 1, b"actor")?;
        let claim = super::super::NormalizedIngestClaim {
            source_record_id: "record-1".into(),
            predicate: "profile.contact".into(),
            value: serde_json::json!({"password":"fixture-super-secret"}),
        };
        let admission = super::super::ImportedEvidenceAdmission::proposed(
            "fixture",
            EntityId::now(),
            super::super::ImportedEvidenceEntityResolution::subject(actor),
            crate::WriteActor::new(actor, crate::EdgeActorClass::Human),
            time,
            1,
        );
        let body = rmp_serde::to_vec_named(&serde_json::json!({"name":"New Person"})).unwrap();
        let error = super::super::admit_imported_mention_claim(
            &vault,
            &claim,
            admission,
            ENTITY_TYPE_PERSON,
            "New Person",
            &body,
            |_| Ok(vec![]),
        )
        .unwrap_err();
        crate::test_util::assert_secret_scan_rejected(error, "gate.secret_scan.sensitive_env");
        assert!(
            vault
                .lookup_identity_key(ENTITY_TYPE_PERSON, "New Person")?
                .is_empty()
        );
        Ok(())
    }
}
