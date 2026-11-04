//! Per-kind identity hints and the lookup-before-mint entity-resolution door.
//! Index hits never prove sameness: only the evidence waterfall selects a link.

use super::resolution::{
    EntityResolutionCandidate, EntityResolutionRoute, EntityResolutionWaterfallDecision,
    evaluate_entity_resolution_waterfall_in_txn,
};
use crate::error::{Error, Result};
#[cfg(test)]
use crate::registry::ENTITY_TYPE_PERSON;
use crate::{EntityId, TimeRange, Vault};
use std::collections::BTreeSet;

pub use crate::store::identity_hints::identity_fields_for_kind;
use crate::store::identity_hints::{IDENTITY_HINT, hint_prefix, hints};
pub(crate) use crate::store::identity_hints::{
    identity_hint_body, identity_hint_digest, reindex_identity_hints,
};

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
    pub(crate) fn lookup_identity_key_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        kind: u8,
        mention: &str,
    ) -> Result<Vec<EntityId>> {
        let prefix = hint_prefix(kind, mention);
        let mut candidates = BTreeSet::new();
        for (_, _, id) in IDENTITY_HINT.scan_keys(&self.store, txn, &prefix)? {
            // Verify indexed evidence at read too; a stale/corrupt shortcut
            // can never create a candidate absent from the stored record.
            if let Some(raw) =
                crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &id)?
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
        self.with_write_txn_grouped(|txn| {
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
        assert_eq!(vault.get(&legacy)?, Some(body));
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
