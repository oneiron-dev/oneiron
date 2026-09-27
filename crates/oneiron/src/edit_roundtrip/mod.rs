//! Engine adapter for the independent document editor.

pub use oneiron_docedit::edit_roundtrip::*;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use oneiron_docedit::{ArtifactSnapshot, ArtifactStorage};

impl ArtifactStorage for Vault {
    type Id = EntityId;
    type Error = Error;

    fn snapshot(&self, artifact_id: &EntityId) -> Result<Option<ArtifactSnapshot>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(head) =
            crate::blob_artifact::read_blob_artifact_head_in_txn(&self.store, &rtxn, artifact_id)?
        else {
            return Ok(None);
        };
        let policy = crate::gate::resolve_policy_manifest(&self.store, &rtxn)?;
        let limits = policy.document_limits().ok_or_else(|| {
            Error::InvalidConfig("document admission policy is missing or malformed".to_owned())
        })?;
        let bytes = self
            .read_blob_artifact_version_in_txn(&rtxn, artifact_id, head.version)?
            .ok_or(Error::EntityNotFound)?;
        let body = self
            .get_blob_artifact_in_txn(&rtxn, artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        Ok(Some(ArtifactSnapshot {
            version: head.version,
            media_type: body.media_type,
            bytes,
            limits,
        }))
    }

    fn missing_artifact(&self) -> Error {
        Error::EntityNotFound
    }
}

impl Vault {
    /// Produce a validated retained output from the current artifact head.
    pub fn propose_blob_artifact_edit<S: EditSession>(
        &self,
        artifact_id: &EntityId,
        session: &S,
        plan: &EditPlan,
        run_ref: &str,
    ) -> Result<EditOutcome> {
        oneiron_docedit::propose_artifact_edit(self, artifact_id, session, plan, run_ref)
    }

    /// Narrow the vault's resolved document budget for this proposal. A caller
    /// cannot widen it; wider admission requires a trusted policy row.
    pub fn propose_blob_artifact_edit_with_limits<S: EditSession>(
        &self,
        artifact_id: &EntityId,
        session: &S,
        plan: &EditPlan,
        run_ref: &str,
        requested: oneiron_docedit::edit_roundtrip::limits::DocumentLimits,
    ) -> Result<EditOutcome> {
        oneiron_docedit::propose_artifact_edit_with_limits(
            self,
            artifact_id,
            session,
            plan,
            run_ref,
            Some(requested),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
    use crate::edge::EdgeActorClass;
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::temporal::TimeRange;
    use crate::write_envelope::WriteActor;

    #[test]
    fn document_errors_keep_engine_error_kinds() {
        use oneiron_docedit::error::Error as DoceditError;
        assert_eq!(
            Error::from(DoceditError::InvalidAnchor("bad")).kind(),
            crate::error::ErrorKind::InvalidAnchor
        );
        assert_eq!(
            Error::from(DoceditError::InvalidEditManifest("bad")).kind(),
            crate::error::ErrorKind::InvalidEditManifest
        );
        assert_eq!(
            Error::from(DoceditError::EditRoundtripFailed("bad")).kind(),
            crate::error::ErrorKind::EditRoundtripFailed
        );
    }

    #[test]
    fn vault_adapter_returns_the_bound_head_snapshot() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        crate::test_util::put_policy_manifest_bytes(
            &vault,
            crate::gate::default_policy_manifest_id()?,
            &crate::gate::default_policy_manifest(),
        )?;
        let id = EntityId::now();
        assert!(ArtifactStorage::snapshot(&vault, &id)?.is_none());
        let time = TimeRange { start: 11, end: 11 };
        let actor_id = EntityId::now();
        vault.put_entity(&actor_id, ENTITY_TYPE_PERSON, time, 11, b"author")?;
        vault.put_blob_artifact(
            &id,
            &BlobArtifactBody::new(
                "workbook.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ),
            time,
            11,
        )?;
        let first = vault.append_blob_artifact_version(
            &id,
            b"first",
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(actor_id, EdgeActorClass::Human),
            time,
            11,
        )?;
        let snapshot = ArtifactStorage::snapshot(&vault, &id)?.ok_or(Error::EntityNotFound)?;
        assert_eq!(snapshot.version, first.version);
        assert_eq!(snapshot.limits.entry_bytes(), 256 * 1024 * 1024);
        assert_eq!(snapshot.limits.package_bytes(), 1024 * 1024 * 1024);
        assert_eq!(snapshot.bytes, b"first");
        assert_eq!(
            snapshot.media_type,
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        );
        Ok(())
    }
}
