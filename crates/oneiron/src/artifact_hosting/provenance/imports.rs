//! Input records for existing import doors and attributed producer exports.
use super::*;
use crate::blob_artifact::{BlobArtifactBody, BlobArtifactVersion, BlobVersionProvenance};

impl Vault {
    /// Records the exact causal request as an immutable input, never as a guessed task.
    pub(crate) fn artifact_input_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        artifact: EntityId,
        bytes: &[u8],
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let input = crate::codebase::entity_id_from_hash_material(
            b"oneiron.artifact.input.v1",
            &[artifact.as_bytes(), blake3::hash(bytes).as_bytes()],
        )?;
        if let Some(raw) = self.store.entities.get(txn, input.as_bytes())? {
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("artifact input header"))?;
            if header.entity_type != crate::registry::ENTITY_TYPE_ASSET
                || raw[ENTITY_METADATA_HEADER_LEN..] != *bytes
            {
                return invalid("artifact input identity collision");
            }
        } else {
            self.batch_in()
                .put(
                    &input,
                    crate::registry::ENTITY_TYPE_ASSET,
                    occurred,
                    learned_at,
                    bytes,
                )
                .apply(txn)?;
        }
        Ok(input)
    }

    /// The engine importer is the writer when a legacy import API has no caller actor.
    pub(crate) fn artifact_import_actor_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<WriteActor> {
        const IDENTITY: &[u8] = b"oneiron.artifact.importer.v1";
        let id = crate::codebase::entity_id_from_hash_material(IDENTITY, &[])?;
        if let Some(raw) = self.store.entities.get(txn, id.as_bytes())? {
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("artifact importer header"))?;
            if header.entity_type != crate::registry::ENTITY_TYPE_MACHINE
                || raw[ENTITY_METADATA_HEADER_LEN..] != *IDENTITY
            {
                return invalid("artifact importer identity collision");
            }
        } else {
            self.batch_in()
                .put(
                    &id,
                    crate::registry::ENTITY_TYPE_MACHINE,
                    occurred,
                    learned_at,
                    IDENTITY,
                )
                .apply(txn)?;
        }
        Ok(WriteActor::new(id, crate::edge::EdgeActorClass::System))
    }

    /// Builds the memo key from one existing input in the caller's snapshot.
    pub(crate) fn artifact_birth_for_input_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        trigger: ArtifactTrigger,
        prompt_ref: EntityId,
        run_ref: Option<String>,
        producer: &str,
        purpose: ArtifactPurpose,
    ) -> Result<ArtifactBirthEnvelope> {
        let raw = self
            .store
            .entities
            .get(txn, prompt_ref.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        if raw.len() < ENTITY_METADATA_HEADER_LEN {
            return Err(Error::CorruptedIndex("artifact input header"));
        }
        Ok(ArtifactBirthEnvelope {
            trigger,
            prompt_ref,
            run_ref,
            content_hash: *blake3::hash(&raw[ENTITY_METADATA_HEADER_LEN..]).as_bytes(),
            model_id: producer.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            params_hash: *blake3::hash(producer.as_bytes()).as_bytes(),
            purpose,
        })
    }

    /// Existing low-level typed imports carry the upload request as their ask.
    /// They do not claim that a task or a human caused an un-attributed import.
    pub(crate) fn import_artifact_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        artifact: EntityId,
        body: ArtifactBirthBody<'_>,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let input_bytes = match body {
            ArtifactBirthBody::Code(body) => crate::code_artifact::encode_code_artifact_body(body)?,
            ArtifactBirthBody::Blob(body) => crate::blob_artifact::encode_blob_artifact_body(body)?,
        };
        if self.store.entities.get(txn, artifact.as_bytes())?.is_some() {
            let kind = match body {
                ArtifactBirthBody::Code(_) => crate::registry::ENTITY_TYPE_CODE_ARTIFACT,
                ArtifactBirthBody::Blob(_) => crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
            };
            return self
                .batch_in()
                .put(&artifact, kind, occurred, learned_at, &input_bytes)
                .apply(txn);
        }
        let input =
            self.artifact_input_in_txn(txn, artifact, &input_bytes, occurred, learned_at)?;
        let actor = self.artifact_import_actor_in_txn(txn, occurred, learned_at)?;
        let birth = self.artifact_birth_for_input_in_txn(
            txn,
            ArtifactTrigger::Ask(input),
            input,
            None,
            "oneiron/artifact-import",
            ArtifactPurpose::Deliverable,
        )?;
        self.create_artifact_with_birth_in_txn(
            txn, artifact, body, &birth, actor, occurred, learned_at,
        )?;
        Ok(())
    }

    /// First registration and exported bytes share the producer's transaction.
    #[expect(
        clippy::too_many_arguments,
        reason = "producer controls the artifact transaction"
    )]
    pub(crate) fn persist_blob_with_birth_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        artifact: EntityId,
        body: &BlobArtifactBody,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<BlobArtifactVersion> {
        if self.store.entities.get(txn, artifact.as_bytes())?.is_none() {
            let input = self.artifact_input_in_txn(txn, artifact, bytes, occurred, learned_at)?;
            let trigger = match provenance {
                BlobVersionProvenance::UserUpload => ArtifactTrigger::Ask(input),
                BlobVersionProvenance::AgentRun { run_ref } => {
                    ArtifactTrigger::Run(run_ref.clone())
                }
            };
            let birth = self.artifact_birth_for_input_in_txn(
                txn,
                trigger,
                input,
                provenance.run_ref().map(str::to_owned),
                "oneiron/blob-import",
                ArtifactPurpose::Deliverable,
            )?;
            self.create_artifact_with_birth_in_txn(
                txn,
                artifact,
                ArtifactBirthBody::Blob(body),
                &birth,
                actor,
                occurred,
                learned_at,
            )?;
        }
        self.append_blob_artifact_version_in_txn(
            txn, &artifact, bytes, provenance, actor, occurred, learned_at,
        )
    }
}
