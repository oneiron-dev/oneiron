//! One immutable born-from envelope in the claim ledger for either artifact family kind.
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::error::{ArtifactError, Error, Result};
use crate::registry::{
    ArtifactFamilyKind, ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SKILL, ENTITY_TYPE_TASK,
};
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
use crate::{EntityId, Vault};
use rmpv::Value;

const PREDICATE: &str = "artifact.born_from";
const MAX_REF_BYTES: usize = 1024;

/// The initiating record, or the stable host run reference when no task initiated it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactTrigger {
    Task(EntityId),
    Run(String),
    Skill(EntityId),
    Ask(EntityId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactPurpose {
    Deliverable,
    SkillReport,
    SkillCandidate,
}

/// The Rule-A memo key plus the birth's input/trigger references. No prompt copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactBirthEnvelope {
    pub trigger: ArtifactTrigger,
    pub prompt_ref: EntityId,
    pub run_ref: Option<String>,
    pub content_hash: [u8; 32],
    pub model_id: String,
    pub version: String,
    pub params_hash: [u8; 32],
    pub purpose: ArtifactPurpose,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactBirthProjection {
    pub artifact_id: EntityId,
    pub kind: ArtifactFamilyKind,
    pub ledger_ref: EntityId,
    pub made_by: ArtifactBirthEnvelope,
    pub approval_status: ClaimApprovalStatus,
}

impl ArtifactBirthEnvelope {
    fn validate(&self) -> Result<()> {
        for value in [&self.model_id, &self.version] {
            nonempty(value)?;
        }
        if let Some(run) = &self.run_ref {
            nonempty(run)?;
        }
        if let ArtifactTrigger::Run(run) = &self.trigger {
            nonempty(run)?;
            if self.run_ref.as_ref().is_some_and(|process| process != run) {
                return invalid("trigger run and producer run differ");
            }
        }
        Ok(())
    }
    fn value(&self) -> Value {
        let (kind, reference) = match &self.trigger {
            ArtifactTrigger::Task(id) => ("task", id.to_hex()),
            ArtifactTrigger::Run(reference) => ("run", reference.clone()),
            ArtifactTrigger::Skill(id) => ("skill", id.to_hex()),
            ArtifactTrigger::Ask(id) => ("ask", id.to_hex()),
        };
        Value::Map(vec![
            ("v".into(), 1u64.into()),
            ("trigger_kind".into(), kind.into()),
            ("trigger_ref".into(), reference.into()),
            ("prompt_ref".into(), self.prompt_ref.to_hex().into()),
            (
                "run_ref".into(),
                self.run_ref
                    .as_ref()
                    .map_or(Value::Nil, |r| r.as_str().into()),
            ),
            (
                "content_hash".into(),
                Value::Binary(self.content_hash.to_vec()),
            ),
            ("model_id".into(), self.model_id.as_str().into()),
            ("version".into(), self.version.as_str().into()),
            (
                "params_hash".into(),
                Value::Binary(self.params_hash.to_vec()),
            ),
            (
                "purpose".into(),
                match self.purpose {
                    ArtifactPurpose::Deliverable => "deliverable",
                    ArtifactPurpose::SkillReport => "skill_report",
                    ArtifactPurpose::SkillCandidate => "skill_candidate",
                }
                .into(),
            ),
        ])
    }
    fn decode(value: &Value) -> Result<Self> {
        let fields = value
            .as_map()
            .ok_or_else(|| error("birth envelope is not a map"))?;
        const KEYS: [&str; 10] = [
            "v",
            "trigger_kind",
            "trigger_ref",
            "prompt_ref",
            "run_ref",
            "content_hash",
            "model_id",
            "version",
            "params_hash",
            "purpose",
        ];
        if fields.len() != KEYS.len()
            || KEYS.iter().any(|key| {
                fields
                    .iter()
                    .filter(|(k, _)| k.as_str() == Some(key))
                    .count()
                    != 1
            })
        {
            return invalid("birth envelope keys mismatch");
        }
        let get = |key: &str| {
            fields
                .iter()
                .find(|(k, _)| k.as_str() == Some(key))
                .map(|(_, v)| v)
                .expect("validated keys")
        };
        let text = |key: &str| {
            get(key)
                .as_str()
                .ok_or_else(|| error("birth reference must be text"))
        };
        if get("v").as_u64() != Some(1) {
            return invalid("unsupported birth envelope version");
        }
        let reference = text("trigger_ref")?;
        let entity =
            || EntityId::from_hex(reference).map_err(|_| error("invalid trigger entity reference"));
        let trigger = match text("trigger_kind")? {
            "task" => ArtifactTrigger::Task(entity()?),
            "run" => ArtifactTrigger::Run(reference.into()),
            "skill" => ArtifactTrigger::Skill(entity()?),
            "ask" => ArtifactTrigger::Ask(entity()?),
            _ => return invalid("invalid trigger kind"),
        };
        let hash = |key: &str| match get(key) {
            Value::Binary(bytes) => bytes
                .as_slice()
                .try_into()
                .map_err(|_| error("birth hash must be 32 bytes")),
            _ => invalid("birth hash must be binary"),
        };
        let envelope = Self {
            trigger,
            prompt_ref: EntityId::from_hex(text("prompt_ref")?)
                .map_err(|_| error("invalid prompt reference"))?,
            run_ref: if get("run_ref").is_nil() {
                None
            } else {
                Some(text("run_ref")?.into())
            },
            content_hash: hash("content_hash")?,
            model_id: text("model_id")?.into(),
            version: text("version")?.into(),
            params_hash: hash("params_hash")?,
            purpose: match text("purpose")? {
                "deliverable" => ArtifactPurpose::Deliverable,
                "skill_report" => ArtifactPurpose::SkillReport,
                "skill_candidate" => ArtifactPurpose::SkillCandidate,
                _ => return invalid("invalid artifact purpose"),
            },
        };
        envelope.validate()?;
        Ok(envelope)
    }
    fn has_trigger(&self, trigger: &ArtifactTrigger) -> bool {
        &self.trigger == trigger
            || matches!(trigger, ArtifactTrigger::Run(run) if self.run_ref.as_ref() == Some(run))
    }
}

fn nonempty(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > MAX_REF_BYTES {
        return invalid("empty or oversized birth reference");
    }
    crate::batch::secret_scan::scan_metadata_field(value)
}
fn error(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidArtifactBirth(reason))
}
fn invalid<T>(reason: &'static str) -> Result<T> {
    Err(error(reason))
}
pub(super) fn birth_id(artifact: EntityId) -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(
        b"oneiron.artifact.born_from.v1",
        &[artifact.as_bytes()],
    )
}

/// A kind retains its own codec; only the family birth contract is shared.
#[derive(Clone, Copy)]
pub enum ArtifactBirthBody<'a> {
    Code(&'a crate::code_artifact::CodeArtifactBody),
    Blob(&'a crate::blob_artifact::BlobArtifactBody),
}

impl Vault {
    /// Atomically creates an artifact and its immutable, authored birth envelope.
    /// Generated reports/candidates stay Proposed and never overwrite a live artifact.
    pub fn create_artifact_with_birth(
        &self,
        artifact: EntityId,
        body: ArtifactBirthBody<'_>,
        birth: &ArtifactBirthEnvelope,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        self.with_write_txn(|txn| {
            self.create_artifact_with_birth_in_txn(
                txn, artifact, body, birth, actor, occurred, learned_at,
            )
        })
    }

    /// Composes artifact birth with its producer's transaction and first export.
    #[expect(
        clippy::too_many_arguments,
        reason = "birth and producer share the caller transaction"
    )]
    pub(crate) fn create_artifact_with_birth_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        artifact: EntityId,
        body: ArtifactBirthBody<'_>,
        birth: &ArtifactBirthEnvelope,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let (kind, data) = match body {
            ArtifactBirthBody::Code(body) => (
                crate::registry::ENTITY_TYPE_CODE_ARTIFACT,
                crate::code_artifact::encode_code_artifact_body(body)?,
            ),
            ArtifactBirthBody::Blob(body) => (
                crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
                crate::blob_artifact::encode_blob_artifact_body(body)?,
            ),
        };
        if let Some(existing) = self.store.entities.get(txn, artifact.as_bytes())? {
            let header = EntityMetadataHeader::parse(&existing)
                .ok_or(Error::CorruptedIndex("artifact header"))?;
            if header.entity_type != kind || existing[ENTITY_METADATA_HEADER_LEN..] != data {
                return invalid("birth cannot replace an existing artifact");
            }
        }
        let permit = guard::birth_permit_key(artifact);
        self.store
            .vault_meta
            .put(txn, &permit, blake3::hash(&data).as_bytes())?;
        self.batch_in()
            .put(&artifact, kind, occurred, learned_at, &data)
            .apply(txn)?;
        let ledger =
            self.record_artifact_birth_in_txn(txn, artifact, birth, actor, occurred, learned_at)?;
        self.store.vault_meta.delete(txn, &permit)?;
        Ok(ledger)
    }

    /// Reads the birth from the same ledger projection used by the reverse task/run view.
    pub fn artifact_birth(&self, artifact: EntityId) -> Result<Option<ArtifactBirthProjection>> {
        let txn = self.store.env.read_txn()?;
        self.artifact_birth_in_txn(&txn, artifact)
    }
    fn artifact_birth_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        artifact: EntityId,
    ) -> Result<Option<ArtifactBirthProjection>> {
        let Some(raw) = self.store.entities.get(txn, artifact.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("artifact header"))?;
        let Some(kind) = crate::registry::artifact_family_kind(header.entity_type) else {
            return invalid("birth subject is not an artifact");
        };
        let ledger_ref = birth_id(artifact)?;
        let Some(claim) = self.get_claim_in_txn(txn, &ledger_ref)? else {
            return Ok(None);
        };
        if claim.subject != ClaimSubject::Entity(artifact) || claim.predicate != PREDICATE {
            return invalid("birth ledger binding mismatch");
        }
        Ok(Some(ArtifactBirthProjection {
            artifact_id: artifact,
            kind,
            ledger_ref,
            made_by: ArtifactBirthEnvelope::decode(&claim.value)?,
            approval_status: claim.approval,
        }))
    }
    /// A bounded reverse projection, not a sidecar source of truth.
    pub fn artifacts_born_from(
        &self,
        trigger: &ArtifactTrigger,
        limit: usize,
    ) -> Result<Vec<ArtifactBirthProjection>> {
        if limit == 0 || limit > 1024 {
            return invalid("birth projection limit must be 1..=1024");
        }
        let txn = self.store.env.read_txn()?;
        let mut result = Vec::new();
        for entry in self
            .store
            .type_index
            .prefix_iter(&txn, &[ENTITY_TYPE_CLAIM])?
        {
            let (key, _) = entry?;
            let id = EntityId::from_bytes(
                key[1..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("claim type key"))?,
            )?;
            let claim = self
                .get_claim_in_txn(&txn, &id)?
                .ok_or(Error::CorruptedIndex("birth claim row"))?;
            if claim.predicate != PREDICATE {
                continue;
            }
            let ClaimSubject::Entity(artifact) = claim.subject else {
                return invalid("birth subject is not an entity");
            };
            if let Some(projection) = self.artifact_birth_in_txn(&txn, artifact)?
                && projection.ledger_ref == id
                && projection.made_by.has_trigger(trigger)
            {
                result.push(projection);
                if result.len() == limit {
                    break;
                }
            }
        }
        Ok(result)
    }
    pub(crate) fn record_artifact_birth_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        artifact: EntityId,
        birth: &ArtifactBirthEnvelope,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        birth.validate()?;
        let id = birth_id(artifact)?;
        if let Some(existing) = self.get_claim_in_txn(txn, &id)? {
            if existing.subject == ClaimSubject::Entity(artifact)
                && existing.predicate == PREDICATE
                && ArtifactBirthEnvelope::decode(&existing.value)? == *birth
            {
                return Ok(id);
            }
            return invalid("artifact birth is immutable");
        }
        let expected = match birth.trigger {
            ArtifactTrigger::Task(id) => Some((id, ENTITY_TYPE_TASK)),
            ArtifactTrigger::Skill(id) => Some((id, ENTITY_TYPE_SKILL)),
            ArtifactTrigger::Ask(_) => None,
            ArtifactTrigger::Run(_) => None,
        };
        if let Some((target, kind)) = expected {
            let raw = self
                .store
                .entities
                .get(txn, target.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            if EntityMetadataHeader::parse(&raw).is_none_or(|h| h.entity_type != kind) {
                return invalid("trigger kind mismatch");
            }
        }
        if let ArtifactTrigger::Ask(target) = birth.trigger {
            let raw = self
                .store
                .entities
                .get(txn, target.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            let kind = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("ask input header"))?
                .entity_type;
            if ![
                ENTITY_TYPE_MESSAGE,
                crate::registry::ENTITY_TYPE_ASSET_TEXT,
                crate::registry::ENTITY_TYPE_ASSET,
            ]
            .contains(&kind)
            {
                return invalid("ask must name a message or an imported input record");
            }
        }
        let raw = self
            .store
            .entities
            .get(txn, birth.prompt_ref.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        if raw.len() < ENTITY_METADATA_HEADER_LEN {
            return Err(Error::CorruptedIndex("prompt input header"));
        }
        if blake3::hash(&raw[ENTITY_METADATA_HEADER_LEN..]).as_bytes() != &birth.content_hash {
            return invalid("prompt input hash mismatch");
        }
        let generated = actor.actor_class() != crate::edge::EdgeActorClass::Human
            || birth.purpose != ArtifactPurpose::Deliverable;
        let envelope = WriteEnvelope::new(
            actor,
            if generated {
                ClaimSource::Generated
            } else {
                ClaimSource::UserStated
            },
            WriteProvenance::new(Value::Map(vec![("made_by".into(), birth.value())]))?,
            if generated {
                ClaimApprovalStatus::Proposed
            } else {
                ClaimApprovalStatus::Auto
            },
        );
        let candidate = ClaimCandidate::new(
            PREDICATE,
            ClaimSubject::Entity(artifact),
            birth.value(),
            1.0,
        );
        self.batch_in()
            .claim_candidate(&id, candidate, &envelope, occurred, learned_at)
            .apply(txn)?;
        Ok(id)
    }
}

mod guard;
mod imports;
#[cfg(feature = "sync")]
pub(crate) use guard::artifact_birth_dependency_pending;
pub(crate) use guard::guard_artifact_put;

#[cfg(test)]
mod tests;
