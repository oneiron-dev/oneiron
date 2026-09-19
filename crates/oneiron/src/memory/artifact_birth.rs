//! One ledger projection for task/run/skill output lists and artifact born-from views.
use super::{Memory, MemoryError, MemoryResult};
use crate::artifact_hosting::{ArtifactBirthProjection, ArtifactPurpose, ArtifactTrigger};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactBirthView {
    pub artifact_ref: String,
    pub kind: String,
    pub ledger_ref: String,
    pub trigger_kind: String,
    pub trigger_ref: String,
    pub prompt_ref: String,
    pub run_ref: Option<String>,
    pub content_hash: String,
    pub model_id: String,
    pub version: String,
    pub params_hash: String,
    pub purpose: String,
    pub approval_status: String,
}

impl From<ArtifactBirthProjection> for ArtifactBirthView {
    fn from(projection: ArtifactBirthProjection) -> Self {
        let birth = projection.made_by;
        let (trigger_kind, trigger_ref) = match birth.trigger {
            ArtifactTrigger::Task(id) => ("task", id.to_hex()),
            ArtifactTrigger::Run(reference) => ("run", reference),
            ArtifactTrigger::Skill(id) => ("skill", id.to_hex()),
            ArtifactTrigger::Ask(id) => ("ask", id.to_hex()),
        };
        Self {
            artifact_ref: projection.artifact_id.to_hex(),
            kind: projection.kind.kind_id().into(),
            ledger_ref: projection.ledger_ref.to_hex(),
            trigger_kind: trigger_kind.into(),
            trigger_ref,
            prompt_ref: birth.prompt_ref.to_hex(),
            run_ref: birth.run_ref,
            content_hash: super::support::hex_string(&birth.content_hash),
            model_id: birth.model_id,
            version: birth.version,
            params_hash: super::support::hex_string(&birth.params_hash),
            purpose: match birth.purpose {
                ArtifactPurpose::Deliverable => "deliverable",
                ArtifactPurpose::SkillReport => "skill_report",
                ArtifactPurpose::SkillCandidate => "skill_candidate",
            }
            .into(),
            approval_status: projection.approval_status.as_str().into(),
        }
    }
}

impl Memory<'_> {
    /// Preserves the structural import surface without letting it skip birth provenance.
    pub(super) fn create_structural_artifact_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: crate::EntityId,
        kind: u8,
        data: &[u8],
        occurred: crate::temporal::TimeRange,
        learned_at: u64,
    ) -> MemoryResult<()> {
        let input = self
            .vault
            .artifact_input_in_txn(txn, id, data, occurred, learned_at)?;
        let birth = self.vault.artifact_birth_for_input_in_txn(
            txn,
            ArtifactTrigger::Ask(input),
            input,
            None,
            "oneiron/structural-import",
            ArtifactPurpose::Deliverable,
        )?;
        let actor = crate::write_envelope::WriteActor::new(self.actor, self.actor_class);
        match crate::registry::artifact_family_kind(kind) {
            Some(crate::registry::ArtifactFamilyKind::Code) => {
                let body = crate::code_artifact::decode_code_artifact_body(data)?;
                self.vault.create_artifact_with_birth_in_txn(
                    txn,
                    id,
                    crate::artifact_hosting::ArtifactBirthBody::Code(&body),
                    &birth,
                    actor,
                    occurred,
                    learned_at,
                )?;
            }
            Some(crate::registry::ArtifactFamilyKind::Blob) => {
                let body = crate::blob_artifact::decode_blob_artifact_body(data)?;
                self.vault.create_artifact_with_birth_in_txn(
                    txn,
                    id,
                    crate::artifact_hosting::ArtifactBirthBody::Blob(&body),
                    &birth,
                    actor,
                    occurred,
                    learned_at,
                )?;
            }
            None => {
                return Err(MemoryError::bad_request(
                    "structural artifact kind is not in the artifact family",
                ));
            }
        }
        Ok(())
    }

    /// Artifact → task/run/skill/ask from the canonical birth ledger.
    pub fn artifact_birth(&self, artifact_ref: &str) -> MemoryResult<Option<ArtifactBirthView>> {
        let id = self.resolve_ref(artifact_ref)?;
        self.vault
            .artifact_birth(id)
            .map(|birth| birth.map(Into::into))
            .map_err(Into::into)
    }

    /// Task/run/skill/ask → artifacts, using the same projection as artifact_birth.
    pub fn artifacts_born_from(
        &self,
        trigger_kind: &str,
        trigger_ref: &str,
        limit: usize,
    ) -> MemoryResult<Vec<ArtifactBirthView>> {
        let trigger = match trigger_kind {
            "task" => ArtifactTrigger::Task(self.resolve_ref(trigger_ref)?),
            "run" => ArtifactTrigger::Run(trigger_ref.into()),
            "skill" => ArtifactTrigger::Skill(self.resolve_ref(trigger_ref)?),
            "ask" => ArtifactTrigger::Ask(self.resolve_ref(trigger_ref)?),
            _ => {
                return Err(MemoryError::bad_request(
                    "trigger_kind must be task, run, skill or ask",
                ));
            }
        };
        self.vault
            .artifacts_born_from(&trigger, limit)
            .map(|artifacts| artifacts.into_iter().map(Into::into).collect())
            .map_err(Into::into)
    }
}
