//! Host-interpreted workflow skill at the Dreamer wake boundary.
//! Skill bytes supply behavior, never actor identity, approval or gate authority.

use crate::dreamer_consolidation::{ConsolidationEvidenceEnvelope, encode_consolidation_evidence};
use crate::dreamer_runner::{
    DREAMER_WEAVE_RECIPE_ATTEMPT_KIND, DreamerAdmittedAttempt, WeaveRecipePin,
};
use crate::write_envelope::WriteProvenance;
use crate::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, Error, Result, TimeRange,
    WriteEnvelope,
};
use rmpv::Value;

use super::{DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext};

/// The host's workflow interpreter. It receives the exact admitted SKILL.md
/// bytes and the cited evidence; it cannot choose an actor or approval lane.
pub trait WeaveRecipeRuntime {
    fn draft(&mut self, markdown: &str, evidence: &[u8]) -> Result<WeaveRecipeDraft>;
}

pub struct WeaveRecipeDraft {
    pub predicate: String,
    pub value: Value,
    pub confidence: f32,
}

impl WeaveRecipeRuntime for Option<&mut dyn WeaveRecipeRuntime> {
    fn draft(&mut self, markdown: &str, evidence: &[u8]) -> Result<WeaveRecipeDraft> {
        self.as_deref_mut()
            .ok_or_else(invalid)?
            .draft(markdown, evidence)
    }
}

/// Composes the ordinary worker with a host-supplied workflow interpreter.
/// No interpreter means a recipe attempt parks rather than completing empty.
pub struct WeaveRecipeExecutor<E, R> {
    pub inner: E,
    pub runtime: R,
}

impl<E: DreamerAttemptExecutor, R: WeaveRecipeRuntime> DreamerAttemptExecutor
    for WeaveRecipeExecutor<E, R>
{
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        if attempt.status.attempt.kind != DREAMER_WEAVE_RECIPE_ATTEMPT_KIND {
            return self.inner.execute(attempt, ctx).await;
        }
        if attempt.status.payload.attempt_type != DREAMER_WEAVE_RECIPE_ATTEMPT_KIND {
            return Err(invalid());
        }
        let pin = WeaveRecipePin::decode(&attempt.status.payload.input)?;
        let vault = ctx.vault;
        let actor = vault.dreamer_actor_for_attempt(attempt.status.attempt.id)?;
        let stored = vault.get_skill_record(&pin.skill)?.ok_or_else(invalid)?;
        if stored.version != pin.version
            || stored
                .content_hash
                .as_ref()
                .map(crate::skill::SkillContentHash::to_hex)
                != Some(pin.content_hash.clone())
        {
            return Err(invalid());
        }
        let loaded = vault.load_attempt_skill_pack(
            attempt.status.attempt.id,
            &pin.skill,
            ctx.now_ms / 1000,
        )?;
        if loaded.record.version != pin.version
            || loaded
                .record
                .content_hash
                .as_ref()
                .map(crate::skill::SkillContentHash::to_hex)
                != Some(pin.content_hash.clone())
        {
            return Err(invalid());
        }
        let markdown = loaded
            .source_files
            .as_ref()
            .ok_or_else(invalid)?
            .iter()
            .find(|file| file.path == "SKILL.md")
            .ok_or_else(invalid)?;
        let text = std::str::from_utf8(&markdown.content).map_err(|_| invalid())?;
        let evidence = vault.get(&pin.evidence)?.ok_or_else(invalid)?;
        let draft = self.runtime.draft(text, &evidence)?;
        let id = crate::codebase::entity_id_from_hash_material(
            b"oneiron:dreamer:weave-recipe-claim:v1",
            &[attempt.status.attempt.id.as_bytes()],
        )?;
        let run_id = attempt
            .status
            .attempt
            .run_id
            .as_deref()
            .ok_or_else(invalid)?;
        let provenance = WriteProvenance::new(Value::Map(vec![
            ("surface".into(), "dreamer".into()),
            ("run_id".into(), run_id.into()),
            ("recipe".into(), pin.skill.to_hex().into()),
            (
                "attempt_id".into(),
                Value::Binary(attempt.status.attempt.id.as_bytes().to_vec()),
            ),
        ]))?;
        let envelope = WriteEnvelope::new(
            actor,
            ClaimSource::Generated,
            provenance,
            ClaimApprovalStatus::Proposed,
        );
        let expected_value = draft.value.clone();
        let cited = encode_consolidation_evidence(&ConsolidationEvidenceEnvelope {
            refs: vec![pin.evidence],
            chain: Vec::new(),
            source_meet: ClaimSource::Generated,
        });
        let expected_evidence =
            crate::write_envelope::write_envelope_evidence(&envelope, Some(cited.clone()));
        let candidate = ClaimCandidate::new(
            draft.predicate,
            ClaimSubject::Entity(pin.subject),
            draft.value,
            draft.confidence,
        )
        .with_evidence(cited);
        let now = ctx.now_ms / 1000;
        vault.with_write_txn(|txn| {
            if let Some(prior) = vault.get_claim_in_txn(txn, &id)? {
                if prior.predicate != candidate.predicate()
                    || prior.value != expected_value
                    || prior.subject != ClaimSubject::Entity(pin.subject)
                    || prior.source != Some(ClaimSource::Generated)
                    || prior.evidence != Some(expected_evidence)
                {
                    return Err(invalid());
                }
                return Ok(());
            }
            vault
                .batch_in()
                .claim_candidate(
                    &id,
                    candidate,
                    &envelope,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                )
                .apply_recording_gate_decisions(txn)
        })?;
        Ok(DreamerAttemptExecution::Completed { completed_units: 0 })
    }
}

fn invalid() -> Error {
    Error::InvalidClaimBody("weave recipe pin, runtime or output is invalid")
}
