//! Host-interpreted workflow skill at the Dreamer wake boundary.
//! Skill bytes supply behavior, never actor identity, read rights or gate authority.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    ScopedReadActorKey, claim_evidence_taint,
};
use crate::dreamer_consolidation::{
    ConsolidationEvidenceEnvelope, encode_consolidation_evidence, evidence_source_from_row,
};
use crate::dreamer_runner::{
    DREAMER_WEAVE_RECIPE_ATTEMPT_KIND, DreamerAdmittedAttempt, WeaveRecipePin,
};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
use crate::write_envelope::{SourceLineage, WriteActor, WriteEnvelope, WriteProvenance};
use crate::{ClaimCandidate, EdgeActorClass, EntityId, Error, Result, TimeRange, Vault};
use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::{DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext};

/// The host's workflow interpreter. It receives the exact actor-readable
/// evidence and admitted SKILL.md bytes, never a vault handle or approval lane.
pub trait WeaveRecipeRuntime {
    /// The interpreter's `id@revision`. The skill load stamps it on the
    /// attempt, so recipe reliability forks by executor like any skill run.
    fn executor(&self) -> Result<&str>;
    fn draft(&mut self, markdown: &str, evidence: &[u8]) -> Result<WeaveRecipeDraft>;
}

pub struct WeaveRecipeDraft {
    pub predicate: String,
    pub value: Value,
    pub confidence: f32,
}

impl<T: WeaveRecipeRuntime + ?Sized> WeaveRecipeRuntime for &mut T {
    fn executor(&self) -> Result<&str> {
        (**self).executor()
    }
    fn draft(&mut self, markdown: &str, evidence: &[u8]) -> Result<WeaveRecipeDraft> {
        (**self).draft(markdown, evidence)
    }
}

impl WeaveRecipeRuntime for Option<&mut dyn WeaveRecipeRuntime> {
    fn executor(&self) -> Result<&str> {
        self.as_deref().ok_or_else(invalid)?.executor()
    }
    fn draft(&mut self, markdown: &str, evidence: &[u8]) -> Result<WeaveRecipeDraft> {
        self.as_deref_mut()
            .ok_or_else(invalid)?
            .draft(markdown, evidence)
    }
}

/// Private result and public claim commit in ONE transaction. A crashed lease
/// checks this binding before touching current skill/evidence or the runtime.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipeResult {
    version: u8,
    pin_hash: [u8; 32],
    actor: String,
    source: String,
    evidence_hash: [u8; 32],
    claim_hash: [u8; 32],
}
const RESULT_PREFIX: &[u8] = b"dreamer:weave:result:v1:";

fn result_key(attempt: &DreamerAdmittedAttempt) -> Vec<u8> {
    [RESULT_PREFIX, attempt.status.attempt.id.as_bytes()].concat()
}
fn claim_id(attempt: &DreamerAdmittedAttempt) -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(
        b"oneiron:dreamer:weave-recipe-claim:v1",
        &[attempt.status.attempt.id.as_bytes()],
    )
}
fn provenance(
    pin: &WeaveRecipePin,
    attempt: &DreamerAdmittedAttempt,
    evidence_hash: [u8; 32],
) -> Result<WriteProvenance> {
    let run_id = attempt
        .status
        .attempt
        .run_id
        .as_deref()
        .ok_or_else(invalid)?;
    WriteProvenance::new(Value::Map(vec![
        ("surface".into(), "dreamer".into()),
        ("run_id".into(), run_id.into()),
        ("recipe".into(), pin.skill.to_hex().into()),
        (
            "recipe_pin".into(),
            Value::Binary(pin.binding_hash().to_vec()),
        ),
        (
            "evidence_revision".into(),
            Value::Binary(evidence_hash.to_vec()),
        ),
        (
            "attempt_id".into(),
            Value::Binary(attempt.status.attempt.id.as_bytes().to_vec()),
        ),
    ]))
}
fn envelope(actor: WriteActor, source: ClaimSource, provenance: WriteProvenance) -> WriteEnvelope {
    WriteEnvelope::with_lineage(
        actor,
        source,
        provenance,
        ClaimApprovalStatus::Proposed,
        SourceLineage::of(ClaimSource::Generated).with(source),
    )
}
fn cited(pin: &WeaveRecipePin, source: ClaimSource) -> Value {
    encode_consolidation_evidence(&ConsolidationEvidenceEnvelope {
        refs: vec![pin.evidence],
        chain: Vec::new(),
        source_meet: source,
    })
}
fn claim_hash(body: &ClaimBody) -> Result<[u8; 32]> {
    // Owner approval may advance the proposal without changing its output.
    let mut original = body.clone();
    original.approval = ClaimApprovalStatus::Proposed;
    Ok(*blake3::hash(&crate::claim::encode_claim_body(&original)?).as_bytes())
}

/// A private result without its claim, or a claim at the deterministic id
/// without its co-committed result, is corruption; neither starts new work.
fn cached_result(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: &DreamerAdmittedAttempt,
    pin: &WeaveRecipePin,
    actor: WriteActor,
    id: &EntityId,
) -> Result<bool> {
    let raw = vault.store.vault_meta.get(txn, &result_key(attempt))?;
    let body = vault.get_claim_in_txn(txn, id)?;
    match (raw, body) {
        (None, None) => Ok(false),
        (Some(raw), Some(body)) => {
            let result: RecipeResult = serde_json::from_slice(&raw).map_err(|_| invalid())?;
            let source = ClaimSource::parse(&result.source).ok_or_else(invalid)?;
            let stamped = envelope(
                actor,
                source,
                provenance(pin, attempt, result.evidence_hash)?,
            );
            if result.version != 1
                || result.pin_hash != pin.binding_hash()
                || result.actor != actor.entity_ref().to_hex()
                || body.subject != ClaimSubject::Entity(pin.subject)
                || body.source != Some(source)
                || body.lifecycle != ClaimLifecycleStatus::Active
                || !matches!(
                    body.approval,
                    ClaimApprovalStatus::Proposed | ClaimApprovalStatus::Approved
                )
                || claim_evidence_taint(&body) != Some(source)
                || body.evidence
                    != Some(crate::write_envelope::write_envelope_evidence(
                        &stamped,
                        Some(cited(pin, source)),
                    ))
                || result.claim_hash != claim_hash(&body)?
            {
                return Err(invalid());
            }
            Ok(true)
        }
        _ => Err(invalid()),
    }
}

/// The same snapshot holds the live scoped grant, source bytes and claim
/// provenance. A queued recipe cannot grant itself `core:read` or read a
/// different evidence ref. This is called again inside the write transaction
/// so a revoked grant or changed source cannot be committed after drafting.
fn read_evidence(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    id: EntityId,
) -> Result<(Vec<u8>, ClaimSource, [u8; 32])> {
    let key = ScopedReadActorKey::with_actor_class(
        actor.entity_ref().to_hex(),
        actor.actor_class().gate_actor_class(),
    )
    .ok_or_else(invalid)?;
    let raw = vault
        .scoped_read(key)
        .entity_raw_live_in(txn, &id)?
        .ok_or_else(invalid)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
    if !matches!(header.entity_type, ENTITY_TYPE_TURN | ENTITY_TYPE_CLAIM)
        || raw.len() == ENTITY_METADATA_HEADER_LEN
    {
        return Err(invalid());
    }
    let bytes = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
    let meet = evidence_source_from_row(header.entity_type, &bytes)?;
    Ok((bytes, meet, *blake3::hash(&raw).as_bytes()))
}

/// Composes the ordinary worker with a host-supplied workflow interpreter.
/// No interpreter means a new attempt parks; an already committed result
/// settles without consulting the runtime or requiring a live skill/source.
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
        if actor.actor_class() != EdgeActorClass::System {
            return Err(invalid());
        }
        let id = claim_id(attempt)?;
        {
            let txn = vault.store.env.read_txn()?;
            if cached_result(vault, &txn, attempt, &pin, actor, &id)? {
                return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
            }
        }
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
        let lease_owner = attempt
            .status
            .attempt
            .lease_owner
            .as_deref()
            .ok_or_else(invalid)?;
        let loaded = vault.load_attempt_skill_pack(
            attempt.status.attempt.id,
            &pin.skill,
            lease_owner,
            attempt.status.attempt.attempt_count,
            self.runtime.executor()?,
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
        let (evidence, source, read_hash) = {
            let txn = vault.store.env.read_txn()?;
            read_evidence(vault, &txn, actor, pin.evidence)?
        };
        let draft = self.runtime.draft(text, &evidence)?;
        let envelope = envelope(actor, source, provenance(&pin, attempt, read_hash)?);
        let candidate = ClaimCandidate::new(
            draft.predicate,
            ClaimSubject::Entity(pin.subject),
            draft.value,
            draft.confidence,
        )
        .with_evidence(cited(&pin, source))
        .with_evidence_taint(source)?;
        let now = ctx.now_ms / 1000;
        vault.with_write_txn(|txn| {
            if cached_result(vault, txn, attempt, &pin, actor, &id)? {
                return Ok(());
            }
            let (_, current_source, current_hash) = read_evidence(vault, txn, actor, pin.evidence)?;
            if current_source != source || current_hash != read_hash {
                return Err(invalid());
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
                .apply_recording_gate_decisions(txn)?;
            let body = vault.get_claim_in_txn(txn, &id)?.ok_or_else(invalid)?;
            let result = RecipeResult {
                version: 1,
                pin_hash: pin.binding_hash(),
                actor: actor.entity_ref().to_hex(),
                source: source.as_str().into(),
                evidence_hash: read_hash,
                claim_hash: claim_hash(&body)?,
            };
            vault.store.vault_meta.put(
                txn,
                &result_key(attempt),
                &serde_json::to_vec(&result).map_err(|_| invalid())?,
            )?;
            Ok(())
        })?;
        Ok(DreamerAttemptExecution::Completed { completed_units: 0 })
    }
}

fn invalid() -> Error {
    Error::InvalidClaimBody("weave recipe pin, scoped input or saved result is invalid")
}

#[cfg(test)]
mod tests;
