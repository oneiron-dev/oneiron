//! The actor-bound compaction step (FIX 4465 B): each paid call of a
//! self-written compaction pass, the tries its gate refused too, filed in the
//! model-step family as one terminal `dreamer.step` claim, under the agent
//! the summary is written as, on the storage route its run captured at entry.
//!
//! The call already ran on its run's funded meter, which settled it once;
//! filing it settles nothing again (resident dreaming's separate-line rule:
//! never two settlements of one call on one meter). Its job is the run whose
//! window it compacted and its run the run's host-derived source: no Dreamer
//! attempt is made up for it. Its surface is not the Dreamer runner's, so the
//! memo index never admits it and no replay returns it as a memo; the pass's
//! receipt names it by claim.
//!
//! The route is the run's own. A canonical run files in base. A room's run
//! on a route that went on record files in base under the room's saver, as
//! its other base writes do. An off-record room's run stages the claim in the
//! room's overlay, where it drops at close; a room keeps no artifact
//! versions, so there the answer stays inline whatever its size.
//!
//! Each step carries the summary's own lineage (FIX 5977): its claim, and
//! a response artifact when it has one, derive from every record the call's
//! words were read from, in the write that files them, so withdrawing one
//! withdraws the step as it withdraws the summary. A record already gone or
//! withdrawn when the step files refuses the filing, which the pass's
//! receipt names as unfiled; the compaction itself still answers.

use rmpv::Value;

use super::super::{LlmRequest, LlmResponse};
use super::response_pins::{StepResponseRef, register_step_response_pin_in_txn};
use super::step_claim::{
    EncodedStepClaim, call_purpose_str, encode_step_claim_value, request_params_hash,
};
use super::types::{
    DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES, DREAMER_STEP_PREDICATE,
    ENVELOPE_PROVENANCE_ATTEMPT_KEY, ENVELOPE_PROVENANCE_RUN_KEY, ENVELOPE_PROVENANCE_SURFACE_KEY,
    StepProgression,
};
use crate::attempt_queue::AttemptId;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance, encode_blob_artifact_body};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::code_run::ExecutorStorage;
use crate::compaction::{COMPACTION_STEP_RESPONSE_NAME, CompactionCall, CompactionStepRef};
use crate::edge::EdgeKind;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::off_record::OffRecordSession;
use crate::ports::EntityStoreRead as _;
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use crate::session_overlay::{RouteTarget, SessionWriteRoute};
use crate::store::ManifestDbs;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope, WriteProvenance};
use crate::{Vault, WriteActor};

/// The provenance surface a compaction step is stamped with.
const COMPACTION_STEP_SURFACE: &str = "code-run-compaction";

/// The refusal a step filing takes when a record its call was read from is
/// already gone or withdrawn (FIX 5977): its words may not land past that
/// record's withdrawal. The pass's receipt names the calls as unfiled.
const COMPACTION_STEP_SOURCE_WITHDRAWN: &str = "compaction_step_source_withdrawn";

/// The refusal a step filing takes when the call's complete input was not
/// witnessed: unknown is never the empty, edgeless set (FIX 11937).
const COMPACTION_STEP_SOURCES_UNKNOWN: &str = "compaction_step_sources_unknown";

/// One decoded call: its request identity, the bytes of its answer and the
/// records its words were read from.
struct FiledCall {
    step_hash: [u8; 32],
    model_id: String,
    purpose: String,
    params_hash: String,
    usage_in: u64,
    usage_out: u64,
    payload: Vec<u8>,
    sources: Option<Vec<EntityId>>,
}

impl FiledCall {
    fn of(call: &CompactionCall) -> Result<Self> {
        let unreadable = || Error::InvariantViolation("a compaction call did not decode");
        let request: LlmRequest =
            serde_json::from_slice(&call.request).map_err(|_| unreadable())?;
        let response: LlmResponse =
            serde_json::from_slice(&call.response).map_err(|_| unreadable())?;
        let step_hash = request.canonical_hash().map_err(|_| unreadable())?;
        let params_hash = request_params_hash(&request).map_err(|_| unreadable())?;
        Ok(Self {
            step_hash,
            model_id: request.model.as_str().to_owned(),
            purpose: call_purpose_str(&request.envelope.purpose),
            params_hash,
            usage_in: response.usage.input.total,
            usage_out: response.usage.output.total,
            payload: call.response.clone(),
            sources: call.sources.clone(),
        })
    }

    /// The complete records this call read, or a refusal when they were not
    /// witnessed. Empty is a proved empty set, never the unknown fallback.
    fn sources(&self) -> Result<&[EntityId]> {
        self.sources
            .as_deref()
            .ok_or(Error::InvalidClaimBody(COMPACTION_STEP_SOURCES_UNKNOWN))
    }

    /// Refuses the filing when a record this call read is gone or withdrawn
    /// as `dbs` reads it in `txn`.
    fn sources_stand_in(&self, dbs: &impl ManifestDbs, txn: &heed::RoTxn<'_>) -> Result<()> {
        for source in self.sources()? {
            if dbs.port_entity_record(txn, source)?.is_none()
                || crate::ports::withdrawn_in_txn(dbs, txn, source)?
            {
                return Err(Error::InvalidClaimBody(COMPACTION_STEP_SOURCE_WITHDRAWN));
            }
        }
        Ok(())
    }

    fn claim_value(
        &self,
        job: AttemptId,
        response_ref: Option<StepResponseRef>,
        at: u64,
    ) -> Result<Value> {
        let response = match response_ref {
            Some(_) => None,
            None => Some(String::from_utf8(self.payload.clone()).map_err(|_| {
                Error::InvalidClaimBody("dreamer step response encoding must be UTF-8 JSON")
            })?),
        };
        Ok(encode_step_claim_value(&EncodedStepClaim {
            attempt_id: job,
            step_hash: self.step_hash,
            progression: StepProgression::Finished,
            model_id: self.model_id.clone(),
            purpose: self.purpose.clone(),
            params_hash: self.params_hash.clone(),
            usage_in: self.usage_in,
            usage_out: self.usage_out,
            response,
            response_ref,
            at,
        }))
    }

    fn filed(&self, claim: EntityId) -> CompactionStepRef {
        CompactionStepRef {
            claim,
            step_hash: bytes_to_hex_lower(&self.step_hash),
        }
    }
}

impl ExecutorStorage<'_> {
    /// Files each of `calls` as one terminal `dreamer.step` claim about and
    /// by `writer`, the run's authenticated actor, on the route this run's
    /// storage captured at entry, and returns their refs in order. Nothing is
    /// settled: the run's meter settled each call once when it ran.
    pub(crate) fn file_compaction_steps(
        &self,
        run_ref: &str,
        run_id: EntityId,
        writer: WriteActor,
        calls: &[CompactionCall],
        now_ms: u64,
    ) -> Result<Vec<CompactionStepRef>> {
        if calls.is_empty() {
            return Ok(Vec::new());
        }
        let job = AttemptId::from_bytes(run_id.as_bytes())?;
        let envelope = compaction_step_envelope(run_ref, job, writer)?;
        let calls = calls
            .iter()
            .map(FiledCall::of)
            .collect::<Result<Vec<_>>>()?;
        let step = StepFiling {
            job,
            writer,
            run_ref,
            envelope: &envelope,
            now_ms,
        };
        match self {
            Self::Canonical(vault) => {
                vault.with_write_txn_grouped(|wtxn| step.file_in_base(vault, wtxn, &calls))
            }
            Self::Session(binding) => binding.answered(|| match binding.route.target() {
                RouteTarget::Overlay => {
                    step.stage_in_room(&binding.session, &binding.route, &calls)
                }
                RouteTarget::Base | RouteTarget::Discard => binding
                    .session
                    .executor_land_base_epoch(&binding.route, |vault, landing| {
                        vault.with_write_txn_grouped(|wtxn| {
                            landing(wtxn)?;
                            step.file_in_base(vault, wtxn, &calls)
                        })
                    }),
            }),
        }
    }
}

/// What every step of one filing shares.
struct StepFiling<'a> {
    job: AttemptId,
    writer: WriteActor,
    run_ref: &'a str,
    envelope: &'a WriteEnvelope,
    now_ms: u64,
}

impl StepFiling<'_> {
    fn occurred(&self) -> TimeRange {
        TimeRange {
            start: self.now_ms,
            end: self.now_ms,
        }
    }

    fn candidate(
        &self,
        call: &FiledCall,
        response_ref: Option<StepResponseRef>,
    ) -> Result<ClaimCandidate> {
        Ok(ClaimCandidate::new(
            DREAMER_STEP_PREDICATE,
            ClaimSubject::Entity(self.writer.entity_ref()),
            call.claim_value(self.job, response_ref, self.now_ms)?,
            1.0,
        ))
    }

    /// Base: an answer over the inline bound lives in a response artifact,
    /// the exact version its claim pins, as every step's does. The claim and
    /// the artifact derive from each of the call's sources in this write.
    fn file_in_base(
        &self,
        vault: &Vault,
        wtxn: &mut heed::RwTxn<'_>,
        calls: &[FiledCall],
    ) -> Result<Vec<CompactionStepRef>> {
        let occurred = self.occurred();
        let mut filed = Vec::with_capacity(calls.len());
        for call in calls {
            call.sources_stand_in(&vault.store, wtxn)?;
            let sources = call.sources()?;
            let claim_id = vault.store.clock.entity_id()?;
            let response_ref = if call.payload.len() <= DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES {
                None
            } else {
                let artifact_id = vault.store.clock.entity_id()?;
                let body = BlobArtifactBody::new(COMPACTION_STEP_RESPONSE_NAME, "application/json");
                let encoded = encode_blob_artifact_body(&body)?;
                let mut batch = vault.batch_in().put(
                    &artifact_id,
                    ENTITY_TYPE_BLOB_ARTIFACT,
                    occurred,
                    self.now_ms,
                    &encoded,
                );
                for source in sources {
                    batch = batch.edge(&artifact_id, EdgeKind::DerivedFrom, source, 1.0);
                }
                batch.apply(wtxn)?;
                let appended = vault.append_blob_artifact_version_in_txn(
                    wtxn,
                    &artifact_id,
                    &call.payload,
                    &BlobVersionProvenance::AgentRun {
                        run_ref: self.run_ref.to_owned(),
                    },
                    self.writer,
                    occurred,
                    self.now_ms,
                )?;
                Some(StepResponseRef {
                    artifact_id,
                    version: appended.version,
                    content_hash: appended.content_hash,
                })
            };
            let candidate = self.candidate(call, response_ref)?;
            let mut envelope = self.envelope.clone();
            vault.sign_retained_machine_claim_in_txn(
                &*wtxn,
                &claim_id,
                &candidate,
                &mut envelope,
            )?;
            let mut batch = vault.batch_in().claim_candidate(
                &claim_id,
                candidate,
                &envelope,
                occurred,
                self.now_ms,
            );
            for source in sources {
                batch = batch.edge(&claim_id, EdgeKind::DerivedFrom, source, 1.0);
            }
            batch.apply(wtxn)?;
            // The claim holds the exact version its answer lives in (FIX 6225).
            if let Some(pin) = &response_ref {
                register_step_response_pin_in_txn(&vault.store, wtxn, &claim_id, pin)?;
            }
            filed.push(call.filed(claim_id));
        }
        Ok(filed)
    }

    /// An off-record room: each claim stages in the room's overlay through
    /// its gate, its answer inline, derived from each of the call's sources
    /// in the same staged write, and drops with the room at close.
    fn stage_in_room(
        &self,
        session: &OffRecordSession<'_>,
        route: &SessionWriteRoute,
        calls: &[FiledCall],
    ) -> Result<Vec<CompactionStepRef>> {
        let mut filed = Vec::with_capacity(calls.len());
        for call in calls {
            let claim_id = {
                let view = session.read_view()?;
                let txn = view.read().base().env.read_txn()?;
                call.sources_stand_in(&view, &txn)?;
                view.clock().entity_id()?
            };
            let sources = call.sources()?;
            session.stage_session_derived_claim(
                route,
                claim_id,
                self.candidate(call, None)?,
                self.envelope,
                self.occurred(),
                self.now_ms,
                sources,
            )?;
            filed.push(call.filed(claim_id));
        }
        Ok(filed)
    }
}

/// The write envelope every step of one run's compaction carries: the agent
/// as its actor, Generated, Proposed, and the compaction surface with the
/// run as its run and its job.
fn compaction_step_envelope(
    run_ref: &str,
    job: AttemptId,
    writer: WriteActor,
) -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        writer,
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (
                Value::from(ENVELOPE_PROVENANCE_SURFACE_KEY),
                Value::from(COMPACTION_STEP_SURFACE),
            ),
            (
                Value::from(ENVELOPE_PROVENANCE_RUN_KEY),
                Value::from(run_ref),
            ),
            (
                Value::from(ENVELOPE_PROVENANCE_ATTEMPT_KEY),
                Value::from(bytes_to_hex_lower(job.as_bytes())),
            ),
        ]))?,
        ClaimApprovalStatus::Proposed,
    ))
}
