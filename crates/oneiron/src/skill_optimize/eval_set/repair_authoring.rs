//! Native Coach Repair jobs retain the original requester as a source reader.
//! The private context is job data, never an owner proof or a wire input.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::doors::EvalAuthoringRef;
use super::repair_case::record_repair_case_in_txn;
use super::{
    EvalRepairCaseRead, EvalRepairCaseRequest, EvalRepairNominationRequest, EvalRepairNominations,
};
use crate::attempt_queue::{AttemptId, AttemptState};
use crate::claim::{ClaimReadStatus, maintenance_kind::COACH_HOST_QUEUE_KIND};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome, decode_dreamer_attempt_payload,
};
use crate::ingest::AgUiFileReadInput;
use crate::memory::stored_read::StoredReadContext;
use crate::memory::{Memory, MemoryResult};
use crate::{EntityId, Error, Result, Vault};

/// Explicit, source-bound Repair authoring; not the nightly sweep's facet.
pub const COACH_EVAL_REPAIR_AUTHORING_FACET: &str = "coach.eval_repair_authoring";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundRepairAuthoring {
    nomination: EvalRepairNominationRequest,
    context: StoredReadContext,
}

impl Memory<'_> {
    /// Queue Repair authoring with this handle's original source authority.
    /// The owner authorizes the request write, not any broader source read.
    /// Each call keeps its own context; it never coalesces with another caller
    /// or the existing nightly authoring job.
    pub fn request_eval_repair_authoring(
        &self,
        owner: &AuthenticatedOwner,
        input: &EvalRepairNominationRequest,
        now: u64,
    ) -> MemoryResult<EvalAuthoringRef> {
        let bound = BoundRepairAuthoring {
            nomination: input.clone(),
            context: StoredReadContext::of(self),
        };
        let input = rmp_serde::to_vec_named(&bound).map_err(|_| invalid())?;
        let vault = self.vault();
        Ok(vault.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(vault, txn)?;
            self.recheck_host_action_in_txn(txn)?;
            let outcome = DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
                txn,
                COACH_HOST_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type: COACH_EVAL_REPAIR_AUTHORING_FACET.into(),
                    input: Value::Binary(input.clone()),
                    parent_attempt: None,
                },
                None,
                None,
                now,
            )?;
            let status = match outcome {
                EnqueueDreamerAttemptOutcome::Enqueued(status)
                | EnqueueDreamerAttemptOutcome::Existing(status) => status,
            };
            Ok(EvalAuthoringRef {
                attempt: EntityId::from_bytes(*status.attempt.id.as_bytes())?,
            })
        })?)
    }
}

/// An actual leased Coach job's source reader and its metadata-only choices.
/// Neither the reader nor the captured context is exposed to the host.
pub struct EvalRepairAuthoringSource<'v> {
    reader: Memory<'v>,
    job: RepairJob,
    nominations: EvalRepairNominations,
}

struct RepairJob {
    id: AttemptId,
    lease_owner: String,
    generation: u32,
    payload: Vec<u8>,
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid source-bound Repair authoring job".into())
}

/// A generic Dreamer enqueue may carry a Coach facet stamp, but cannot write
/// the private coach.host kind. Read the canonical row, not the admitted
/// argument's decoded payload, and keep its stamp and lease in this snapshot.
fn job_payload_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
    lease_owner: &str,
    generation: u32,
) -> Result<Vec<u8>> {
    let row = crate::store::attempt_record_read::get_in_txn(&vault.store, txn, id)?
        .ok_or_else(invalid)?;
    let stamp = vault
        .dreamer_attempt_authority_in_txn(txn, id)?
        .ok_or_else(invalid)?;
    if row.kind != COACH_HOST_QUEUE_KIND
        || row.state != AttemptState::Leased
        || row.lease_owner.as_deref() != Some(lease_owner)
        || row.attempt_count != generation
        || stamp.facet != COACH_EVAL_REPAIR_AUTHORING_FACET
        || stamp.actor != crate::store::base_agent::coach_actor_id()?
    {
        return Err(invalid());
    }
    let payload = decode_dreamer_attempt_payload(&row.payload)?;
    if payload.attempt_type != COACH_EVAL_REPAIR_AUTHORING_FACET {
        return Err(invalid());
    }
    Ok(row.payload)
}

impl Vault {
    /// Restore only the reader captured by this canonical leased Coach job.
    /// Its nominations still use the original credential, room, locality and
    /// destination, with their ordinary current standing and source checks.
    pub fn coach_eval_repair_authoring_source(
        &self,
        attempt: &DreamerAdmittedAttempt,
    ) -> MemoryResult<EvalRepairAuthoringSource<'_>> {
        let record = &attempt.status.attempt;
        let lease_owner = record.lease_owner.as_ref().ok_or_else(invalid)?.clone();
        let payload = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            job_payload_in_txn(self, &txn, record.id, &lease_owner, record.attempt_count)?
        };
        let decoded = decode_dreamer_attempt_payload(&payload)?;
        let Value::Binary(body) = decoded.input else {
            return Err(invalid().into());
        };
        let bound: BoundRepairAuthoring = rmp_serde::from_slice(&body).map_err(|_| invalid())?;
        let reader = bound.context.restore(self)?;
        let nominations = reader.nominate_eval_repairs(&bound.nomination)?;
        Ok(EvalRepairAuthoringSource {
            reader,
            job: RepairJob {
                id: record.id,
                lease_owner,
                generation: record.attempt_count,
                payload,
            },
            nominations,
        })
    }
}

impl EvalRepairAuthoringSource<'_> {
    /// Original per-source/task errors and scoped receipts, without task bodies
    /// or expected responses. Only successful recipes can be selected to write.
    pub fn nominations(&self) -> &EvalRepairNominations {
        &self.nominations
    }

    /// Record a nominated recipe as the actual leased Coach, not as an owner.
    /// Source/hash reconstruction, family assignment and case admission share
    /// the same writer with the canonical job's current stamp and lease check.
    pub fn record_case(&self, input: &EvalRepairCaseRequest) -> MemoryResult<EvalRepairCaseRead> {
        let nominated = self
            .nominations
            .sources
            .iter()
            .flat_map(|source| &source.tasks)
            .filter_map(|read| read.as_ref().ok())
            .any(|read| read.recipe.as_ref() == Some(&input.recipe));
        if !nominated {
            return Err(invalid().into());
        }
        let source = &input.recipe.source;
        let id = EntityId::from_hex(&source.claim_ref)?;
        let source_pin = AgUiFileReadInput {
            claim_ref: source.claim_ref.clone(),
            source_hash: source.source_hash.clone(),
        };
        let lane = self.reader.read_lane(ClaimReadStatus::Recorded)?;
        lane.persist_grant_clock()?;
        let vault = self.reader.vault();
        let _bodies = vault.pin_all_result_bodies();
        let now = vault.now_recorded_at();
        Ok(vault.with_write_txn_grouped(|txn| {
            let payload = job_payload_in_txn(
                vault,
                txn,
                self.job.id,
                &self.job.lease_owner,
                self.job.generation,
            )?;
            if payload != self.job.payload {
                return Err(invalid());
            }
            record_repair_case_in_txn(vault, txn, &lane, id, &source_pin, input, now)
        })?)
    }
}
