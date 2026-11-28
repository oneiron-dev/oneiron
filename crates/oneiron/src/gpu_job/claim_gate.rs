//! The one start gate's line half (design pass 32 r2, section 5.3; LM-8 = A). An offer that a
//! `GPU_LINE` names is line-managed. A job starts on it only as the one job of a unit claim of
//! that line, through [`Vault::start_claimed_gpu_job`]; the plain start refuses it before any
//! reservation (`offer_line_managed`), and nothing resumes on it in version 1
//! (`resume_line_managed`). The claim, not a `vault.gpu.jobs.start` Grant or a
//! `GPU_JOB_ALLOWANCE` row, bounds the unit: the engine reads the line, the family, the Grant,
//! the wallet and the allocation from the claim, and no request field names them.
//!
//! A claimed start takes no admission on the host account and holds no permit: the claim is the
//! job's hold on its line's allocation (section 7.2 point 3). Its checks, the job row and the
//! claim's `Claimed -> Started` run in one write. A refusal after the gate found the caller's
//! own claim ends that claim `Released(<code>)` in the same write, so its draws return once.

use crate::experiment_arm::StartedUnitCancel;
use crate::gpu_line::claim::{CUSTODY_LAPSED, release_claim_in_txn, start_claim_in_txn};
use crate::gpu_line::{
    ClaimKey, ClaimState, UnitClaim, claim_in_txn, custody_lapsed_in_txn, line_in_txn,
    offer_line_managed_in_txn,
};
use crate::job_workload::{WorkloadStartAsk, WorkloadStartRefusal, WorkloadStarter};
use crate::llm::run_admission::{MaximumShown, ResumeOffer};
use crate::{EntityId, Vault};

use super::start::{CancelFor, next_chunk};
use super::{
    GPU_JOBS, GpuJob, GpuJobActor, GpuJobConnector, GpuJobError, GpuJobPermits, GpuJobQuote,
    GpuJobRequest, GpuOffer,
};

/// The job type of a unit's job (design pass 32 r2, 3.6; pass 33, 5.1).
pub const UNIT_JOB_TYPE: &str = "pinned_workload";

/// What a unit's start asks: who presses it, and the offer and quote of the claim's one job.
/// It carries no run admission (the claim is the job's hold) and no resume (version 1 units
/// have no checkpoint flow).
#[derive(Debug, Clone, Copy)]
pub struct UnitJobStart<'a> {
    pub actor: GpuJobActor<'a>,
    pub offer: &'a GpuOffer,
    pub quote: &'a GpuJobQuote,
}

/// Why the start gate refused a start on a line-managed offer. Each message leads with its
/// code, as the unit doors' refusals do.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LineStartRefused {
    /// A plain start on an offer a GPU line names.
    #[error(
        "offer_line_managed: a GPU line manages this offer; vault.arms.units.reserve reserves a unit and starts its job"
    )]
    OfferLineManaged,
    /// A resume on a line-managed offer: version 1 units have no checkpoint flow.
    #[error(
        "resume_line_managed: a job on a line-managed offer does not resume; reserve the unit's next attempt"
    )]
    ResumeLineManaged,
    /// No claim stands under the key, the caller did not reserve it, or the start's terms are
    /// not the claim's (the field named).
    #[error("claim_mismatch: {0}")]
    ClaimMismatch(&'static str),
    /// The claim already started its job, or it ended.
    #[error("claim_not_claimed: the unit's claim has started its job or ended")]
    ClaimNotClaimed,
    /// The claim's custody lapsed before this start, and the start released it.
    #[error("claim_released: the unit's claim was not started within its custody; reserve again")]
    ClaimReleased,
    /// The workload is not approved for the claim's reserver on the machine the quote names.
    #[error("workload_not_approved: {0}")]
    Workload(WorkloadStartRefusal),
}

impl LineStartRefused {
    /// The refusal's code: the first word of its message.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::OfferLineManaged => "offer_line_managed",
            Self::ResumeLineManaged => "resume_line_managed",
            Self::ClaimMismatch(_) => "claim_mismatch",
            Self::ClaimNotClaimed => "claim_not_claimed",
            Self::ClaimReleased => "claim_released",
            Self::Workload(_) => "workload_not_approved",
        }
    }
}

/// The release reason a refused claimed start writes on its claim.
fn release_reason(refused: &GpuJobError) -> String {
    match refused {
        GpuJobError::LineManaged(refused) => refused.code().to_owned(),
        GpuJobError::QuoteChanged => "quote_changed".to_owned(),
        GpuJobError::QuoteExpired => "quote_expired".to_owned(),
        GpuJobError::QuoteUsed => "quote_used".to_owned(),
        GpuJobError::Order(refused) => refused.code().to_owned(),
        _ => "start_refused".to_owned(),
    }
}

fn line_managed(refused: LineStartRefused) -> GpuJobError {
    GpuJobError::LineManaged(refused)
}

impl Vault {
    /// The plain start's half of the gate, read in `txn`: an offer no GPU line names passes; a
    /// start on a line-managed offer is refused, and a resume there too.
    pub(super) fn plain_start_gate_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        offer: &GpuOffer,
        resume: Option<&ResumeOffer>,
    ) -> crate::Result<Result<(), GpuJobError>> {
        if !offer_line_managed_in_txn(self, txn, &offer.name)? {
            return Ok(Ok(()));
        }
        Ok(Err(line_managed(if resume.is_some() {
            LineStartRefused::ResumeLineManaged
        } else {
            LineStartRefused::OfferLineManaged
        })))
    }

    /// `start.actor` starts the one job of the unit claim under `claim`, on `start.quote` (quoted
    /// with [`GpuOffer::quote_for`] on the claim's id and [`Self::unit_job_request`]), which
    /// must quote the claim's id as its job (design 5.3). The claim must stand `Claimed` within
    /// its custody and be the caller's own: an agent's under the Grant it reserved with, the
    /// owner's under their proof, or, for `GpuJobActor::Order`, the claim a work order's attempt
    /// reserved for its requester (row H3), while that attempt is the order's live one, no
    /// cancel reached the order and its requester's authority lives. The quote's maximum is the claim's reserved seconds, its image
    /// the claim's workload, its offer one the claim's line names, its machine the claim's pin
    /// (when it has one), and the workload is still approved for the reserver on that machine
    /// (R2's recheck, in the write). The caller needs no `vault.gpu.jobs.start` Grant and no
    /// `GPU_JOB_ALLOWANCE` row. It takes no admission and holds no permit: the claim is the
    /// job's hold. The job row and the claim's start are one write; the provider is asked after
    /// it, and a provider's refusal holds the job and releases the claim in one write.
    ///
    /// # Errors
    ///
    /// [`GpuJobError::LineManaged`] for a claim that is missing, not the caller's, no longer
    /// `Claimed`, past its custody or other than the start's terms; [`GpuJobError::QuoteChanged`]
    /// or [`GpuJobError::QuoteExpired`] for a stale quote. Every refusal after the gate found the
    /// caller's own `Claimed` claim releases it.
    pub fn start_claimed_gpu_job(
        &self,
        start: UnitJobStart<'_>,
        claim: &ClaimKey,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        let UnitJobStart {
            actor,
            offer,
            quote,
        } = start;
        if let GpuJobActor::Owner(owner) = actor {
            owner.revalidate(self)?;
        }
        let written =
            self.with_write_txn_grouped(|txn| -> crate::Result<Result<GpuJob, GpuJobError>> {
                let Some(stored) = claim_in_txn(self, txn, claim)? else {
                    return Ok(Err(line_managed(LineStartRefused::ClaimMismatch(
                        "no unit claim stands under this key",
                    ))));
                };
                if stored.state != ClaimState::Claimed {
                    return Ok(Err(line_managed(LineStartRefused::ClaimNotClaimed)));
                }
                if custody_lapsed_in_txn(self, txn, &stored, now_ms)? {
                    release_claim_in_txn(self, txn, &stored, CUSTODY_LAPSED, now_ms)?;
                    return Ok(Err(line_managed(LineStartRefused::ClaimReleased)));
                }
                // Another caller's start refuses and writes nothing: only the reserver's own
                // refused start gives the claim up.
                let starter = match self.claim_starter_in_txn(txn, actor, &stored)? {
                    Ok(starter) => starter,
                    Err(refused) => return Ok(Err(refused)),
                };
                // A work order's attempt starts its claim only while the attempt is the order's
                // live one: a cancel or an ended authority since its reserve gives the claim up.
                let in_turn = match actor {
                    GpuJobActor::Order(attempt) => self
                        .order_attempt_starts_in_txn(txn, attempt, &stored.id)?
                        .map_err(GpuJobError::Order),
                    GpuJobActor::Owner(_) | GpuJobActor::Agent(_) => Ok(()),
                };
                let made = match in_turn {
                    Ok(()) => {
                        self.claimed_job_in_txn(txn, &stored, starter, offer, quote, now_ms)?
                    }
                    Err(refused) => Err(refused),
                };
                match made {
                    Ok(job) => Ok(Ok(job)),
                    Err(refused) => {
                        release_claim_in_txn(
                            self,
                            txn,
                            &stored,
                            &release_reason(&refused),
                            now_ms,
                        )?;
                        Ok(Err(refused))
                    }
                }
            })?;
        self.create_gpu_chunk(written?, permits, connector, now_ms)
    }

    /// The job request of the unit claim under `claim`, while it stands `Claimed`, for its
    /// quote: job type `pinned_workload`, the claim's workload as the image, its reserved
    /// seconds as the maximum, and inputs naming the machine and the claim (design 3.6), and the
    /// claim's result binding when it has one (row RSI-ARM-RESULT). The
    /// machine is the claim's pin, or else the first machine of its line on which the workload
    /// is approved for the claim's reserver, as the reserve judged it. `None` for a claim that
    /// is missing or no longer `Claimed`; inputs with no machine when no machine approves it,
    /// which the start then refuses and releases.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn unit_job_request(
        &self,
        claim: &ClaimKey,
        now_ms: u64,
    ) -> crate::Result<Option<GpuJobRequest>> {
        let txn = self.store.env.read_txn()?;
        let Some(stored) = claim_in_txn(self, &txn, claim)? else {
            return Ok(None);
        };
        if stored.state != ClaimState::Claimed {
            return Ok(None);
        }
        let machine = match stored.machine {
            Some(machine) => Some(machine),
            None => {
                let machines = line_in_txn(self, &txn, &stored.line)?
                    .map(|line| line.machines)
                    .unwrap_or_default();
                let mut placed = None;
                for machine in machines {
                    let ask = WorkloadStartAsk {
                        workload: &stored.workload,
                        machine,
                        maximum_secs: stored.reserved_secs,
                        starter: match (stored.grant, stored.reserved_by) {
                            (Some(grant), _) => WorkloadStarter::Grant(grant),
                            (None, Some(owner)) => WorkloadStarter::Owner(owner),
                            (None, None) => break,
                        },
                    };
                    if self.workload_approval_in_txn(&txn, &ask, now_ms)?.is_ok() {
                        placed = Some(machine);
                        break;
                    }
                }
                placed
            }
        };
        let mut inputs = serde_json::json!({
            "claim": {
                "arm": stored.arm.to_hex(),
                "rung": stored.rung,
                "unit_key": stored.unit_key,
                "attempt": stored.attempt,
            },
        });
        if let Some(machine) = machine {
            inputs["machine"] = serde_json::Value::String(machine.to_hex());
        }
        // The result the reserve admitted (row RSI-ARM-RESULT): the issuer lands the job's
        // returnable outputs through it, as for any GPU job whose quote binds one.
        if let Some(result) = stored.result.filter(|_| false) {
            inputs["result"] = serde_json::json!({
                "artifact": result.artifact.to_hex(),
                "task": result.task.to_hex(),
            });
        }
        Ok(Some(GpuJobRequest {
            job_type: UNIT_JOB_TYPE.to_owned(),
            image: stored.workload,
            maximum_secs: Some(stored.reserved_secs),
            inputs,
        }))
    }

    /// The scoped cancel of a unit's started job (design 5.3): `vault.arms.units.cancel` judged
    /// the line, the lead role and "the reserver, or the owner" when it made `cancel`, so this
    /// needs no `vault.gpu.jobs.cancel` Grant. It cancels only the job of the claim `cancel`
    /// names, as [`Self::cancel_gpu_job`] does: a live chunk ends now (a unit's job holds no
    /// permit), and the claim ends at the job's terminal.
    ///
    /// # Errors
    ///
    /// [`GpuJobError::Ended`] for a job that already ended; [`GpuJobError::NotFound`] when the
    /// job is not that claim's.
    pub fn cancel_unit_gpu_job(
        &self,
        cancel: StartedUnitCancel,
        permits: &GpuJobPermits,
        connector: &dyn GpuJobConnector,
        now_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        self.cancel_gpu_job_for(
            CancelFor::Unit(&cancel.claim),
            &cancel.job,
            permits,
            connector,
            now_ms,
        )
    }

    /// The caller as the starter of `claim`: the owner, of a claim the owner reserved; an
    /// agent, of a claim it reserved under a Grant; a work order's attempt, of the claim its
    /// reserve made for the order's requester (row H3), who is then the job's starter.
    fn claim_starter_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: GpuJobActor<'_>,
        claim: &UnitClaim,
    ) -> crate::Result<Result<EntityId, GpuJobError>> {
        let starter = match actor {
            GpuJobActor::Owner(owner) => {
                let owner = owner.revalidate_in_txn(self, txn)?;
                claim.grant.is_none().then_some(owner)
            }
            GpuJobActor::Agent(agent) => (claim.grant.is_some()
                && claim.reserved_by == Some(agent.actor()))
            .then(|| agent.actor()),
            GpuJobActor::Order(attempt) => self.order_claim_starter_in_txn(txn, attempt, claim)?,
        };
        Ok(starter.ok_or_else(|| {
            line_managed(LineStartRefused::ClaimMismatch(
                "only the caller who reserved the unit starts its job",
            ))
        }))
    }

    /// The claim's job, checked against the claim and written with the claim's start, in
    /// `txn`. Nothing is written on a refusal.
    fn claimed_job_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        claim: &UnitClaim,
        starter: EntityId,
        offer: &GpuOffer,
        quote: &GpuJobQuote,
        now_ms: u64,
    ) -> crate::Result<Result<GpuJob, GpuJobError>> {
        if let Some(field) = claim_term_mismatch(self, txn, claim, offer, quote)? {
            return Ok(Err(line_managed(LineStartRefused::ClaimMismatch(field))));
        }
        if let Err(refused) = quote.check(offer, now_ms) {
            return Ok(Err(refused));
        }
        // R2's workload gate, rechecked in this write on the machine the quote names.
        // Seams, until they are on this base: R5's `not_the_issuer` (this server issues the
        // vault machine's jobs) and R4-2's `machine_job_guard_refusal` (the machine is not
        // drained) join this check here.
        let reserver = match claim.grant {
            Some(grant) => WorkloadStarter::Grant(grant),
            None => WorkloadStarter::Owner(starter),
        };
        let approved = match WorkloadStartAsk::from_quote(quote, reserver) {
            Ok(ask) => self.workload_approval_in_txn(txn, &ask, now_ms)?.map(drop),
            Err(refused) => Err(refused),
        };
        if let Err(refused) = approved {
            return Ok(Err(line_managed(LineStartRefused::Workload(refused))));
        }
        let current = GPU_JOBS.get(&self.store, txn, &quote.job)?;
        let shown = MaximumShown {
            at_ms: claim.reserved_at_ms,
        };
        let mut job = match next_chunk(current, offer, quote, None, shown, now_ms) {
            Ok(job) => job,
            Err(refused) => return Ok(Err(refused)),
        };
        if start_claim_in_txn(self, txn, claim)?.is_none() {
            return Ok(Err(line_managed(LineStartRefused::ClaimNotClaimed)));
        }
        job.started_by = Some(starter);
        job.claim = Some(claim.key());
        job.revision += 1;
        job.updated_at_ms = now_ms;
        GPU_JOBS.put(&self.store, txn, &job.id, &job)?;
        Ok(Ok(job))
    }
}

/// The first term of `quote` on `offer` that is not `claim`'s, read in `txn`: the job, the
/// maximum, the workload, the offer (one the claim's line names), the pinned machine and the
/// result binding.
fn claim_term_mismatch(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: &UnitClaim,
    offer: &GpuOffer,
    quote: &GpuJobQuote,
) -> crate::Result<Option<&'static str>> {
    if quote.job != claim.id {
        return Ok(Some("the quote's job is not the claim's id"));
    }
    if quote.offer != offer.name {
        return Ok(Some("the quote is not on this offer"));
    }
    if quote.maximum_secs != claim.reserved_secs {
        return Ok(Some(
            "the quote's maximum is not the claim's reserved seconds",
        ));
    }
    if quote.image != claim.workload {
        return Ok(Some("the quote's image is not the claim's workload"));
    }
    if quote.job_type != UNIT_JOB_TYPE {
        return Ok(Some("a unit's job type is pinned_workload"));
    }
    let Some(line) = line_in_txn(vault, txn, &claim.line)? else {
        return Ok(Some("the claim's line is gone"));
    };
    if !line.offers.iter().any(|name| *name == offer.name) {
        return Ok(Some("the claim's line does not name this offer"));
    }
    let quoted = quote
        .inputs
        .get("machine")
        .and_then(serde_json::Value::as_str)
        .and_then(|hex| EntityId::from_hex(hex).ok());
    let placed = match (claim.machine, quoted) {
        (Some(pinned), Some(quoted)) => pinned == quoted,
        (None, Some(quoted)) => line.machines.contains(&quoted),
        (_, None) => false,
    };
    if !placed {
        return Ok(Some(
            "the quote's machine is not the claim's pin or a machine of its line",
        ));
    }
    // The quote binds the result the reserve admitted for the claim, or none (row
    // RSI-ARM-RESULT): a start never lands a unit's outputs anywhere else.
    let bound = match quote.inputs.get("result").filter(|value| !value.is_null()) {
        Some(value) => match serde_json::from_value::<super::GpuJobResultBinding>(value.clone()) {
            Ok(binding) => Some(binding),
            Err(_) => return Ok(Some("the quote's result does not read as a binding")),
        },
        None => None,
    };
    if bound != claim.result {
        return Ok(Some("the quote's result is not the claim's"));
    }
    Ok(None)
}
