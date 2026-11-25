//! The workload-approval check (pass 33, door 7; Engine ruling LM-8 = A): the
//! one function the start gate in `start_gpu_job` calls before the
//! reservation. It answers whether this starter may start this workload on
//! this machine now, and whether the machine's own answer still fits the pin.
//! Nothing is held when it says no.
//!
//! The check has two halves. The vault half reads the `JOB_WORKLOAD` row: the
//! pin exists, is not revoked, and was let go: by the owner's approval, which
//! governs once given (its expiry, starters and machines), or else by its
//! check-in (pass 34, 6.5), until `jobs.workloads.approval_days` after it
//! went, for the Grant it was pinned under, on a machine that holds a live
//! job-protocol grant. A pin a `compute.pin` grant let go is read again
//! live: a live grant must still cover it with `machine:<id>` added, so a
//! revoked or narrowed grant stops the next start. Its maximum covers the
//! quote's. The node half
//! judges what the machine answered to `Node` and `Availability`: it was
//! reached, it holds the pin's template under the same digest, and it did not
//! refuse. The vault half alone is also the recheck inside the reservation
//! write and before every dispatch that could make work.
use crate::gpu_job::GpuJobQuote;
use crate::{EntityId, Vault};

use super::compute_bound::pin_candidate;
use super::record::{JobWorkload, PinCheckInOutcome, PinGoBasis};
use super::{JOB_ALPN, WorkloadPin};

/// Who starts a workload, as the start gate resolved the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadStarter {
    /// The vault owner under their own proof (their revalidated id). The
    /// owner may start any approved workload.
    Owner(EntityId),
    /// An agent, under the Grant the standing rule picks for it and
    /// `vault.gpu.jobs.start` now.
    Grant(EntityId),
}

/// The start the gate asks about, as the quote fixes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkloadStartAsk<'a> {
    /// The workload digest: the quote's `image`, 64 lower-hex characters.
    pub workload: &'a str,
    /// The machine that runs it: the quote's `inputs.machine`.
    pub machine: EntityId,
    /// The quote's maximum run time.
    pub maximum_secs: u64,
    pub starter: WorkloadStarter,
}

impl<'a> WorkloadStartAsk<'a> {
    /// The ask a start on `quote` makes for `starter`.
    ///
    /// # Errors
    ///
    /// [`WorkloadStartRefusal::MachineMissing`] when the quote's inputs name
    /// no machine as an id in hex.
    pub fn from_quote(
        quote: &'a GpuJobQuote,
        starter: WorkloadStarter,
    ) -> Result<Self, WorkloadStartRefusal> {
        let machine = quote
            .inputs
            .get("machine")
            .and_then(serde_json::Value::as_str)
            .and_then(|hex| EntityId::from_hex(hex).ok())
            .ok_or(WorkloadStartRefusal::MachineMissing)?;
        Ok(Self {
            workload: &quote.image,
            machine,
            maximum_secs: quote.maximum_secs,
            starter,
        })
    }
}

/// What the machine answered to `Node` and `Availability` for a pin, as the
/// gate's caller read it from the job protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadNodeAnswer {
    /// No answer: no route, a timeout, or a busy service.
    Unreachable { reason: String },
    /// The machine answered.
    Answered {
        /// The digest the machine reports for the pin's template; `None` when
        /// it holds no template of that name.
        template_digest: Option<String>,
        /// The machine's own no: paused, drained, no room on disk, no device
        /// that fits, a scope it does not permit. `None` when it could take
        /// the job.
        refusal: Option<String>,
    },
}

/// Why the start gate refuses a workload start, before anything is held.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkloadStartRefusal {
    #[error("the quote names no machine")]
    MachineMissing,
    #[error("no workload is pinned under this digest")]
    WorkloadUnknown,
    #[error("the owner has not approved this workload")]
    WorkloadNotApproved,
    #[error("this workload's check-in waits for an answer")]
    WorkloadWaiting,
    #[error("no live compute.pin grant covers this workload on this machine")]
    ComputeGrantEnded,
    #[error("the owner revoked this workload")]
    WorkloadRevoked,
    #[error("the owner's approval of this workload has expired")]
    WorkloadExpired,
    #[error("the workload's approval does not name the Grant that starts it")]
    StarterNotNamed,
    #[error("the quote's maximum is above the workload's pinned maximum")]
    RequestAbovePin,
    #[error("the workload's approval does not name this machine")]
    MachineNotApproved,
    #[error("the machine did not answer: {reason}")]
    MachineUnreachable { reason: String },
    #[error("the machine refuses the workload: {reason}")]
    MachineRefuses { reason: String },
}

impl WorkloadStartRefusal {
    /// The refusal's name on door 7.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MachineMissing => "machine_missing",
            Self::WorkloadUnknown => "workload_unknown",
            Self::WorkloadNotApproved => "workload_not_approved",
            Self::WorkloadWaiting => "workload_waiting",
            Self::ComputeGrantEnded => "compute_grant_ended",
            Self::WorkloadRevoked => "workload_revoked",
            Self::WorkloadExpired => "workload_expired",
            Self::StarterNotNamed => "starter_not_named",
            Self::RequestAbovePin => "request_above_pin",
            Self::MachineNotApproved => "machine_not_approved",
            Self::MachineUnreachable { .. } => "machine_unreachable",
            Self::MachineRefuses { .. } => "machine_refuses",
        }
    }

    /// Whether the refusal names the machine or what it said, which only a
    /// caller who may read `vault.machines.execution.get` is shown.
    #[must_use]
    pub const fn discloses_machine(&self) -> bool {
        matches!(
            self,
            Self::MachineUnreachable { .. } | Self::MachineRefuses { .. }
        )
    }
}

/// The reason a machine refuses a pin whose template it holds under another
/// digest: the template changed since the pin, so the pin no longer binds it.
pub const TEMPLATE_CHANGED: &str = "template_changed";
/// The reason a machine refuses a pin whose template it does not hold.
pub const TEMPLATE_NOT_OFFERED: &str = "template_not_offered";

impl Vault {
    /// The start gate's workload check: `ask.starter` may start the workload
    /// `ask.workload` on `ask.machine` now. The vault half runs first, in its
    /// own read; only when it passes is the machine asked, through
    /// `ask_node`, and no read spans that call. The machine's answer must hold
    /// the pin's template under the pinned digest and must not refuse.
    /// Returns the pin the start runs.
    ///
    /// # Errors
    ///
    /// A store read failure. Every refusal is the inner `Err`.
    pub fn check_workload_start(
        &self,
        ask: &WorkloadStartAsk<'_>,
        ask_node: &mut dyn FnMut(&WorkloadPin) -> WorkloadNodeAnswer,
        now_ms: u64,
    ) -> crate::Result<Result<WorkloadPin, WorkloadStartRefusal>> {
        let pin = {
            let txn = self.store.env.read_txn()?;
            match self.workload_approval_in_txn(&txn, ask, now_ms)? {
                Ok(pin) => pin,
                Err(refused) => return Ok(Err(refused)),
            }
        };
        let answer = ask_node(&pin);
        Ok(judge_node_answer(&pin, answer).map(|()| pin))
    }

    /// The vault half of the workload check, read in `txn`: the pin exists,
    /// is not revoked, and was let go, by the owner's approval or its
    /// check-in, unexpired at `now_ms`, for the starter and the machine; its
    /// maximum covers the ask's. A recheck before a dispatch passes `now_ms`
    /// plus the window the approval must still cover.
    ///
    /// # Errors
    ///
    /// A store read failure. Every refusal is the inner `Err`.
    pub fn workload_approval_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        ask: &WorkloadStartAsk<'_>,
        now_ms: u64,
    ) -> crate::Result<Result<WorkloadPin, WorkloadStartRefusal>> {
        let Some(row) = self.job_workload_in_txn(txn, ask.workload)? else {
            return Ok(Err(WorkloadStartRefusal::WorkloadUnknown));
        };
        if row.revoked.is_some() {
            return Ok(Err(WorkloadStartRefusal::WorkloadRevoked));
        }
        if row.approval.is_some() {
            return Ok(judge_approval(row, ask, now_ms));
        }
        self.judge_check_in_in_txn(txn, row, ask, now_ms)
    }

    /// The vault half's verdict on a row the owner has not approved: its
    /// check-in let it go and that has not expired; the starter is the Grant
    /// it was pinned under (or the owner); the machine holds a live grant of
    /// the job protocol and, for a pin a `compute.pin` grant let go, a live
    /// grant still covers it on that machine.
    fn judge_check_in_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        row: JobWorkload,
        ask: &WorkloadStartAsk<'_>,
        now_ms: u64,
    ) -> crate::Result<Result<WorkloadPin, WorkloadStartRefusal>> {
        let (basis, until_ms) = match row.check_in.as_ref().map(|check_in| &check_in.outcome) {
            Some(PinCheckInOutcome::Went {
                basis, until_ms, ..
            }) => (*basis, *until_ms),
            Some(PinCheckInOutcome::Waits { .. }) => {
                return Ok(Err(WorkloadStartRefusal::WorkloadWaiting));
            }
            None => return Ok(Err(WorkloadStartRefusal::WorkloadNotApproved)),
        };
        if until_ms <= now_ms {
            return Ok(Err(WorkloadStartRefusal::WorkloadExpired));
        }
        if let WorkloadStarter::Grant(grant) = ask.starter
            && row.pinned_under != Some(grant)
        {
            return Ok(Err(WorkloadStartRefusal::StarterNotNamed));
        }
        if ask.maximum_secs > row.pin.request.maximum_secs {
            return Ok(Err(WorkloadStartRefusal::RequestAbovePin));
        }
        if !self.mesh_machine_granted_in_txn(txn, ask.machine, JOB_ALPN)? {
            return Ok(Err(WorkloadStartRefusal::MachineNotApproved));
        }
        if basis == PinGoBasis::StandingRow {
            let Some(grant) = row.pinned_under else {
                return Ok(Err(WorkloadStartRefusal::ComputeGrantEnded));
            };
            let candidate = pin_candidate(grant, row.project, &row.pin, Some(ask.machine))?;
            if self
                .covering_compute_grant_in_txn(txn, &candidate)?
                .is_none()
            {
                return Ok(Err(WorkloadStartRefusal::ComputeGrantEnded));
            }
        }
        Ok(Ok(row.pin))
    }
}

/// The vault half's verdict on a row the owner approved: his approval
/// governs it once given.
fn judge_approval(
    row: JobWorkload,
    ask: &WorkloadStartAsk<'_>,
    now_ms: u64,
) -> Result<WorkloadPin, WorkloadStartRefusal> {
    let Some(approval) = row.approval.as_ref() else {
        return Err(WorkloadStartRefusal::WorkloadNotApproved);
    };
    if approval.expires_at_ms <= now_ms {
        return Err(WorkloadStartRefusal::WorkloadExpired);
    }
    let starter_named = match ask.starter {
        WorkloadStarter::Owner(_) => true,
        WorkloadStarter::Grant(grant) if approval.starters.is_empty() => {
            row.pinned_under == Some(grant)
        }
        WorkloadStarter::Grant(grant) => approval.starters.contains(&grant),
    };
    if !starter_named {
        return Err(WorkloadStartRefusal::StarterNotNamed);
    }
    if ask.maximum_secs > row.pin.request.maximum_secs {
        return Err(WorkloadStartRefusal::RequestAbovePin);
    }
    if !approval.machines.contains(&ask.machine) {
        return Err(WorkloadStartRefusal::MachineNotApproved);
    }
    Ok(row.pin)
}

/// The node half's verdict: the machine answered, did not refuse, and holds
/// the pin's template under the pinned digest.
fn judge_node_answer(
    pin: &WorkloadPin,
    answer: WorkloadNodeAnswer,
) -> Result<(), WorkloadStartRefusal> {
    match answer {
        WorkloadNodeAnswer::Unreachable { reason } => {
            Err(WorkloadStartRefusal::MachineUnreachable { reason })
        }
        WorkloadNodeAnswer::Answered {
            refusal: Some(reason),
            ..
        } => Err(WorkloadStartRefusal::MachineRefuses { reason }),
        WorkloadNodeAnswer::Answered {
            template_digest: None,
            refusal: None,
        } => Err(WorkloadStartRefusal::MachineRefuses {
            reason: TEMPLATE_NOT_OFFERED.to_owned(),
        }),
        WorkloadNodeAnswer::Answered {
            template_digest: Some(digest),
            refusal: None,
        } if digest != pin.template_digest => Err(WorkloadStartRefusal::MachineRefuses {
            reason: TEMPLATE_CHANGED.to_owned(),
        }),
        WorkloadNodeAnswer::Answered { .. } => Ok(()),
    }
}
