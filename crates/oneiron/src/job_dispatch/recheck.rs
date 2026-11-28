//! What the issuer checks again before it sends a vault machine anything that could make work,
//! and at every step of a job that runs (pass 33 sections 8.2 and 9).
//!
//! - The live recheck, before the first reserve and before every reserve or submit sent again:
//!   the starter still stands (the owner is a live owner; the agent's Grant still names
//!   `vault.gpu.jobs.start` and keeps its allowance), the workload's approval holds through
//!   row R2's check, and this vault grants the node both job protocols. None of these may end
//!   within the horizon (the submit window plus the staging limit). Only the owner approves a
//!   workload (row R2), so no Grant stands behind an approval. The node's own vault holds the
//!   issuer's grant, and the node checks that one at each request.
//! - The revoke check, at every step: a revoke of the starter's Grant, the approval or the
//!   workload stops the job; an expiry does not, since the job started within its terms
//!   (EN-4, recommended option A).
use crate::authority::principal_standing_covering_or_lapse_in_txn;
use crate::federation::{FederationGrant, agent_grants_for_store_in_txn};
use crate::gpu_job::GpuJobVerb;
use crate::job_workload::{
    JOB_ALPN, JOB_STATUS_ALPN, WorkloadPin, WorkloadStartAsk, WorkloadStartRefusal, WorkloadStarter,
};
use crate::policy_model::is_live_vault_owner_in_txn;
use crate::{EdgeActorClass, EntityId, Vault};

/// The dispatch a recheck is about: who started it, the workload, the node and the chunk's
/// maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchAsk<'a> {
    pub starter: WorkloadStarter,
    /// The workload digest: the quote's `image`.
    pub workload: &'a str,
    /// The machine that runs the chunk: the quote's `inputs.machine`.
    pub node: EntityId,
    pub maximum_secs: u64,
}

/// Why a dispatch may not go out, or a running job must stop.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DispatchRefusal {
    /// The owner is no live owner, or the agent's Grant was withdrawn or no longer names the
    /// start verb for its agent.
    #[error("the job's starter no longer stands")]
    StarterLapsed,
    /// The agent's Grant has expired, or ends within the horizon.
    #[error("the starter's Grant ends before the dispatch window closes")]
    StarterExpiring,
    /// The owner removed the GPU job maximum beside the agent's Grant.
    #[error("the owner removed the starter Grant's GPU job allowance")]
    AllowanceRemoved,
    /// Row R2's approval check refused.
    #[error(transparent)]
    Workload(WorkloadStartRefusal),
    /// This vault grants the node no live grant for a job protocol.
    #[error("the machine holds no live grant for a job protocol")]
    MachineGrantEnded,
    /// The node's grant for a job protocol ends within the horizon.
    #[error("the machine's job protocol grant ends before the dispatch window closes")]
    MachineGrantExpiring,
}

impl DispatchRefusal {
    /// The refusal's name, as a job and its view carry it.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::StarterLapsed => "starter_lapsed",
            Self::StarterExpiring => "starter_expiring",
            Self::AllowanceRemoved => "allowance_removed",
            Self::Workload(refusal) => refusal.code(),
            Self::MachineGrantEnded => "machine_grant_ended",
            Self::MachineGrantExpiring => "machine_grant_expiring",
        }
    }
}

/// Where the starter's Grant stands now.
enum GrantStanding {
    /// It stands for its agent and the start verb, until this time (vault seconds), if it ends.
    Stands { expires_at: Option<u64> },
    /// It has expired.
    Expired,
    /// It was withdrawn, or no longer stands for its agent and the start verb.
    Lapsed,
}

impl Vault {
    /// The starter of a job begun by `started_by`, as the start admitted it: the owner, when
    /// `started_by` is a live owner; else the agent's Grant that the standing rule picks for
    /// `vault.gpu.jobs.start` now. `None` when neither stands. The issuer reads it once, at
    /// the chunk's first dispatch, and signs it into the submit; every later check reads the
    /// starter from the submit. A job row that records its starter Grant replaces this read.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn dispatch_starter(&self, started_by: EntityId) -> crate::Result<Option<WorkloadStarter>> {
        let txn = self.store.env.read_txn()?;
        if is_live_vault_owner_in_txn(self, &txn, &started_by)? {
            return Ok(Some(WorkloadStarter::Owner(started_by)));
        }
        for class in [EdgeActorClass::Agent, EdgeActorClass::System] {
            let standing = crate::authority::principal_standing_in_txn(
                self,
                &txn,
                started_by,
                class,
                GpuJobVerb::Start.name(),
            )?;
            if let Some(grant) = standing.and_then(|standing| standing.grant) {
                return Ok(Some(WorkloadStarter::Grant(grant)));
            }
        }
        Ok(None)
    }

    /// The live recheck of a dispatch at `now_ms`: nothing it reads may end before
    /// `now_ms + horizon_ms`. Answers the pin the dispatch runs.
    ///
    /// # Errors
    ///
    /// A store read failure. Every refusal is the inner `Err`.
    pub fn dispatch_recheck(
        &self,
        ask: &DispatchAsk<'_>,
        now_ms: u64,
        horizon_ms: u64,
    ) -> crate::Result<Result<WorkloadPin, DispatchRefusal>> {
        let pin = {
            let txn = self.store.env.read_txn()?;
            let now_secs = self.instant_in_txn(&txn)?.secs();
            let until_secs = now_secs.saturating_add(horizon_ms.div_ceil(1000));
            match ask.starter {
                WorkloadStarter::Owner(owner) => {
                    if !is_live_vault_owner_in_txn(self, &txn, &owner)? {
                        return Ok(Err(DispatchRefusal::StarterLapsed));
                    }
                }
                WorkloadStarter::Grant(grant) => {
                    match self.start_grant_standing_in_txn(&txn, grant, now_secs)? {
                        GrantStanding::Stands { expires_at } => {
                            if expires_at.is_some_and(|at| at <= until_secs) {
                                return Ok(Err(DispatchRefusal::StarterExpiring));
                            }
                        }
                        GrantStanding::Expired => {
                            return Ok(Err(DispatchRefusal::StarterExpiring));
                        }
                        GrantStanding::Lapsed => return Ok(Err(DispatchRefusal::StarterLapsed)),
                    }
                }
            }
            let workload = WorkloadStartAsk {
                workload: ask.workload,
                machine: ask.node,
                maximum_secs: ask.maximum_secs,
                starter: ask.starter,
            };
            let pin = match self.workload_approval_in_txn(
                &txn,
                &workload,
                now_ms.saturating_add(horizon_ms),
            )? {
                Ok(pin) => pin,
                Err(refused) => return Ok(Err(DispatchRefusal::Workload(refused))),
            };
            for alpn in [JOB_ALPN, JOB_STATUS_ALPN] {
                match self.mesh_grant_live_until_in_txn(&txn, ask.node, alpn)? {
                    None => return Ok(Err(DispatchRefusal::MachineGrantEnded)),
                    Some(at) if at <= until_secs => {
                        return Ok(Err(DispatchRefusal::MachineGrantExpiring));
                    }
                    Some(_) => {}
                }
            }
            pin
        };
        // The allowance has its own read: it opens its own snapshot.
        if let WorkloadStarter::Grant(grant) = ask.starter
            && self.gpu_job_allowance(&grant)?.is_none()
        {
            return Ok(Err(DispatchRefusal::AllowanceRemoved));
        }
        Ok(Ok(pin))
    }

    /// The revoke check of a running dispatch at `now_ms`: `Some` only when the starter's Grant
    /// was withdrawn or no longer stands, the owner who started it is no live owner, or the
    /// approval or the workload was revoked. An expiry answers `None`: the job runs on.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn dispatch_revoked(
        &self,
        ask: &DispatchAsk<'_>,
        now_ms: u64,
    ) -> crate::Result<Option<DispatchRefusal>> {
        let txn = self.store.env.read_txn()?;
        let now_secs = self.instant_in_txn(&txn)?.secs();
        match ask.starter {
            WorkloadStarter::Owner(owner) => {
                if !is_live_vault_owner_in_txn(self, &txn, &owner)? {
                    return Ok(Some(DispatchRefusal::StarterLapsed));
                }
            }
            WorkloadStarter::Grant(grant) => {
                if matches!(
                    self.start_grant_standing_in_txn(&txn, grant, now_secs)?,
                    GrantStanding::Lapsed
                ) {
                    return Ok(Some(DispatchRefusal::StarterLapsed));
                }
            }
        }
        let workload = WorkloadStartAsk {
            workload: ask.workload,
            machine: ask.node,
            maximum_secs: ask.maximum_secs,
            starter: ask.starter,
        };
        Ok(
            match self.workload_approval_in_txn(&txn, &workload, now_ms)? {
                Ok(_) | Err(WorkloadStartRefusal::WorkloadExpired) => None,
                Err(refused) => Some(DispatchRefusal::Workload(refused)),
            },
        )
    }

    /// Whether `starter`, as a chunk's signed submit names it, stands now: a live owner, or
    /// that exact Grant, unexpired and standing for its agent and `vault.gpu.jobs.start`.
    /// Another live Grant of the same agent does not count. A returned result reads it to pick
    /// the lane it lands in (RESULT-LANDING-LAPSED-STARTER = A).
    pub(crate) fn dispatch_starter_stands(&self, starter: WorkloadStarter) -> crate::Result<bool> {
        let txn = self.store.env.read_txn()?;
        match starter {
            WorkloadStarter::Owner(owner) => is_live_vault_owner_in_txn(self, &txn, &owner),
            WorkloadStarter::Grant(grant) => {
                let now_secs = self.instant_in_txn(&txn)?.secs();
                Ok(matches!(
                    self.start_grant_standing_in_txn(&txn, grant, now_secs)?,
                    GrantStanding::Stands { .. }
                ))
            }
        }
    }

    /// Where the Grant `grant` stands for its agent and `vault.gpu.jobs.start` at `now_secs`.
    /// A Grant another live Grant of the same agent outranks still stands: the standing rule
    /// is asked for this Grant first.
    fn start_grant_standing_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        grant: EntityId,
        now_secs: u64,
    ) -> crate::Result<GrantStanding> {
        let Some(listed) = agent_grants_for_store_in_txn(&self.store, txn)?
            .into_iter()
            .find(|standing| standing.id == grant)
        else {
            return Ok(GrantStanding::Lapsed);
        };
        if listed.grant.expires_at.is_some_and(|at| at <= now_secs) {
            return Ok(GrantStanding::Expired);
        }
        let ours = listed.grant;
        let covers = |candidate: &FederationGrant| *candidate == ours;
        for class in [EdgeActorClass::Agent, EdgeActorClass::System] {
            let standing = principal_standing_covering_or_lapse_in_txn(
                self,
                txn,
                ours.member_ref,
                class,
                GpuJobVerb::Start.name(),
                &covers,
            )?;
            if standing.is_ok_and(|standing| standing.grant == Some(grant)) {
                return Ok(GrantStanding::Stands {
                    expires_at: ours.expires_at,
                });
            }
        }
        Ok(GrantStanding::Lapsed)
    }
}
