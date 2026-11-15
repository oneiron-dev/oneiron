//! The per-job maximum an agent's Grant carries for starting GPU jobs
//! (RULING L10-31-STARTER = B: "an agent may start a job when its grant
//! names `vault.gpu.jobs.start`. That grant carries a per-job maximum the
//! owner saw when granting"). A Grant has no numeric field, so the owner sets
//! the maximum beside it, in one row keyed by the Grant's id, through
//! `vault.gpu.jobs.allow`; setting it is the owner's showing of that maximum.
//! An agent's start is judged against the row of the Grant that admits it to
//! start now; with no row, the agent starts nothing.
use serde::{Deserialize, Serialize};

use crate::authority::principal_standing_in_txn;
use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, Named, SideTable};
use crate::{EdgeActorClass, EntityId, Vault};

use super::{GpuJobError, GpuJobVerb};

const GPU_JOB_ALLOWANCES: SideTable<EntityId, GpuJobAllowance, Named> =
    SideTable::new(&side_table::GPU_JOB_ALLOWANCE);

/// The longest run time, in seconds, one GPU job an agent starts under the
/// Grant `grant` may declare, as the owner set it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuJobAllowance {
    pub grant: EntityId,
    /// The agent the Grant names.
    pub agent: EntityId,
    /// The largest total maximum of one job, over all its chunks.
    pub maximum_secs: u64,
    /// The owner who set it; `None` after their erase.
    pub set_by: Option<EntityId>,
    /// When the owner set it: the showing an agent's start records.
    pub set_at_ms: u64,
}

impl Vault {
    /// The owner sets the per-job maximum the agent Grant `grant` carries for
    /// starting GPU jobs; `maximum_secs` 0 removes it. The Grant must be the
    /// one that admits its agent to `vault.gpu.jobs.start` now.
    ///
    /// # Errors
    ///
    /// [`GpuJobError::Caller`] for a Grant that does not admit its agent to
    /// start now.
    pub fn allow_gpu_jobs(
        &self,
        owner: &AuthenticatedOwner,
        grant: &EntityId,
        maximum_secs: u64,
        now_ms: u64,
    ) -> Result<Option<GpuJobAllowance>, GpuJobError> {
        owner.revalidate(self)?;
        self.with_write_txn_grouped(
            |txn| -> crate::Result<Result<Option<GpuJobAllowance>, GpuJobError>> {
                let set_by = owner.revalidate_in_txn(self, txn)?;
                if maximum_secs == 0 {
                    GPU_JOB_ALLOWANCES.delete(&self.store, txn, grant)?;
                    return Ok(Ok(None));
                }
                let Some(agent) = start_grant_agent_in_txn(self, txn, grant)? else {
                    return Ok(Err(GpuJobError::Caller(super::caller::refused(
                        GpuJobVerb::Allow,
                        "the Grant does not admit its agent to vault.gpu.jobs.start now; name \
                         the verb in a live Grant first",
                    ))));
                };
                let row = GpuJobAllowance {
                    grant: *grant,
                    agent,
                    maximum_secs,
                    set_by: Some(set_by),
                    set_at_ms: now_ms,
                };
                GPU_JOB_ALLOWANCES.put(&self.store, txn, grant, &row)?;
                Ok(Ok(Some(row)))
            },
        )?
    }

    /// The per-job maximum the Grant `grant` carries, if the owner set one.
    pub fn gpu_job_allowance(&self, grant: &EntityId) -> crate::Result<Option<GpuJobAllowance>> {
        GPU_JOB_ALLOWANCES.get(&self.store, &self.store.env.read_txn()?, grant)
    }

    pub(super) fn gpu_job_allowance_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        grant: &EntityId,
    ) -> crate::Result<Option<GpuJobAllowance>> {
        GPU_JOB_ALLOWANCES.get(&self.store, txn, grant)
    }
}

/// The agent the Grant `grant` names, when that Grant is the one the standing
/// rule picks for its agent and `vault.gpu.jobs.start` now.
fn start_grant_agent_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant: &EntityId,
) -> crate::Result<Option<EntityId>> {
    let Some(agent) = crate::federation::agent_grants_for_store_in_txn(&vault.store, txn)?
        .into_iter()
        .find(|standing| standing.id == *grant)
        .map(|standing| standing.grant.member_ref)
    else {
        return Ok(None);
    };
    let standing = principal_standing_in_txn(
        vault,
        txn,
        agent,
        EdgeActorClass::Agent,
        GpuJobVerb::Start.name(),
    )?;
    Ok((standing.and_then(|standing| standing.grant) == Some(*grant)).then_some(agent))
}

/// Takes the erased actor out of every allowance: an agent's rows go, and
/// an owner's name leaves the rows they set (the side table's actor scrub).
pub(crate) fn erase_allowance_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::Result<()> {
    for (grant, mut row) in GPU_JOB_ALLOWANCES.scan(&vault.store, wtxn)? {
        if row.agent == *actor {
            GPU_JOB_ALLOWANCES.delete(&vault.store, wtxn, &grant)?;
        } else if row.set_by == Some(*actor) {
            row.set_by = None;
            GPU_JOB_ALLOWANCES.put(&vault.store, wtxn, &grant, &row)?;
        }
    }
    Ok(())
}
