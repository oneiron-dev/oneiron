//! Doors for `tests/project_lead_turn.rs` (FIX NEON-LEAD-TURN-TRIGGER): a GPU job row planted
//! live and moved out of live through the job's own row writer (`put_gpu_job_in_txn`, where the
//! lead-turn hook runs), a unit claim planted as given, a registration that does not decode, and
//! one timer pass at a given time.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::gpu_job::{GpuJob, GpuJobState};
use crate::gpu_line::{ClaimKey, UnitClaim};
use crate::llm::run_admission::{DeclaredMaximum, JobMaximum, LeaseUnit, MaximumShown};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// The GPU job rows, as the job's own table keys them.
const JOBS: SideTable<EntityId, GpuJob, Named> = SideTable::new(&side_table::GPU_JOB);

/// Plants a running GPU job `job` started by `started_by`, the one job of the unit claim under
/// `claim` when given. The row is built through its own serde shape, so a field the job's owner
/// adds later keeps this door building.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn plant_running_gpu_job(
    vault: &Vault,
    job: EntityId,
    started_by: Option<EntityId>,
    claim: Option<&ClaimKey>,
    now_ms: u64,
) -> Result<()> {
    let unit = LeaseUnit::new("seconds").expect("a valid lease unit");
    let maximum = JobMaximum::start(
        job.to_hex(),
        DeclaredMaximum { units: 600, unit },
        Some(MaximumShown { at_ms: now_ms }),
    )
    .map_err(|error| Error::InvalidConfig(error.to_string()))?;
    let row: GpuJob = serde_json::from_value(serde_json::json!({
        "id": job,
        "started_by": started_by,
        "offer": {
            "name": "fixture-gpu",
            "class": "fixture",
            "provider": "fixture",
            "region": "home",
            "price_shape": "at_oneiron_list",
        },
        "job_type": "fixture",
        "image": "registry.example.com/fixture@sha256:00",
        "maximum": maximum,
        "chunks": [],
        "state": "running",
        "stop": null,
        "overrun_reported": false,
        "created_at_ms": now_ms,
        "updated_at_ms": now_ms,
        "revision": 1,
        "claim": claim,
    }))
    .map_err(|error| Error::InvalidConfig(error.to_string()))?;
    vault.with_write_txn(|txn| JOBS.put(&vault.store, txn, &job, &row))
}

/// Moves job `job` to `state` at `now_ms` through the job's own row writer. Answers whether the
/// write landed; `stale` writes over an older revision, as a step that lost to another write.
///
/// # Errors
/// No job under `job`, or the store's.
#[doc(hidden)]
pub fn move_gpu_job(
    vault: &Vault,
    job: EntityId,
    state: GpuJobState,
    stale: bool,
    now_ms: u64,
) -> Result<bool> {
    vault.with_write_txn(|txn| {
        let mut row = JOBS
            .get(&vault.store, txn, &job)?
            .ok_or_else(|| Error::InvalidConfig("no GPU job under this id".to_owned()))?;
        if stale {
            row.revision = row.revision.saturating_sub(1);
        }
        row.state = state;
        vault.put_gpu_job_in_txn(txn, &mut row, now_ms)
    })
}

/// Plants `claim` as its key's unit claim row.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn plant_unit_claim(vault: &Vault, claim: &UnitClaim) -> Result<()> {
    vault.with_write_txn(|txn| crate::gpu_line::claim::put_claim_row_in_txn(vault, txn, claim))
}

/// Writes bytes no registration decodes from as `project`'s lead-turn registration.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn plant_undecodable_registration(vault: &Vault, project: EntityId) -> Result<()> {
    vault.with_write_txn(|txn| {
        crate::project_lead_turn::store::REGISTRATIONS.put_undecodable(
            &vault.store,
            txn,
            &project,
            b"\xff\x00 not a registration",
        )
    })
}

/// One timer pass of `project`'s lead turns at `now_ms`; answers when it is due next.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn timer_pass(vault: &Vault, project: EntityId, now_ms: u64) -> Result<Option<u64>> {
    vault.with_write_txn(|txn| {
        crate::project_lead_turn::store::timer_pass_in_txn(vault, txn, project, now_ms)
    })
}
