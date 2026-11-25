//! Doors for `tests/archive_lane_economy_tables_retained.rs` (FIX
//! LANE-ECONOMY-TABLES-ARCHIVE-CLASS) and `tests/archive_lane_economy_sibling_tables_retained.rs`
//! (FIX LANE-ECONOMY-SIBLING-TABLES-ARCHIVE-CLASS): the lane economy's live side rows and its
//! sibling tables' rows, the rows of them the whole-vault export carries as retained copies, and
//! typed puts of the two sibling rows no public door writes without a provider or a live Grant.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::gpu_job::{
    GPU_QUOTE_VALID_MS, GpuChunk, GpuJob, GpuJobAllowance, GpuJobQuote, GpuJobState, GpuOfferPin,
    GpuResourceRef, PriceShape,
};
use crate::llm::run_admission::{DeclaredMaximum, JobMaximum, LeaseUnit, MaximumShown};
use crate::side_table::{self, Named, SideTable, SideTableDecl};
use crate::{EntityId, Error, Vault};

const GPU_JOBS: SideTable<EntityId, GpuJob, Named> = SideTable::new(&side_table::GPU_JOB);
const GPU_JOB_ALLOWANCES: SideTable<EntityId, GpuJobAllowance, Named> =
    SideTable::new(&side_table::GPU_JOB_ALLOWANCE);

/// The lane economy's five side tables, by declared name.
pub const LANE_ECONOMY_TABLES: [&str; 5] = [
    "EXPERIMENT_ARM",
    "EXPERIMENT_ARM_UNIT",
    "GPU_LINE",
    "GPU_LINE_PERIOD",
    "LANE_ECONOMY_INTENT",
];

/// The seven side tables beside the lane economy's that hold its jobs, their dispatches and
/// orders, and the machines' answers, by declared name.
pub const SIBLING_TABLES: [&str; 7] = [
    "GPU_ALLOCATION_NODE",
    "GPU_JOB",
    "GPU_JOB_ALLOWANCE",
    "JOB_DISPATCH",
    "JOB_OBSERVATION",
    "JOB_WORKLOAD",
    "WORK_ORDER",
];

/// The declaration of the lane-economy or sibling table named `table`.
fn lane_economy_decl(table: &str) -> crate::Result<&'static SideTableDecl> {
    [
        &side_table::EXPERIMENT_ARM,
        &side_table::EXPERIMENT_ARM_UNIT,
        &side_table::GPU_LINE,
        &side_table::GPU_LINE_PERIOD,
        &side_table::LANE_ECONOMY_INTENT,
        &side_table::GPU_ALLOCATION_NODE,
        &side_table::GPU_JOB,
        &side_table::GPU_JOB_ALLOWANCE,
        &side_table::JOB_DISPATCH,
        &side_table::JOB_OBSERVATION,
        &side_table::JOB_WORKLOAD,
        &side_table::WORK_ORDER,
    ]
    .into_iter()
    .find(|decl| decl.name == table)
    .ok_or_else(|| {
        Error::InvalidConfig(format!(
            "{table} is not a lane-economy or sibling side table"
        ))
    })
}

/// The live rows of `table`, as (stored key after the declared prefix, value) in key order.
///
/// # Errors
///
/// A name that is none of [`LANE_ECONOMY_TABLES`] or [`SIBLING_TABLES`]; the store's.
#[doc(hidden)]
pub fn live_rows(vault: &Vault, table: &str) -> crate::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let decl = lane_economy_decl(table)?;
    let rtxn = vault.store.env.read_txn()?;
    decl.iter_raw(&vault.store, &rtxn)?.collect()
}

/// The (source key, source value) tuples of `table` this vault's whole-vault export carries as
/// retained rows, live and inert, in physical key order: the export's own collection.
///
/// # Errors
///
/// The collection's.
#[doc(hidden)]
pub fn exported_rows(vault: &Vault, table: &str) -> crate::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    crate::batch::export::archive_retained_side_rows::exported_retained_tuples(vault, table)
}

/// Writes a GPU job that `started_by` started at `now_ms` and whose one chunk runs now at its
/// provider, as the host's step leaves it: dispatched, its resource known, 30 seconds used of a
/// 600-second maximum. It stands for a start through a provider rig, which the archive test does
/// not need. Returns the stored job.
///
/// # Errors
///
/// A job whose stored form gained a field with no serde default (this door then names it); the
/// store's.
#[doc(hidden)]
pub fn put_running_gpu_job(
    vault: &Vault,
    started_by: EntityId,
    now_ms: u64,
) -> crate::Result<GpuJob> {
    put_running_gpu_job_with_inputs(
        vault,
        started_by,
        now_ms,
        serde_json::json!({ "dataset": "owen-notes" }),
    )
}

/// [`put_running_gpu_job`] with `inputs` as its quote's inputs: the JSON its starter gave the
/// quote, stored as given.
///
/// # Errors
///
/// As [`put_running_gpu_job`].
#[doc(hidden)]
pub fn put_running_gpu_job_with_inputs(
    vault: &Vault,
    started_by: EntityId,
    now_ms: u64,
    inputs: serde_json::Value,
) -> crate::Result<GpuJob> {
    const MAXIMUM_SECS: u64 = 600;
    const OVERHEAD_SECS: u64 = 20;
    let id = EntityId::now();
    let key = format!("{}:0", id.to_hex());
    let unit = |name: &str| {
        LeaseUnit::new(name).map_err(|error| Error::InvalidConfig(format!("{error:?}")))
    };
    let maximum = JobMaximum::start(
        id.to_hex(),
        DeclaredMaximum {
            units: MAXIMUM_SECS,
            unit: unit("seconds")?,
        },
        Some(MaximumShown { at_ms: now_ms }),
    )
    .map_err(|error| Error::InvalidConfig(format!("{error:?}")))?;
    let quote = GpuJobQuote {
        job: id,
        offer: "h100-fixture".to_owned(),
        job_type: "fine-tune".to_owned(),
        image: "registry.example.com/trainer@sha256:00".to_owned(),
        inputs,
        maximum_secs: MAXIMUM_SECS,
        overhead_secs: OVERHEAD_SECS,
        quantity: MAXIMUM_SECS + OVERHEAD_SECS,
        unit_cost: 2,
        units: (MAXIMUM_SECS + OVERHEAD_SECS) * 2,
        unit: unit("credit-micros")?,
        catalog_revision: Some("gpu-prices-1".to_owned()),
        price_shape: PriceShape::AtOneironList,
        list_cost: None,
        quoted_at_ms: now_ms,
        valid_until_ms: now_ms + GPU_QUOTE_VALID_MS,
        digest: "0".repeat(64),
    };
    let offer = GpuOfferPin {
        name: quote.offer.clone(),
        class: "h100".to_owned(),
        provider: "fixture-cloud".to_owned(),
        region: "test-1".to_owned(),
        price_shape: PriceShape::AtOneironList,
    };
    let job_type = quote.job_type.clone();
    let image = quote.image.clone();
    let chunk = GpuChunk {
        idempotency_key: key.clone(),
        quote,
        base_used_secs: 0,
        checkpoint_from: None,
        permit: serde_json::Value::Null,
        dispatched: true,
        resource: Some(GpuResourceRef(format!("resource-{key}"))),
        used_secs: 30,
        signalled_percents: Vec::new(),
        newest_checkpoint: None,
        billed_secs: None,
        settled_units: None,
        unbilled_secs: 0,
        admission_lost: false,
    };
    // The job is read from its stored form, not written as a struct literal: a field the job
    // gains with a serde default takes that default here, so a new field breaks no test build.
    let job: GpuJob = serde_json::from_value(serde_json::json!({
        "id": id,
        "started_by": started_by,
        "offer": offer,
        "job_type": job_type,
        "image": image,
        "maximum": maximum,
        "chunks": [chunk],
        "state": GpuJobState::Running,
        "stop": null,
        "resume_quote": null,
        "overrun_reported": false,
        "created_at_ms": now_ms,
        "updated_at_ms": now_ms,
        "revision": 2,
        "orphaned_resources": [],
    }))
    .map_err(|error| Error::InvalidConfig(format!("running GPU job fixture: {error}")))?;
    vault.with_write_txn_grouped(|txn| GPU_JOBS.put(&vault.store, txn, &id, &job))?;
    Ok(job)
}

/// Writes `row` under its Grant, as the owner's `vault.gpu.jobs.allow` writes it, without the
/// allow's check that the Grant admits its agent now.
///
/// # Errors
///
/// The store's.
#[doc(hidden)]
pub fn put_gpu_job_allowance(vault: &Vault, row: &GpuJobAllowance) -> crate::Result<()> {
    vault.with_write_txn_grouped(|txn| GPU_JOB_ALLOWANCES.put(&vault.store, txn, &row.grant, row))
}
