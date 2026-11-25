//! `[gpu_jobs]`: the GPU offers this host posts for customer GPU jobs
//! (CROSS-ARCH-0023 lifecycle, C2, C3). There is none by default, and then
//! every quote refuses as naming no offer.
//!
//! Each offer is one GPU class at a provider and region, at our posted price
//! per second of the class (C3 A: one price per class, `at_oneiron_list`),
//! and names the backend that provisions it. A backend only provisions (C6
//! 02): the server's backend registry maps the name to a connector, and an
//! offer whose backend nothing registers refuses at start, before any
//! reservation. The host pays the provider, so a job is admitted against the
//! vault's allocation (FRAUD-1: paid credits only).
//!
//! ```toml
//! [gpu_jobs]
//! default_maximum_secs = 3600
//! step_secs = 30
//!
//! [gpu_jobs.offers.h100-us-east]
//! class = "h100"
//! provider = "example-cloud"
//! region = "us-east"
//! backend = "skypilot"
//! price_per_second = 2
//! cost_unit = "credit-micros"
//! catalog_revision = "gpu-prices-2026-11"
//! startup_secs = 60
//! teardown_secs = 30
//! rounding_secs = 60
//!
//! [gpu_jobs.vault_machine]
//! enabled = true
//! issuer = "<this install's MACHINE id, 32 hex>"
//!
//! [gpu_jobs.offers.own-a6000]
//! backend = "vault_machine"
//! at_maximum = "stop"
//! # class, provider, region, price and seconds as above
//! ```
//!
//! `[gpu_jobs.vault_machine]` sets up the `vault_machine` backend, which runs a pinned workload
//! on one of the vault's own machines (pass 33 section 8). It registers only on the install whose
//! MACHINE is the `issuer`, never on a managed server; `paused` stops new dispatches and cancels
//! nothing. The windows are settings with the design's values as defaults.
//!
//! An offer's `at_maximum` says what follows the cutoff at the job's maximum (pass 34, 9.2; the
//! cutoff itself is invariant I5). A `vault_machine` offer states `"stop"`: its node ends the run
//! at the maximum, with or without a checkpoint (pass 33, 8.6). An offer that leaves it out
//! follows C2 at the maximum (warning, checkpoint first, resume), which is what a customer buys.
//!
//! `[gpu_jobs.devices]` names the GPUs of this machine that it offers to the
//! vault's GPU jobs, by the driver's device id (`nvidia-smi -L` shows each
//! UUID). There is none by default, so a machine offers no GPU until its
//! owner lists one. `withheld_file` names a file of the GPUs another booker
//! holds now, one device id per line, read at every ask: such a GPU is never
//! offered, and once the file is named, a file that cannot be read offers
//! nothing. Once `drain_after_failures` jobs in a row (3 by default; 0
//! never) finish failed, the machine takes no new GPU job until a person
//! clears the drain. `drain_file` keeps the drain across a restart, and
//! deleting it clears the drain. `owner_lock_dir` is where the server takes
//! one lock file per offered GPU while it runs, and where a launched job's
//! record keeps its GPU past a restart of its server, so no other Oneiron
//! server on the machine offers that GPU. A machine that offers a GPU names
//! it, and the directory must already exist. It is one directory of the
//! host, named by every server that sees these GPUs; a server in a container
//! names a bind mount of that host directory, since a container's own
//! `/dev/shm` or `/tmp` is not the host's.
//!
//! While a GPU is offered, every managed model worker names its CUDA device
//! (`[models.workers.<id>].device`) by device id, and never an offered one:
//! a worker with no device would see every GPU. A worker that runs on no
//! GPU names `"-1"`.
//!
//! `[gpu_jobs.host_allocation]` funds this server's host account, which every offer's job reserves
//! on, from the owner's own config (R6-VAULT-MACHINE-FUNDING = A). With no supervisor to deliver
//! an allocation, a self-hosted server's account starts empty and every start answers that the
//! host has delivered none. At each start the server grants the account `units` of `unit`, which
//! must be the `cost_unit` of one of the offers above, as the walletless allocation `id`. The
//! account lives in memory until the durable allocation ledger is wired, so every start begins
//! with the full `units` again: one process, one budget. A managed server refuses the section at
//! start: its supervisor funds its account.
//!
//! ```toml
//! [gpu_jobs.host_allocation]
//! id = "own-gpu"
//! units = 3600
//! unit = "credit-micros"
//! ```
//!
//! ```toml
//! [gpu_jobs.devices]
//! offered = ["GPU-0b3c5f52-6e1d-4a8e-9f0a-2d7c1e4b8a61"]
//! withheld_file = "/var/lib/oneiron/gpu-withheld"
//! drain_after_failures = 3
//! drain_file = "/var/lib/oneiron/gpu-drained"
//! owner_lock_dir = "/run/oneiron/gpu-owners"
//! ```
//!
//! A CPU class is an offer like any other (pass 32 row M3-D; pass 34 9.2):
//! its `cost_unit` is the CPU unit the host grants an allocation in, and its
//! jobs claim no device. Nothing here or in the engine lists units or
//! classes. A job holds only on an allocation in its offer's `cost_unit`, so a
//! `cpu_seconds` allocation beside a `gpu_seconds` one on the same account
//! funds CPU jobs alone. An offer carries no rates, so no CPU second ever
//! converts into a GPU second or into money.
//!
//! ```toml
//! [gpu_jobs.offers.cpu-16-us-east]
//! class = "cpu-16"
//! provider = "example-cloud"
//! region = "us-east"
//! backend = "skypilot"
//! price_per_second = 1
//! cost_unit = "cpu_seconds"
//! catalog_revision = "cpu-prices-2026-11"
//! startup_secs = 30
//! teardown_secs = 10
//! rounding_secs = 60
//! ```
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use oneiron::gpu_job::{GpuOffer, PriceShape};
use oneiron::llm::run_admission::{
    AllocationRef, KeyCustody, LeaseUnit, OfferRoute, PaidConnector, Payer, is_gpu_line_allocation,
};
use oneiron::{EntityId, ModelLocality};
use serde::{Deserialize, Serialize};

use crate::gpu_execution_node::issuer::VAULT_MACHINE_BACKEND;
use crate::gpu_execution_node::{GPU_DRAIN_AFTER_FAILURES, GpuDeviceOffer};

/// The maximum a job takes when its request names none: one hour.
pub const GPU_JOB_DEFAULT_MAXIMUM_SECS: u64 = 3600;
/// How often the worker steps each live job.
pub const GPU_JOB_STEP_SECS: u64 = 30;
/// The adapter prefix an offer's route names; the backend follows it.
const GPU_BACKEND_ADAPTER: &str = "gpu-backend";
/// How long after it is signed a vault machine job's reserve and submit may still be sent: its
/// `not_after` (pass 33, 5.1).
pub const VAULT_MACHINE_SUBMIT_WINDOW_SECS: u64 = 300;
/// How far ahead the live recheck before a dispatch looks: nothing it reads may end sooner. The
/// submit window plus the node's staging limit (pass 33, 8.2 step 2).
pub const VAULT_MACHINE_RECHECK_HORIZON_SECS: u64 = 900;
/// How long one job protocol call to a node may take, the dial included.
pub const VAULT_MACHINE_CALL_TIMEOUT_SECS: u64 = 10;
/// The generation of a `[gpu_jobs.host_allocation]` grant: each start's host account is fresh and
/// holds it once.
pub const HOST_ALLOCATION_GENERATION: u64 = 1;

/// `[gpu_jobs]` as written.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GpuJobsFile {
    #[serde(default)]
    default_maximum_secs: Option<u64>,
    #[serde(default)]
    step_secs: Option<u64>,
    #[serde(default)]
    offers: BTreeMap<String, GpuOfferFile>,
    #[serde(default)]
    vault_machine: VaultMachineFile,
    #[serde(default)]
    devices: Option<GpuDevicesFile>,
    #[serde(default)]
    host_allocation: Option<HostAllocationFile>,
}

/// `[gpu_jobs.host_allocation]` as written.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostAllocationFile {
    id: String,
    units: u64,
    unit: String,
}

/// `[gpu_jobs.vault_machine]` as written.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultMachineFile {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    paused: bool,
    /// The MACHINE id, in hex, of the one install that issues vault machine jobs.
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    submit_window_secs: Option<u64>,
    #[serde(default)]
    recheck_horizon_secs: Option<u64>,
    #[serde(default)]
    call_timeout_secs: Option<u64>,
}

/// `[gpu_jobs.devices]` as written.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct GpuDevicesFile {
    #[serde(default)]
    offered: Vec<String>,
    #[serde(default)]
    withheld_file: Option<PathBuf>,
    #[serde(default)]
    drain_after_failures: Option<u32>,
    #[serde(default)]
    drain_file: Option<PathBuf>,
    #[serde(default)]
    owner_lock_dir: Option<PathBuf>,
}

/// `[gpu_jobs.offers.<name>]` as written.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct GpuOfferFile {
    class: String,
    provider: String,
    region: String,
    backend: String,
    /// C3 A: an offer's class is priced at our list; any other shape refuses.
    #[serde(default)]
    price_shape: Option<PriceShape>,
    price_per_second: u64,
    cost_unit: String,
    catalog_revision: String,
    #[serde(default)]
    list_cost_per_second: Option<u64>,
    startup_secs: u64,
    teardown_secs: u64,
    rounding_secs: u64,
    #[serde(default)]
    at_maximum: Option<AtMaximum>,
}

/// What follows the cutoff at a job's maximum, as an offer states it (pass 34, 9.2). Row W1 adds
/// `renew`, a paid next chunk for a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtMaximum {
    /// The run ends at the maximum, with or without a checkpoint; its end reason says the
    /// maximum was reached (pass 33, 8.6).
    Stop,
}

/// The GPU offers this host posts, and how its worker steps their jobs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpuJobsSettings {
    /// The maximum a job takes when its request names none.
    pub default_maximum_secs: u64,
    /// How often the worker steps each live job, in seconds.
    pub step_secs: u64,
    pub offers: BTreeMap<String, GpuOfferSettings>,
    pub vault_machine: VaultMachineSettings,
    /// The GPUs of this machine it offers to the vault's GPU jobs.
    pub devices: GpuDeviceOffer,
    /// The allocation a self-hosted server grants its own host account at start; `None`, the
    /// default, grants none.
    pub host_allocation: Option<HostAllocationSettings>,
}

/// The one allocation `[gpu_jobs.host_allocation]` names (R6-VAULT-MACHINE-FUNDING = A): granted
/// to the host account at each start, walletless.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostAllocationSettings {
    /// The allocation's id, at [`HOST_ALLOCATION_GENERATION`].
    pub reference: AllocationRef,
    /// Units granted to this server's host account at each start; the account lives in memory
    /// until the durable allocation ledger is wired.
    pub units: u64,
    /// One offer's `cost_unit`: a job holds only on an allocation in its offer's unit.
    pub unit: LeaseUnit,
}

impl Default for GpuJobsSettings {
    fn default() -> Self {
        Self {
            default_maximum_secs: GPU_JOB_DEFAULT_MAXIMUM_SECS,
            step_secs: GPU_JOB_STEP_SECS,
            offers: BTreeMap::new(),
            vault_machine: VaultMachineSettings::default(),
            devices: GpuDeviceOffer::default(),
            host_allocation: None,
        }
    }
}

/// The `vault_machine` backend's settings (pass 33 section 8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultMachineSettings {
    /// Whether this install registers the backend. Off by default.
    pub enabled: bool,
    /// No new dispatch while set; every admitted job runs on and is stepped (pass 33, 7.9).
    pub paused: bool,
    /// The one install that issues vault machine jobs (R5-ISSUER-IDENTITY = A). A start on any
    /// other install answers `not_the_issuer`.
    pub issuer: Option<EntityId>,
    /// How long after signing a reserve or submit may still be sent.
    pub submit_window_secs: u64,
    /// How far ahead the live recheck before a dispatch looks.
    pub recheck_horizon_secs: u64,
    /// How long one job protocol call to a node may take.
    pub call_timeout_secs: u64,
}

impl Default for VaultMachineSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            paused: false,
            issuer: None,
            submit_window_secs: VAULT_MACHINE_SUBMIT_WINDOW_SECS,
            recheck_horizon_secs: VAULT_MACHINE_RECHECK_HORIZON_SECS,
            call_timeout_secs: VAULT_MACHINE_CALL_TIMEOUT_SECS,
        }
    }
}

impl VaultMachineFile {
    fn resolve(self) -> anyhow::Result<VaultMachineSettings> {
        let issuer = self
            .issuer
            .map(|hex| {
                EntityId::from_hex(hex.trim()).map_err(|_| {
                    anyhow::anyhow!("gpu_jobs.vault_machine.issuer must be a MACHINE id in hex")
                })
            })
            .transpose()?;
        let submit_window_secs = self
            .submit_window_secs
            .unwrap_or(VAULT_MACHINE_SUBMIT_WINDOW_SECS);
        let recheck_horizon_secs = self
            .recheck_horizon_secs
            .unwrap_or(VAULT_MACHINE_RECHECK_HORIZON_SECS);
        let call_timeout_secs = self
            .call_timeout_secs
            .unwrap_or(VAULT_MACHINE_CALL_TIMEOUT_SECS);
        anyhow::ensure!(
            submit_window_secs > 0 && call_timeout_secs > 0,
            "gpu_jobs.vault_machine.submit_window_secs and call_timeout_secs must be greater than zero"
        );
        anyhow::ensure!(
            recheck_horizon_secs >= submit_window_secs,
            "gpu_jobs.vault_machine.recheck_horizon_secs must cover the submit window"
        );
        anyhow::ensure!(
            !self.enabled || issuer.is_some(),
            "gpu_jobs.vault_machine.enabled needs the issuer's MACHINE id"
        );
        Ok(VaultMachineSettings {
            enabled: self.enabled,
            paused: self.paused,
            issuer,
            submit_window_secs,
            recheck_horizon_secs,
            call_timeout_secs,
        })
    }
}

/// One posted GPU offer and the backend that provisions it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpuOfferSettings {
    /// The backend registry's name for the provisioning connector.
    pub backend: String,
    pub offer: GpuOffer,
    /// What follows the cutoff at the maximum; `None` follows C2 (a checkpoint first).
    pub at_maximum: Option<AtMaximum>,
}

impl GpuJobsSettings {
    /// The offer named `name`, if this host posts one.
    #[must_use]
    pub fn offer(&self, name: &str) -> Option<&GpuOfferSettings> {
        self.offers.get(name)
    }
}

/// A config name: not empty, no whitespace or control characters.
fn plain_name(name: &str) -> bool {
    !name.is_empty() && !name.chars().any(|c| c.is_whitespace() || c.is_control())
}

impl GpuJobsFile {
    pub(crate) fn resolve(self) -> anyhow::Result<GpuJobsSettings> {
        let default_maximum_secs = self
            .default_maximum_secs
            .unwrap_or(GPU_JOB_DEFAULT_MAXIMUM_SECS);
        anyhow::ensure!(
            default_maximum_secs > 0,
            "gpu_jobs.default_maximum_secs must be greater than zero: a job runs only under a maximum"
        );
        let step_secs = self.step_secs.unwrap_or(GPU_JOB_STEP_SECS);
        anyhow::ensure!(
            step_secs > 0,
            "gpu_jobs.step_secs must be greater than zero"
        );
        let offers = self
            .offers
            .into_iter()
            .map(|(name, file)| Ok((name.clone(), file.resolve(&name)?)))
            .collect::<anyhow::Result<_>>()?;
        let host_allocation = self
            .host_allocation
            .map(|file| file.resolve(&offers))
            .transpose()?;
        Ok(GpuJobsSettings {
            default_maximum_secs,
            step_secs,
            offers,
            vault_machine: self.vault_machine.resolve()?,
            devices: self.devices.unwrap_or_default().resolve()?,
            host_allocation,
        })
    }
}

impl HostAllocationFile {
    fn resolve(
        self,
        offers: &BTreeMap<String, GpuOfferSettings>,
    ) -> anyhow::Result<HostAllocationSettings> {
        anyhow::ensure!(
            plain_name(&self.id),
            "gpu_jobs.host_allocation.id must be a plain name: not empty, no whitespace"
        );
        let reference = AllocationRef {
            id: self.id,
            generation: HOST_ALLOCATION_GENERATION,
        };
        anyhow::ensure!(
            !is_gpu_line_allocation(&reference),
            "gpu_jobs.host_allocation.id names a GPU line's allocation, which only its claims draw on"
        );
        anyhow::ensure!(
            self.units > 0,
            "gpu_jobs.host_allocation.units must be greater than zero"
        );
        let unit = LeaseUnit::new(self.unit)
            .map_err(|error| anyhow::anyhow!("gpu_jobs.host_allocation.unit: {error}"))?;
        anyhow::ensure!(
            offers
                .values()
                .any(|offer| offer.offer.connector.cost_unit == unit),
            "gpu_jobs.host_allocation.unit must be the cost_unit of a [gpu_jobs.offers] offer"
        );
        Ok(HostAllocationSettings {
            reference,
            units: self.units,
            unit,
        })
    }
}

/// Refuses a GPU `[gpu_jobs.devices]` offers that a managed model worker's
/// launch device names (`[models.workers.<id>].device`), or could use
/// because it names none, so one GPU has one booker inside Oneiron too. A
/// worker this server does not launch takes no GPU from it.
pub(crate) fn refuse_offered_worker_devices(
    devices: &GpuDeviceOffer,
    models: Option<&super::ModelsConfig>,
) -> anyhow::Result<()> {
    let Some(models) = models else {
        return Ok(());
    };
    refuse_worker_device_overlap(
        &devices.offered,
        models.workers.iter().filter_map(|worker| {
            Some((
                worker.id.as_str(),
                worker.launch.as_ref()?.device.as_deref(),
            ))
        }),
    )
}

/// Refuses an offered GPU that one of `workers` (each its id and its
/// `CUDA_VISIBLE_DEVICES` entry, `None` when it names none) names or could
/// use. A worker that names no device sees every GPU, so while any GPU is
/// offered each worker names its own. CUDA takes a unique prefix of a UUID,
/// and the older MIG form `MIG-GPU-<uuid>/<gi>/<ci>` holds its GPU's id, so
/// an entry names an offered GPU when it is a prefix of the GPU's id or
/// holds it, in any letter case. An index (`0`) names no device id until
/// the driver is read, and CUDA may number the cards otherwise, so while
/// any GPU is offered a worker names its GPU by device id. `-1` names no
/// GPU.
///
/// # Errors
///
/// The worker and the GPU that overlap, the worker that names no device,
/// or the worker that names a GPU by index.
pub fn refuse_worker_device_overlap<'a>(
    offered: &BTreeSet<String>,
    workers: impl IntoIterator<Item = (&'a str, Option<&'a str>)>,
) -> anyhow::Result<()> {
    if offered.is_empty() {
        return Ok(());
    }
    for (worker, named) in workers {
        let Some(named) = named else {
            anyhow::bail!(
                "the model worker {worker} names no device while gpu_jobs.devices offers GPUs, so it would see every GPU, offered ones too: name its GPU by device id (nvidia-smi -L), or \"-1\" for none"
            );
        };
        for entry in named
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            let lower = entry.to_ascii_lowercase();
            if let Some(gpu) = offered.iter().find(|gpu| {
                let gpu = gpu.to_ascii_lowercase();
                gpu.starts_with(&lower) || lower.contains(&gpu)
            }) {
                anyhow::bail!(
                    "gpu_jobs.devices.offered names GPU {gpu}, which the model worker {worker} runs on ({entry}): a GPU has one booker"
                );
            }
            anyhow::ensure!(
                !entry.chars().all(|c| c.is_ascii_digit()),
                "the model worker {worker} names its GPU by index ({entry}) while gpu_jobs.devices offers GPUs: name it by device id (nvidia-smi -L), so no offered GPU is one it runs on"
            );
        }
    }
    Ok(())
}

impl GpuDevicesFile {
    fn resolve(self) -> anyhow::Result<GpuDeviceOffer> {
        let mut offered = BTreeSet::new();
        for device in self.offered {
            anyhow::ensure!(
                plain_name(&device),
                "gpu_jobs.devices.offered: {device:?} is not a device id (it has whitespace or control characters, or is empty)"
            );
            anyhow::ensure!(
                offered.insert(device.clone()),
                "gpu_jobs.devices.offered names {device} twice"
            );
        }
        for (field, file) in [
            ("withheld_file", &self.withheld_file),
            ("drain_file", &self.drain_file),
            ("owner_lock_dir", &self.owner_lock_dir),
        ] {
            if let Some(file) = file {
                anyhow::ensure!(
                    file.is_absolute(),
                    "gpu_jobs.devices.{field} must be an absolute path: {}",
                    file.display()
                );
            }
        }
        // A drain written nowhere would be cleared by the next restart.
        if let Some(file) = &self.drain_file {
            anyhow::ensure!(
                file.parent().is_some_and(std::path::Path::is_dir),
                "gpu_jobs.devices.drain_file's directory must exist, or a drain would not outlast a restart: {}",
                file.display()
            );
        }
        // No default: only the owner knows which directory every server that
        // sees these GPUs shares (a container's /dev/shm is its own).
        if !offered.is_empty() {
            let Some(dir) = &self.owner_lock_dir else {
                anyhow::bail!(
                    "gpu_jobs.devices.owner_lock_dir must be named while GPUs are offered: one host directory that every Oneiron server seeing these GPUs names (in a container, a bind mount of it), so one server owns each GPU"
                );
            };
            anyhow::ensure!(
                dir.is_dir(),
                "gpu_jobs.devices.owner_lock_dir must be an existing directory, the one every server seeing these GPUs shares: {}",
                dir.display()
            );
        }
        Ok(GpuDeviceOffer {
            withheld_file: self.withheld_file,
            drain_after_failures: self
                .drain_after_failures
                .unwrap_or(GPU_DRAIN_AFTER_FAILURES),
            drain_file: self.drain_file,
            owner_lock_dir: self.owner_lock_dir,
            offered,
        })
    }
}

impl GpuOfferFile {
    fn resolve(self, name: &str) -> anyhow::Result<GpuOfferSettings> {
        let at = format!("gpu_jobs.offers.{name}");
        anyhow::ensure!(
            plain_name(name),
            "{at}: an offer name has no whitespace or control characters"
        );
        for (field, value) in [
            ("class", &self.class),
            ("provider", &self.provider),
            ("region", &self.region),
            ("backend", &self.backend),
        ] {
            anyhow::ensure!(
                plain_name(value),
                "{at}.{field} must be a name with no whitespace or control characters"
            );
        }
        let price_shape = self.price_shape.unwrap_or(PriceShape::AtOneironList);
        anyhow::ensure!(
            price_shape == PriceShape::AtOneironList,
            "{at}.price_shape must be at_oneiron_list: an offer's class takes one posted price whichever provider serves it"
        );
        anyhow::ensure!(
            self.price_per_second > 0,
            "{at}.price_per_second must be greater than zero"
        );
        anyhow::ensure!(
            !self.catalog_revision.trim().is_empty(),
            "{at}.catalog_revision must name the price list the quote freezes"
        );
        if self.backend == VAULT_MACHINE_BACKEND {
            anyhow::ensure!(
                self.at_maximum == Some(AtMaximum::Stop),
                "{at}.at_maximum must be \"stop\" for the {VAULT_MACHINE_BACKEND} backend: its node ends the run at the maximum"
            );
        } else {
            anyhow::ensure!(
                self.at_maximum.is_none(),
                "{at}.at_maximum is for the {VAULT_MACHINE_BACKEND} backend only: a provisioned offer follows C2 at the maximum"
            );
        }
        let cost_unit = LeaseUnit::new(self.cost_unit)
            .map_err(|error| anyhow::anyhow!("{at}.cost_unit: {error}"))?;
        let route = OfferRoute::new(
            format!("{GPU_BACKEND_ADAPTER}.{}", self.backend),
            self.provider.clone(),
        )
        .map_err(|error| anyhow::anyhow!("{at}: {error}"))?;
        let offer = GpuOffer {
            name: name.to_owned(),
            class: self.class,
            provider: self.provider,
            region: self.region,
            connector: PaidConnector {
                connector: name.to_owned(),
                route,
                locality: ModelLocality::ThirdParty,
                payer: Payer::Host,
                // The backend's name; a job records it as the backend it keeps
                // (`GpuOffer::backend`, design pass 33, 8.1).
                credential_binding: Some(self.backend.clone()),
                catalog_revision: Some(self.catalog_revision),
                custody: KeyCustody::T0,
                unit_cost: self.price_per_second,
                cost_unit,
                rates: Vec::new(),
            },
            price_shape,
            list_cost_per_second: self.list_cost_per_second,
            startup_secs: self.startup_secs,
            teardown_secs: self.teardown_secs,
            rounding_secs: self.rounding_secs,
        };
        Ok(GpuOfferSettings {
            backend: self.backend,
            offer,
            at_maximum: self.at_maximum,
        })
    }
}
