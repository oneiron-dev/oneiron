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
//! ```
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
//! one lock file per offered GPU while it runs, so a second Oneiron server
//! on the machine does not offer the same GPU. Unless named it is one path
//! for the whole machine, `/dev/shm/oneiron-gpu-owners` on Linux (else
//! `/tmp/oneiron-gpu-owners`), which neither TMPDIR nor a private `/tmp`
//! changes. Every server of one machine that names it must name the same
//! directory.
//!
//! ```toml
//! [gpu_jobs.devices]
//! offered = ["GPU-0b3c5f52-6e1d-4a8e-9f0a-2d7c1e4b8a61"]
//! withheld_file = "/var/lib/oneiron/gpu-withheld"
//! drain_after_failures = 3
//! drain_file = "/var/lib/oneiron/gpu-drained"
//! owner_lock_dir = "/run/oneiron/gpu-owners"
//! ```
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use oneiron::ModelLocality;
use oneiron::gpu_job::{GpuOffer, PriceShape};
use oneiron::llm::run_admission::{KeyCustody, LeaseUnit, OfferRoute, PaidConnector, Payer};
use serde::Deserialize;

use crate::gpu_execution_node::{GPU_DRAIN_AFTER_FAILURES, GpuDeviceOffer};

/// The owner lock directory when none is named: one path for every server
/// on the machine, whatever its TMPDIR or a private `/tmp` says (the shipped
/// `oneiron.service` sets `PrivateTmp=true`), so two servers lock the same
/// file for one GPU.
#[must_use]
pub fn default_owner_lock_dir() -> PathBuf {
    if cfg!(target_os = "linux") {
        PathBuf::from("/dev/shm/oneiron-gpu-owners")
    } else if cfg!(unix) {
        PathBuf::from("/tmp/oneiron-gpu-owners")
    } else {
        std::env::temp_dir().join("oneiron-gpu-owners")
    }
}

/// The maximum a job takes when its request names none: one hour.
pub const GPU_JOB_DEFAULT_MAXIMUM_SECS: u64 = 3600;
/// How often the worker steps each live job.
pub const GPU_JOB_STEP_SECS: u64 = 30;
/// The adapter prefix an offer's route names; the backend follows it.
const GPU_BACKEND_ADAPTER: &str = "gpu-backend";

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
    devices: Option<GpuDevicesFile>,
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
    /// C3 A: a GPU class is priced at our list; any other shape refuses.
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
}

/// The GPU offers this host posts, and how its worker steps their jobs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpuJobsSettings {
    /// The maximum a job takes when its request names none.
    pub default_maximum_secs: u64,
    /// How often the worker steps each live job, in seconds.
    pub step_secs: u64,
    pub offers: BTreeMap<String, GpuOfferSettings>,
    /// The GPUs of this machine it offers to the vault's GPU jobs.
    pub devices: GpuDeviceOffer,
}

impl Default for GpuJobsSettings {
    fn default() -> Self {
        Self {
            default_maximum_secs: GPU_JOB_DEFAULT_MAXIMUM_SECS,
            step_secs: GPU_JOB_STEP_SECS,
            offers: BTreeMap::new(),
            devices: GpuDeviceOffer::default(),
        }
    }
}

/// One posted GPU offer and the backend that provisions it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpuOfferSettings {
    /// The backend registry's name for the provisioning connector.
    pub backend: String,
    pub offer: GpuOffer,
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
        Ok(GpuJobsSettings {
            default_maximum_secs,
            step_secs,
            offers,
            devices: self.devices.unwrap_or_default().resolve()?,
        })
    }
}

/// Refuses a GPU `[gpu_jobs.devices]` offers that a managed model worker's
/// launch device names (`[models.workers.<id>].device`), so one GPU has one
/// booker inside Oneiron too.
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
                worker.launch.as_ref()?.device.as_deref()?,
            ))
        }),
    )
}

/// Refuses an offered GPU that one of `workers` (each its id and its
/// `CUDA_VISIBLE_DEVICES` entry) names. CUDA takes a unique prefix of a
/// UUID, and the older MIG form `MIG-GPU-<uuid>/<gi>/<ci>` holds its GPU's
/// id, so an entry names an offered GPU when it is a prefix of the GPU's id
/// or holds it, in any letter case. An index (`0`) names no device id until
/// the driver is read, and CUDA may number the cards otherwise, so while
/// any GPU is offered a worker names its GPU by device id.
///
/// # Errors
///
/// The worker and the GPU that overlap, or the worker that names a GPU by
/// index.
pub fn refuse_worker_device_overlap<'a>(
    offered: &BTreeSet<String>,
    workers: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> anyhow::Result<()> {
    if offered.is_empty() {
        return Ok(());
    }
    for (worker, named) in workers {
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
        Ok(GpuDeviceOffer {
            withheld_file: self.withheld_file,
            drain_after_failures: self
                .drain_after_failures
                .unwrap_or(GPU_DRAIN_AFTER_FAILURES),
            drain_file: self.drain_file,
            owner_lock_dir: self
                .owner_lock_dir
                .or_else(|| (!offered.is_empty()).then(default_owner_lock_dir)),
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
            "{at}.price_shape must be at_oneiron_list: a GPU class takes one posted price whichever provider serves it"
        );
        anyhow::ensure!(
            self.price_per_second > 0,
            "{at}.price_per_second must be greater than zero"
        );
        anyhow::ensure!(
            !self.catalog_revision.trim().is_empty(),
            "{at}.catalog_revision must name the price list the quote freezes"
        );
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
        })
    }
}
