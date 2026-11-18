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
use std::collections::BTreeMap;

use oneiron::ModelLocality;
use oneiron::gpu_job::{GpuOffer, PriceShape};
use oneiron::llm::run_admission::{KeyCustody, LeaseUnit, OfferRoute, PaidConnector, Payer};
use serde::Deserialize;

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
}

impl Default for GpuJobsSettings {
    fn default() -> Self {
        Self {
            default_maximum_secs: GPU_JOB_DEFAULT_MAXIMUM_SECS,
            step_secs: GPU_JOB_STEP_SECS,
            offers: BTreeMap::new(),
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
