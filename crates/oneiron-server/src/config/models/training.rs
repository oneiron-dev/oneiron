//! `[models.training]`: the trainer connectors this host dispatches an
//! owner-authorized training run through (FIX 7263). There is none by
//! default, and then every authorized run holds as having no trainer.
//!
//! The one transport is a local process on this server's own host: the
//! pinned interpreter runs `scripts/training_pack/worker.py`, which trains a
//! question head on a CUDA GPU of this host. Each connector names its
//! interpreter, its worker and the private directory its jobs live in, and
//! the quote a run is admitted under: `unit_cost` of `cost_unit` per GPU wall
//! second, the unit the worker reports.
//!
//! ```toml
//! [models.training.connectors.gpu-box]
//! python = "/opt/oneiron/training-venv/bin/python"
//! worker = "/opt/oneiron/checkout/scripts/training_pack/worker.py"
//! jobs_root = "/var/lib/oneiron/training-jobs"
//! revision = "<commit of that checkout>"
//! unit_cost = 1
//! cost_unit = "gpu_wall_second"
//! service_unit = "gpu_wall_second"
//! ```
use std::collections::BTreeMap;
use std::path::PathBuf;

use oneiron::ModelLocality;
use oneiron::llm::run_admission::{KeyCustody, LeaseUnit, OfferRoute, PaidConnector, Payer};
use serde::Deserialize;

/// The one service unit a trainer's quote is per: the GPU wall seconds the
/// worker measures from loading its encoder to its export comparison.
pub const TRAINING_SERVICE_UNIT: &str = "gpu_wall_second";
/// The adapter a trainer connector's route names: the worker process.
const TRAINER_ADAPTER: &str = "training-pack-worker";
/// The origin it names: this server's own host.
const TRAINER_ORIGIN: &str = "host";

/// `[models.training]` as written.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrainingFile {
    #[serde(default)]
    connectors: BTreeMap<String, ConnectorFile>,
}

/// `[models.training.connectors.<name>]` as written.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectorFile {
    python: PathBuf,
    worker: PathBuf,
    jobs_root: PathBuf,
    revision: String,
    unit_cost: u64,
    cost_unit: String,
    service_unit: String,
}

/// The trainer connectors this host names, by connector name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrainingSettings {
    pub connectors: BTreeMap<String, TrainingConnectorSettings>,
}

/// One trainer connector: the process it runs and the paid connector its
/// runs are admitted and dispatched as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrainingConnectorSettings {
    /// The pinned interpreter, an absolute path; it runs isolated (`-I`).
    pub python: PathBuf,
    /// `worker.py`, an absolute path.
    pub worker: PathBuf,
    /// Where each run's private job directory is made, an absolute path.
    pub jobs_root: PathBuf,
    /// Its route, locality, payer, custody and quote: keyless, on this
    /// host, paid by no one per call, at `revision`.
    pub binding: PaidConnector,
}

impl TrainingSettings {
    /// The trainer connector named `name`, if this host names one.
    #[must_use]
    pub fn connector(&self, name: &str) -> Option<&TrainingConnectorSettings> {
        self.connectors.get(name)
    }
}

impl TrainingFile {
    pub(super) fn resolve(self) -> anyhow::Result<TrainingSettings> {
        let connectors = self
            .connectors
            .into_iter()
            .map(|(name, file)| Ok((name.clone(), file.resolve(&name)?)))
            .collect::<anyhow::Result<_>>()?;
        Ok(TrainingSettings { connectors })
    }
}

impl ConnectorFile {
    fn resolve(self, name: &str) -> anyhow::Result<TrainingConnectorSettings> {
        let at = format!("models.training.connectors.{name}");
        anyhow::ensure!(
            !name.is_empty() && !name.chars().any(|c| c.is_whitespace() || c.is_control()),
            "{at}: a connector name has no whitespace or control characters"
        );
        for (field, path) in [
            ("python", &self.python),
            ("worker", &self.worker),
            ("jobs_root", &self.jobs_root),
        ] {
            anyhow::ensure!(path.is_absolute(), "{at}.{field} must be an absolute path");
        }
        anyhow::ensure!(
            !self.revision.trim().is_empty()
                && !matches!(
                    self.revision.as_str(),
                    "main" | "master" | "latest" | "HEAD"
                ),
            "{at}.revision must name an immutable revision of the worker"
        );
        anyhow::ensure!(
            self.service_unit == TRAINING_SERVICE_UNIT,
            "{at}.service_unit must be {TRAINING_SERVICE_UNIT}: the worker reports GPU wall seconds"
        );
        anyhow::ensure!(
            self.unit_cost > 0,
            "{at}.unit_cost must be greater than zero"
        );
        let cost_unit = LeaseUnit::new(self.cost_unit)
            .map_err(|error| anyhow::anyhow!("{at}.cost_unit: {error}"))?;
        let route = OfferRoute::new(TRAINER_ADAPTER, TRAINER_ORIGIN)
            .map_err(|error| anyhow::anyhow!("{at}: {error}"))?;
        Ok(TrainingConnectorSettings {
            python: self.python,
            worker: self.worker,
            jobs_root: self.jobs_root,
            binding: PaidConnector {
                connector: name.to_owned(),
                route,
                locality: ModelLocality::OwnServer,
                payer: Payer::Local,
                credential_binding: None,
                catalog_revision: Some(self.revision),
                custody: KeyCustody::Keyless,
                unit_cost: self.unit_cost,
                cost_unit,
                rates: Vec::new(),
            },
        })
    }
}
