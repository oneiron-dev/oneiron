//! `[models.training.role_trainers]`: the trainer connectors that train a
//! model for one manifest role on the owner's consented corpus
//! (ROLE-TRAINING-RUN, LEARN-TRAIN Q2). There is none by default, and then
//! an authorized role run holds with `training.no_connector`.
//!
//! The one transport is a local process on this server's own host, as for
//! the question-head trainer (`[models.training.connectors]`): the pinned
//! interpreter runs the connector's worker on the role job wire
//! (`oneiron.training-pack.role-job/1`, `scripts/training_pack/README.md`).
//! Each connector names the role recipes its worker trains, its interpreter,
//! its worker and the private directory its jobs live in, all absolute paths
//! on this host, and the quote a run is admitted under: `unit_cost` of
//! `cost_unit` per GPU wall second, the unit the worker reports.
//!
//! ```toml
//! [models.training.role_trainers.house-gpu]
//! python = "/opt/oneiron/role-training-venv/bin/python"
//! worker = "/opt/oneiron/role-trainer/worker.py"
//! jobs_root = "/var/lib/oneiron/role-training-jobs"
//! revision = "<commit of that worker>"
//! unit_cost = 1
//! cost_unit = "gpu_wall_second"
//! service_unit = "gpu_wall_second"
//! recipes = ["<the recipe a role plan's settings.recipe names>"]
//! ```
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use oneiron::ModelLocality;
use oneiron::llm::run_admission::{KeyCustody, LeaseUnit, OfferRoute, PaidConnector, Payer};
use serde::Deserialize;

use super::training::TRAINING_SERVICE_UNIT;

/// The adapter a role trainer connector's route names: the worker process.
const ROLE_TRAINER_ADAPTER: &str = "role-trainer-worker";
/// The origin it names: this server's own host.
const ROLE_TRAINER_ORIGIN: &str = "host";

/// `[models.training.role_trainers.<name>]` as written.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RoleTrainerFile {
    python: PathBuf,
    worker: PathBuf,
    jobs_root: PathBuf,
    revision: String,
    unit_cost: u64,
    cost_unit: String,
    service_unit: String,
    recipes: BTreeSet<String>,
}

/// One role trainer connector: the process it runs, the role recipes that
/// process trains, and the paid connector its runs are admitted and
/// dispatched as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleTrainerSettings {
    /// The pinned interpreter, an absolute path; it runs isolated (`-I`).
    pub python: PathBuf,
    /// The worker script, an absolute path.
    pub worker: PathBuf,
    /// Where each run's private job directory is made, an absolute path.
    pub jobs_root: PathBuf,
    /// The recipes (a role plan's `settings.recipe`) its worker trains.
    pub recipes: BTreeSet<String>,
    /// Its route, locality, payer, custody and quote: keyless, on this
    /// host, paid by no one per call, at its revision.
    pub binding: PaidConnector,
}

pub(super) fn resolve(
    files: BTreeMap<String, RoleTrainerFile>,
) -> anyhow::Result<BTreeMap<String, RoleTrainerSettings>> {
    files
        .into_iter()
        .map(|(name, file)| Ok((name.clone(), file.resolve(&name)?)))
        .collect()
}

impl RoleTrainerFile {
    fn resolve(self, name: &str) -> anyhow::Result<RoleTrainerSettings> {
        let at = format!("models.training.role_trainers.{name}");
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
        anyhow::ensure!(
            !self.recipes.is_empty() && self.recipes.iter().all(|id| !id.trim().is_empty()),
            "{at}.recipes must name at least one role recipe"
        );
        let cost_unit = LeaseUnit::new(self.cost_unit)
            .map_err(|error| anyhow::anyhow!("{at}.cost_unit: {error}"))?;
        let route = OfferRoute::new(ROLE_TRAINER_ADAPTER, ROLE_TRAINER_ORIGIN)
            .map_err(|error| anyhow::anyhow!("{at}: {error}"))?;
        Ok(RoleTrainerSettings {
            python: self.python,
            worker: self.worker,
            jobs_root: self.jobs_root,
            recipes: self.recipes,
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
