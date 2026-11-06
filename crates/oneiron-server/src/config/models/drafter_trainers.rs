//! `[models.training.drafters]`: the trainer connectors that train a vault's
//! own drafter (FIX 14974). There is none by default, and then every night
//! holds with `no_trainer_recipe`.
//!
//! The one transport is a local process on this server's own host, as for
//! the question-head trainer (`[models.training.connectors]`): the pinned
//! interpreter runs `scripts/drafter/worker.py` on a CUDA GPU of this host.
//! Each connector names the recipe families its worker trains, the
//! checkpoints the worker reads (the trainable stock drafter, the target
//! checkpoint its taps come from, the served target's directory) and the
//! serving-format converter, all absolute paths on this host, and the quote
//! a night is admitted under: `unit_cost` of `cost_unit` per GPU wall second.
//!
//! ```toml
//! [models.training.drafters.house-gpu]
//! python = "/opt/oneiron/drafter-venv/bin/python"
//! worker = "/opt/oneiron/checkout/scripts/drafter/worker.py"
//! jobs_root = "/var/lib/oneiron/drafter-jobs"
//! revision = "<commit of that checkout>"
//! unit_cost = 1
//! cost_unit = "gpu_wall_second"
//! service_unit = "gpu_wall_second"
//! recipes = ["drafter.dflash.exl3.v1"]
//! stock_drafter = "/var/lib/oneiron-house/models/<trainable stock drafter>"
//! tap_model = "/var/lib/oneiron-house/models/<target checkpoint>"
//! served_target = "/var/lib/oneiron-house/models/qwen3.8-27b-exl3-4bpw"
//! converter = "/opt/exllamav3/convert.py"
//! ```
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use oneiron::ModelLocality;
use oneiron::llm::run_admission::{KeyCustody, LeaseUnit, OfferRoute, PaidConnector, Payer};
use serde::Deserialize;

use super::training::TRAINING_SERVICE_UNIT;

/// The adapter a drafter trainer connector's route names: the worker process.
const DRAFTER_TRAINER_ADAPTER: &str = "drafter-trainer-worker";
/// The origin it names: this server's own host.
const DRAFTER_TRAINER_ORIGIN: &str = "host";

/// `[models.training.drafters.<name>]` as written.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DrafterTrainerFile {
    python: PathBuf,
    worker: PathBuf,
    jobs_root: PathBuf,
    revision: String,
    unit_cost: u64,
    cost_unit: String,
    service_unit: String,
    recipes: BTreeSet<String>,
    stock_drafter: PathBuf,
    tap_model: PathBuf,
    served_target: PathBuf,
    converter: PathBuf,
}

/// One drafter trainer connector: the process it runs, what that process
/// reads, and the paid connector its jobs are admitted and dispatched as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrafterTrainerSettings {
    /// The pinned interpreter, an absolute path; it runs isolated (`-I`).
    pub python: PathBuf,
    /// `scripts/drafter/worker.py`, an absolute path.
    pub worker: PathBuf,
    /// Where each job's private directory is made, an absolute path.
    pub jobs_root: PathBuf,
    /// The recipe families (`DrafterRecipe::id`) its worker trains.
    pub recipes: BTreeSet<String>,
    /// The trainable stock drafter a version continued from stock trains
    /// from: its HF `config.json` and safetensors.
    pub stock_drafter: PathBuf,
    /// The target checkpoint the worker reads the target's taps from.
    pub tap_model: PathBuf,
    /// The served target's directory: its tokenizer, which must be the
    /// drafter target's tokenizer pin, and its chat template.
    pub served_target: PathBuf,
    /// The serving-format converter the worker runs on the trained drafter.
    pub converter: PathBuf,
    /// Its route, locality, payer, custody and quote: keyless, on this
    /// host, paid by no one per call, at its revision.
    pub binding: PaidConnector,
}

pub(super) fn resolve(
    files: BTreeMap<String, DrafterTrainerFile>,
) -> anyhow::Result<BTreeMap<String, DrafterTrainerSettings>> {
    files
        .into_iter()
        .map(|(name, file)| Ok((name.clone(), file.resolve(&name)?)))
        .collect()
}

impl DrafterTrainerFile {
    fn resolve(self, name: &str) -> anyhow::Result<DrafterTrainerSettings> {
        let at = format!("models.training.drafters.{name}");
        anyhow::ensure!(
            !name.is_empty() && !name.chars().any(|c| c.is_whitespace() || c.is_control()),
            "{at}: a connector name has no whitespace or control characters"
        );
        for (field, path) in [
            ("python", &self.python),
            ("worker", &self.worker),
            ("jobs_root", &self.jobs_root),
            ("stock_drafter", &self.stock_drafter),
            ("tap_model", &self.tap_model),
            ("served_target", &self.served_target),
            ("converter", &self.converter),
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
            "{at}.recipes must name at least one recipe family"
        );
        let cost_unit = LeaseUnit::new(self.cost_unit)
            .map_err(|error| anyhow::anyhow!("{at}.cost_unit: {error}"))?;
        let route = OfferRoute::new(DRAFTER_TRAINER_ADAPTER, DRAFTER_TRAINER_ORIGIN)
            .map_err(|error| anyhow::anyhow!("{at}: {error}"))?;
        Ok(DrafterTrainerSettings {
            python: self.python,
            worker: self.worker,
            jobs_root: self.jobs_root,
            recipes: self.recipes,
            stock_drafter: self.stock_drafter,
            tap_model: self.tap_model,
            served_target: self.served_target,
            converter: self.converter,
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
