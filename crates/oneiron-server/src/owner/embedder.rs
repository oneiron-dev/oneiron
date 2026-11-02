//! The embedder section of `doctor` and `GET /v1/owner/status`: what config
//! asks for, what the vault pins and what a running server loaded, kept
//! apart. Only a running server reports a loaded model; doctor reads a vault
//! no server is serving, and says it did not observe one.

use serde::Serialize;

use crate::config::{EmbedderConfig, EmbedderProvider};
use crate::embedder::{DenseState, LoadedModel};

/// Why dense recall does not run on a vault with no provider configured.
const NOT_CONFIGURED: &str =
    "no [embedder] provider is configured, so recall runs on its sparse signals";

/// Why dense recall does not run yet on a server still loading its model.
const LOADING: &str =
    "the model has not loaded and been admitted yet; recall runs sparse until it is";

/// The embedder as an owner reads it.
#[derive(Debug, Serialize)]
pub(crate) struct EmbedderReport {
    /// What `[embedder]` asks for. Absent when it asks for no provider.
    pub(crate) configured: Option<ConfiguredEmbedder>,
    /// What the vault pins: the model its stored vectors came from and their
    /// width. Absent when the vault could not be read.
    pub(crate) persisted: Option<PersistedEmbedder>,
    /// The model serving this vault now: loaded on this host, its files
    /// checked, and admitted by the vault. Absent while it loads or after a
    /// refusal, for an endpoint (its model runs elsewhere), and whenever no
    /// running server was asked.
    pub(crate) loaded: Option<LoadedModel>,
    /// Whether dense recall runs: `ready`, `loading`, `refused`,
    /// `not_configured`, or `not_observed` when no running server was asked.
    pub(crate) dense: &'static str,
    /// Why dense recall does not run now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
    /// What the owner should know about a model that serves: its hub ref
    /// now names another commit than the vault's pinned one, which keeps
    /// serving until `reembed` (FIX 9489).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) warning: Option<String>,
}

/// What `[embedder]` asks for.
#[derive(Debug, Serialize)]
pub(crate) struct ConfiguredEmbedder {
    pub(crate) provider: &'static str,
    pub(crate) model_id: String,
    pub(crate) dimensions: usize,
    /// The local provider's device as written: `auto` resolves at load.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) device: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) quant: Option<&'static str>,
}

/// What the vault pins for its vectors.
#[derive(Debug, Serialize)]
pub(crate) struct PersistedEmbedder {
    pub(crate) model_id: Option<String>,
    pub(crate) dimensions: Option<usize>,
}

impl ConfiguredEmbedder {
    fn of(config: Option<&EmbedderConfig>) -> Option<Self> {
        let config = config.filter(|config| config.is_active())?;
        let local = config.provider == EmbedderProvider::Local;
        Some(Self {
            provider: config.provider.as_str(),
            model_id: config.model_id.clone(),
            dimensions: config.dimensions,
            device: local.then_some(config.local.device.as_str()),
            quant: local.then_some(config.local.quant.as_str()),
        })
    }
}

impl PersistedEmbedder {
    fn of(doctor: &oneiron::VaultDoctorReport) -> Self {
        Self {
            model_id: doctor.embedding_model_id.clone(),
            dimensions: doctor.hnsw.vector_dimensions,
        }
    }
}

impl EmbedderReport {
    /// A running server's report: `state` is its slot's, `None` when it has
    /// no provider configured.
    pub(crate) fn served(
        config: Option<&EmbedderConfig>,
        doctor: &oneiron::VaultDoctorReport,
        state: Option<DenseState>,
    ) -> Self {
        let (dense, loaded, reason) = match state {
            None => ("not_configured", None, Some(NOT_CONFIGURED.to_owned())),
            Some(DenseState::Ready { loaded }) => ("ready", loaded, None),
            Some(DenseState::Loading) => ("loading", None, Some(LOADING.to_owned())),
            Some(DenseState::Refused { reason }) => ("refused", None, Some(reason)),
        };
        Self {
            configured: ConfiguredEmbedder::of(config),
            persisted: Some(PersistedEmbedder::of(doctor)),
            loaded,
            dense,
            reason,
            warning: None,
        }
    }

    /// A report on a vault no running server was asked about: nothing here
    /// loaded a model, so none is claimed, whatever the files on disk or the
    /// vault's pins say.
    pub(crate) fn unobserved(
        config: Option<&EmbedderConfig>,
        doctor: Option<&oneiron::VaultDoctorReport>,
        reason: &str,
    ) -> Self {
        Self {
            configured: ConfiguredEmbedder::of(config),
            persisted: doctor.map(PersistedEmbedder::of),
            loaded: None,
            dense: "not_observed",
            reason: Some(reason.to_owned()),
            warning: None,
        }
    }
}
