//! The `[phonetic_embedder]` section: the model behind the learned phonetic
//! rung (CROSS-ARCH-0013 `#ladder` rung 2). File-only, like `[line]`. Absent,
//! or `provider = "none"`, binds no model, and names keep their codes alone.
//!
//! ```toml
//! [phonetic_embedder]
//! provider = "endpoint"                          # endpoint | none
//! endpoint = "http://127.0.0.1:8790/embed-names"
//! model_id = "symphonym-v7"
//! dimensions = 128                               # 1..=1024
//! locality = "owner-server"                      # on-device | owner-server
//! timeout_ms = 60000
//! ```
//!
//! The model runs out of process, so the engine never holds a model name. A
//! fine-tuned checkpoint swaps in under a new `model_id`, and the next passes
//! embed every name again under it. The endpoint takes `{"names": [..]}` and
//! answers `{"vectors": [[..], ..]}`: one vector of `dimensions` per name, in
//! order.

use std::time::Duration;

use serde::Deserialize;

use super::EmbedderLocality;

const DEFAULT_TIMEOUT_MS: u64 = 60_000;

/// Which model serves the learned phonetic rung.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum PhoneticEmbedderProvider {
    /// A process that answers the names wire at `endpoint`.
    Endpoint,
    /// No model: the code rung alone, stated.
    None,
}

/// The `[phonetic_embedder]` section as the file states it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PhoneticEmbedderConfig {
    pub provider: PhoneticEmbedderProvider,
    /// The URL the names are posted to, `http` or `https`.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// The model's id. Every stored vector is keyed by it, so a new id
    /// makes them all stale.
    #[serde(default)]
    pub model_id: Option<String>,
    /// The width of every vector the model answers.
    #[serde(default)]
    pub dimensions: Option<usize>,
    /// Where the model runs. `third-party` is refused: no host egress gate
    /// binds a phonetic endpoint.
    #[serde(default = "default_locality")]
    pub locality: EmbedderLocality,
    /// How long one request may take.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

/// The model an endpoint section binds, checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhoneticEndpointBinding {
    pub url: reqwest::Url,
    pub model_id: String,
    pub dimensions: usize,
    pub locality: EmbedderLocality,
    pub timeout: Duration,
}

const fn default_locality() -> EmbedderLocality {
    EmbedderLocality::OwnerServer
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

impl PhoneticEmbedderConfig {
    /// The model this section binds; `None` for `provider = "none"`.
    ///
    /// # Errors
    /// An endpoint section that names no endpoint, model or width, a URL that
    /// is not `http` or `https`, a width outside
    /// 1..=[`oneiron::phonetic_learned::PHONETIC_VECTOR_MAX_DIMENSIONS`], a
    /// zero timeout, or a third-party locality.
    pub fn binding(&self) -> anyhow::Result<Option<PhoneticEndpointBinding>> {
        if self.provider == PhoneticEmbedderProvider::None {
            return Ok(None);
        }
        let endpoint = self
            .endpoint
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("phonetic_embedder.endpoint is required"))?;
        let url = reqwest::Url::parse(endpoint)
            .ok()
            .filter(|url| matches!(url.scheme(), "http" | "https"))
            .ok_or_else(|| {
                anyhow::anyhow!("phonetic_embedder.endpoint must be an http or https URL")
            })?;
        let model_id = self
            .model_id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| anyhow::anyhow!("phonetic_embedder.model_id is required"))?;
        let max = oneiron::phonetic_learned::PHONETIC_VECTOR_MAX_DIMENSIONS;
        let dimensions = self
            .dimensions
            .filter(|width| (1..=max).contains(width))
            .ok_or_else(|| anyhow::anyhow!("phonetic_embedder.dimensions must be 1..={max}"))?;
        if self.locality == EmbedderLocality::ThirdParty {
            anyhow::bail!(
                "phonetic_embedder.locality = \"third-party\" is refused: no egress gate binds \
                 a phonetic endpoint; serve the model on-device or on the owner's server"
            );
        }
        if self.timeout_ms == 0 {
            anyhow::bail!("phonetic_embedder.timeout_ms must be at least 1");
        }
        Ok(Some(PhoneticEndpointBinding {
            url,
            model_id: model_id.to_owned(),
            dimensions,
            locality: self.locality,
            timeout: Duration::from_millis(self.timeout_ms),
        }))
    }

    pub(super) fn validate(&self) -> anyhow::Result<()> {
        self.binding().map(drop)
    }
}
