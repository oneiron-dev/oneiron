//! The learned phonetic rung on this server (CROSS-ARCH-0013 `#ladder` rung
//! 2): the model `[phonetic_embedder]` names, reached over HTTP, and its fill.
//! Each media backfill pass also embeds the names of live PERSON, ORG and
//! PLACE entities through it ([`oneiron::Vault::reconcile_phonetic_embeddings_admitted`]),
//! so a commit wakes it as it wakes the media pass. The model runs out of
//! process: the engine never holds a model name, and a fine-tuned checkpoint
//! swaps in under a new `model_id` with no engine change.

use std::sync::{Arc, Mutex, PoisonError};

use oneiron::embed::{
    EgressDecision, EgressPredicate, EmbedderLocality, MediaEmbeddingInput, PendingEmbeddingInput,
};
use oneiron::phonetic_learned::PhoneticEmbedder;
use serde::{Deserialize, Serialize};

use super::core::SyncServer;
use crate::config::{PhoneticEmbedderConfig, PhoneticEndpointBinding};

/// Names one pass sends the model at most.
const PHONETIC_BATCH: usize = 64;
/// The largest answer read: 64 names of 1,024 components, at about 24 bytes
/// a component, with room to spare.
const MAX_ANSWER_BYTES: usize = 8 * 1024 * 1024;
/// Tool name on every failure of the endpoint.
const PHONETIC_EMBEDDER_TOOL: &str = "phonetic-embedder-endpoint";

/// The `[phonetic_embedder]` endpoint: one client, and the reason its last
/// pass failed, logged once until it changes.
pub(crate) struct PhoneticEndpoint {
    binding: PhoneticEndpointBinding,
    client: reqwest::Client,
    failing: Mutex<Option<String>>,
}

#[derive(Serialize)]
struct NamesRequest<'a> {
    names: &'a [&'a str],
}

#[derive(Deserialize)]
struct NamesAnswer {
    vectors: Vec<Vec<f32>>,
}

impl PhoneticEndpoint {
    /// The endpoint `section` binds; `None` with no section or none bound.
    /// One attempt per request and no redirects: the next pass is the retry.
    fn from_config(section: Option<&PhoneticEmbedderConfig>) -> anyhow::Result<Option<Self>> {
        let Some(binding) = section
            .map(PhoneticEmbedderConfig::binding)
            .transpose()?
            .flatten()
        else {
            return Ok(None);
        };
        let client = reqwest::Client::builder()
            .timeout(binding.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| anyhow::anyhow!("phonetic embedder http client: {error}"))?;
        tracing::info!(
            endpoint = %binding.url,
            model = %binding.model_id,
            dimensions = binding.dimensions,
            "phonetic embedder configured"
        );
        Ok(Some(Self {
            binding,
            client,
            failing: Mutex::new(None),
        }))
    }

    /// One vector per name, as the endpoint answers them. A failure names
    /// its class and status only: an endpoint that echoes its input in an
    /// error must not put a vault's names into this server's logs.
    async fn embed(&self, names: &[&str]) -> oneiron::Result<Vec<Vec<f32>>> {
        let failure = |code: String| oneiron::Error::UpstreamToolFailure {
            tool: PHONETIC_EMBEDDER_TOOL,
            code,
        };
        let transport = |error: reqwest::Error| {
            let class = if error.is_timeout() {
                "timed out"
            } else if error.is_connect() {
                "connection failed"
            } else {
                "failed"
            };
            failure(format!("phonetic embedder request {class}"))
        };
        let mut response = self
            .client
            .post(self.binding.url.clone())
            .json(&NamesRequest { names })
            .send()
            .await
            .map_err(transport)?;
        if !response.status().is_success() {
            return Err(failure(format!(
                "phonetic embedder answered {}",
                response.status().as_u16()
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport)? {
            if body.len() + chunk.len() > MAX_ANSWER_BYTES {
                return Err(failure(
                    "phonetic embedder answer exceeds the body cap".to_owned(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice::<NamesAnswer>(&body)
            .map(|answer| answer.vectors)
            .map_err(|_| failure("phonetic embedder answer is not {\"vectors\": [..]}".to_owned()))
    }

    /// Logs a pass's failure once until its reason changes, and the first
    /// pass that fills the rung again.
    fn settle(&self, failure: Option<String>) {
        let mut failing = self.failing.lock().unwrap_or_else(PoisonError::into_inner);
        match failure {
            None => {
                if failing.take().is_some() {
                    tracing::info!(model = %self.binding.model_id, "phonetic embedding fills the learned rung again");
                }
            }
            Some(reason) => {
                if failing.as_deref() != Some(reason.as_str()) {
                    tracing::warn!(model = %self.binding.model_id, %reason, "phonetic embedding cannot fill the learned rung; it retries");
                    *failing = Some(reason);
                }
            }
        }
    }
}

/// The endpoint as the engine's synchronous model door, each call driven on
/// the server's runtime from the pass's blocking thread.
struct EndpointOnRuntime<'a> {
    endpoint: &'a PhoneticEndpoint,
    runtime: &'a tokio::runtime::Handle,
}

impl PhoneticEmbedder for EndpointOnRuntime<'_> {
    fn model_id(&self) -> &str {
        &self.endpoint.binding.model_id
    }

    fn dimensions(&self) -> usize {
        self.endpoint.binding.dimensions
    }

    fn locality(&self) -> EmbedderLocality {
        match self.endpoint.binding.locality {
            crate::config::EmbedderLocality::OnDevice => EmbedderLocality::OnDevice,
            crate::config::EmbedderLocality::OwnerServer => EmbedderLocality::OwnerServer,
            crate::config::EmbedderLocality::ThirdParty => EmbedderLocality::ThirdParty,
        }
    }

    fn embed_names(&self, names: &[&str]) -> oneiron::Result<Vec<Vec<f32>>> {
        self.runtime.block_on(self.endpoint.embed(names))
    }
}

/// The gate an off-device model's pass reads through. It allows every name,
/// so the engine still keeps home each name whose entity a device-local world
/// keeps (DEC-0005), a check it runs only behind a gate. A model on this
/// device reads no gate.
struct NamesToTheOwnersServer;

impl EgressPredicate for NamesToTheOwnersServer {
    fn decide(&self, _input: &PendingEmbeddingInput) -> EgressDecision {
        EgressDecision::NoVerdict
    }

    fn decide_media(&self, _input: &MediaEmbeddingInput<'_>) -> EgressDecision {
        EgressDecision::Allow
    }
}

impl SyncServer {
    /// Binds the model `section` names to the learned phonetic rung, before
    /// the server is shared. No section, or `provider = "none"`, binds none.
    ///
    /// # Errors
    /// A section that does not check ([`PhoneticEmbedderConfig::binding`]),
    /// or a client that cannot be built.
    pub(crate) fn with_phonetic_embedder(
        mut self,
        section: Option<&PhoneticEmbedderConfig>,
    ) -> anyhow::Result<Self> {
        self.phonetic_embedder = PhoneticEndpoint::from_config(section)?.map(Arc::new);
        Ok(self)
    }

    /// One pass of the learned phonetic rung while a model is bound: up to
    /// [`PHONETIC_BATCH`] names embedded and stored. Returns the names
    /// stored; a failure stores none, is logged once until its reason
    /// changes, and the next pass retries. Blocking.
    pub(super) fn backfill_phonetic_names(&self, runtime: &tokio::runtime::Handle) -> usize {
        let Some(endpoint) = self.phonetic_embedder.as_deref() else {
            return 0;
        };
        let model = EndpointOnRuntime { endpoint, runtime };
        let gate = NamesToTheOwnersServer;
        match self
            .vault
            .reconcile_phonetic_embeddings_admitted(&model, PHONETIC_BATCH, Some(&gate))
        {
            Ok(report) => {
                endpoint.settle(None);
                report.embedded
            }
            Err(error) => {
                endpoint.settle(Some(error.to_string()));
                0
            }
        }
    }
}
