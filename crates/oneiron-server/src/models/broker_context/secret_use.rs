//! A secret-free installed adapter for `self.use`'s broker model listing.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use oneiron::secret_custody::{
    BrokerModelListingCall, BrokerModelListingHost, BrokerModelListingReply,
};
use oneiron_broker::{BrokerClient, BrokerConnection, CallHeader, Outcome, Shape};
use oneiron_llm_anthropic::AnthropicMessagesConfig;
use serde_json::Value;
use zeroize::Zeroizing;

use super::super::broker::{REPLY_MARGIN, answered, join};
use super::{BrokerContext, is_cloud_node};
use crate::config::models::{ModelsConfig, ProviderKind};

struct Provider {
    origin: String,
    path: String,
    shape: Shape,
    headers: Vec<(String, String)>,
    wire_model: String,
    client: Result<BrokerClient, String>,
}

struct ListingHost {
    runtime: tokio::runtime::Handle,
    providers: BTreeMap<String, Provider>,
}

impl fmt::Debug for ListingHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrokerModelListingHost")
            .finish_non_exhaustive()
    }
}

impl BrokerContext {
    /// Installs only broker clients and configured request templates, not
    /// this context's key door: retaining that door on the vault would form
    /// a Vault -> transports -> key door -> Vault reference cycle.
    pub(crate) fn secret_use_models(
        &self,
        models: &ModelsConfig,
    ) -> Arc<dyn BrokerModelListingHost> {
        let mut providers = BTreeMap::new();
        for rung in models.roles.values().flatten() {
            let name = &rung.model.provider;
            if providers.contains_key(name) {
                continue;
            }
            let Some(provider) = models.providers.get(name) else {
                continue;
            };
            if provider.key_secret.is_none()
                || !matches!(
                    provider.kind,
                    ProviderKind::OpenaiCompat
                        | ProviderKind::LocalOpenaiCompat
                        | ProviderKind::Gemini
                        | ProviderKind::AnthropicCompat
                )
            {
                continue;
            }
            let Ok(url) = reqwest::Url::parse(&provider.base_url) else {
                continue;
            };
            let prefix = url.path().trim_end_matches('/');
            let (shape, path) = if provider.kind == ProviderKind::Gemini {
                (
                    Shape::GeminiModels,
                    join(
                        prefix.strip_suffix("/v1beta").unwrap_or(prefix),
                        "/v1beta/models",
                    ),
                )
            } else if provider.kind == ProviderKind::AnthropicCompat {
                (Shape::AnthropicModels, join(prefix, "/v1/models"))
            } else {
                (Shape::OpenAiModels, join(prefix, "/v1/models"))
            };
            let mut headers: Vec<_> = provider
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    let name = name.to_ascii_lowercase();
                    // The broker's existing bodyless shape carries no content type.
                    (name != "content-type").then(|| (name, value.clone()))
                })
                .collect();
            if provider.kind == ProviderKind::AnthropicCompat {
                // Native wire headers take precedence over configured extras.
                headers.retain(|(name, _)| name != "anthropic-version");
                headers.push((
                    "anthropic-version".to_owned(),
                    AnthropicMessagesConfig::from_catalog([]).anthropic_version,
                ));
            }
            let timeout = Duration::from_secs(provider.timeout_secs) + REPLY_MARGIN;
            let client = self
                .inner
                .site
                .as_ref()
                .map_err(Clone::clone)
                .and_then(|site| site.client(timeout).map_err(|error| error.to_string()));
            providers.insert(
                name.clone(),
                Provider {
                    origin: url.origin().ascii_serialization(),
                    path,
                    shape,
                    headers,
                    // A bodyless listing has no wire selector. Bind it to one
                    // actual configured model, as the existing endpoint probe
                    // does; this neither filters the listing nor proves serving.
                    wire_model: rung.model.model.clone(),
                    client,
                },
            );
        }
        Arc::new(ListingHost {
            runtime: self.inner.runtime.clone(),
            providers,
        })
    }
}

impl BrokerModelListingHost for ListingHost {
    fn prepare(
        &self,
        provider: &str,
        call: &str,
    ) -> Result<Box<dyn BrokerModelListingCall>, String> {
        let provider = self.providers.get(provider).ok_or_else(|| {
            "name a configured broker-backed OpenAI-compatible, Anthropic-compatible or Gemini provider with a model rung"
                .to_owned()
        })?;
        let header = CallHeader::new(
            call.to_owned(),
            provider.shape,
            provider.origin.clone(),
            provider.path.clone(),
            provider.headers.clone(),
            provider.wire_model.clone(),
            is_cloud_node(),
            &[],
        );
        header.check(&[]).map_err(|error| error.to_string())?;
        let client = provider.client.as_ref().map_err(Clone::clone)?;
        let connection = self
            .runtime
            .block_on(client.connect())
            .map_err(|error| error.to_string())?;
        Ok(Box::new(ListingCall {
            runtime: self.runtime.clone(),
            connection,
            header,
        }))
    }
}

struct ListingCall {
    runtime: tokio::runtime::Handle,
    connection: BrokerConnection,
    header: CallHeader,
}

impl BrokerModelListingCall for ListingCall {
    fn present(self: Box<Self>, value: &[u8]) -> BrokerModelListingReply {
        let Self {
            runtime,
            connection,
            header,
        } = *self;
        let mut key = Zeroizing::new(Vec::with_capacity(value.len()));
        key.extend_from_slice(value);
        let reply = match runtime.block_on(connection.call(&header, &[], key)) {
            Ok(reply) => reply,
            Err(error) => {
                return BrokerModelListingReply {
                    result: Err(error.to_string()),
                    presented: false,
                };
            }
        };
        let presented = !matches!(reply.outcome, Outcome::Refused { .. });
        let result = match answered(reply.outcome) {
            Ok((status, _)) if (200..300).contains(&status) => {
                serde_json::from_slice::<Value>(&reply.body)
                    .map_err(|error| format!("the provider's model listing is not JSON: {error}"))
            }
            Ok((status, _)) => Err(format!(
                "the provider's model listing answered HTTP {status}: {}",
                String::from_utf8_lossy(&reply.body),
            )),
            Err(error) => Err(error.to_string()),
        };
        BrokerModelListingReply { result, presented }
    }
}
