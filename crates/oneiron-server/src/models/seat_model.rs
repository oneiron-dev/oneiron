//! The model door's broker leg (FIX 15702 slice 1; ARCH-0069
//! `#door-sign-loopback`): one buffered model request from an official CLI
//! seat, its bytes as the seat's SDK wrote them, sent through the vault's
//! credential broker with the provider key read at the custody door for that
//! one request.
//!
//! The door fixes everything but the body: the provider the run's slot was
//! bound to gives the origin, the path, the auth shape and the headers, and
//! the slot's model list the models a request may name. A streamed request
//! and every model outside the list are refused before any key is read. The
//! key is released only while the run's seat-child credential holds, its
//! slip names the key and carries the model door's channel, and the run's
//! registration is open and records the key's taint first.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use oneiron::authority::SeatChildCredential;
use oneiron::{FatalLlmError, LlmError, LlmResult, Vault};
use oneiron_broker::{CallHeader, Shape};
use serde_json::Value as JsonValue;
use zeroize::Zeroizing;

use super::broker::{KeyDoor, join};
use super::broker_context::{BrokerAnswer, BrokerContext};
use super::http::is_cloud_node;
use crate::config::models::{ModelsConfig, ProviderConfig, ProviderKind};
use crate::runtime::{SeatHelperRun, SeatModelProtocol};

/// The Anthropic API version a request that names none is sent with.
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// The request headers of an Anthropic SDK the door carries on: the API
/// version and the beta features the request asks for. No other request
/// header leaves the host.
const ANTHROPIC_CARRIED: [&str; 2] = ["anthropic-version", "anthropic-beta"];

/// The `chat_path` value that selects an OpenAI provider's unversioned
/// `/chat/completions`.
const CHAT_PATH_UNVERSIONED: &str = "unversioned";

/// One `[models]` provider a seat's model door may send through: a
/// `key_secret` provider that speaks OpenAI chat or Anthropic Messages.
#[derive(Debug, Clone)]
pub(crate) struct SeatModelProvider {
    /// The custody name of its key.
    pub(crate) secret: String,
    pub(crate) protocol: SeatModelProtocol,
    shape: Shape,
    /// Its `https://host[:port]`.
    origin: String,
    /// The protocol's endpoint under its base URL's path.
    path: String,
    /// Its configured non-credential headers, names lowercase.
    headers: BTreeMap<String, String>,
    timeout: Duration,
}

/// The providers of `models` a seat's model door may send through, by name.
pub(super) fn seat_model_providers(models: &ModelsConfig) -> BTreeMap<String, SeatModelProvider> {
    models
        .providers
        .iter()
        .filter_map(|(name, provider)| Some((name.clone(), SeatModelProvider::of(provider)?)))
        .collect()
}

impl SeatModelProvider {
    fn of(provider: &ProviderConfig) -> Option<Self> {
        let secret = provider.key_secret.clone()?;
        let url = reqwest::Url::parse(&provider.base_url).ok()?;
        let prefix = url.path().trim_end_matches('/');
        let (protocol, shape, endpoint) = match provider.kind {
            ProviderKind::AnthropicCompat => (
                SeatModelProtocol::AnthropicMessages,
                Shape::AnthropicMessages,
                "/v1/messages",
            ),
            ProviderKind::OpenaiCompat | ProviderKind::LocalOpenaiCompat => {
                if provider.chat_path.as_deref() == Some(CHAT_PATH_UNVERSIONED) {
                    (
                        SeatModelProtocol::OpenAiChat,
                        Shape::OpenAiChatUnversioned,
                        "/chat/completions",
                    )
                } else {
                    (
                        SeatModelProtocol::OpenAiChat,
                        Shape::OpenAiChat,
                        "/v1/chat/completions",
                    )
                }
            }
            _ => return None,
        };
        Some(Self {
            secret,
            protocol,
            shape,
            origin: url.origin().ascii_serialization(),
            path: join(prefix, endpoint),
            headers: provider
                .headers
                .iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
                .collect(),
            timeout: Duration::from_secs(provider.timeout_secs),
        })
    }
}

/// The custody door of one seat's model call: the key leaves only through
/// [`Vault::inject_seat_model_key`], for the run's own credential, and only
/// once the run's registration has recorded the key's taint, so a closed
/// registration sends nothing and the run's exhaust names every key it used.
pub(crate) struct SeatKeyDoor {
    vault: Arc<Vault>,
    credential: SeatChildCredential,
    run: SeatHelperRun,
}

impl SeatKeyDoor {
    pub(crate) fn new(
        vault: Arc<Vault>,
        credential: SeatChildCredential,
        run: SeatHelperRun,
    ) -> Self {
        Self {
            vault,
            credential,
            run,
        }
    }
}

impl KeyDoor for SeatKeyDoor {
    fn check(&self, name: &str) -> anyhow::Result<()> {
        Ok(self.vault.check_seat_model_key(&self.credential, name)?)
    }

    fn read(&self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let mut key = Zeroizing::new(Vec::new());
        let receipt =
            self.vault
                .inject_seat_model_key(&self.credential, name, &mut |value: &[u8]| {
                    // Sized once, so no reallocation leaves an unwiped copy.
                    key.reserve_exact(value.len());
                    key.extend_from_slice(value);
                    Ok(())
                })?;
        for taint in receipt.taint_token {
            anyhow::ensure!(
                self.run.record_taint(taint),
                "the seat's run closed before its key left"
            );
        }
        Ok(key)
    }
}

/// Sends one seat request through `provider`: `body` as the seat sent it,
/// under the provider's origin, path and headers and the Anthropic headers
/// in `asked` the door carries on, its key read at `keys`. Refused before
/// any key is read unless `body` is one JSON object naming one of `models`
/// and asking for no stream.
pub(crate) async fn send_seat_model(
    context: &BrokerContext,
    provider: &SeatModelProvider,
    models: &BTreeSet<String>,
    asked: &[(String, String)],
    body: &[u8],
    keys: &Arc<dyn KeyDoor>,
) -> LlmResult<BrokerAnswer> {
    let model = admitted_model(body, models)?;
    let mut headers = provider.headers.clone();
    if provider.protocol == SeatModelProtocol::AnthropicMessages {
        for (name, value) in asked {
            if ANTHROPIC_CARRIED.contains(&name.as_str()) {
                headers.insert(name.clone(), value.clone());
            }
        }
        headers
            .entry("anthropic-version".to_owned())
            .or_insert_with(|| ANTHROPIC_VERSION.to_owned());
    }
    headers.insert("content-type".to_owned(), "application/json".to_owned());
    let header = CallHeader::new(
        format!("seat-model-{}", oneiron::EntityId::now().to_hex()),
        provider.shape,
        provider.origin.clone(),
        provider.path.clone(),
        headers.into_iter().collect(),
        model,
        is_cloud_node(),
        body,
    );
    context
        .send_with_keys(keys, &provider.secret, &header, body, provider.timeout)
        .await
}

/// The model `body` names, when it is one of `models` and the request asks
/// for no stream: the door relays one buffered reply, so a streamed request
/// is refused, never answered whole. The broker's own check refuses a body
/// naming its model twice or asking for another route.
fn admitted_model(body: &[u8], models: &BTreeSet<String>) -> LlmResult<String> {
    let invalid = || LlmError::from(FatalLlmError::InvalidRequest);
    let request: serde_json::Map<String, JsonValue> =
        serde_json::from_slice(body).map_err(|_| invalid())?;
    if !matches!(
        request.get("stream"),
        None | Some(JsonValue::Null | JsonValue::Bool(false))
    ) {
        return Err(invalid());
    }
    let model = request
        .get("model")
        .and_then(JsonValue::as_str)
        .filter(|model| models.contains(*model))
        .ok_or_else(invalid)?;
    Ok(model.to_owned())
}
