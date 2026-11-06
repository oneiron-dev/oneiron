//! The model door's broker leg (FIX 15702; ARCH-0069
//! `#door-sign-loopback`): one model request from an official CLI seat, its
//! bytes as the seat's SDK wrote them, sent through the vault's credential
//! broker with the provider key read at the custody door for that one
//! request. A request that asks for a stream gets the provider's events as
//! the broker clears them of the key (slice 2); any other, one buffered
//! reply (slice 1).
//!
//! The door fixes everything but the body: the provider the run's slot was
//! bound to gives the origin, the path, the auth shape and the headers, and
//! the slot's model list the models a request may name. Every model outside
//! the list is refused before any key is read. The key is released only
//! while the run's seat-child credential holds, its slip names the key and
//! carries the model door's channel, and the run's registration is open and
//! records the key's taint first.
//!
//! Each request is a paid call of the run's claim (slice 3,
//! [`super::seat_model_admission`]): admitted for its exact bytes through
//! the offer its provider binds for the model it names, before the key is
//! read; its permit started after the key is read and before the broker
//! sends; and settled on what the reply reports, as the reply goes back.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use oneiron::authority::SeatChildCredential;
use oneiron::llm::run_admission::{OfferBinding, RunDenied};
use oneiron::{FatalLlmError, LlmError, LlmResult, Vault};
use oneiron_broker::{CallHeader, Shape};
use serde_json::Value as JsonValue;
use zeroize::Zeroizing;

use super::broker::{KeyDoor, answered, join};
use super::broker_context::{BrokerAnswer, BrokerContext};
use super::http::is_cloud_node;
use super::offer::provider_offer;
use super::seat_model_admission::{SeatModelCall, SeatModelMeter};
use crate::config::models::{ModelRef, ModelsConfig, ProviderConfig, ProviderKind};
use crate::runtime::{SeatHelperRun, SeatModelProtocol};

/// The Anthropic API version a request that names none is sent with.
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// The request headers of an Anthropic SDK the door carries on: the API
/// version and the beta features the request asks for. No other request
/// header leaves the host.
const ANTHROPIC_CARRIED: [&str; 2] = ["anthropic-version", "anthropic-beta"];

/// The query Claude Code adds to Messages, carried on exactly as sent.
const ANTHROPIC_BETA_QUERY: &str = "?beta=true";

/// The `chat_path` value that selects an OpenAI provider's unversioned
/// `/chat/completions`.
const CHAT_PATH_UNVERSIONED: &str = "unversioned";

/// One `[models]` provider a seat's model door may send through: a
/// `key_secret` provider that speaks OpenAI chat or Anthropic Messages.
#[derive(Debug, Clone)]
pub(crate) struct SeatModelProvider {
    /// Its name in `[models]`.
    name: String,
    /// Its `[models]` entry, which binds the offer each call is admitted
    /// through: its route, locality, payer, key custody and rates.
    config: ProviderConfig,
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
        .filter_map(|(name, provider)| Some((name.clone(), SeatModelProvider::of(name, provider)?)))
        .collect()
}

impl SeatModelProvider {
    fn of(name: &str, provider: &ProviderConfig) -> Option<Self> {
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
            name: name.to_owned(),
            config: provider.clone(),
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

impl SeatModelProvider {
    /// The offer this provider binds for `wire_model`, the model a request
    /// names on the wire: the engine model id `[models]` gives it, at this
    /// provider's route, payer, key custody and rates. `None` when the name
    /// makes no model id or the provider's URL no route.
    fn offer(&self, wire_model: &str) -> Option<OfferBinding> {
        let model = ModelRef {
            provider: self.name.clone(),
            model: wire_model.to_owned(),
        }
        .engine_id(&self.config.revision)
        .ok()?;
        provider_offer(&self.config, model, false).ok()
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

/// What the provider answered a seat request: one buffered body, its call
/// settled, or, for a request that asked for events, its status, whether its
/// reply is an event stream, the reply as the broker clears it, and the call
/// the reply settles as it goes back.
pub(crate) enum SeatModelAnswer {
    Whole(BrokerAnswer),
    Events {
        status: u16,
        event_stream: bool,
        reply: oneiron_broker::BrokerStream,
        call: SeatModelCall,
    },
}

/// Why a seat request was not sent, or got no answer.
#[derive(Debug)]
pub(crate) enum SeatModelRefusal {
    /// The door, the broker or the provider's transport refused it.
    Llm(LlmError),
    /// The claim's run admission refused it: nothing was reserved or sent.
    Denied(RunDenied),
    /// The claim's spend scope names a payer this host cannot bill yet, for
    /// this reason: nothing was reserved or sent.
    Unfunded(&'static str),
}

impl From<LlmError> for SeatModelRefusal {
    fn from(error: LlmError) -> Self {
        Self::Llm(error)
    }
}

/// Sends one seat request through `provider`: `body` as the seat sent it,
/// under the provider's origin, path and headers, Anthropic's `beta=true`
/// query when `beta`, and the Anthropic headers in `asked` the door carries
/// on, its key read at `keys`. Refused before any key is read unless `body`
/// is one JSON object naming one of `models`, whose `stream` is absent,
/// null, `false` or `true`, each once. A request with `stream: true` goes as
/// a stream and its events come back as the broker clears them (slice 2).
/// Each request is admitted on the claim's `meter` before its key is read,
/// and settled on what its reply reports (slice 3).
#[expect(
    clippy::too_many_arguments,
    reason = "one seat request, its provider, its key door and its claim's meter"
)]
pub(crate) async fn send_seat_model(
    context: &BrokerContext,
    provider: &SeatModelProvider,
    models: &BTreeSet<String>,
    asked: &[(String, String)],
    beta: bool,
    body: &[u8],
    keys: &Arc<dyn KeyDoor>,
    meter: &Arc<SeatModelMeter>,
) -> Result<SeatModelAnswer, SeatModelRefusal> {
    let (model, events) = admitted_request(body, models)?;
    let invalid = || LlmError::from(FatalLlmError::InvalidRequest);
    let shape = if events {
        provider.shape.with_events().ok_or_else(invalid)?
    } else {
        provider.shape
    };
    let mut headers = provider.headers.clone();
    let mut path = provider.path.clone();
    if provider.protocol == SeatModelProtocol::AnthropicMessages {
        for (name, value) in asked {
            if ANTHROPIC_CARRIED.contains(&name.as_str()) {
                headers.insert(name.clone(), value.clone());
            }
        }
        headers
            .entry("anthropic-version".to_owned())
            .or_insert_with(|| ANTHROPIC_VERSION.to_owned());
        if beta {
            path.push_str(ANTHROPIC_BETA_QUERY);
        }
    } else if beta {
        return Err(invalid().into());
    }
    headers.insert("content-type".to_owned(), "application/json".to_owned());
    let offer = provider.offer(&model);
    let mut header = CallHeader::new(
        String::new(),
        shape,
        provider.origin.clone(),
        path,
        headers.into_iter().collect(),
        model.clone(),
        is_cloud_node(),
        body,
    );
    let Some(offer) = offer else {
        return Err(meter.refuse_unoffered(&model));
    };
    let mut call = meter.admit(&offer, &model, &header.digest, provider.protocol)?;
    // The broker echoes the permit's lease as the call's id.
    header.call = call
        .lease()
        .map(|lease| lease.id().to_owned())
        .unwrap_or_default();
    // The permit starts after the key is read, immediately before the send.
    let release: oneiron::llm::DispatchRelease<'_> = &|| call.start();
    if !events {
        let answer = context
            .send_with_keys(
                keys,
                &provider.secret,
                &header,
                body,
                provider.timeout,
                Some(release),
                call.lease(),
            )
            .await?;
        call.end_whole(answer.status, &answer.body);
        return Ok(SeatModelAnswer::Whole(answer));
    }
    let reply = context
        .open_with_keys(
            keys,
            &provider.secret,
            &header,
            body,
            provider.timeout,
            Some(release),
            call.lease(),
        )
        .await?;
    let (status, reply_headers) = answered(reply.outcome().clone())?;
    call.answered(status);
    let event_stream = reply_headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type")
            && value
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("text/event-stream")
    });
    Ok(SeatModelAnswer::Events {
        status,
        event_stream,
        reply,
        call,
    })
}

/// The model `body` names, when it is one of `models`, and whether the
/// request asks for events. `stream` is read once, its repeats refused, so
/// the mode chosen here is the one the provider reads; any value but absent,
/// null, `false` or `true` refuses. The broker's own check refuses a body
/// naming its model twice or asking for another route, and binds an event
/// shape to `stream: true` again.
fn admitted_request(body: &[u8], models: &BTreeSet<String>) -> LlmResult<(String, bool)> {
    let invalid = || LlmError::from(FatalLlmError::InvalidRequest);
    let events = match oneiron_broker::json_member(body, "stream").map_err(|_| invalid())? {
        None | Some(JsonValue::Null | JsonValue::Bool(false)) => false,
        Some(JsonValue::Bool(true)) => true,
        Some(_) => return Err(invalid()),
    };
    let model = match oneiron_broker::json_member(body, "model").map_err(|_| invalid())? {
        Some(JsonValue::String(model)) if models.contains(&model) => model,
        _ => return Err(invalid()),
    };
    Ok((model, events))
}
