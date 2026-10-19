//! How an endpoint embedder's requests reach their server: a plain client,
//! whose default headers carry an `api_key_env` key, or the credential broker
//! (ARCH-0069 `#broker-design`), which reads a `key_secret` key at the vault's
//! custody door for each request and sends it once over verified TLS. The
//! broker sends an embedder's requests to the OpenAI-compatible
//! `…/v1/embeddings` and `…/v1/models` paths only, and a GPU pod's to the
//! same two, each to the configured origin.
use std::time::Duration;

use oneiron_broker::{CallHeader, Shape};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

use super::endpoint::{EMBEDDER_TOOL, MAX_RESPONSE_BYTES, bounded_body, transport_error};
use crate::config::EndpointEmbedderConfig;
use crate::models::BrokerContext;
use crate::runtime::GpuPool;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// What one request came back with: its status, and for a success its body
/// read within the cap (an error when it is over it, or its read failed).
pub(super) struct Reply {
    pub(super) status: reqwest::StatusCode,
    pub(super) body: oneiron::Result<Vec<u8>>,
}

/// How one endpoint's, or one pool's pods', requests are sent.
pub(super) enum Reach {
    /// A plain client. No proxy: one from the environment or the system
    /// would receive the key and every text the vault embeds.
    Plain(reqwest::blocking::Client),
    /// The credential broker, with the key the vault secret holds.
    Broker(BrokerReach),
}

pub(super) struct BrokerReach {
    /// `None` where no broker context was opened (a command with no vault
    /// open): each request then fails before it is sent.
    broker: Option<BrokerContext>,
    secret: String,
    /// How long one request may take.
    timeout: Duration,
}

impl Reach {
    /// How the endpoint `config` configures is reached: through `broker`
    /// for a `key_secret` key, or with its `api_key_env` key, or none, in
    /// the client's default headers. One attempt, no redirects, a bounded
    /// body: the worker loop is the retry, and a retry inside the client
    /// would hide a dead remote behind a long stall and re-charge a metered
    /// one.
    pub(super) fn endpoint(
        config: &EndpointEmbedderConfig,
        broker: Option<&BrokerContext>,
    ) -> oneiron::Result<Self> {
        let timeout = Duration::from_millis(config.timeout_ms);
        if let Some(secret) = &config.key_secret {
            return Ok(Self::Broker(BrokerReach {
                broker: broker.cloned(),
                secret: secret.clone(),
                timeout,
            }));
        }
        let mut headers = HeaderMap::new();
        if let Some(name) = &config.api_key_env {
            let key = std::env::var(name).map_err(|_| {
                oneiron::Error::InvalidConfig("embedder key environment variable is missing".into())
            })?;
            let mut value = HeaderValue::from_str(&format!("Bearer {key}")).map_err(|_| {
                oneiron::Error::InvalidConfig("invalid embedder authorization value".into())
            })?;
            value.set_sensitive(true);
            headers.insert(AUTHORIZATION, value);
        }
        plain(headers, timeout)
            .map_err(|e| oneiron::Error::InvalidConfig(format!("embedder http client: {e}")))
    }

    /// How `pool`'s pods are reached, with the pods' own key, never the
    /// endpoint's: through the broker for a `key_secret` key, or with the
    /// `api_key_env` bearer in a plain client's default headers.
    pub(super) fn pods(pool: &GpuPool, timeout: Duration) -> oneiron::Result<Self> {
        if let Some((secret, broker)) = pool.key_secret() {
            return Ok(Self::Broker(BrokerReach {
                broker: broker.cloned(),
                secret: secret.to_owned(),
                timeout,
            }));
        }
        let mut headers = HeaderMap::new();
        if let Some(bearer) = pool.bearer() {
            headers.insert(AUTHORIZATION, bearer.clone());
        }
        plain(headers, timeout)
            .map_err(|e| oneiron::Error::InvalidConfig(format!("gpu pod http client: {e}")))
    }

    /// What a request can fail on before anything is sent, checked before
    /// its permit starts: for the broker, a broker to send through and a key
    /// the custody door would hand over. A plain client checks nothing.
    pub(super) fn preflight(&self) -> oneiron::Result<()> {
        match self {
            Self::Plain(_) => Ok(()),
            Self::Broker(reach) => reach
                .broker()?
                .ready(&reach.secret)
                .map_err(|error| reach.failed("request", &format!("cannot go: {error}"))),
        }
    }

    /// `GET url`, a model listing, its call bound to `model`.
    pub(super) fn get(&self, url: &str, model: &str, what: &str) -> oneiron::Result<Reply> {
        match self {
            Self::Plain(client) => {
                let response = client
                    .get(url)
                    .send()
                    .map_err(|e| transport_error(what, &e))?;
                Ok(read(response))
            }
            Self::Broker(reach) => reach.call(url, Shape::OpenAiModels, model, Vec::new(), what),
        }
    }

    /// `POST url` with `body` as JSON, an embeddings request naming `model`.
    pub(super) fn post(
        &self,
        url: &str,
        model: &str,
        body: &impl serde::Serialize,
        what: &str,
    ) -> oneiron::Result<Reply> {
        match self {
            Self::Plain(client) => {
                let response = client
                    .post(url)
                    .json(body)
                    .send()
                    .map_err(|e| transport_error(what, &e))?;
                Ok(read(response))
            }
            Self::Broker(reach) => {
                let bytes = serde_json::to_vec(body)
                    .map_err(|_| reach.failed(what, "could not be written"))?;
                reach.call(url, Shape::OpenAiEmbeddings, model, bytes, what)
            }
        }
    }
}

impl BrokerReach {
    fn broker(&self) -> oneiron::Result<&BrokerContext> {
        self.broker.as_ref().ok_or_else(|| {
            self.failed(
                "request",
                "has no credential broker: its key_secret is read at the vault's custody door, and no vault's broker was opened",
            )
        })
    }

    fn failed(&self, what: &str, why: &str) -> oneiron::Error {
        oneiron::Error::UpstreamToolFailure {
            tool: EMBEDDER_TOOL,
            code: format!("embedder {what} {why}"),
        }
    }

    /// One broker call of `shape` to `url`, `body` its exact bytes and
    /// `model` its binding. The broker strips the key from the reply; the
    /// reply's body is held to the embedder's cap.
    fn call(
        &self,
        url: &str,
        shape: Shape,
        model: &str,
        body: Vec<u8>,
        what: &str,
    ) -> oneiron::Result<Reply> {
        let broker = self.broker()?;
        let url = reqwest::Url::parse(url).map_err(|_| self.failed(what, "has an invalid URL"))?;
        let headers = if body.is_empty() {
            Vec::new()
        } else {
            vec![("content-type".to_owned(), "application/json".to_owned())]
        };
        let header = CallHeader::new(
            oneiron::EntityId::now().to_hex(),
            shape,
            url.origin().ascii_serialization(),
            url.path().to_owned(),
            headers,
            model.to_owned(),
            &body,
        );
        let mut answer = broker
            .send_blocking(&self.secret, &header, &body, self.timeout)
            .map_err(|error| {
                self.failed(
                    what,
                    &format!("through the credential broker failed: {error}"),
                )
            })?;
        let status = reqwest::StatusCode::from_u16(answer.status)
            .map_err(|_| self.failed(what, "answered with an invalid status"))?;
        let body = if !status.is_success() {
            Ok(Vec::new())
        } else if answer.body.len() > MAX_RESPONSE_BYTES {
            Err(self.failed(what, "response exceeds the body cap"))
        } else {
            Ok(std::mem::take(&mut *answer.body))
        };
        Ok(Reply { status, body })
    }
}

fn plain(headers: HeaderMap, timeout: Duration) -> reqwest::Result<Reach> {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(timeout)
        .build()
        .map(Reach::Plain)
}

/// A plain response's status, and its body for a success.
fn read(response: reqwest::blocking::Response) -> Reply {
    let status = response.status();
    let body = if status.is_success() {
        bounded_body(response)
    } else {
        Ok(Vec::new())
    };
    Reply { status, body }
}
