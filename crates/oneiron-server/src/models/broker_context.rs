//! One vault's credential-broker context (ARCH-0069 `#broker-design`): the
//! custody door its vault-secret keys are read at, and the broker that sends
//! with them. Serve builds it once from the opened vault, before the embedder
//! and the model seats. The `[models]` providers (chat and media), the System
//! One seat, the endpoint embedder, its remote rung and the GPU pods send
//! through it, each request one broker call: the exact request is built and
//! checked as the broker will check it, the broker is reached, and only then
//! is the key read at the door (effector `broker:model`, zeroizing bytes) and
//! handed over with that one request. No key is read once into a long-lived
//! bearer or a default header. The built-in Google Sheets connector sends
//! through it too (`sheets`), its OAuth access token read at its own
//! custody door by the engine. An outside import's git exchanges go through
//! the same broker (OSH-3, `git`).
mod git;
mod secret_use;
mod sheets;

pub(crate) use git::WeakBrokerContext;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use oneiron::{BudgetLease, FatalLlmError, LlmError, LlmResult, RetryableLlmError, Vault};
use oneiron_broker::{CallHeader, Shape};
use oneiron_llm_systemone::{
    SystemOneHttpRequest, SystemOneHttpResponse, SystemOneTransport, SystemOneTransportFuture,
};
use zeroize::Zeroizing;

use super::broker::{
    BrokerSite, KeyDoor, REPLY_MARGIN, VaultKeyDoor, answered, call_with_key_released,
    open_with_key,
};
use super::http::is_cloud_node;
use super::seat_model::{SeatModelProvider, seat_model_providers};
use crate::config::ServeConfig;
use crate::config::models::{BrokerConfig, ModelsConfig};

/// The longest one System One send runs in the broker. The seat names no
/// timeout of its own: each call waits its decision's time left.
const SYSTEM_ONE_SEND: Duration = Duration::from_secs(60);

/// One vault's custody door and credential broker, cheap to clone.
#[derive(Clone)]
pub(crate) struct BrokerContext {
    inner: Arc<Inner>,
}

struct Inner {
    keys: Arc<dyn KeyDoor>,
    /// The broker, or why none could be made (no broker program beside this
    /// binary, say): every call then fails before anything is sent.
    site: Result<BrokerSite, String>,
    /// The serve runtime, which a blocking caller's sends run on.
    runtime: tokio::runtime::Handle,
    /// The `[models]` providers a seat's model door may send through (FIX
    /// 15702), by name, as serve resolved them.
    seat_providers: BTreeMap<String, SeatModelProvider>,
}

/// A provider's answer through the broker: its status, and its body with the
/// key stripped.
pub(crate) struct BrokerAnswer {
    pub(crate) status: u16,
    pub(crate) body: Zeroizing<Vec<u8>>,
}

impl BrokerContext {
    /// The context serve builds from the opened `vault`. Its broker is the
    /// one `[models.broker]` names, by default the same-user child beside
    /// this binary, which gives each send the longest timeout of the
    /// consumers `config` gives a vault-secret key (a `[models]` provider,
    /// the System One seat, the endpoint embedder, its remote rung or the
    /// GPU pods). A vault where none does still sends its outside imports'
    /// git exchanges through it (OSH-3), each waiting the transfer idle
    /// limit without progress. `None` outside the serve runtime.
    pub(crate) fn for_serve(vault: &Arc<Vault>, config: &ServeConfig) -> Option<Self> {
        let timeout = vault_secret_sends(config)
            .into_iter()
            .max()
            .unwrap_or_else(|| Duration::from_millis(config.limits.transfer_idle_timeout_ms));
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::warn!("the credential broker context is built inside the serve runtime");
            return None;
        };
        let broker = config
            .models
            .as_ref()
            .map_or_else(BrokerConfig::default, |models| models.broker.clone());
        let keys: Arc<dyn KeyDoor> = Arc::new(VaultKeyDoor::new(Arc::clone(vault)));
        let seat_providers = config
            .models
            .as_ref()
            .map(seat_model_providers)
            .unwrap_or_default();
        Some(Self::build(keys, &broker, timeout, runtime, seat_providers))
    }

    /// The context over the door `keys` for the `[models]` providers alone,
    /// when one of them names a `key_secret`, for a runtime built with no
    /// serve context ([`super::ModelRuntime::build_with_keys`]); `None` when
    /// none does, or outside a runtime.
    pub(super) fn for_providers(keys: Arc<dyn KeyDoor>, models: &ModelsConfig) -> Option<Self> {
        let timeout = provider_sends(models).max()?;
        let runtime = tokio::runtime::Handle::try_current().ok()?;
        Some(Self::new(keys, &models.broker, timeout, runtime))
    }

    /// The context over the door `keys` and the broker `broker` names, whose
    /// same-user child gives each send `timeout`. The child starts at its
    /// first call.
    pub(crate) fn new(
        keys: Arc<dyn KeyDoor>,
        broker: &BrokerConfig,
        timeout: Duration,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self::build(keys, broker, timeout, runtime, BTreeMap::new())
    }

    fn build(
        keys: Arc<dyn KeyDoor>,
        broker: &BrokerConfig,
        timeout: Duration,
        runtime: tokio::runtime::Handle,
        seat_providers: BTreeMap<String, SeatModelProvider>,
    ) -> Self {
        let site = BrokerSite::with_timeout(broker, timeout).map_err(|error| error.to_string());
        if let Err(error) = &site {
            tracing::warn!(%error, "no credential broker for the vault's secret keys");
        }
        Self {
            inner: Arc::new(Inner {
                keys,
                site,
                runtime,
                seat_providers,
            }),
        }
    }

    /// The broker this context sends through, or why none could be made.
    pub(super) fn site(&self) -> &Result<BrokerSite, String> {
        &self.inner.site
    }

    /// The custody door this context reads its keys at.
    pub(super) fn keys(&self) -> &Arc<dyn KeyDoor> {
        &self.inner.keys
    }

    /// The provider named `name` a seat's model door may send through (FIX
    /// 15702): a `key_secret` provider speaking OpenAI chat or Anthropic
    /// Messages.
    pub(crate) fn seat_model_provider(&self, name: &str) -> Option<&SeatModelProvider> {
        self.inner.seat_providers.get(name)
    }

    fn client(&self, wait: Duration) -> LlmResult<oneiron_broker::BrokerClient> {
        let site = self.inner.site.as_ref().map_err(|error| {
            tracing::warn!(%error, "no credential broker to send through");
            LlmError::from(RetryableLlmError::StreamCut)
        })?;
        site.client(wait).map_err(|error| {
            tracing::warn!(%error, "the credential broker is not one this server may use");
            LlmError::from(FatalLlmError::Auth)
        })
    }

    /// Whether a call with the key `secret` could go now, checked without
    /// reading it: a broker to send through (the same-user child starts here
    /// at its first call), and a key the custody door would release to
    /// `broker:model`. A missing broker or key is refused here, before a
    /// call's permit or measurement starts.
    pub(crate) fn ready(&self, secret: &str) -> LlmResult<()> {
        if let Err(error) = self.client(REPLY_MARGIN)?.ready() {
            tracing::warn!(%error, "no credential broker to send through");
            return Err(RetryableLlmError::StreamCut.into());
        }
        self.inner.keys.check(secret).map_err(|_| {
            tracing::warn!(
                reason = "key_custody_refused",
                "the custody door would refuse a vault-secret key"
            );
            LlmError::from(FatalLlmError::Auth)
        })
    }

    /// Sends the one request `header` checks: reaches the broker, reads the
    /// key `secret` at the door, and hands the broker the key with that
    /// request, waiting at most `wait` for the reply. Nothing reads the key
    /// before the request is checked and the broker reached.
    pub(crate) async fn send(
        &self,
        secret: &str,
        header: &CallHeader,
        body: &[u8],
        wait: Duration,
    ) -> LlmResult<BrokerAnswer> {
        self.send_with_keys(&self.inner.keys, secret, header, body, wait, None, None)
            .await
    }

    /// [`Self::send`] with the key read at `keys`, a door scoped to one
    /// caller (a seat's model door, FIX 15702), over this context's broker.
    /// `release`, when given, runs after the key is read and before the
    /// broker sends: an admitted call's permit starts there (slice 3), and
    /// `lease` counts the physical attempt.
    #[expect(
        clippy::too_many_arguments,
        reason = "one broker call's request, its key door and its release"
    )]
    pub(crate) async fn send_with_keys(
        &self,
        keys: &Arc<dyn KeyDoor>,
        secret: &str,
        header: &CallHeader,
        body: &[u8],
        wait: Duration,
        release: Option<oneiron::llm::DispatchRelease<'_>>,
        lease: Option<&BudgetLease>,
    ) -> LlmResult<BrokerAnswer> {
        header
            .check(body)
            .map_err(|_| LlmError::from(FatalLlmError::InvalidRequest))?;
        // The reply timeout runs a frame past `wait`, so the broker answers
        // `Timeout` before the daemon gives up (FIX 8559).
        let client = self.client(wait.saturating_add(oneiron_broker::FRAME_DEADLINE))?;
        let reply =
            call_with_key_released(&client, keys, secret, header, body, release, lease).await?;
        let (status, _) = answered(reply.outcome)?;
        Ok(BrokerAnswer {
            status,
            body: reply.body,
        })
    }

    /// Opens the one streamed call `header` checks, with the key read at
    /// `keys` (a seat's model door, FIX 15702 slice 2), and leaves its reply
    /// to the caller: its outcome, then its body as the broker clears it.
    /// The request is checked before the broker is reached and the key read;
    /// the whole reply must end within `wait`. `release` and `lease` are as
    /// [`Self::send_with_keys`] takes them.
    #[expect(
        clippy::too_many_arguments,
        reason = "one broker call's request, its key door and its release"
    )]
    pub(crate) async fn open_with_keys(
        &self,
        keys: &Arc<dyn KeyDoor>,
        secret: &str,
        header: &CallHeader,
        body: &[u8],
        wait: Duration,
        release: Option<oneiron::llm::DispatchRelease<'_>>,
        lease: Option<&BudgetLease>,
    ) -> LlmResult<oneiron_broker::BrokerStream> {
        header
            .check(body)
            .map_err(|_| LlmError::from(FatalLlmError::InvalidRequest))?;
        let client = self.client(wait.saturating_add(oneiron_broker::FRAME_DEADLINE))?;
        open_with_key(&client, keys, secret, header, body, release, lease).await
    }

    /// [`Self::send`] for a blocking caller, run on the serve runtime: from
    /// this thread, or from a scoped one when this thread is inside a
    /// runtime (a blocking task, or a Dreamer pass's own runtime).
    pub(crate) fn send_blocking(
        &self,
        secret: &str,
        header: &CallHeader,
        body: &[u8],
        wait: Duration,
    ) -> LlmResult<BrokerAnswer> {
        let run = || {
            self.inner
                .runtime
                .block_on(self.send(secret, header, body, wait))
        };
        if tokio::runtime::Handle::try_current().is_err() {
            return run();
        }
        std::thread::scope(|scope| {
            crate::engine_thread("model-broker-send".into())
                .spawn_scoped(scope, run)
                .expect("failed to spawn thread")
                .join()
        })
        .unwrap_or_else(|_| Err(RetryableLlmError::StreamCut.into()))
    }

    /// The System One seat's transport over this broker, its key the vault
    /// secret `secret`.
    pub(crate) fn system_one(&self, secret: &str) -> Box<dyn SystemOneTransport> {
        Box::new(SystemOneLeg {
            context: self.clone(),
            secret: secret.to_owned(),
        })
    }
}

/// How long each send may run, for every consumer `config` gives a
/// vault-secret key: the `[models]` providers' timeouts, the System One
/// seat's ceiling, the embedder endpoint's and its remote rung's request
/// timeouts, and for the GPU pods their probes and the endpoint's document
/// batches they take.
fn vault_secret_sends(config: &ServeConfig) -> Vec<Duration> {
    let millis = |ms: u64| Duration::from_secs(ms.div_ceil(1000));
    let mut sends: Vec<Duration> = config.models.iter().flat_map(provider_sends).collect();
    if config
        .models
        .as_ref()
        .and_then(|models| models.decisions.system_one.as_ref())
        .is_some_and(|seat| seat.key_secret.is_some())
    {
        sends.push(SYSTEM_ONE_SEND);
    }
    if let Some(embedder) = &config.embedder {
        if embedder.endpoint.key_secret.is_some() {
            sends.push(millis(embedder.endpoint.timeout_ms));
        }
        if let Some(remote) = embedder
            .remote
            .as_ref()
            .filter(|remote| remote.key_secret.is_some())
        {
            sends.push(millis(remote.timeout_ms));
        }
    }
    if config
        .gpu
        .as_ref()
        .is_some_and(|gpu| gpu.key_secret.is_some())
    {
        sends.push(crate::runtime::POD_PROBE_TIMEOUT);
        if let Some(embedder) = &config.embedder {
            sends.push(millis(embedder.endpoint.timeout_ms));
        }
    }
    sends
}

/// The timeout of each `[models]` provider that names a `key_secret`.
fn provider_sends(models: &ModelsConfig) -> impl Iterator<Item = Duration> + '_ {
    models
        .providers
        .values()
        .filter(|provider| provider.key_secret.is_some())
        .map(|provider| Duration::from_secs(provider.timeout_secs))
}

/// The System One seat's requests, each one broker call under the
/// measurement's lease.
struct SystemOneLeg {
    context: BrokerContext,
    secret: String,
}

impl SystemOneTransport for SystemOneLeg {
    fn send<'a>(
        &'a self,
        request: SystemOneHttpRequest,
        lease: &'a BudgetLease,
    ) -> SystemOneTransportFuture<'a> {
        Box::pin(async move {
            let url = reqwest::Url::parse(&request.endpoint)
                .map_err(|_| LlmError::from(FatalLlmError::InvalidRequest))?;
            let header = CallHeader::new(
                lease.id().to_owned(),
                Shape::SystemOne,
                url.origin().ascii_serialization(),
                url.path().to_owned(),
                request.headers,
                request.model,
                is_cloud_node(),
                &request.body,
            );
            let mut answer = self
                .context
                .send(&self.secret, &header, &request.body, request.time_left)
                .await?;
            Ok(SystemOneHttpResponse {
                status: answer.status,
                body: std::mem::take(&mut *answer.body),
            })
        })
    }

    fn preflight(&self) -> LlmResult<()> {
        self.context.ready(&self.secret)
    }
}
