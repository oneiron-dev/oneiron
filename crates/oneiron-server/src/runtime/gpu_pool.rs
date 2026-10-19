//! The serve host's owner of the per-region GPU registry. It registers the
//! configured pods, polls their transport/app/inference health, hands out
//! leases that renew themselves and release on drop, and binds derivation jobs
//! to the holding vault's account. Workers pick a pod only through a lease, so
//! the registry stays the one router; this adds no second scheduler.
use super::gpu::{
    GPU_RENEW_SECONDS, GpuDerivationLease, GpuHealth, GpuLease, GpuRegistry, GpuRegistryError,
};
use crate::models::BrokerContext;
use oneiron::federation::derivation::{DerivationScope, SealedOutput};
use oneiron_broker::{CallHeader, Shape};
use rand_core::RngCore;
use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// One rented inference pod: a stable id, its base URL and how many leases it
/// serves at once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuPodConfig {
    pub id: String,
    pub url: String,
    pub capacity: usize,
}

/// The `[gpu]` serve section: one region's batch pods (ARCH-0019 §5, the
/// batch lane). Voice keeps its own warm tier and never routes here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuPoolConfig {
    pub region: String,
    #[serde(default)]
    pub pods: Vec<GpuPodConfig>,
    /// App liveness path on each pod; a 2xx marks the app healthy.
    #[serde(default = "default_health_path")]
    pub health_path: String,
    /// Inference readiness path; a 2xx marks the model loaded and serving.
    #[serde(default = "default_ready_path")]
    pub ready_path: String,
    #[serde(default = "default_poll_seconds")]
    pub poll_seconds: u64,
    /// The environment variable holding the pods' bearer key, if they take
    /// one. Pods never see the embedder endpoint's own key.
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// The vault secret holding the pods' bearer key, sent through the
    /// credential broker for each probe and batch; HTTPS pods only. Never
    /// the embedder endpoint's own key.
    #[serde(default)]
    pub key_secret: Option<String>,
}

impl GpuPoolConfig {
    /// Pods are reached as the embedder endpoint is: HTTPS unless loopback,
    /// and no credential or query in the URL.
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.region.is_empty(), "gpu.region must not be empty");
        anyhow::ensure!(self.poll_seconds > 0, "gpu.poll_seconds must be at least 1");
        for path in [&self.health_path, &self.ready_path] {
            anyhow::ensure!(path.starts_with('/'), "gpu health paths start with '/'");
        }
        if let Some(secret) = &self.key_secret {
            anyhow::ensure!(
                self.api_key_env.is_none(),
                "gpu: set api_key_env or key_secret, not both"
            );
            anyhow::ensure!(
                !secret.is_empty()
                    && secret.len() <= 256
                    && secret.bytes().all(|b| b.is_ascii_graphic()),
                "gpu.key_secret must name a vault secret (printable ASCII, no spaces); put the key itself in the vault, never in the config file"
            );
            anyhow::ensure!(
                Shape::Health.check_path(&self.health_path).is_ok()
                    && Shape::OpenAiModels.check_path(&self.ready_path).is_ok(),
                "gpu.key_secret: the credential broker probes a pod at …/health and …/v1/models only"
            );
        }
        let mut ids = std::collections::BTreeSet::new();
        for pod in &self.pods {
            anyhow::ensure!(
                !pod.id.is_empty() && ids.insert(pod.id.as_str()),
                "gpu.pods ids must be non-empty and distinct"
            );
            anyhow::ensure!(
                pod.capacity > 0,
                "gpu pod {} needs a capacity of at least 1",
                pod.id
            );
            let url = reqwest::Url::parse(&pod.url)
                .map_err(|_| anyhow::anyhow!("gpu pod {} has an invalid URL", pod.id))?;
            anyhow::ensure!(
                matches!(url.scheme(), "http" | "https")
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "gpu pod {} URL must not contain credentials or query secrets",
                pod.id
            );
            let loopback = url.host_str().is_some_and(|host| {
                host == "localhost"
                    || host
                        .trim_matches(['[', ']'])
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
            anyhow::ensure!(
                loopback || url.scheme() == "https",
                "gpu pod {} is a network pod and needs HTTPS",
                pod.id
            );
            anyhow::ensure!(
                self.key_secret.is_none()
                    || (url.scheme() == "https"
                        && url.path().trim_end_matches('/').ends_with("/v1")),
                "gpu pod {}: the credential broker sends to an https pod URL ending in /v1 only",
                pod.id
            );
        }
        Ok(())
    }
}

fn default_health_path() -> String {
    "/health".into()
}
fn default_ready_path() -> String {
    "/v1/models".into()
}
fn default_poll_seconds() -> u64 {
    15
}

/// How long one pod probe may take.
pub(crate) const POD_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn entropy() -> [u64; 2] {
    [rand_core::OsRng.next_u64(), rand_core::OsRng.next_u64()]
}

struct Inner {
    registry: Mutex<GpuRegistry>,
    urls: BTreeMap<String, String>,
    config: GpuPoolConfig,
    bearer: Option<HeaderValue>,
    secret: Option<PodSecret>,
    runtime: tokio::runtime::Handle,
}

/// The vault secret the pods' key is read from for each request, and the
/// credential-broker context that sends it: `None` where serve opened none,
/// so every request to a pod fails before it is sent.
struct PodSecret {
    name: String,
    broker: Option<BrokerContext>,
}

/// The production owner of one region's [`GpuRegistry`]. Cheap to clone.
#[derive(Clone)]
pub struct GpuPool {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for GpuPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpuPool")
            .field("region", &self.inner.config.region)
            .field("pods", &self.inner.urls.len())
            .finish()
    }
}

impl GpuPool {
    /// Registers every pod as unhealthy; nothing routes to a pod before its
    /// first health poll passes. Must be called inside the serve runtime.
    pub fn new(config: GpuPoolConfig) -> anyhow::Result<Self> {
        Self::with_broker(config, None)
    }

    /// [`Self::new`], with the vault's credential-broker context a
    /// `key_secret` pool's probes and batches send through.
    pub(crate) fn with_broker(
        config: GpuPoolConfig,
        broker: Option<&BrokerContext>,
    ) -> anyhow::Result<Self> {
        config.validate()?;
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| anyhow::anyhow!("the GPU pool starts inside the serve runtime"))?;
        let mut registry = GpuRegistry::new(config.region.clone())?;
        let mut urls = BTreeMap::new();
        for pod in &config.pods {
            registry.register(pod.id.clone(), pod.capacity, GpuHealth::default())?;
            urls.insert(pod.id.clone(), pod.url.trim_end_matches('/').to_owned());
        }
        let bearer = match &config.api_key_env {
            Some(name) => {
                let key = std::env::var(name).map_err(|_| {
                    anyhow::anyhow!("gpu.api_key_env names a variable that is not set")
                })?;
                let mut value = HeaderValue::from_str(&format!("Bearer {key}"))
                    .map_err(|_| anyhow::anyhow!("invalid GPU pod authorization value"))?;
                value.set_sensitive(true);
                Some(value)
            }
            None => None,
        };
        let secret = config.key_secret.clone().map(|name| PodSecret {
            name,
            broker: broker.cloned(),
        });
        Ok(Self {
            inner: Arc::new(Inner {
                registry: Mutex::new(registry),
                urls,
                config,
                bearer,
                secret,
                runtime,
            }),
        })
    }

    /// The pods' own authorization header, for a worker's pod client.
    pub fn bearer(&self) -> Option<&HeaderValue> {
        self.inner.bearer.as_ref()
    }

    /// The vault secret the pods' key is read from, and the broker context
    /// that sends it, for a worker's pod requests.
    pub(crate) fn key_secret(&self) -> Option<(&str, Option<&BrokerContext>)> {
        self.inner
            .secret
            .as_ref()
            .map(|secret| (secret.name.as_str(), secret.broker.as_ref()))
    }

    pub fn region(&self) -> &str {
        &self.inner.config.region
    }

    fn registry(&self) -> std::sync::MutexGuard<'_, GpuRegistry> {
        self.inner
            .registry
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn url(&self, pod: &str) -> Result<String, GpuRegistryError> {
        self.inner
            .urls
            .get(pod)
            .cloned()
            .ok_or(GpuRegistryError::Unavailable)
    }

    /// Probes one pod: transport is any HTTP answer, app is a 2xx on the
    /// health path, inference is a 2xx on the readiness path. Both paths
    /// resolve against the pod's origin, as an absolute link does: `/health`
    /// on `https://pod/v1` is `https://pod/health`.
    async fn probe(&self, client: &reqwest::Client, pod: &str, url: &str) -> GpuHealth {
        if let Some(secret) = &self.inner.secret {
            return self.probe_brokered(pod, url, secret).await;
        }
        let at = |path: &str| reqwest::Url::parse(url).and_then(|base| base.join(path));
        let (Ok(health_url), Ok(ready_url)) = (
            at(&self.inner.config.health_path),
            at(&self.inner.config.ready_path),
        ) else {
            return GpuHealth::default();
        };
        let health = client
            .get(health_url)
            .timeout(POD_PROBE_TIMEOUT)
            .send()
            .await;
        let Ok(health) = health else {
            return GpuHealth::default();
        };
        let app = health.status().is_success();
        let inference = app
            && client
                .get(ready_url)
                .timeout(POD_PROBE_TIMEOUT)
                .send()
                .await
                .is_ok_and(|r| r.status().is_success());
        GpuHealth {
            transport: true,
            app,
            inference,
        }
    }

    /// [`Self::probe`] through the credential broker, with the key the
    /// vault secret holds: each probe is one broker call to the pod's own
    /// origin, `GET …/health` then `GET …/v1/models`. A broker or key that
    /// is not there leaves the pod unhealthy.
    async fn probe_brokered(&self, pod: &str, url: &str, secret: &PodSecret) -> GpuHealth {
        let (Some(broker), Ok(base)) = (&secret.broker, reqwest::Url::parse(url)) else {
            return GpuHealth::default();
        };
        let origin = base.origin().ascii_serialization();
        // A probe names no model: the pod's id is its call's binding.
        let get = |shape: Shape, path: &str| {
            CallHeader::new(
                format!("gpu:{pod}"),
                shape,
                origin.clone(),
                path.to_owned(),
                Vec::new(),
                pod.to_owned(),
                &[],
            )
        };
        let config = &self.inner.config;
        let health_call = get(Shape::Health, &config.health_path);
        let Ok(health) = broker
            .send(&secret.name, &health_call, &[], POD_PROBE_TIMEOUT)
            .await
        else {
            return GpuHealth::default();
        };
        let app = (200..300).contains(&health.status);
        let ready_call = get(Shape::OpenAiModels, &config.ready_path);
        let inference = app
            && broker
                .send(&secret.name, &ready_call, &[], POD_PROBE_TIMEOUT)
                .await
                .is_ok_and(|answer| (200..300).contains(&answer.status));
        GpuHealth {
            transport: true,
            app,
            inference,
        }
    }

    pub async fn poll_health(&self, client: &reqwest::Client) {
        for (id, url) in &self.inner.urls {
            let health = self.probe(client, id, url).await;
            let _ = self.registry().set_health(id, health);
            if !health.healthy() {
                tracing::warn!(region = %self.region(), pod = %id, ?health, "gpu pod unhealthy");
            }
        }
        self.registry().expire(now());
    }

    /// Polls every pod at once, then on the configured cadence, for the life
    /// of the serve runtime.
    pub fn spawn_health_poller(&self) -> tokio::task::JoinHandle<()> {
        let pool = self.clone();
        let period = Duration::from_secs(self.inner.config.poll_seconds.max(1));
        self.inner.runtime.spawn(async move {
            let mut headers = reqwest::header::HeaderMap::new();
            if let Some(bearer) = pool.bearer() {
                headers.insert(reqwest::header::AUTHORIZATION, bearer.clone());
            }
            let client = match reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .default_headers(headers)
                .build()
            {
                Ok(client) => client,
                Err(error) => {
                    tracing::warn!(%error, "gpu health client; no pod turns healthy");
                    return;
                }
            };
            let mut tick = tokio::time::interval(period);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                pool.poll_health(&client).await;
            }
        })
    }

    fn spawn_renewer(&self, id: u64, lost: Arc<AtomicBool>) -> tokio::task::AbortHandle {
        let pool = self.clone();
        let period = Duration::from_secs(GPU_RENEW_SECONDS);
        self.inner
            .runtime
            .spawn(async move {
                let mut tick =
                    tokio::time::interval_at(tokio::time::Instant::now() + period, period);
                loop {
                    tick.tick().await;
                    if pool.registry().renew(id, now()).is_err() {
                        lost.store(true, Ordering::Release);
                        return;
                    }
                }
            })
            .abort_handle()
    }

    /// Routes one batch job to a healthy pod by two-choice load. The lease
    /// renews every [`GPU_RENEW_SECONDS`] and releases when dropped.
    pub fn acquire(&self) -> Result<GpuLeaseGuard, GpuRegistryError> {
        let lease = self.registry().acquire(now(), entropy())?;
        let url = match self.url(&lease.pod) {
            Ok(url) => url,
            Err(e) => {
                self.registry().release(lease.id);
                return Err(e);
            }
        };
        let lost = Arc::new(AtomicBool::new(false));
        let renewer = self.spawn_renewer(lease.id, lost.clone());
        Ok(GpuLeaseGuard {
            pool: self.clone(),
            lease,
            url,
            lost,
            renewer,
        })
    }

    /// Routes one derivation for the holding vault's account. The host, not
    /// the pod, supplies `scope`, so the output seals to that account.
    pub fn acquire_derivation(
        &self,
        scope: DerivationScope,
        computation: Vec<u8>,
        content: Vec<u8>,
    ) -> Result<GpuDerivationJob, GpuRegistryError> {
        let job =
            self.registry()
                .acquire_derivation(scope, computation, content, now(), entropy())?;
        let url = match self.url(&job.lease().pod) {
            Ok(url) => url,
            Err(e) => {
                self.registry().release(job.lease().id);
                return Err(e);
            }
        };
        let lost = Arc::new(AtomicBool::new(false));
        let renewer = self.spawn_renewer(job.lease().id, lost.clone());
        Ok(GpuDerivationJob {
            pool: self.clone(),
            job: Some(job),
            url,
            lost,
            renewer,
        })
    }
}

/// A live batch lease on one pod.
pub struct GpuLeaseGuard {
    pool: GpuPool,
    lease: GpuLease,
    url: String,
    lost: Arc<AtomicBool>,
    renewer: tokio::task::AbortHandle,
}

impl GpuLeaseGuard {
    pub fn lease(&self) -> &GpuLease {
        &self.lease
    }
    /// The pod's base URL, without a trailing slash.
    pub fn url(&self) -> &str {
        &self.url
    }
    /// False once a renewal failed: the pod went unhealthy or the lease
    /// expired. The worker should finish or drop the batch and re-acquire.
    pub fn is_live(&self) -> bool {
        !self.lost.load(Ordering::Acquire)
    }
}

impl Drop for GpuLeaseGuard {
    fn drop(&mut self) {
        self.renewer.abort();
        self.pool.registry().release(self.lease.id);
    }
}

/// A live derivation lease, bound to the holding account until completed.
pub struct GpuDerivationJob {
    pool: GpuPool,
    job: Option<GpuDerivationLease>,
    url: String,
    lost: Arc<AtomicBool>,
    renewer: tokio::task::AbortHandle,
}

impl GpuDerivationJob {
    pub fn url(&self) -> &str {
        &self.url
    }
    pub fn is_live(&self) -> bool {
        !self.lost.load(Ordering::Acquire)
    }
    /// Seals `output` to the bound account and frees the pod slot.
    pub fn complete(mut self, output: Vec<u8>) -> Result<SealedOutput, GpuRegistryError> {
        self.renewer.abort();
        let job = self.job.take().ok_or(GpuRegistryError::LeaseExpired)?;
        self.pool.registry().complete_derivation(job, output, now())
    }
}

impl Drop for GpuDerivationJob {
    fn drop(&mut self) {
        self.renewer.abort();
        if let Some(job) = self.job.take() {
            self.pool.registry().release(job.lease().id);
        }
    }
}
