//! The `reranker` role's backend for one provider: over the provider's own HTTP client, over
//! the credential broker for a `key_secret` key (L9-12), or on its `listen = "unix"` workers'
//! sockets alone (L9-15).

use super::*;

/// The rerank client for provider `name`'s reranker `models`: over the
/// provider's own HTTP client; for a `key_secret` key, over the credential
/// broker at `site` with the key read at `keys` (L9-12), as the offer's T0
/// custody says; or, for a provider its `listen = "unix"` worker rows serve
/// (L9-15), on those workers' sockets alone. Beside it, that last client's
/// on-device alternative, when this process launches those workers: the
/// same client, whose every call stays on this device.
pub(super) fn build_reranker(
    name: &str,
    provider: &ProviderConfig,
    models: &[ModelRef],
    workers: &[WorkerConfig],
    site: Option<&Result<broker::BrokerSite, String>>,
    keys: Option<&Arc<dyn KeyDoor>>,
) -> anyhow::Result<(Arc<dyn SingleRouteBackend>, Option<NativeLocal>)> {
    anyhow::ensure!(
        provider.siwc.is_none(),
        "SIWC credentials serve Responses, not reranking"
    );
    let socket_served = workers
        .iter()
        .any(|row| row.binding.provider == name && row.listens_on_socket());
    let mut socket_workers = BTreeMap::new();
    let transport = if socket_served {
        let socket = rerank::SocketRerank::new(
            worker_host::socket_routes(name, provider, workers),
            http::SocketHeaders::new(provider)?,
            Duration::from_secs(provider.timeout_secs),
        );
        socket_workers = socket.workers();
        rerank::RerankTransport::Socket(socket)
    } else if provider.key_secret.is_some() {
        rerank::RerankTransport::Broker(broker_rerank::BrokerRerank::new(provider, site, keys)?)
    } else {
        rerank::RerankTransport::Direct(http::ProviderHttp::new(provider, http::KeyStyle::Bearer)?)
    };
    let wire_models = models
        .iter()
        .map(|model| Ok((engine_model_id(model, provider)?, model.model.clone())))
        .collect::<anyhow::Result<_>>()?;
    let backend: Arc<dyn SingleRouteBackend> =
        Arc::new(rerank::RerankBackend::new(transport, wire_models));
    let on_device = (!socket_workers.is_empty()).then(|| NativeLocal {
        backend: Arc::clone(&backend),
        workers: socket_workers,
    });
    Ok((backend, on_device))
}
