//! The HTTP observer every routed request passes, and the tick that keeps
//! the observed window.
use std::sync::Arc;

pub(crate) async fn observe_http(
    axum::extract::State(server): axum::extract::State<Arc<crate::server::SyncServer>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map_or("unmatched", axum::extract::MatchedPath::as_str);
    let verb = format!("{} {route}", request.method());
    // An MCP envelope counts on its matched route alone, under no caller,
    // whether it came over HTTP or a held socket: the call it carries counts
    // once at the gateway, under the caller it resolves and the tool it
    // names (FIX 1085). A held socket's router serves these two routes
    // alone, so every call on the owner's held socket ends here.
    let surfaces = [
        crate::cli::McpSurface::Primary.path(),
        crate::cli::McpSurface::ToolFirst.path(),
    ];
    if request.method() == axum::http::Method::POST && surfaces.contains(&route) {
        start_window_receipts(&server);
        let _ = server
            .wire_telemetry
            .record_mcp_envelope(&verb, oneiron_vault_contract::now_ts());
        return next.run(request).await;
    }
    // The request's one caller, as its door takes it: on a managed vault the
    // owner his supervisor attested counts as himself.
    let auth = crate::auth::CoreAuth::for_managed_request(
        request.headers(),
        request.extensions(),
        request.uri().path(),
        &server,
    )
    .unwrap_or_else(|| {
        crate::auth::CoreAuth::from_headers(
            request.headers(),
            &server.config,
            server.vault().as_ref(),
        )
    })
    .ok();
    let actor = auth
        .as_ref()
        .map_or("unauthenticated", |a| match a.principal_ref() {
            Some(principal) => principal,
            // An owner-grade credential with no person behind it (the
            // shared secret) speaks for the vault's owner, so its traffic
            // counts as the owner's own (FIX 1087).
            None if a.is_owner_grade() => embedded_owner().unwrap_or(a.principal()),
            None => a.principal(),
        });
    start_window_receipts(&server);
    let _ = server
        .wire_telemetry
        .record(&verb, actor, oneiron_vault_contract::now_ts());
    next.run(request).await
}

/// The vault owner's actor id, as `Vault::ensure_embedded_owner_actor` makes
/// it: the wire actor an owner-grade credential with no person counts under.
fn embedded_owner() -> Option<&'static str> {
    static OWNER: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    OWNER
        .get_or_init(|| {
            oneiron::EntityId::derive(
                oneiron_contracts::entity_id::derived_domains::EMBEDDED_OWNER_ACTOR,
                &[],
            )
            .ok()
            .map(|owner| owner.to_hex())
        })
        .as_deref()
}

pub(crate) fn start_window_receipts(server: &Arc<crate::server::SyncServer>) {
    // The retrieval meters ride along: their worker has its own latch, so
    // either may already run (FIX 11011).
    crate::server::SyncServer::start_retrieval_meter_flush(server);
    // Router construction may happen before its runtime exists. The first
    // runtime-backed request retries this start without losing the flush latch.
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    if server
        .wire_telemetry
        .flusher_started
        .swap(true, std::sync::atomic::Ordering::AcqRel)
    {
        return;
    }
    let weak = Arc::downgrade(server);
    runtime.spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tick.tick().await;
            let Some(server) = weak.upgrade() else {
                break;
            };
            // The tick writes pending limit questions, and the window once it
            // has elapsed, off the runtime's workers: a write that waits for
            // the vault's writer holds back only the tick.
            let now = oneiron_vault_contract::now_ts();
            let _ =
                tokio::task::spawn_blocking(move || server.wire_telemetry.flush_if_expired(now))
                    .await;
        }
    });
}
