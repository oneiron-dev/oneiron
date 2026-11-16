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
    let verb = format!("{} {route}", method_label(request.method()));
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
        record_on_blocking_pool(&server, move |telemetry, now| {
            telemetry.record_mcp_envelope(&verb, now)
        })
        .await;
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
        })
        .to_owned();
    start_window_receipts(&server);
    record_on_blocking_pool(&server, move |telemetry, now| {
        telemetry.record(&verb, &actor, now)
    })
    .await;
    next.run(request).await
}

/// The method as the wire window names it: one of the nine methods HTTP
/// defines (RFC 9110 section 9, and PATCH, RFC 5789), or `OTHER` for any
/// extension method, which the router refuses only after this observer has
/// counted the call. A route so has at most ten labels however many methods
/// its callers invent (FIX [WIRE-TELEMETRY-METHOD-LABELS-UNBOUNDED]).
fn method_label(method: &axum::http::Method) -> &str {
    match method.as_str() {
        standard @ ("GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS"
        | "TRACE" | "PATCH") => standard,
        _ => "OTHER",
    }
}

/// Runs one count on the blocking pool and waits for it. A window's rollover
/// keeps the window, and a crossing keeps a question, both through the
/// vault's write door under the counter's std mutex, so the wait holds a
/// blocking thread, never one of the runtime's workers (FIX
/// [WIRE-TELEMETRY-SYNC-PERSIST-ON-ASYNC-PATH]). The count still lands before
/// the caller goes on. A count that fails is telemetry lost, never a refusal.
///
/// A count on the blocking pool runs to its end even when its call is
/// dropped, so each holds one of `MAX_PENDING_COUNTS` permits until it ends.
/// A call with no permit free waits for one here, on the runtime, and that
/// wait ends with the call: calls dropped while the counter is held leave at
/// most that many counts behind.
pub(crate) async fn record_on_blocking_pool(
    server: &Arc<crate::server::SyncServer>,
    count: impl FnOnce(&super::WireTelemetry, u64) -> oneiron::Result<()> + Send + 'static,
) {
    let now = oneiron_vault_contract::now_ts();
    let Ok(permit) = Arc::clone(&server.wire_telemetry.pending_counts)
        .acquire_owned()
        .await
    else {
        return;
    };
    let server = Arc::clone(server);
    let _ = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        count(&server.wire_telemetry, now)
    })
    .await;
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
