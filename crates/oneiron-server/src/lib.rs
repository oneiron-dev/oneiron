//! Oneiron CRDT sync server library.
//!
//! Hosts the root + per-window Loro Docs OVER LMDB (vault + sync_state) per
//! ARCH-0023b Fig. 1: imported client updates are persisted synchronously to
//! `sync_state` before fan-out, window/root snapshots reload on boot, and the
//! `/ws` upgrade requires a logged, holder-bound capability slip (fail-closed
//! when configured).
//!
//! The binary (`main.rs`) and the integration tests share this construction
//! path: [`server::SyncServer::new`] + [`build_app`].
//!
//! [`managed`] adds a second, opt-in way to run that same path: as a
//! supervised child process behind `--managed-by-hypnos`. Without the switch
//! nothing in this crate behaves differently.
#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        reason = "a test process starts its own subprocesses; the rule covers the server's crates"
    )
)]

pub mod actions;
mod admission;
pub mod ai_host;
mod api;
mod auth;
mod big_rung;
mod broadcast;
mod byte_line;
pub mod cli;
pub mod commands;
pub mod config;
pub mod control_keys;
mod decision_graph;
pub mod decision_host;
mod decision_verdict;
mod device_local;
mod embedder;
pub mod error;
pub mod feedback_delivery;
mod handler;
mod http_listener;
mod idempotency;
mod linear_host;
mod livequery;
pub mod logging;
mod machine;
pub mod managed;
pub mod mcp;
pub mod models;
mod oauth_relay;
mod oneironer;
mod owner;
pub mod projection;
mod protocol;
pub mod replay_judge;
pub mod runtime;
pub mod server;
mod skills_pack;
pub mod usage;
mod wake_adapters;
pub mod web_client;
pub mod wire_health;
pub mod wire_telemetry;
// Process-local driver attachment only; this adds no HTTP/MCP route.
// The stream/output owner still has to supply production serve prerequisites.
#[cfg(unix)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "private voice bindings are host-injected; no provider factory in this daemon"
    )
)]
#[doc(hidden)]
pub mod voice_host;

use std::sync::Arc;

use axum::Router;

use crate::server::SyncServer;

pub use crate::projection::View;

/// Builds the complete Axum app (WebSocket + HTTP API routes).
///
/// Serve it on a multi-thread Tokio runtime, outside a `LocalSet`. WebSocket
/// read RPCs run synchronously and leave the worker with `block_in_place`,
/// which a `LocalSet` forbids; on a current-thread runtime they hold the only
/// executor thread while they read.
pub fn build_app(server: Arc<SyncServer>) -> Router {
    let position = if server.managed_issuer.is_some() || server.vault().is_host_readable() {
        web_client::DeploymentPosition::Cloud
    } else {
        web_client::DeploymentPosition::LocalDaemon
    };
    build_app_for_position(server, position)
}

/// The shared HTTP surface over a host-selected transport, including an
/// in-process app's channel. A binding that embeds the router declares
/// `Embedded` so discovery never describes its grants as a process boundary.
pub fn build_app_for_position(
    server: Arc<SyncServer>,
    position: web_client::DeploymentPosition,
) -> Router {
    let mode = if server.managed_issuer.is_some() {
        oneiron::HostingPrivacyPosture::Hosted
    } else {
        server.vault().privacy_posture()
    };
    Router::new()
        .merge(handler::ws_routes(server.clone()))
        .merge(api::api_routes(server))
        .merge(web_client::routes(web_client::EndpointDescriptor::engine(
            position, mode,
        )))
}

/// Builds the artifact-only app: `/a/` and nothing else, for a listener of
/// its own, so a code bundle's scripts run on an origin that holds no API.
/// Serve it beside [`build_app`] over the same server, and record its port
/// with [`SyncServer::with_artifact_listener`] before the server is shared.
pub fn build_artifact_app(server: Arc<SyncServer>) -> Router {
    api::artifact_app(server)
}

#[cfg(test)]
#[path = "../tests/support/fake_llm.rs"]
mod fake_llm;
#[cfg(test)]
mod test_credentials;
