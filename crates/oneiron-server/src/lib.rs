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

pub mod actions;
pub mod ai_host;
mod api;
mod auth;
mod broadcast;
pub mod cli;
pub mod commands;
pub mod config;
pub mod control_keys;
mod embedder;
pub mod error;
pub mod feedback_delivery;
mod handler;
mod idempotency;
mod linear_host;
mod livequery;
pub mod managed;
pub mod mcp;
pub mod models;
mod oauth_relay;
mod oneironer;
mod owner;
pub mod projection;
mod protocol;
pub mod runtime;
pub mod server;
mod skills_pack;
pub mod usage;
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
    Router::new()
        .merge(handler::ws_routes(server.clone()))
        .merge(api::api_routes(server))
}

#[cfg(test)]
#[path = "../tests/support/fake_llm.rs"]
mod fake_llm;
#[cfg(test)]
mod test_credentials;
