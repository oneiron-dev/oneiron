//! Oneiron CRDT sync server library.
//!
//! Hosts the root + per-window Loro Docs OVER LMDB (vault + sync_state) per
//! ARCH-0023b Fig. 1: imported client updates are persisted synchronously to
//! `sync_state` before fan-out, window/root snapshots reload on boot, and the
//! `/ws` upgrade enforces the Phase-1 shared secret (fail-closed when
//! configured).
//!
//! The binary (`main.rs`) and the integration tests share this construction
//! path: [`server::SyncServer::new`] + [`build_app`].
//!
//! [`managed`] adds a second, opt-in way to run that same path: as a
//! supervised child process behind `--managed-by-hypnos`. Without the switch
//! nothing in this crate behaves differently.

mod api;
mod auth;
mod broadcast;
pub mod cli;
pub mod commands;
pub mod config;
pub mod error;
mod handler;
mod idempotency;
mod livequery;
pub mod managed;
pub mod mcp;
mod oauth_relay;
pub mod projection;
mod protocol;
pub mod runtime;
pub mod server;
mod skills_pack;
pub mod usage;
// No production backend/prompt/budget owner is constructed by this daemon yet.
// Keep the integration private and inert until that owner supplies the bindings.
#[cfg(unix)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "private voice bindings are host-injected; no provider factory in this daemon"
    )
)]
mod voice_host;

use std::sync::Arc;

use axum::Router;

use crate::server::SyncServer;

pub use crate::projection::View;

/// Builds the complete Axum app (WebSocket + HTTP API routes).
pub fn build_app(server: Arc<SyncServer>) -> Router {
    Router::new()
        .merge(handler::ws_routes(server.clone()))
        .merge(api::api_routes(server))
}
