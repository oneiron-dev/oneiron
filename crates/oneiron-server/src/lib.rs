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

mod api;
mod broadcast;
pub mod cli;
pub mod commands;
pub mod config;
pub mod error;
mod handler;
mod idempotency;
pub mod projection;
mod protocol;
pub mod server;
mod skills_pack;
pub mod usage;

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
