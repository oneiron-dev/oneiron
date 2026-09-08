//! WebSocket upgrade handler and connection lifecycle.
//!
//! Each WebSocket connection follows the protocol from ARCH-023 §3.2:
//! 1. Phase 1: Root doc sync (send snapshot to new client)
//! 2. Phase 2: Default windows (current + previous) via VV exchange + updates
//! 3. Phase 3: Historical windows via BulkTransfer (oldest first) + BulkTransferDone
//! 4. Ongoing: bidirectional incremental sync via WindowSync + ephemeral state

mod app_tier;
mod conn_state;
mod connection;
mod ephemeral;
mod hello;
mod transport;
mod window_sync;

pub(crate) use self::connection::ws_routes;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod app_tier_tests;

// The flat handler.rs module used to provide these names to the sibling test
// modules through `use super::*`: every handler-internal item the tests name
// bare, and the external names the old file's import header supplied. After
// the directory split the seam re-imports both so `tests.rs` and
// `app_tier_tests.rs` resolve exactly as they did before.
#[cfg(test)]
use self::{
    app_tier::*, conn_state::*, connection::*, ephemeral::*, hello::*, transport::*, window_sync::*,
};
#[cfg(test)]
use crate::auth::{CoreAuth, RevokedTokenJtis};
#[cfg(test)]
use crate::protocol::{self, ProtocolError, SyncMessage, close_codes, window_sub_tags};
#[cfg(test)]
use crate::server::SyncServer;
#[cfg(test)]
use axum::extract::ws::{CloseFrame, Message as WsMessage, Utf8Bytes};
#[cfg(test)]
use futures_util::StreamExt;
#[cfg(test)]
use loro::VersionVector;
#[cfg(test)]
use oneiron::sync::{AllowBlock, FederationQuotaConfig, WindowKey};
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::task::Poll;
