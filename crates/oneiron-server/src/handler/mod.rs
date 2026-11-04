//! WebSocket upgrade handler and connection lifecycle.
//!
//! Each WebSocket connection follows the protocol from ARCH-023 §3.2:
//! 1. Phase 1: Root doc sync (send snapshot to new client)
//! 2. Phase 2: Default windows (current + previous) via VV exchange + updates
//! 3. Phase 3: Historical windows via BulkTransfer (oldest first) + BulkTransferDone
//! 4. Ongoing: bidirectional incremental sync via WindowSync + ephemeral state

mod admitted_windows;
mod app_tier;
mod asset_bodies;
mod conn_state;
mod connection;
mod document_copy;
mod documents;
mod ephemeral;
mod federation;
mod hello;
mod lag_resync;
#[cfg(test)]
mod lag_resync_tests;
mod leaf_keys;
mod lfs_chunks;
mod mcp_socket;
pub(crate) mod mesh;
#[cfg(test)]
mod note_socket_tests;
mod protocol_close;
#[cfg(test)]
mod residence_socket_tests;
mod socket_stop;
mod transport;
mod window_copy;
mod window_pads;
#[cfg(test)]
pub(crate) mod window_row_tests;
mod window_sync;

pub(crate) use self::connection::ws_routes;
pub(crate) use self::leaf_keys::LeafKeyRelay;
pub(crate) use self::mcp_socket::{MCP_RPC_METHOD, MCP_SUBPROTOCOL};
pub(crate) use self::window_sync::selector_grant_scope;

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
use oneiron::sync::WindowKey;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::task::Poll;

#[cfg(test)]
mod message_stream_tests;
