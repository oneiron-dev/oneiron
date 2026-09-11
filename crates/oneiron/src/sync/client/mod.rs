//! Client-side sync over WebSocket.
//!
//! Implements the device side of the ARCH-0023b connection flow:
//! 1. Phase 1: Root doc sync (server sends snapshot, client imports)
//! 2. Phase 2: Default windows (current + previous) via VV exchange + updates
//! 3. Phase 3: Historical windows arrive via BulkTransfer + BulkTransferDone
//! 4. Ongoing: bidirectional incremental sync via WindowSync
//!
//! Reconnection with exponential backoff (1s → 60s cap).
//! 50ms debounce for rapid edits before sending.
//!
//! # Manager-owned windows (ONE-1126)
//!
//! Window docs are NOT private bare `LoroDoc`s: every window the client
//! touches is a manager-owned [`LoadedWindow`] obtained through
//! [`WindowManager::open_window`], which consults persisted `sync_state`
//! first (`d:w:{key}` snapshot + pending `u:w:{key}:*` replay — ARCH-0023b
//! startup step 2), runs the pinned recovery order, and attaches
//! Observer A + B last. Remote updates imported here therefore reach LMDB
//! through Observer B, and local commits flow outbound through Observer A's
//! [`crate::sync::bridge::OutboundSink`].
//!
//! # Client-persisted sync_state rows (ARCH-0023b key table)
//!
//! - `d:root` / `sv:root` / `svf:root` — root doc snapshot + state vector,
//!   persisted on every accepted root import; reloaded on restart with
//!   pending `u:root:*` replay (startup step 1).
//! - `m:client_id` — this device's CRDT client id (u64 LE, 8 bytes), minted
//!   once and stable per install (mint lives in `crate::identity`, OD-2).
//! - `m:device_sk` / `m:device_pk` — this device's Ed25519 attestation
//!   keypair (32 B each; ONE-1140, OD-2), minted alongside the client id.
//! - `ls:{vault_id_hex}:{client_id_hex}` — device-lease registry mirror rows
//!   (66 B pinned record, ONE-1140 OD-3/OD-4): full-mirrored from the root
//!   doc's `leases` map in the SAME txn as every root persist.
//! - `m:last_sync` — last successful sync timestamp (u64 LE, 8 bytes).
//! - `bulk:w:{key}` — BulkTransfer in-progress marker (device only);
//!   cleared when `BulkTransferDone` persistence succeeds.
//! - `sv:w:{key}` / `svf:w:{key}` — read by the fast-reconnect path in
//!   [`SyncClient::generate_initial_sync`]: a fresh flag lets the client
//!   answer the VV exchange from the persisted state vector without
//!   loading the window doc.

mod base;
mod federated;
mod inbound;
mod sync_frames;
mod types;

pub use self::base::SyncClient;
pub use self::sync_frames::next_backoff;
pub use self::types::{EphemeralChangeOrigin, SyncClientConfig, SyncEvent, SyncStatus};

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::{federated::*, types::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::error::{Error, SyncConfigField, SyncProtocolValidation};
#[cfg(test)]
use crate::sync::loro_support::export_updates_since;
#[cfg(test)]
use crate::sync::manager::WindowManager;
#[cfg(test)]
use crate::sync::selector::{FederationAdmissionRole, SyncSelector};
#[cfg(test)]
use crate::sync::transport;
#[cfg(test)]
use crate::sync::transport::{
    MAX_DECODED_PAYLOAD_BYTES, TAG_SYNC_UPDATE, TAG_VERSION_VECTOR, TAG_WINDOW_SYNC,
    TransportError, window_sub_tags,
};
#[cfg(test)]
use crate::sync::types::{WindowKey, parse_window_key_str};
#[cfg(test)]
use crate::sync::window::LoadedWindow;
#[cfg(test)]
use loro::{LoroDoc, VersionVector};
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use tokio::sync::mpsc;
