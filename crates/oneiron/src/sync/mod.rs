//! CRDT sync layer for Oneiron.
//!
//! This module implements the dual-storage pattern (CRDT Doc ↔ LMDB vault)
//! per ONEIRON-ARCH-023 and ONEIRON-ARCH-023b.
//!
//! # Architecture
//!
//! - **CRDT Doc** (Loro) is the sync truth (determines what propagates to remote)
//! - **LMDB vault** is the retrieval truth (powers queries, search, PPR)
//! - **Entity bridge** (Observer A + B) keeps them synchronized
//!
//! # Modules
//!
//! - `engine` — Engine-agnostic CRDT traits (`CrdtDoc`, `CrdtMap`)
//! - `loro_engine` — Loro implementation of the engine traits
//! - `types` — Sync configuration, window keys
//! - `schema` — CRDT Doc schema creation (root + window)
//! - `bridge` — Observer-based CRDT ↔ LMDB materialization
//! - `window` — Window lifecycle (load/unload/persist)

pub mod bridge;
pub mod client;
pub mod engine;
pub mod loro_engine;
pub mod schema;
pub mod transport;
pub mod types;
pub mod window;

pub use client::{SyncClient, SyncClientConfig, SyncEvent, SyncStatus};
pub use engine::{CrdtDoc, CrdtMap, MapChange, Subscription};
pub use loro_engine::{LoroDocument, LoroMapHandle};
pub use transport::{
    decode_bulk_transfer, decode_bulk_transfer_done, decode_window_sync, encode_bulk_transfer,
    encode_bulk_transfer_done, encode_window_sync, TransportError, TAG_BULK_TRANSFER,
    TAG_BULK_TRANSFER_DONE, TAG_WINDOW_SYNC,
};
pub use types::{SyncConfig, WindowKey};
