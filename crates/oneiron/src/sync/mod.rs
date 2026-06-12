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
//! - `loro_support` — internal Loro-native byte map and encoding helpers
//! - `types` — Sync configuration, window keys
//! - `schema` — CRDT Doc schema creation (root + window)
//! - `bridge` — Observer-based CRDT ↔ LMDB materialization
//! - `window` — Window lifecycle (load/unload/persist)
//! - `manager` — Production window registry + ARCH-0023b startup recovery
//!   orchestration (pm replay → reverse remat → forward remat → observers)
//! - `quarantine` — `x:` quarantine sink + `rm:` rematerialization markers

pub mod bridge;
pub mod client;
pub mod connection;
pub(crate) mod loro_support;
pub mod manager;
pub mod quarantine;
pub mod queue;
pub mod schema;
pub mod transport;
pub mod types;
pub mod window;

pub use client::{SyncClient, SyncClientConfig, SyncEvent, SyncStatus};
pub use connection::{ConnectionConfig, LocalUpdate, SyncConnection};
pub use loro::Subscription;
pub use loro_support::export_updates_since;
pub use manager::WindowManager;
pub use quarantine::{
    MAX_QUARANTINE_ROWS, QUARANTINE_MAX_AGE_SECS, QuarantineContainer, QuarantineRecord,
    RematDrainReport, SyncQuarantineReport, drain_remat_markers, pending_remat_windows,
    quarantined_records, sync_doctor,
};
pub use queue::{QueuedEmbedJob, QueuedUpdate, SyncQueue};
pub use transport::{
    MAX_DECODED_PAYLOAD_BYTES, PROTOCOL_VERSION, TAG_BULK_TRANSFER, TAG_BULK_TRANSFER_DONE,
    TAG_PROTOCOL_HELLO, TAG_WINDOW_SYNC, TransportError, decode_bulk_transfer,
    decode_bulk_transfer_done, decode_protocol_hello, decode_window_sync, encode_bulk_transfer,
    encode_bulk_transfer_done, encode_protocol_hello, encode_window_sync,
};
pub use types::{SyncConfig, WindowKey};
