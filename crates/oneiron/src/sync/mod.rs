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
//!   + `ra:` tombstone re-assertion markers (ONE-1156)
//! - `lease` — device-lease registry + receipt origin attestation (ONE-1140)
//! - `selector` — grant-backed closed-subgraph window export selectors
//! - `quota` — per-federated-connection quota plus local maintenance-ingest quota
//! - `server_state` — server-side sync_state persistence (Observer-A-equivalent)

pub mod bridge;
pub mod client;
pub mod connection;
#[cfg(test)]
mod convergence_props_internal;
mod diagnostic_ingest;
pub mod lease;
pub(crate) mod loro_support;
pub mod manager;
pub mod quarantine;
pub mod queue;
pub mod quota;
pub mod schema;
pub mod selector;
pub mod server_state;
pub mod transport;
pub mod types;
pub mod window;

pub use client::{EphemeralChangeOrigin, SyncClient, SyncClientConfig, SyncEvent, SyncStatus};
pub use connection::{ConnectionConfig, LocalUpdate, SyncConnection};
pub use lease::{
    LEASE_DURATION_SECS, LEASE_KEY_PREFIX, LEASE_POP_DOMAIN, LEASE_RECORD_LEN,
    LEASE_RECORD_VERSION, LeaseRecord, LeaseStatus, ROOT_LEASES_MAP, client_id_hex,
    decode_lease_record, encode_lease_record, lease_key, lease_key_prefix, lease_pop_transcript,
    mirror_leases_from_root, vault_id_hex, verify_lease_pop,
};
pub use loro::awareness::{EphemeralEventTrigger, EphemeralStore, EphemeralStoreEvent};
pub use loro::{LoroValue, Subscription};
pub use loro_support::export_updates_since;
pub use manager::WindowManager;
pub use quarantine::{
    MAX_QUARANTINE_ROWS, MAX_QUARANTINE_ROWS_PER_PASS, QUARANTINE_MAX_AGE_SECS,
    QuarantineContainer, QuarantineRecord, ReassertDrainReport, RematDrainReport,
    SyncQuarantineReport, drain_reassert_markers, drain_remat_markers, pending_reassert_windows,
    pending_remat_windows, quarantined_records, sync_doctor,
};
pub use queue::{QueuedEmbedJob, QueuedUpdate, SyncQueue};
pub use quota::{
    AllowBlock, DEFAULT_FEDERATION_FLOOD_PAUSE_SECS,
    DEFAULT_MAINTENANCE_INGEST_MAX_OPS_PER_PEER_WINDOW,
    DEFAULT_MAINTENANCE_INGEST_QUOTA_WINDOW_SECS, DEFAULT_MAX_FEDERATION_WINDOWS_PER_CONNECTION,
    FederationBlockReason, FederationConnectionQuota, FederationPauseReason, FederationQuotaConfig,
    FederationQuotaSnapshot, MaintenanceIngestQuotaConfig, MaintenanceIngestQuotaSnapshot,
    maintenance_ingest_quota_config, maintenance_ingest_quota_snapshots,
    set_maintenance_ingest_quota_config,
};
#[cfg(feature = "test-hooks")]
pub use selector::put_selector_test_federation_grant;
pub use selector::{
    FederationAdmissionRole, SYNC_SELECTOR_SCHEMA_VERSION, SelectorVvRequest, SyncSelector,
    SyncSelectorWorld, admit_federated_window_update, authorize_sync_selector,
    decode_selector_vv_request, decode_sync_selector, encode_selector_vv_request,
    encode_sync_selector, filtered_window_doc,
};
pub use transport::{
    EphemeralWireState, LEGACY_FULL_WINDOW_PROTOCOL_VERSION, MAX_DECODED_PAYLOAD_BYTES,
    PROTOCOL_VERSION, TAG_BULK_TRANSFER, TAG_BULK_TRANSFER_DONE, TAG_EPHEMERAL, TAG_PROTOCOL_HELLO,
    TAG_WINDOW_SYNC, TransportError, decode_bulk_transfer, decode_bulk_transfer_done,
    decode_ephemeral_states, decode_protocol_hello, decode_window_sync, encode_bulk_transfer,
    encode_bulk_transfer_done, encode_ephemeral, encode_ephemeral_states,
    encode_legacy_full_window_protocol_hello, encode_protocol_hello, encode_window_sync,
};
pub use types::{SyncConfig, WindowKey};
