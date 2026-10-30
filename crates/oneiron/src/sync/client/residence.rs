//! Bounded on-demand home reads on an independent short-lived authenticated
//! socket. The steady sync socket keeps sole ownership of its own reader.
//! Device-side opened-item residence; the home side lives in `crate::sync::residence`.

mod authority;
mod bundle;
mod checkpoint_roots;
pub(crate) mod custody;
pub(crate) mod home_handoff;
mod index;
pub(super) mod kit_fetch;
mod machine_history;
mod pad_custody;
mod promoted_pads;
mod rpc;
mod search;
mod items;
mod search_client;
mod windows;
pub(crate) use authority::{catch_up_authority, pinned_checkpoint_pending};
pub use bundle::{
    PadAdmissionReport, SealedBundleRelay, SealedBundleRelayObservation,
    sealed_bundle_relay_observation,
};
pub(crate) use bundle::{observe_sealed_bundle_relay, relay_sealed_bundle};
pub(crate) use checkpoint_roots::exchange_checkpoint_roots;
pub use index::ResidenceIndexWindow;
pub use kit_fetch::{fetch_sealed_bundle_index_with_kit, fetch_sealed_bundle_with_kit};
pub(crate) use machine_history::fetch_owed_machine_history;
use self::windows::PromotionReply;
pub(crate) use self::windows::retry_refused_retains;
pub(crate) use self::search_client::search_resident;

use serde::Deserialize;

use super::base::{SyncClient, home_reads_window};
use super::types::SyncClientConfig;
use crate::EntityId;
use crate::sync::types::WindowKey;
use rpc::{ResidenceRpc, refused, residence_budgets};

/// Search explicitly distinguishes a complete home answer from a partial
/// offline answer over this device's previously opened, cached items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchSource {
    Home,
    LocalOnly,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResidenceHit {
    pub entity_id: String,
    pub score: f32,
    /// The canonical window holding the hit, so a first touch can open it.
    pub window: WindowKey,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResidenceSearch {
    pub hits: Vec<ResidenceHit>,
    pub source: SearchSource,
    pub complete: bool,
}

/// One grant-checked read cache entry. It is NOT a writable ledger replica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThinItem {
    pub entity_id: EntityId,
    pub window: WindowKey,
    /// The entity header and body, exactly as returned by the home.
    pub raw: Vec<u8>,
    /// The separately grant-checked text document frame.
    pub document: Vec<u8>,
}

/// One item as a host shows it when a person opens it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenedItem {
    /// A canonical local row: a sync-all replica's, a promoted window's or
    /// one this machine wrote.
    Resident {
        entity_id: EntityId,
        window: WindowKey,
        raw: Vec<u8>,
    },
    /// A grant-checked read cache; its window is promoted before any edit.
    Thin(ThinItem),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchHit {
    entity_id: String,
    score: f32,
    window: String,
}

/// The home is a peer, so its promotion snapshot passes the same carrier
/// admission as a raw window update before any byte reaches the window.
#[cfg(test)]
pub(super) fn import_promotion_snapshot(doc: &loro::LoroDoc, snapshot: &[u8]) -> bool {
    crate::sync::window::validate_window_update_locality(doc, snapshot).is_ok()
        && doc.import(snapshot).is_ok()
}

impl SyncClient {
}
