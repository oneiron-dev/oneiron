//! Bounded on-demand home reads on an independent short-lived authenticated
//! socket. The steady sync socket keeps sole ownership of its own reader.
//! Device-side opened-item residence; the home side lives in `crate::sync::residence`.

mod authority;
mod bundle;
mod checkpoint_roots;
mod claim_vectors;
pub(crate) use claim_vectors::default_claim_vector;
pub(crate) mod custody;
pub(crate) mod home_handoff;
mod index;
mod items;
pub(super) mod kit_fetch;
mod machine_history;
mod media_vectors;
mod pad_custody;
mod promoted_pads;
mod rpc;
mod search;
mod search_client;
mod windows;
pub(crate) use self::search_client::search_resident;
use self::windows::PromotionReply;
pub(crate) use self::windows::retry_refused_retains;
pub(crate) use authority::{catch_up_authority, pinned_checkpoint_pending};
pub use bundle::{
    PadAdmissionReport, SealedBundleRelay, SealedBundleRelayObservation, UnmergedUpload,
    sealed_bundle_relay_observation,
};
pub(crate) use bundle::{observe_sealed_bundle_relay, relay_sealed_bundle};
pub(crate) use checkpoint_roots::exchange_checkpoint_roots;
pub use index::ResidenceIndexWindow;
pub use kit_fetch::{fetch_sealed_bundle_index_with_kit, fetch_sealed_bundle_with_kit};
pub(crate) use machine_history::fetch_owed_machine_history;
pub(crate) use media_vectors::request_media_vectors;
pub use search::ResidenceSearchPage;

use serde::Deserialize;

use super::base::{SyncClient, home_reads_window};
use super::types::SyncClientConfig;
use crate::EntityId;
use crate::sync::types::WindowKey;
use rpc::{ResidenceRpc, refused, residence_budgets};

pub use crate::memory::residence_item::{
    OpenedItem, ResidenceHit, ResidenceSearch, SearchSource, ThinItem,
};

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

impl SyncClient {}
