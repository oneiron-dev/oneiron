//! Moved from `crates/oneiron/src/world_keys/owner_work/diagnostics.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Serialize;

/// Why a bundle publication's home may keep no sealed copy, as its profile
/// stands here (FIX 4786), or which worlds its newest generation leaves to a
/// reader (FIX 4496). The request stays pending as it was; this only says
/// why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BundleHomeWarning {
    /// The home's profile is a phone's: its own doors keep no sealed copy
    /// (DEC-0005, SEALED_BUNDLE_DEVICE_POLICY), so no publisher's upload
    /// lands there.
    HomeDoesNotKeepSealedBundles,
    /// No live profile of the home is known here: whether it keeps sealed
    /// copies is unknown.
    HomeProfileUnknown,
    /// The home's newest generation, as this install's relay last read it,
    /// files each of these worlds' authority capsule sealed to no recovery
    /// root pinned here now: the current kit restores that world's keys only
    /// once a machine that reads it publishes again (FIX 4496).
    AwaitingReader { worlds: Vec<EntityId> },
}

impl BundleHomeWarning {
    /// The words a surface shows.
    #[must_use]
    pub fn text(&self) -> &'static str {
        match self {
            Self::HomeDoesNotKeepSealedBundles => {
                "the home is a phone, which keeps no sealed copy; the request stays pending until \
                 you ask for a home that keeps one"
            }
            Self::HomeProfileUnknown => {
                "no profile of the home is known here, so whether it keeps sealed copies is unknown"
            }
            Self::AwaitingReader { .. } => {
                "the home's newest copy keeps these worlds' keys sealed for an earlier recovery \
                 kit or none; the current kit restores each once a machine that reads it \
                 publishes again"
            }
        }
    }
}
