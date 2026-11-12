//! Moved from `crates/oneiron/src/vault_shape/apply.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Where one item stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ShapeItemState {
    /// Not reached yet; a torn apply resumes here.
    Pending,
    /// Landed through its door, with that door's receipt.
    Landed { at: u64, receipt: String },
    /// Waits for the owner's word: an owner's apply that approves its `seq`
    /// lands it.
    Proposed,
    /// A new grant an actor's apply filed to the owner's widen inbox, where
    /// accepting `proposal_ref` mints it. Until the owner answers, it waits
    /// as [`Self::Proposed`] does, and an owner's apply may land it.
    Filed {
        proposal_ref: String,
        expires_at: u64,
    },
    /// A new grant an actor's apply tried to file, but the widen inbox
    /// refused, with the reason it gave. It waits as [`Self::Proposed`]
    /// does, and an owner's apply may land it.
    FileRefused { reason: String },
    /// A channel retire the identity's lifecycle gate holds for the owner's
    /// approve-once press on `approval_digest` (FIX 2577). It waits as
    /// [`Self::Proposed`] does, and the owner's next apply asks again as
    /// exactly this request: under `request_ref`, with the quarantine bound
    /// and the clock it first asked with, so the gate reads the same request
    /// and asks for no second approval.
    Held {
        request_ref: String,
        approval_digest: String,
        quarantine_until: u64,
        requested_at: u64,
    },
    /// A channel provision the identity's lifecycle gate holds for the
    /// owner's approve-once press on `approval_digest` (FIX 2300). It waits
    /// as [`Self::Proposed`] does, and the owner's next apply asks again as
    /// exactly this request: under `request_ref`, for the identity
    /// `identity_ref` it first asked for, on the clock it first asked with.
    HeldProvision {
        request_ref: String,
        approval_digest: String,
        identity_ref: String,
        requested_at: u64,
    },
    /// An authority operation, for its AUTHORITY_LOG ceremony.
    Ceremony,
    /// The vault has no door for it yet; nothing landed.
    NoDoor,
    /// Its door refused it, the structure changed since the plan read it,
    /// or the owner declined it.
    Refused { reason: String },
}
