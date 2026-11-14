//! Moved from `crates/oneiron/src/memory/campaign_records/membership.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One page request against a campaign's or a query's membership.
///
/// `owner_ref` is the CAMPAIGN for [`read_campaign_members`] and the
/// SAVED_QUERY for [`read_saved_query_members`]. `at_epoch`, when present,
/// reads saved-query history as of that membership epoch — the bitemporal
/// read. It is a saved-query epoch, not a clock: a manual enrollment carries
/// none, and [`MANUAL_MEMBERSHIP_EPOCH_POLICY`] says how its row is treated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipReadRequest {
    /// The campaign or saved query whose membership is being paged.
    pub owner_ref: EntityId,
    /// Opaque cursor from a prior page's `next_cursor`.
    pub cursor: Option<String>,
    /// Requested page size; `0` means [`MEMBERSHIP_PAGE_DEFAULT_LIMIT`] and
    /// anything above [`MEMBERSHIP_PAGE_MAX_LIMIT`] is clamped to it.
    pub limit: u32,
    /// Optional saved-query epoch ceiling; query events after it are not
    /// folded into the row.
    pub at_epoch: Option<u64>,
}

/// Where a membership row's clocks, state and cause come from.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MembershipRowSource {
    /// A saved query derived the membership: the row folds CA-02's
    /// entered/exited history for the query, the entity and the campaign.
    SavedQuery {
        /// The query that derived the membership.
        query_ref: EntityId,
        /// The live `campaign.member` head.
        membership_claim_ref: EntityId,
        /// Epoch of the newest folded event.
        epoch: u64,
    },
    /// A manual enrollment wrote the membership (FIX 9669): the row reports
    /// the live head claim itself, its state and its own clocks. No
    /// saved-query event exists for it, and none is implied.
    ManualClaim {
        /// The live `campaign.member` head.
        membership_claim_ref: EntityId,
    },
}
