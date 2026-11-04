//! Cursor-page request and projection values for cohort membership.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;

/// Page size used when a caller passes `limit = 0`.
pub const MEMBERSHIP_PAGE_DEFAULT_LIMIT: u32 = 50;

/// Hard ceiling on one membership page.
pub const MEMBERSHIP_PAGE_MAX_LIMIT: u32 = 200;

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

/// How a page under an `at_epoch` ceiling treats a manual enrollment, which
/// carries no saved-query epoch to compare.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManualEpochPolicy {
    /// The row is on the page: the ceiling filters saved-query history only,
    /// and the row's `manual_claim` source says it is not versioned by one.
    IncludeUnversionedClaim,
    /// The row is left off any page that names a ceiling.
    OmitUnderEpochCeiling,
}

/// The manual-enrollment epoch policy campaign pages run (canon-silent; FIX
/// 9669). Including the row withholds nothing and invents no history: its
/// clocks are the claim's own, never compared to the query epoch.
pub const MANUAL_MEMBERSHIP_EPOCH_POLICY: ManualEpochPolicy =
    ManualEpochPolicy::IncludeUnversionedClaim;

/// One membership row.
///
/// A saved-query row folds its entered/exited history; a manual row reports
/// its head claim. [`Self::source`] says which, and so what every clock means.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipRow {
    /// The member.
    pub entity_ref: EntityId,
    /// A saved-query row: `entered` or `exited`, the direction of the newest
    /// folded event. A manual row: the head's own member state, `enrolled`,
    /// `paused`, `exited` or `suppressed`.
    pub state: String,
    /// A saved-query row: valid time of the newest `entered` event. A manual
    /// row: the head claim's valid time.
    pub entered_valid: u64,
    /// A saved-query row: detection time of the newest `entered` event. A
    /// manual row: when the head claim was recorded.
    pub entered_detected: u64,
    /// Valid time of the newest `exited` event, when a saved-query row is
    /// currently out; `None` on a manual row.
    pub exited_valid: Option<u64>,
    /// Detection time of the newest `exited` event, when a saved-query row is
    /// currently out; `None` on a manual row.
    pub exited_detected: Option<u64>,
    /// `data_change`, `scope_change`, or `definition_change`, exactly as CA-02
    /// produced it for the newest folded event; `None` on a manual row.
    pub cause: Option<String>,
    /// Where the row comes from.
    pub source: MembershipRowSource,
}

/// One page of membership rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipPage {
    /// Rows in stable cursor order.
    pub rows: Vec<MembershipRow>,
    /// Cursor for the next page; `None` when the page is the last one.
    pub next_cursor: Option<String>,
}
