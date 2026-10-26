//! Manual-enrollment rows: a head no saved query derived reports its own claim.

use super::{
    MANUAL_MEMBERSHIP_EPOCH_POLICY, ManualEpochPolicy, MembershipHead, MembershipRow,
    MembershipRowSource,
};
use crate::campaign::claims::CampaignMemberState;

/// The row for a manually enrolled head (FIX 9669).
///
/// Its state is the head's own member state, and its clocks are the head
/// claim's: its valid time and when it was recorded. No CA-02 event exists for
/// it, so it carries no exit clocks and no cause, and its source says
/// `manual_claim` rather than implying an entry event. Under an `at_epoch`
/// ceiling, [`MANUAL_MEMBERSHIP_EPOCH_POLICY`] decides whether it is on the
/// page; the ceiling is never compared with the claim's clocks.
pub(super) fn manual_membership_row(
    head: &MembershipHead,
    state: CampaignMemberState,
    valid_at: u64,
    recorded_at: u64,
    at_epoch: Option<u64>,
) -> Option<MembershipRow> {
    let on_page = match MANUAL_MEMBERSHIP_EPOCH_POLICY {
        ManualEpochPolicy::IncludeUnversionedClaim => true,
        ManualEpochPolicy::OmitUnderEpochCeiling => at_epoch.is_none(),
    };
    on_page.then(|| MembershipRow {
        entity_ref: head.entity_ref,
        state: state.as_str().to_owned(),
        entered_valid: valid_at,
        entered_detected: recorded_at,
        exited_valid: None,
        exited_detected: None,
        cause: None,
        source: MembershipRowSource::ManualClaim {
            membership_claim_ref: head.claim_ref,
        },
    })
}
