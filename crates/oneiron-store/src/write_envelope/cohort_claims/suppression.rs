//! Restrictive contact-suppression inputs, causes and receipts.

use oneiron_contracts::entity_id::EntityId;

/// Why a suppression is being written.
///
/// Closed on purpose: these are the two facts that permanently stop contact. A
/// soft bounce, a complaint, and a delivery are health signals and have no
/// variant here, because giving them one would make "does this suppress?" a
/// property of the call site rather than of the cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionCause {
    /// A permanent delivery failure observed by the sending identity.
    HardBounce,
    /// The counterparty asked to stop.
    Unsubscribe,
}

/// Everything one suppression write turn needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionInput {
    /// PERSON being suppressed.
    pub person_ref: EntityId,
    /// Campaign whose membership is superseded.
    ///
    /// Absent for an inbound signal that names no campaign. The enforcement
    /// claim still lands: `comm.do_not_contact` carries no campaign field by
    /// construction, so a suppression can never be scoped away by moving the
    /// person to another campaign.
    pub campaign_ref: Option<EntityId>,
    /// Channel the suppression is scoped to; normalized here.
    pub channel: String,
    /// Sending identity that observed the failure. Required for
    /// [`SuppressionCause::HardBounce`], which is a fact ABOUT a sender.
    pub sender_ref: Option<EntityId>,
    /// The persisted inbound evidence this suppression derives from.
    pub evidence_ref: EntityId,
    /// When the suppressing event occurred.
    pub occurred_at: u64,
}

/// What one suppression write turn landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionReceipt {
    /// The `comm.bounce` head, for [`SuppressionCause::HardBounce`] only.
    pub bounce_claim_ref: Option<EntityId>,
    /// The `comm.do_not_contact` head. Always present — this is the claim the
    /// external-effect gate reads.
    pub do_not_contact_claim_ref: EntityId,
    /// The suppressed `campaign.member` heads, one per live head the campaign
    /// had, in their own claim-id order; empty when none matched.
    pub member_claim_refs: Vec<EntityId>,
}
