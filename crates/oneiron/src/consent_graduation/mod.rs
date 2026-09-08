//! DEC-0006 consent-graduation ramp (ARCH-0055 r7 / ONE-1748, MS-06): the
//! per-scope outcome statistics that decide when the engine may OFFER to stop
//! asking, and the transparent self-demotion that takes the offer back.
//!
//! The ramp is a dial on ASKING FREQUENCY, never a wall on ops. It governs one
//! question and one only — *may this actor skip the propose lane for this kind
//! of op on this class of target?* — and it answers it with the owner's own
//! ruling history rather than a heuristic.
//!
//! Three surfaces, deliberately separated:
//!
//! 1. **Measurement** ([`ScopeOutcomeStats`]) is universal. Every resolved
//!    proposal folds into its scope's counters, whatever the op kind. Counters
//!    are a rebuildable projection (CID-7): every input is a durable,
//!    receipt-visible act, and [`Vault::rebuild_ramp_stats_from_receipts`]
//!    drops the whole table and refolds those acts, landing byte-identically
//!    on what incremental maintenance produced. There are exactly two input
//!    families, and NOTHING moves a counter outside them:
//!    - identity-topology **resolution events** (the type-76 ledger, which the
//!      ARCH-0055 r7 proposal-outcome receipts project), and
//!    - this module's own append-only rows — door-recorded outcomes and
//!      demotions — which project as `Gate` receipts (surface 4 below).
//!
//!    The refold reads the LEDGER for the first family rather than its receipt
//!    projection: `identity_topology_events_in_txn` is documented as the one
//!    enumeration surface "the fold, the receipt projection, and any rebuild
//!    share", and unlike the public receipt query it is not truncated to the
//!    newest `MAX_RECEIPT_QUERY_SCAN` rows — a bounded rebuild would delete a
//!    complete projection and refold a suffix of it, silently erasing trust
//!    older scopes had earned. Suppression matches the receipt projection's
//!    exactly: a resolution the fold rejects as a duplicate ruling is not an
//!    outcome anywhere.
//! 2. **Graduation** (offer → owner tap → standing grant) is GATED by
//!    [`op_kind_is_ramp_eligible`]. Identity-topology ops (merge/split/facet/…)
//!    ride their own consent axis — `IdentityOpWrite::approval`, chosen per
//!    write by the caller — and are AUTO day one (r3), so they are never placed
//!    on the propose→auto ramp: no offer is ever surfaced for them, no standing
//!    grant is ever minted from them, and no apply path consults this module.
//!    Oracle: `ms06_merge_split_never_gated_by_ramp`.
//! 3. **Authority** is not ours to mint. A crossed streak surfaces an OFFER;
//!    only [`Vault::accept_graduation_offer`] — which demands an
//!    [`AuthenticatedOwner`] because it routes through the one
//!    [`Vault::create_standing_grant`] door — creates a grant. DEC-0006
//!    invariant 5, enforced by the type system rather than by review.
//!
//! 4. **Nothing this module records is silent.** A demotion revokes the
//!    standing grant and appends a durable demotion row (oracle
//!    `ms06_self_demotion_is_receipted_never_silent`); a ruling recorded
//!    through [`Vault::record_proposal_outcome_for_ramp`] — the propose-lane
//!    door for surfaces that have no identity-topology ledger event — appends
//!    a durable outcome row. Both project as a SECOND [`ReceiptKind::Gate`]
//!    receipt family, registered beside the gate-decision projector in
//!    `receipt::collect_receipt_records` and discriminated by receipt-id
//!    prefix ([`is_ramp_demotion_receipt`] / [`is_ramp_outcome_receipt`]).
//!    Without the outcome row a streak would be trust no receipt witnesses and
//!    the next rebuild would erase it — apparent earned autonomy backed by
//!    nothing.
//!
//! These are deliberately NOT synthetic `GateDecisionRecord`s in the
//! gate-decision store: ONE-1637 made that store the erasure chain's H0 index,
//! and a ramp bookkeeping row has no business in it. They are equally
//! deliberately not `ReceiptKind::ProposalOutcome`: every member of that family
//! names a real type-76 resolution event, and ED-01 joins it on
//! `proposal_ref` / `amended_body`. `ProposalOutcome` likewise stays at exactly
//! three states (`ms05_proposal_outcome_has_exactly_three_states`) — a demotion
//! is an act on a scope, not a fourth way to rule a proposal.
//!
//! ED-05 ([`crate::edit_distance::graduation`], ONE-1761) is the policy and UX
//! layer above this projector, and it owns two things this module deliberately
//! no longer decides:
//!
//! * **What a streak has to be worth.** [`DEFAULT_GRADUATION_STREAK_FLOOR`] is
//!   now the streak axis of ED-05's compiled catch-all threshold row, which
//!   pairs it with a posterior guard; `derive_state_in_txn` asks
//!   `graduation_policy_in_txn` rather than comparing against a floor itself.
//!   [`Vault::set_ramp_streak_floor`] survives unchanged as the per-scope
//!   override, and is the most specific statement in that resolution.
//! * **Whether to ASK.** Snooze and manual-pin are ED-05 state, consulted by
//!   [`Vault::graduation_offers`] alone. [`RampState`] is untouched by them on
//!   purpose: it answers what authority is live, and an offer the owner
//!   snoozed is still an offer they may accept.

mod doors;
mod fold;
mod receipts;
mod scope;
mod state;
mod storage;

pub use self::receipts::{is_ramp_demotion_receipt, is_ramp_outcome_receipt};
pub use self::scope::{DEFAULT_GRADUATION_STREAK_FLOOR, RampScope, op_kind_is_ramp_eligible};
pub use self::state::{DemotionReason, RampState, ScopeOutcomeStats};

pub(crate) use self::doors::accept_graduation_offer_in_txn;
pub(crate) use self::fold::{
    active_grant_ref_in_txn, offer_is_standing_in_txn, ramp_floor_override_in_txn,
    ramp_stats_in_txn, record_ramp_outcome_in_txn,
};
pub(crate) use self::receipts::ramp_receipts;

#[cfg(test)]
mod tests;

// The flat consent_graduation.rs module used to provide these names to the
// sibling test module through `use super::*`. After the directory split the
// `pub use` seam above covers every public name the tests use bare; the glob
// below covers the `pub(super)` internals (`decode_row`, `StoredScopeStats`,
// the fold helpers) that no re-export carries.
#[cfg(test)]
use self::{fold::*, storage::*};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::identity_topology::ProposalOutcome;
#[cfg(test)]
use crate::receipt::{ReceiptKind, ReceiptQuery};
#[cfg(test)]
use crate::vault::Vault;
