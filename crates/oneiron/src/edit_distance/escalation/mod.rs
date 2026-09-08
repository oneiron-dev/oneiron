//! ED-06 (ONE-1762, ARCH-0056 §7): the schema behind an escalated ask — what
//! the engine asked, what the human ruled, and what a stable pattern of rulings
//! is allowed to become.
//!
//! # The split with ES-07
//!
//! ES-07 (ONE-1720) decides WHEN to escalate and consumes the answer. This
//! module owns the STORAGE schema those seams write into and read back — the
//! punt `effect_spine_oracle.rs` recorded as "storage schema deferred to
//! workbench #6". One function is the seam in the other direction:
//! [`standing_policy_for`], the widened public read ES-07 consults to skip an
//! ask it already has a standing answer for.
//!
//! # Three surfaces
//!
//! 1. **The escalation ledger.** [`record_escalation`] appends one
//!    [`EscalationReceipt`] per ruled ask: the task it was about, the scope it
//!    fell in, which of the three [`EscalationTrigger`]s fired, the question,
//!    the [`EscalationRuling`], and the rationale. Rows are append-only and
//!    scope-major, so one scope's history is a contiguous range.
//! 2. **Aggregation.** [`escalation_stats`] folds one `(scope, trigger)` pair's
//!    rows into counts plus the newest [`ESCALATION_LAST_RULINGS_BOUND`]
//!    rulings. It reads the same rows the receipt projector does, so a caller
//!    can rebuild the identical numbers from receipts alone (CID-7).
//! 3. **Standing policy.** [`maybe_propose_standing_policy`] mints ONE
//!    *proposed* [`StandingPolicy`] row when the newest N rulings on a
//!    `(scope, trigger)` agree, citing the receipts that earned it.
//!    [`accept_standing_policy`] is the owner's tap and the only door to
//!    [`StandingPolicyStatus::Accepted`] — nothing here graduates silently.
//!
//! # One delta language
//!
//! An [`EscalationRuling::Amend`] carries ED-01's [`AmendmentDelta`], stored as
//! the bytes [`AmendmentDelta::encode`] produced and read back through
//! [`AmendmentDelta::decode`]. Same bytes, same decode, lane-wide — a Δ that
//! rode an inbox approve-with-edit and a Δ that rode an escalation amendment
//! are the same artifact, down to the receipt field key they land in.
//!
//! # Storage and receipts
//!
//! Rows live in `vault_meta` under this module's own key prefixes (the house
//! per-feature pattern, as `inbox::INBOX_REVIEW_DIAL_KEY` does; `settings.rs`
//! is UI customization and is not involved — the N dial's key const lives
//! here). Receipts are PROJECTIONS of those rows, in the `Gate` family beside
//! MS-06's demotion rows and ED-05's offer answers: an escalation is a gate
//! decision a human made, so it mints no new [`ReceiptKind`]. The `escalation`
//! FIELD CLASS (`crate::receipt::FIELD_ESCALATION_SCOPE` and its siblings) is
//! what tells the families apart inside the kind.
//!
//! # The budget guard
//!
//! `unsure` and `policy` asks are alike within a scope, so `(scope, trigger)`
//! is the whole key. A `budget` ask is not: four approvals of a trivial amount
//! are no evidence at all about a large one. Budget rows therefore carry
//! [`StandingPolicy::budget_band_ceiling`] — the largest band EVERY citing
//! ruling covered — and [`StandingPolicy::covers_ask`] is the one place that
//! comparison happens, so ES-07 consults a decision rather than re-deriving it.

mod ledger;
mod policy;
mod receipts;
mod storage;
mod types;

pub use self::ledger::{
    DEFAULT_ESCALATION_STANDING_N, ESCALATION_LAST_RULINGS_BOUND, ESCALATION_STANDING_N_KEY,
    escalation_standing_n, escalation_stats, record_escalation, set_escalation_standing_n,
};
pub use self::policy::{
    accept_standing_policy, maybe_propose_standing_policy, standing_policy_for,
};
pub(crate) use self::receipts::escalation_receipts;
#[cfg(test)]
pub(crate) use self::ledger::record_escalation_at;
#[cfg(test)]
pub(crate) use self::policy::{accept_standing_policy_at, maybe_propose_standing_policy_at};
pub use self::receipts::{is_escalation_receipt, is_standing_policy_receipt};
pub use self::types::{
    EscalationReceipt, EscalationRuling, EscalationStats, EscalationTrigger, StandingPolicy,
    StandingPolicyStatus,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::storage::*;
#[cfg(test)]
use crate::edit_distance::delta::AmendmentDelta;
#[cfg(test)]
use crate::entity_id::{ENTITY_ID_LEN, EntityId, bytes_to_hex_lower};
#[cfg(test)]
use crate::error::Error;
#[cfg(test)]
use crate::receipt::{
    FIELD_AMENDMENT_DELTA, FIELD_ESCALATION_BUDGET_BAND, FIELD_ESCALATION_CITED_RECEIPTS,
    FIELD_ESCALATION_QUESTION, FIELD_ESCALATION_RATIONALE, FIELD_ESCALATION_RULING,
    FIELD_ESCALATION_SCOPE, FIELD_ESCALATION_TRIGGER, FIELD_TASK_REF, ReceiptKind, ReceiptQuery,
    ReceiptRecord,
};
#[cfg(test)]
use crate::vault::Vault;
