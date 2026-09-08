//! ED-01 (ARCH-0056 §2, ONE-1757): the amendment-Δ schema, its two capture
//! lanes, and the chooser every production caller rides.
//!
//! # What a Δ is
//!
//! [`AmendmentDelta`] answers "how much did the decider change, and how do I
//! find both ends?" for one proposal→outcome window. It is TELEMETRY: the
//! edit-distance loop mines it, and no door blocks on it. That single fact
//! shapes the module — capture failure is reported, never raised into the
//! approval path (see [`capture_delta_best`]'s callers).
//!
//! # Two lanes, one precedence
//!
//! * [`DeltaSource::RecordedOps`] — ED-00's finalized op window
//!   ([`FinalizedProposalText`]) replayed per change. It sees CHURN (text
//!   typed then retyped) that an endpoint comparison cannot, which is why it
//!   outranks the others.
//! * [`DeltaSource::FieldDiff`] — two canonical-MessagePack bodies (claim
//!   bodies, identity-topology op amendments) walked as trees, counting
//!   changed leaves. Cheaper and far more legible than op replay for
//!   structured payloads, where "the survivor field changed" beats "eleven
//!   characters moved".
//! * [`DeltaSource::Reconstructed`] — two endpoint TEXTS diffed line by line
//!   ([`crate::edit_distance::myers`], ED-02). The lane of last resort: it is
//!   the only one that works when an edit arrived out of band, with no op log
//!   and no structured body, and the only one that can report a MOVE.
//!
//! [`capture_delta_best`] pins the precedence `recorded_ops > field_diff >
//! reconstructed` HERE, so no caller hand-picks a lane.
//!
//! # The Δ's own bytes
//!
//! [`AmendmentDelta::encode`] serializes through the house canonical JSON
//! (`crate::llm::canonical_json_bytes`) — sorted keys, so a receipt's Δ
//! payload is stable bytes across processes and orderings.
//!
//! # Where a Δ lives
//!
//! Receipts are PROJECTIONS, not stored rows, so a Δ cannot be stamped onto
//! one after the fact. It lives in its own `vault_meta` row keyed by the
//! RECEIPT ID it belongs to, and `attach_amendment_deltas` folds it into
//! the reserved `amendment_delta` slot as every receipt query projects. The
//! producer artifact the Δ was computed FROM (`amended_body`, ONE-1747) is
//! never touched: two slots, two meanings.
//!
//! A capture that FAILS writes that same row as
//! `AMENDMENT_DELTA_UNCAPTURED_ROW` and projects its own receipt marker.
//! Non-fatal, but never silent: an approval whose Δ could not be measured
//! must not look identical to one nothing has measured yet.

mod lanes;
mod schema;
mod store;

pub use self::lanes::{
    DeltaCaptureContext, capture_delta_best, delta_from_field_diff, delta_from_reconstructed,
    delta_from_recorded_ops,
};
pub(super) use self::schema::u32_saturating;
pub use self::schema::{AmendmentDelta, DeltaSource, OpsSummary};
pub(crate) use self::store::{
    OUTCOME_APPROVED_AMENDED, amendment_recorded_in_txn, attach_amendment_deltas,
    put_amendment_delta_in_txn,
};
pub use self::store::{amendment_delta, project_identity_amendment_deltas};

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::{lanes::*, store::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::edit_distance::FinalizedProposalText;
#[cfg(test)]
use crate::entity_id::{EntityId, bytes_to_hex_lower};
#[cfg(test)]
use crate::error::Error;
#[cfg(test)]
use crate::receipt::{
    FIELD_AMENDMENT_DELTA, FIELD_AMENDMENT_DELTA_UNCAPTURED, ReceiptKind, ReceiptRecord,
    proposal_outcome_amended_body,
};
#[cfg(test)]
use rmpv::Value;
