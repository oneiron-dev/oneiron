//! ED-05 (ONE-1761, ARCH-0056 §6 · OF-399 · DEC-0006): the graduation POLICY
//! and the offer-answer UX above MS-06's outcome-stats projector.
//!
//! MS-06 ([`crate::consent_graduation`]) MEASURES: it folds every ruling into a
//! per-scope clean streak and derives the consent posture from it. It shipped
//! exactly one policy knob — a single compiled streak floor. This module is the
//! layer that decides what a streak has to LOOK LIKE before the engine offers
//! to stop asking, and what becomes of an offer once the owner has seen it.
//!
//! # Three surfaces
//!
//! 1. **Threshold rows.** [`ThresholdRow`] is `(scope pattern, required streak,
//!    posterior guard)`: a streak length a human can read out loud ("five clean
//!    approvals") plus a floor on what that streak is worth as EVIDENCE. Rows
//!    are DATA — a compiled default table plus runtime rows the owner writes
//!    through [`set_graduation_policy`] — and [`graduation_policy_for`] is the
//!    one function that resolves them for a scope. MS-06's offer check calls
//!    it; the compiled streak floor it replaced survives as that table's
//!    catch-all row.
//! 2. **The posterior guard.** A bare streak is a run of luck at small `n`: two
//!    clean approvals and twelve clean approvals are the same SHAPE of evidence
//!    and wildly different amounts of it, and a scope that was corrected ten
//!    times before its current clean run has not earned what a spotless scope
//!    earned. The guard is a floor on the Beta posterior's one-sided 95% LOWER
//!    bound — see [`posterior_lower_bound`] — so a row can demand confidence,
//!    not just repetition.
//! 3. **The offer answer.** An offer has three answers, not two:
//!    [`OfferAnswer::GoAuto`] mints the standing grant through MS-06's
//!    owner-only door; [`OfferAnswer::NotNow`] snoozes it on a compiled
//!    backoff; and the THIRD answer is emergent — a third "not now" is the
//!    owner saying *stop asking*, which lands as
//!    [`SnoozeState::ManualPinned`] and is undone only by [`unpin_scope`].
//!
//! # What a pin is, and is not
//!
//! A pin suppresses ASKS. It does not suppress the propose lane, it is not
//! distrust, and it never expires: it is a dial the owner set, so nothing in
//! here may auto-unpin, age it out, or reinterpret it as evidence about the
//! scope. A pinned scope keeps proposing exactly as it did, keeps folding
//! outcomes, and keeps its posture in [`crate::consent_graduation::RampState`]
//! — the ramp state answers *what authority is live*, the snooze state answers
//! *are we asking about it*, and the two are deliberately orthogonal columns of
//! [`trust_table`]. That is also why [`OfferAnswer::GoAuto`] is accepted while
//! snoozed or pinned: suppression silences the engine, never the owner.
//!
//! # Storage
//!
//! Two `vault_meta` key families, both owned here (the house pattern of a
//! per-feature key const over `vault_meta`, as `inbox::INBOX_REVIEW_DIAL_KEY`
//! does; `settings.rs` is UI customization and is not involved):
//!
//! * threshold rows, keyed by a digest of their pattern, and
//! * the append-only ANSWER LOG, keyed by scope then time.
//!
//! The snooze state is not stored. It is replayed from that scope's answers on
//! every read ([`snooze_state`]), so there is no projection that can drift from
//! the acts that produced it and no rebuild door to keep honest — the log is
//! both the truth and the state. It is also what `answer_receipts_in_txn`
//! projects, which is how "every transition is receipted" is mechanical rather
//! than remembered.

use serde::Serialize;

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Keyspace + pinned strings
// ---------------------------------------------------------------------------
/// `vault_meta` key prefix of a runtime threshold row. The full key is this
/// prefix followed by [`pattern_key`] — a digest rather than the pattern text,
/// because a pattern of three [`crate::consent::MAX_CONSENT_REF_LEN`] segments
/// is far past what belongs in a key.
const THRESHOLD_KEY_PREFIX: &[u8] = b"graduation_threshold:v1:";

/// `vault_meta` key prefix of the append-only offer-answer log. The full key is
/// this prefix ‖ [`RampScope::key`] (16 B) ‖ row id (16 B).
///
/// Keying by SCOPE first is what makes replay cheap: one scope's answers are a
/// contiguous range. The trailing id is a UUIDv7, so key order is WRITE order —
/// MS-06's law that caller-supplied wall time is data and never order holds
/// here too, and it has to: an unpin recorded with an earlier `at` than the
/// decline it undoes would otherwise replay before it and undo nothing.
const ANSWER_KEY_PREFIX: &[u8] = b"graduation_answer:v1:";

/// Receipt-id prefix of an offer-answer receipt — the
/// [`is_graduation_answer_receipt`] discriminator inside the `Gate` family,
/// beside MS-06's two.
const ANSWER_RECEIPT_PREFIX: &str = "graduation_answer:";

/// Only accepted schema version for either stored row.
const ROW_VERSION: u8 = 1;

/// Domain separator for the threshold-pattern digest.
const PATTERN_DIGEST_DOMAIN: &[u8] = b"oneiron.edit_distance.graduation.pattern.v1";

const THRESHOLD_ROW_LABEL: &str = "graduation threshold row";

const ANSWER_ROW_LABEL: &str = "graduation answer row";

fn encode_row<T: Serialize>(row: &T, label: &'static str) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| Error::InvariantViolation(label))
}

fn decode_row<T: serde::de::DeserializeOwned>(raw: &[u8], label: &'static str) -> Result<T> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex(label))
}

fn meta_key(prefix: &[u8], handle: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + handle.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(handle);
    key
}

mod answers;
mod pattern;
mod posterior;
mod receipts;
mod threshold_policy;
mod trust_table;

pub use self::answers::{
    OfferAnswer, OfferAnswerOutcome, SnoozeState, answer_graduation_offer, snooze_state,
    unpin_scope,
};
pub use self::pattern::{WILDCARD_PATTERN, exact_pattern};
pub use self::posterior::{guard_evidence, posterior_lower_bound};
pub use self::receipts::is_graduation_answer_receipt;
pub use self::threshold_policy::{
    DEFAULT_POSTERIOR_GUARD, ThresholdRow, clear_graduation_policy, graduation_policy_for,
    graduation_policy_rows, set_graduation_policy,
};
pub use self::trust_table::{TrustTableRow, trust_table};

pub(crate) use self::answers::{asks_are_suppressed_in_txn, record_go_auto_answer_in_txn};
pub(crate) use self::receipts::answer_receipts_in_txn;
pub(crate) use self::threshold_policy::graduation_policy_in_txn;

#[cfg(test)]
mod tests;

// The flat graduation.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every graduation-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::{answers::*, receipts::*, threshold_policy::*};
#[cfg(test)]
use crate::consent::AuthenticatedOwner;
#[cfg(test)]
use crate::consent_graduation::{DEFAULT_GRADUATION_STREAK_FLOOR, RampScope, RampState};
#[cfg(test)]
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
#[cfg(test)]
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
#[cfg(test)]
use crate::vault::Vault;
