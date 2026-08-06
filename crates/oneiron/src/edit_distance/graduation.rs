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
//! both the truth and the state. It is also what [`answer_receipts_in_txn`]
//! projects, which is how "every transition is receipted" is mechanical rather
//! than remembered.

use serde::{Deserialize, Serialize};

use crate::consent::{AuthenticatedOwner, ConsentReceipt};
use crate::consent_graduation::{
    DEFAULT_GRADUATION_STREAK_FLOOR, RampScope, RampState, ScopeOutcomeStats,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use crate::store::Store;
use crate::vault::Vault;

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

// ---------------------------------------------------------------------------
// Threshold rows
// ---------------------------------------------------------------------------

/// The pattern segment that matches any value on its axis.
const PATTERN_WILDCARD: &str = "*";

/// The pattern axis separator.
const PATTERN_SEPARATOR: char = '/';

/// The character a lone [`PATTERN_WILDCARD`] axis is spelled with.
const PATTERN_WILDCARD_CHAR: char = '*';

/// Escapes the next character, so a pattern axis can spell a scope field that
/// contains a reserved one.
///
/// A [`RampScope`] field is arbitrary text — MS-06 trims it, rejects empty and
/// caps its length, and nothing more — so `op_kind = "send/email"` and
/// `target_class = "*"` are ordinary valid scopes. Without an escape,
/// [`exact_pattern`] would produce four axes for the first and a wildcard for
/// the second: a pattern that no row can be built from, and a pattern that
/// governs every scope on that axis. Either would make `exact_pattern` a lie
/// over part of the domain it accepts.
const PATTERN_ESCAPE: char = '\\';

/// Whether `ch` must be escaped to appear literally in a pattern axis.
const fn is_pattern_reserved(ch: char) -> bool {
    matches!(
        ch,
        PATTERN_ESCAPE | PATTERN_SEPARATOR | PATTERN_WILDCARD_CHAR
    )
}

/// The catch-all pattern: every scope matches it, which is what makes the
/// compiled table total.
pub const WILDCARD_PATTERN: &str = "*/*/*";

/// The compiled catch-all guard.
///
/// Co-designed with [`DEFAULT_GRADUATION_STREAK_FLOOR`], not picked apart from
/// it: a SPOTLESS twelve-approval streak clears exactly 0.819 on
/// [`posterior_lower_bound`], so the default row fires for a scope that has
/// never been corrected and holds one that has — a twelve-streak with two
/// earlier corrections behind it sits at 0.657 and keeps proposing until it has
/// built more evidence.
pub const DEFAULT_POSTERIOR_GUARD: f32 = 0.8;

/// The compiled policy table: patterns the engine ships believing.
///
/// One row, deliberately. The catch-all is the FLOOR every scope falls back to
/// — a per-op-kind default the canon never ruled would be policy this module
/// invented. Everything narrower is the owner's, minted at runtime through
/// [`set_graduation_policy`], and a narrower row always wins.
const COMPILED_POLICY: &[(&str, u32, f32)] = &[(
    WILDCARD_PATTERN,
    DEFAULT_GRADUATION_STREAK_FLOOR,
    DEFAULT_POSTERIOR_GUARD,
)];

/// One legible graduation threshold: which scopes it governs, how long a clean
/// streak they owe, and how strong that streak has to be as evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct ThresholdRow {
    /// `op_kind/target_class/actor`, each axis either a literal or `*`, with
    /// `\` escaping a reserved character inside a literal ([`exact_pattern`]
    /// writes those; the owner rarely needs to).
    pub scope_pattern: String,
    /// Consecutive clean rulings before the scope may be offered graduation.
    pub required_streak: u32,
    /// Minimum [`posterior_lower_bound`] of the scope's history.
    pub posterior_guard: f32,
}

impl ThresholdRow {
    /// Builds a row, rejecting what could never govern anything.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConsentBound`] when the pattern is not three non-empty
    /// `/`-separated axes with well-formed escapes, when the streak is zero (a
    /// threshold nothing has to clear), or when the guard is not a real number
    /// in `[0, 1]`.
    pub fn new(
        scope_pattern: impl Into<String>,
        required_streak: u32,
        posterior_guard: f32,
    ) -> Result<Self> {
        let scope_pattern = scope_pattern.into();
        if pattern_axes(&scope_pattern).is_none() {
            return Err(Error::InvalidConsentBound(
                "graduation scope pattern must be op_kind/target_class/actor, each a literal or *",
            ));
        }
        if required_streak == 0 {
            return Err(Error::InvalidConsentBound(
                "a graduation threshold of zero clean rulings is not a threshold",
            ));
        }
        if !(0.0..=1.0).contains(&posterior_guard) {
            return Err(Error::InvalidConsentBound(
                "graduation posterior guard must be a probability in [0, 1]",
            ));
        }
        Ok(Self {
            scope_pattern,
            required_streak,
            posterior_guard,
        })
    }

    /// Whether this row governs `scope`.
    #[must_use]
    pub fn matches(&self, scope: &RampScope) -> bool {
        let Some(axes) = pattern_axes(&self.scope_pattern) else {
            return false;
        };
        let fields = [&scope.op_kind, &scope.target_class, &scope.actor];
        axes.iter()
            .zip(fields)
            .all(|(axis, field)| axis_matches(axis, field))
    }

    /// Whether a history of `streak` clean rulings and `corrections`
    /// amendments-or-rejections clears this row.
    #[must_use]
    pub fn is_cleared_by(&self, streak: u32, corrections: u32) -> bool {
        streak >= self.required_streak
            && posterior_lower_bound(streak, corrections) >= self.posterior_guard
    }

    /// The row MS-06's one-axis per-scope override
    /// ([`Vault::set_ramp_streak_floor`]) means in a two-axis world: the streak
    /// the owner dialed, guarded at exactly what a SPOTLESS run of that length
    /// is worth.
    ///
    /// This is what keeps that dial honest. Pair a dialed streak of two with a
    /// catch-all guard meant for twelve and the dial silently never fires;
    /// pair it with no guard at all and a scope with ten corrections behind it
    /// graduates on two lucky approvals. Guarding at `lower_bound(streak, 0)`
    /// says precisely "this many CLEAN rulings" — spotless clears it, the same
    /// length with corrections behind it does not.
    fn for_dialed_streak(scope: &RampScope, streak: u32) -> Result<Self> {
        // A dialed floor of zero is still a dial, not a waiver: it becomes the
        // smallest real threshold, and the trust table shows the one it became.
        let streak = streak.max(1);
        Self::new(
            exact_pattern(scope),
            streak,
            posterior_lower_bound(streak, 0),
        )
    }

    /// Literal (non-wildcard) axes: the more specific row wins.
    fn specificity(&self) -> u8 {
        pattern_axes(&self.scope_pattern).map_or(0, |axes| {
            axes.iter()
                .map(|axis| u8::from(*axis != PATTERN_WILDCARD))
                .sum()
        })
    }
}

/// The three axes of a pattern — still escaped — or `None` when it is not
/// three well-formed non-empty ones.
///
/// Splits on UNESCAPED separators only, and rejects an escape that names
/// nothing or escapes an unreserved character. The second half is what keeps
/// the encoding canonical: one axis has exactly one spelling, so one pattern
/// has exactly one [`pattern_key`], and two rows can never mean the same thing
/// under two keys.
fn pattern_axes(pattern: &str) -> Option<[&str; 3]> {
    let mut axes = [""; 3];
    let mut filled = 0;
    let mut start = 0;
    let mut escaped = false;
    for (idx, ch) in pattern.char_indices() {
        if escaped {
            if !is_pattern_reserved(ch) {
                return None;
            }
            escaped = false;
        } else if ch == PATTERN_ESCAPE {
            escaped = true;
        } else if ch == PATTERN_SEPARATOR {
            *axes.get_mut(filled)? = pattern.get(start..idx)?;
            filled += 1;
            start = idx + ch.len_utf8();
        }
    }
    if escaped {
        return None;
    }
    *axes.get_mut(filled)? = pattern.get(start..)?;
    if filled != 2 || axes.iter().any(|axis| axis.is_empty()) {
        return None;
    }
    Some(axes)
}

/// Whether one escaped pattern axis governs one scope field.
///
/// Compares against the unescaped axis without materializing it — the axis is
/// well-formed by [`pattern_axes`], so a walk in lockstep with the field is the
/// whole comparison.
fn axis_matches(axis: &str, field: &str) -> bool {
    if axis == PATTERN_WILDCARD {
        return true;
    }
    let mut field = field.chars();
    let mut escaped = false;
    for ch in axis.chars() {
        if !escaped && ch == PATTERN_ESCAPE {
            escaped = true;
            continue;
        }
        escaped = false;
        if field.next() != Some(ch) {
            return false;
        }
    }
    field.next().is_none()
}

/// The pattern that names exactly one scope and nothing else — for every scope
/// [`RampScope::new`] accepts, reserved characters included.
#[must_use]
pub fn exact_pattern(scope: &RampScope) -> String {
    let mut pattern = String::new();
    for (index, field) in [&scope.op_kind, &scope.target_class, &scope.actor]
        .into_iter()
        .enumerate()
    {
        if index > 0 {
            pattern.push(PATTERN_SEPARATOR);
        }
        for ch in field.chars() {
            if is_pattern_reserved(ch) {
                pattern.push(PATTERN_ESCAPE);
            }
            pattern.push(ch);
        }
    }
    pattern
}

// ---------------------------------------------------------------------------
// The posterior guard
// ---------------------------------------------------------------------------

/// One-sided 95% normal quantile.
///
/// The same constant, over the same Beta standard deviation, that SK-05's
/// `skill_reliability::SkillReliabilityPosterior::lower_bound` rides. The two
/// implementations are deliberately local and deliberately identical: neither
/// module depends on the other, and a second Z or a second σ would let the
/// engine hold two different opinions about how much evidence is enough.
const POSTERIOR_GUARD_Z: f64 = 1.645;

/// The uniform Beta(1, 1) prior every scope starts from — no scope is born
/// trusted, and none is born suspect.
const POSTERIOR_PRIOR: f64 = 1.0;

/// One-sided 95% lower confidence bound on the success rate of a history of
/// `wins` clean rulings and `losses` corrections, on a Beta(1, 1) prior:
/// `mean − Z·σ` clamped to `[0, 1]`, with `σ = sqrt(αβ / ((α+β)²(α+β+1)))`.
///
/// This is what makes the guard an EVIDENCE floor rather than a second streak
/// count. Anchors, both of which a threshold row of 0.8 sorts correctly:
/// 2 wins / 0 losses → ≈ 0.43 (two clean approvals are barely evidence at all),
/// 90 / 10 → ≈ 0.84.
// The f64 intermediate exists so the square root keeps its digits; the
// compared value never needed the width.
#[expect(
    clippy::cast_possible_truncation,
    reason = "f64 intermediate narrowed to the f32 a threshold row stores"
)]
#[must_use]
pub fn posterior_lower_bound(wins: u32, losses: u32) -> f32 {
    let alpha = POSTERIOR_PRIOR + f64::from(wins);
    let beta = POSTERIOR_PRIOR + f64::from(losses);
    let total = alpha + beta;
    let std_dev = (alpha * beta / (total * total * (total + 1.0))).sqrt();
    (alpha / total - POSTERIOR_GUARD_Z * std_dev).clamp(0.0, 1.0) as f32
}

/// The `(wins, losses)` a scope's counters present to the guard.
///
/// Wins are the CURRENT clean streak, losses are every correction the scope has
/// ever drawn. Asymmetric on purpose: MS-06 zeroes the streak on any
/// non-clean ruling but keeps the lifetime amendment and rejection counts, so
/// this is the honest reading of what it stores — a scope must re-earn its run,
/// and the corrections it earned it against do not evaporate.
#[must_use]
pub fn guard_evidence(stats: &ScopeOutcomeStats) -> (u32, u32) {
    (
        stats.untouched_streak,
        stats.amended.saturating_add(stats.rejected),
    )
}

// ---------------------------------------------------------------------------
// Offer answers + snooze state
// ---------------------------------------------------------------------------

/// The compiled snooze backoff: the `N`th "not now" holds the offer for
/// `SNOOZE_BACKOFF_SECONDS[N - 1]`.
///
/// A snooze past the end of the schedule is no longer "later" — it is the owner
/// saying *stop asking*, so the ladder's LENGTH is what defines the pin
/// threshold. There is no separate maximum to drift from it.
const SNOOZE_BACKOFF_SECONDS: [u64; 2] = [7 * 86_400, 30 * 86_400];

/// What the owner answered when the engine offered to stop asking.
///
/// [`Self::GoAuto`] carries the [`AuthenticatedOwner`] because it, and only it,
/// mints authority: DEC-0006 invariant 5 is enforced here by the type system
/// rather than by review, exactly as MS-06 enforces it on
/// [`Vault::accept_graduation_offer`]. Declining needs no authority — reducing
/// what the engine may ask never did.
#[derive(Debug, Clone, Copy)]
pub enum OfferAnswer<'owner> {
    /// Accept: mint the standing grant and let this scope run auto.
    GoAuto(&'owner AuthenticatedOwner),
    /// Decline for now: hold the offer for the next backoff step, or — on the
    /// answer past the end of the ladder — pin the scope to manual.
    NotNow,
}

impl OfferAnswer<'_> {
    /// The pinned wire/receipt string for this answer.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GoAuto(_) => ANSWER_GO_AUTO,
            Self::NotNow => ANSWER_NOT_NOW,
        }
    }
}

const ANSWER_GO_AUTO: &str = "go_auto";
const ANSWER_NOT_NOW: &str = "not_now";
const ANSWER_UNPIN: &str = "unpin";

/// Whether, and until when, the engine has been told to hold this scope's
/// graduation offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SnoozeState {
    /// Nothing declined: an earned offer surfaces.
    None,
    /// Declined `count` times; the offer surfaces again at `next_eligible_at`.
    Snoozed {
        /// How many times the owner has said "not now" for this scope.
        count: u8,
        /// The first second at which the offer may surface again.
        next_eligible_at: u64,
    },
    /// The owner asked to stop being asked. Never expires, never auto-clears —
    /// [`unpin_scope`] is the only door out.
    ManualPinned,
}

impl SnoozeState {
    /// Whether an earned offer must stay unsurfaced at `now`.
    #[must_use]
    pub const fn suppresses_asks_at(self, now: u64) -> bool {
        match self {
            Self::None => false,
            Self::Snoozed {
                next_eligible_at, ..
            } => now < next_eligible_at,
            Self::ManualPinned => true,
        }
    }

    /// The state one more "not now" at `at` produces.
    fn declined_at(self, at: u64) -> Self {
        let prior = match self {
            Self::ManualPinned => return Self::ManualPinned,
            Self::Snoozed { count, .. } => count,
            Self::None => 0,
        };
        // Indexed by declines ALREADY given, so the ladder's length is the pin
        // threshold and a decline past its end is the owner saying stop.
        match SNOOZE_BACKOFF_SECONDS.get(usize::from(prior)) {
            Some(backoff) => Self::Snoozed {
                count: prior.saturating_add(1),
                next_eligible_at: at.saturating_add(*backoff),
            },
            None => Self::ManualPinned,
        }
    }
}

// ---------------------------------------------------------------------------
// Stored rows
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredThresholdRow {
    v: u8,
    scope_pattern: String,
    required_streak: u32,
    posterior_guard: f32,
}

/// One answer the owner gave, and the whole of what this module stores about
/// the offer UX: [`replay_snooze`] derives the state from these rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredAnswer {
    v: u8,
    op_kind: String,
    target_class: String,
    actor: String,
    answer: String,
    at: u64,
}

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

/// The 16-byte storage handle of a threshold pattern.
fn pattern_key(pattern: &str) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PATTERN_DIGEST_DOMAIN);
    hasher.update(pattern.as_bytes());
    meta_key(
        THRESHOLD_KEY_PREFIX,
        &hasher.finalize().as_bytes()[..ENTITY_ID_LEN],
    )
}

/// The answer-log key range of one scope.
fn answer_scope_prefix(scope: &RampScope) -> Vec<u8> {
    meta_key(ANSWER_KEY_PREFIX, &scope.key())
}

fn answer_key(scope: &RampScope, id: &EntityId) -> Vec<u8> {
    let mut key = answer_scope_prefix(scope);
    key.extend_from_slice(id.as_bytes());
    key
}

/// The row id embedded in an answer key.
fn answer_key_id(key: &[u8]) -> Result<EntityId> {
    let tail = key
        .get(ANSWER_KEY_PREFIX.len() + ENTITY_ID_LEN..)
        .and_then(|tail| <[u8; ENTITY_ID_LEN]>::try_from(tail).ok())
        .ok_or(Error::CorruptedIndex(ANSWER_ROW_LABEL))?;
    EntityId::from_bytes(tail).map_err(|_| Error::CorruptedIndex(ANSWER_ROW_LABEL))
}

fn threshold_row_parts(row: StoredThresholdRow) -> Result<ThresholdRow> {
    if row.v != ROW_VERSION {
        return Err(Error::CorruptedIndex(THRESHOLD_ROW_LABEL));
    }
    ThresholdRow::new(row.scope_pattern, row.required_streak, row.posterior_guard)
        .map_err(|_| Error::CorruptedIndex(THRESHOLD_ROW_LABEL))
}

// ---------------------------------------------------------------------------
// Policy resolution
// ---------------------------------------------------------------------------

/// The threshold in force for one scope: the most specific row that governs it.
///
/// Three sources feed one ranking — the owner's runtime rows, MS-06's per-scope
/// streak dial (as [`ThresholdRow::for_dialed_streak`], an exact-scope row the
/// ENGINE wrote), and the compiled table. Most literal axes first; on equal
/// specificity a row the owner wrote beats one the engine did; remaining ties
/// break on the pattern string, so the winner never depends on scan order. The
/// compiled catch-all matches everything, so a scope always has a policy:
/// absence of rows is the compiled default, never a zero threshold.
///
/// Rows are returned AS WRITTEN. A guard that binds above the row's own streak
/// is not malformed, it is the point — the streak is a floor on repetition and
/// the guard is a floor on evidence, and either may be the one that holds.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] when a stored row is unreadable or no longer forms
/// a legal threshold — fail-closed, because a policy this engine cannot read is
/// not a policy to substitute a guess for. Plus storage failures.
pub fn graduation_policy_for(vault: &Vault, scope: &RampScope) -> Result<ThresholdRow> {
    let rtxn = vault.store.env.read_txn()?;
    graduation_policy_in_txn(&vault.store, &rtxn, scope)
}

pub(crate) fn graduation_policy_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    scope: &RampScope,
) -> Result<ThresholdRow> {
    let mut best: Option<Ranked> = None;
    for row in stored_threshold_rows_in_txn(store, txn)? {
        consider(&mut best, row, false, scope);
    }
    if let Some(streak) = crate::consent_graduation::ramp_floor_override_in_txn(store, txn, scope)?
    {
        consider(
            &mut best,
            ThresholdRow::for_dialed_streak(scope, streak)?,
            true,
            scope,
        );
    }
    for (pattern, streak, guard) in COMPILED_POLICY {
        let row = ThresholdRow::new(*pattern, *streak, *guard)
            .map_err(|_| Error::InvariantViolation("compiled graduation policy row is illegal"))?;
        consider(&mut best, row, true, scope);
    }

    Ok(best
        .ok_or(Error::InvariantViolation(
            "the compiled graduation policy has no catch-all row",
        ))?
        .row)
}

/// A matching row with the two keys that rank it against the others.
struct Ranked {
    specificity: u8,
    compiled: bool,
    row: ThresholdRow,
}

impl Ranked {
    /// Most literal axes first, a runtime row ahead of a compiled row of equal
    /// specificity, remaining ties on the pattern string — so the winner never
    /// depends on scan order.
    fn rank(&self) -> (std::cmp::Reverse<u8>, bool, &str) {
        (
            std::cmp::Reverse(self.specificity),
            self.compiled,
            &self.row.scope_pattern,
        )
    }
}

/// Keeps the best-ranked row that governs `scope`.
fn consider(best: &mut Option<Ranked>, row: ThresholdRow, compiled: bool, scope: &RampScope) {
    if !row.matches(scope) {
        return;
    }
    let candidate = Ranked {
        specificity: row.specificity(),
        compiled,
        row,
    };
    if best
        .as_ref()
        .is_none_or(|current| candidate.rank() < current.rank())
    {
        *best = Some(candidate);
    }
}

fn stored_threshold_rows_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Vec<ThresholdRow>> {
    let mut rows = Vec::new();
    for entry in store.vault_meta.prefix_iter(txn, THRESHOLD_KEY_PREFIX)? {
        let (_, raw) = entry?;
        rows.push(threshold_row_parts(decode_row(&raw, THRESHOLD_ROW_LABEL)?)?);
    }
    Ok(rows)
}

/// Every runtime threshold row, pattern-ordered — the editable half of the
/// policy table. The compiled half is reached through
/// [`graduation_policy_for`] on any scope no runtime row governs.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] on an unreadable row, plus storage failures.
pub fn graduation_policy_rows(vault: &Vault) -> Result<Vec<ThresholdRow>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rows = stored_threshold_rows_in_txn(&vault.store, &rtxn)?;
    rows.sort_by(|left, right| left.scope_pattern.cmp(&right.scope_pattern));
    Ok(rows)
}

/// Writes one runtime threshold row, replacing any row on the same pattern.
///
/// The row is re-validated HERE rather than trusted from its constructor. A
/// [`ThresholdRow`]'s fields are `pub`, so [`ThresholdRow::new`] is a door and
/// not a gate: a caller may assemble a threshold of zero, or a pattern that is
/// not three axes, without ever passing through it. Since every read re-parses
/// the stored row and fails CLOSED on one it cannot rebuild, an unvalidated
/// write would not corrupt this scope's policy — it would take every policy
/// read in the vault down until the row was deleted. So the check belongs at
/// the one door bytes get in through: a malformed threshold is a typed error
/// here, and the policy already in force stays in force.
///
/// # Errors
///
/// [`Error::InvalidConsentBound`] when the row's fields are not a legal
/// threshold, plus storage failures.
pub fn set_graduation_policy(vault: &Vault, row: &ThresholdRow) -> Result<()> {
    let row = ThresholdRow::new(
        row.scope_pattern.clone(),
        row.required_streak,
        row.posterior_guard,
    )?;
    let stored = StoredThresholdRow {
        v: ROW_VERSION,
        scope_pattern: row.scope_pattern.clone(),
        required_streak: row.required_streak,
        posterior_guard: row.posterior_guard,
    };
    let data = encode_row(&stored, THRESHOLD_ROW_LABEL)?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, &pattern_key(&row.scope_pattern), &data)?;
        Ok(())
    })
}

/// Drops the runtime row on `pattern`, returning whether one was there. The
/// scopes it governed fall back to the next-best row, ultimately the compiled
/// catch-all.
///
/// # Errors
///
/// Storage failures.
pub fn clear_graduation_policy(vault: &Vault, pattern: &str) -> Result<bool> {
    vault.with_write_txn(|wtxn| vault.store.vault_meta.delete(wtxn, &pattern_key(pattern)))
}

// ---------------------------------------------------------------------------
// The offer-answer state machine
// ---------------------------------------------------------------------------

/// The snooze state replayed from one scope's answers.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] on an unreadable answer row, plus storage
/// failures.
pub fn snooze_state(vault: &Vault, scope: &RampScope) -> Result<SnoozeState> {
    let rtxn = vault.store.env.read_txn()?;
    snooze_state_in_txn(&vault.store, &rtxn, scope)
}

pub(crate) fn snooze_state_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    scope: &RampScope,
) -> Result<SnoozeState> {
    let mut state = SnoozeState::None;
    for entry in store
        .vault_meta
        .prefix_iter(txn, &answer_scope_prefix(scope))?
    {
        let (_, raw) = entry?;
        let row: StoredAnswer = decode_row(&raw, ANSWER_ROW_LABEL)?;
        if row.v != ROW_VERSION {
            return Err(Error::CorruptedIndex(ANSWER_ROW_LABEL));
        }
        state = replay_snooze(state, &row)?;
    }
    Ok(state)
}

/// Folds one answer. Key order IS answer order, so this is a left fold over the
/// scope's log: a decline advances the ladder, and both an acceptance and an
/// unpin clear it — the owner having said yes, or having deliberately reopened
/// the question, supersedes every earlier "not now".
fn replay_snooze(state: SnoozeState, row: &StoredAnswer) -> Result<SnoozeState> {
    match row.answer.as_str() {
        ANSWER_NOT_NOW => Ok(state.declined_at(row.at)),
        ANSWER_GO_AUTO | ANSWER_UNPIN => Ok(SnoozeState::None),
        _ => Err(Error::CorruptedIndex(ANSWER_ROW_LABEL)),
    }
}

/// Whether an earned offer for this scope must stay unsurfaced at `now` — the
/// consult MS-06's [`Vault::graduation_offers`] runs before it lists a scope.
pub(crate) fn asks_are_suppressed_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    scope: &RampScope,
    now: u64,
) -> Result<bool> {
    Ok(snooze_state_in_txn(store, txn, scope)?.suppresses_asks_at(now))
}

/// What answering an offer produced.
#[derive(Debug, Clone)]
pub enum OfferAnswerOutcome {
    /// The grant MS-06's owner-only door minted.
    Graduated(ConsentReceipt),
    /// The offer is held; this is where the ladder now stands.
    Snoozed(SnoozeState),
}

/// Answers a standing graduation offer.
///
/// [`OfferAnswer::GoAuto`] mints the standing grant through
/// [`Vault::accept_graduation_offer`]'s own door — this module adds a record of
/// the answer, never a second way to create authority — and it is accepted
/// whenever the offer is EARNED, including while snoozed or pinned: suppression
/// silences the engine, not the owner.
///
/// [`OfferAnswer::NotNow`] requires an offer that is actually being made. An
/// offer already snoozed is not being made, which is what keeps the ladder
/// meaning three separate declines spread across the backoff rather than three
/// taps in one sitting.
///
/// # Errors
///
/// [`Error::InvalidConsentBound`] when the scope tuple is unbuildable, when no
/// offer is standing, or (for [`OfferAnswer::NotNow`]) when the ask is already
/// suppressed; plus whatever the grant door rejects, and storage failures.
pub fn answer_graduation_offer(
    vault: &Vault,
    scope: &RampScope,
    answer: OfferAnswer<'_>,
) -> Result<OfferAnswerOutcome> {
    answer_graduation_offer_at(vault, scope, answer, crate::unix_seconds_now())
}

/// [`answer_graduation_offer`] against a caller-supplied clock.
pub(crate) fn answer_graduation_offer_at(
    vault: &Vault,
    scope: &RampScope,
    answer: OfferAnswer<'_>,
    at: u64,
) -> Result<OfferAnswerOutcome> {
    scope.validate()?;
    vault.with_write_txn(|wtxn| {
        if !crate::consent_graduation::offer_is_standing_in_txn(vault, &*wtxn, scope)? {
            return Err(Error::InvalidConsentBound(
                "no graduation offer is standing for this scope",
            ));
        }
        match answer {
            OfferAnswer::GoAuto(owner) => {
                // The go-auto row is appended by the grant door itself, not
                // here — see [`record_go_auto_answer_in_txn`].
                let receipt = crate::consent_graduation::accept_graduation_offer_in_txn(
                    vault, wtxn, owner, scope, at,
                )?;
                Ok(OfferAnswerOutcome::Graduated(receipt))
            }
            OfferAnswer::NotNow => {
                let state = snooze_state_in_txn(&vault.store, &*wtxn, scope)?;
                if state.suppresses_asks_at(at) {
                    return Err(Error::InvalidConsentBound(
                        "this scope's graduation offer is already held; there is nothing to decline",
                    ));
                }
                append_answer_in_txn(vault, wtxn, scope, ANSWER_NOT_NOW, at)?;
                Ok(OfferAnswerOutcome::Snoozed(state.declined_at(at)))
            }
        }
    })
}

/// Unpins a scope: the settings door out of [`SnoozeState::ManualPinned`], and
/// the only one. Clears the ladder, so the next offer is asked afresh.
///
/// Deliberately unconditional — an owner reopening a question they closed needs
/// no offer to be standing, and unpinning a scope that was merely snoozed is
/// the same act said earlier.
///
/// # Errors
///
/// [`Error::InvalidConsentBound`] when the scope tuple is unbuildable, plus
/// storage failures.
pub fn unpin_scope(vault: &Vault, scope: &RampScope) -> Result<()> {
    unpin_scope_at(vault, scope, crate::unix_seconds_now())
}

/// [`unpin_scope`] against a caller-supplied clock.
pub(crate) fn unpin_scope_at(vault: &Vault, scope: &RampScope, at: u64) -> Result<()> {
    scope.validate()?;
    vault.with_write_txn(|wtxn| append_answer_in_txn(vault, wtxn, scope, ANSWER_UNPIN, at))
}

/// Records an accepted offer, called by MS-06's grant door inside the
/// transaction that mints the grant.
///
/// The answer belongs to the ACT, not to the API it arrived through.
/// [`Vault::accept_graduation_offer`] and [`answer_graduation_offer`] are two
/// public doors onto one owner decision, and only the grant door is common to
/// both — so recording it anywhere else would let the two doors leave different
/// durable state. Concretely: a pin that survived an acceptance would suppress
/// the scope forever the next time a correction took the grant away and the
/// scope re-earned its threshold, since [`replay_snooze`] would still see three
/// declines and no answer.
pub(crate) fn record_go_auto_answer_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: &RampScope,
    at: u64,
) -> Result<()> {
    append_answer_in_txn(vault, wtxn, scope, ANSWER_GO_AUTO, at)
}

/// Appends one answer row. The row is the state AND the receipt — there is no
/// third place a transition could be recorded, and therefore no place it could
/// go unrecorded.
fn append_answer_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: &RampScope,
    answer: &str,
    at: u64,
) -> Result<()> {
    let row = StoredAnswer {
        v: ROW_VERSION,
        op_kind: scope.op_kind.clone(),
        target_class: scope.target_class.clone(),
        actor: scope.actor.clone(),
        answer: answer.to_owned(),
        at,
    };
    let data = encode_row(&row, ANSWER_ROW_LABEL)?;
    vault
        .store
        .vault_meta
        .put(wtxn, &answer_key(scope, &EntityId::now()), &data)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Receipts (third projector in the `Gate` family)
// ---------------------------------------------------------------------------

/// Whether a receipt is an answered graduation offer — the discriminator
/// inside the `Gate` family, beside MS-06's demotion and outcome prefixes.
#[must_use]
pub fn is_graduation_answer_receipt(record: &ReceiptRecord) -> bool {
    record.receipt_kind == ReceiptKind::Gate && record.receipt_id.starts_with(ANSWER_RECEIPT_PREFIX)
}

/// Names the first key past the answer-log family, so the reverse walk has the
/// explicit half-open range `OverlayDb` needs (it exposes no reverse prefix
/// iterator). The prefix is an ASCII literal, so bumping its final byte is the
/// exclusive bound.
fn answer_key_range_end() -> Vec<u8> {
    let mut end = ANSWER_KEY_PREFIX.to_vec();
    if let Some(last) = end.last_mut() {
        *last = last.saturating_add(1);
    }
    end
}

/// Projects the answer log as `Gate` receipts, on the caller's read txn.
///
/// Called from `consent_graduation::ramp_receipts`, which is what is registered
/// in `receipt::collect_receipt_records`: the ramp's receipt families share one
/// registration and one transaction rather than opening a second, nested one.
///
/// Walks the family NEWEST-FIRST under [`crate::receipt::MAX_RECEIPT_QUERY_SCAN`],
/// as `receipt::attempt_pack_receipts` does and for the same reason. Direction
/// is the whole point of the cap: these rows never drain — [`unpin_scope`]
/// appends unconditionally and the log is the state — so an oldest-first cap
/// would permanently hide the owner's RECENT decisions behind their oldest
/// ones, which is the opposite of what any receipt query wants. The key is
/// scope-major and time-minor, so this is newest-first within each scope, with
/// the bound spent on the scopes at the far end of the digest order.
///
/// Above the cap the answer is a bounded prefix of the family rather than the
/// family, which [`note_answer_scan_capped`] says out loud instead of
/// truncating in silence.
pub(crate) fn answer_receipts_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let end = answer_key_range_end();
    let bounds = (
        std::ops::Bound::Included(ANSWER_KEY_PREFIX),
        std::ops::Bound::Excluded(&end[..]),
    );
    let mut out = Vec::new();
    // One row PAST the cap is reached and never decoded: it is what separates a
    // log holding exactly the cap from one the cap truncated.
    for (scanned, entry) in store
        .vault_meta
        .rev_range(txn, &bounds)?
        .take(crate::receipt::MAX_RECEIPT_QUERY_SCAN + 1)
        .enumerate()
    {
        if scanned == crate::receipt::MAX_RECEIPT_QUERY_SCAN {
            note_answer_scan_capped();
            break;
        }
        let (key, raw) = entry?;
        let row: StoredAnswer = decode_row(&raw, ANSWER_ROW_LABEL)?;
        if row.v != ROW_VERSION {
            return Err(Error::CorruptedIndex(ANSWER_ROW_LABEL));
        }
        let receipt = answer_receipt_record(&answer_key_id(&key)?, &row);
        if query.matches(&receipt) {
            out.push(receipt);
        }
    }
    Ok(out)
}

/// Surfaces an answer-log scan that stopped at the work cap.
///
/// The discarded remainder is unbounded by construction, so it is never
/// counted — the signal is that the cap FIRED, which is the fact an operator
/// (or a test) needs to know the query answered from a prefix.
fn note_answer_scan_capped() {
    tracing::warn!(
        scan_cap = crate::receipt::MAX_RECEIPT_QUERY_SCAN,
        "graduation answer scan hit the receipt-family work cap; older rows were not projected"
    );
    #[cfg(test)]
    ANSWER_SCAN_CAPPED.with(|fired| fired.set(fired.get() + 1));
}

#[cfg(test)]
thread_local! {
    static ANSWER_SCAN_CAPPED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn answer_scan_capped() -> usize {
    ANSWER_SCAN_CAPPED.get()
}

#[cfg(test)]
fn reset_answer_scan_capped() {
    ANSWER_SCAN_CAPPED.set(0);
}

fn answer_receipt_record(id: &EntityId, row: &StoredAnswer) -> ReceiptRecord {
    let fields = std::collections::BTreeMap::from([
        (
            crate::receipt::FIELD_OP_KIND.to_owned(),
            row.op_kind.clone(),
        ),
        (
            crate::receipt::FIELD_TARGET_CLASS.to_owned(),
            row.target_class.clone(),
        ),
        (
            crate::receipt::FIELD_SCOPE_ACTOR.to_owned(),
            row.actor.clone(),
        ),
    ]);

    ReceiptRecord {
        receipt_id: format!("{ANSWER_RECEIPT_PREFIX}{}", id.to_hex()),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: row.at,
        actor: Some(row.actor.clone()),
        on_behalf_of: None,
        outcome: row.answer.clone(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: vec![format!("consent.graduation.answer.{}", row.answer)],
        fields,
    }
}

// ---------------------------------------------------------------------------
// The trust table
// ---------------------------------------------------------------------------

/// One scope's row in the trust table: everything a settings or console screen
/// needs about it in one place.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TrustTableRow {
    /// The scope this row is about.
    pub scope: RampScope,
    /// MS-06's consent posture — what authority is live.
    pub state: RampState,
    /// MS-06's folded counters.
    pub stats: ScopeOutcomeStats,
    /// The threshold in force — the row that actually decides, not the
    /// compiled default it may have shadowed.
    pub threshold: ThresholdRow,
    /// Whether the engine is currently asking about this scope.
    pub snooze: SnoozeState,
    /// The live standing grant, when [`RampState::Graduated`].
    pub grant_ref: Option<String>,
    /// Whether the history clears [`Self::threshold`] right now. Distinct from
    /// `state == Offered` only in that it survives the read: it is what
    /// [`OfferAnswer::GoAuto`] may act on.
    pub offer_is_earned: bool,
}

/// Every scope with ramp history, with the policy and offer state governing it.
///
/// Ordered by scope, so two reads of an unchanged vault produce the same table.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] on an unreadable stats, threshold or answer row,
/// plus storage failures.
pub fn trust_table(vault: &Vault) -> Result<Vec<TrustTableRow>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    for stats in crate::consent_graduation::ramp_stats_in_txn(vault, &rtxn)? {
        let threshold = graduation_policy_in_txn(&vault.store, &rtxn, &stats.scope)?;
        let (wins, losses) = guard_evidence(&stats);
        let offer_is_earned = stats.scope.is_graduatable() && threshold.is_cleared_by(wins, losses);
        rows.push(TrustTableRow {
            state: stats.state,
            threshold,
            snooze: snooze_state_in_txn(&vault.store, &rtxn, &stats.scope)?,
            grant_ref: crate::consent_graduation::active_grant_ref_in_txn(
                vault,
                &rtxn,
                &stats.scope,
            )?,
            offer_is_earned,
            scope: stats.scope.clone(),
            stats,
        });
    }
    rows.sort_by(|left, right| left.scope.cmp(&right.scope));
    Ok(rows)
}

#[cfg(test)]
mod tests;
