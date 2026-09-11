//! Threshold rows and graduation-policy resolution.

use serde::{Deserialize, Serialize};

use super::pattern::{
    PATTERN_WILDCARD, WILDCARD_PATTERN, axis_matches, exact_pattern, pattern_axes,
};
use super::posterior::posterior_lower_bound;
use super::{
    PATTERN_DIGEST_DOMAIN, ROW_VERSION, THRESHOLD_KEY_PREFIX, THRESHOLD_ROW_LABEL, decode_row,
    encode_row, meta_key,
};
use crate::consent_graduation::{DEFAULT_GRADUATION_STREAK_FLOOR, RampScope};
use crate::entity_id::ENTITY_ID_LEN;
use crate::error::{Error, GateError, Result};
use crate::store::Store;
use crate::vault::Vault;

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
    /// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound) when the pattern is not three non-empty
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
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "graduation scope pattern must be op_kind/target_class/actor, each a literal or *",
            )));
        }
        if required_streak == 0 {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "a graduation threshold of zero clean rulings is not a threshold",
            )));
        }
        if !(0.0..=1.0).contains(&posterior_guard) {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "graduation posterior guard must be a probability in [0, 1]",
            )));
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
    pub(super) fn specificity(&self) -> u8 {
        pattern_axes(&self.scope_pattern).map_or(0, |axes| {
            axes.iter()
                .map(|axis| u8::from(*axis != PATTERN_WILDCARD))
                .sum()
        })
    }
}

// ---------------------------------------------------------------------------
// Stored rows
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredThresholdRow {
    pub(super) v: u8,
    pub(super) scope_pattern: String,
    pub(super) required_streak: u32,
    pub(super) posterior_guard: f32,
}

/// The 16-byte storage handle of a threshold pattern.
pub(super) fn pattern_key(pattern: &str) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PATTERN_DIGEST_DOMAIN);
    hasher.update(pattern.as_bytes());
    meta_key(
        THRESHOLD_KEY_PREFIX,
        &hasher.finalize().as_bytes()[..ENTITY_ID_LEN],
    )
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
/// streak dial (as `ThresholdRow::for_dialed_streak`, an exact-scope row the
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
/// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound) when the row's fields are not a legal
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
