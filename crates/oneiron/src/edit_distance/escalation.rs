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
//! FIELD CLASS ([`crate::receipt::FIELD_ESCALATION_SCOPE`] and its siblings) is
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

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::edit_distance::delta::AmendmentDelta;
use crate::entity_id::{ENTITY_ID_LEN, EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::receipt::{
    FIELD_AMENDMENT_DELTA, FIELD_ESCALATION_BAND_CEILING, FIELD_ESCALATION_BUDGET_BAND,
    FIELD_ESCALATION_CITED_RECEIPTS, FIELD_ESCALATION_QUESTION, FIELD_ESCALATION_RATIONALE,
    FIELD_ESCALATION_RULING, FIELD_ESCALATION_SCOPE, FIELD_ESCALATION_TRIGGER, FIELD_TASK_REF,
    ReceiptKind, ReceiptQuery, ReceiptRecord, retain_newest_receipt,
};
use crate::store::Store;
use crate::vault::Vault;

// ---------------------------------------------------------------------------
// Keyspace + pinned strings
// ---------------------------------------------------------------------------

/// `vault_meta` key prefix of the escalation ledger. The full key is this
/// prefix ‖ [`scope_key`] (16 B) ‖ row id (16 B).
///
/// Scope-major so one scope's history is a contiguous range, and the trailing
/// id is a UUIDv7 so key order is WRITE order. A caller-supplied `at` is data,
/// never ordering — which is what keeps "the newest N rulings" meaningful when
/// an ask is recorded with a backdated clock.
const ESCALATION_KEY_PREFIX: &[u8] = b"edit_distance/escalation/v1\0";

/// `vault_meta` key prefix of the standing-policy family. The full key is this
/// prefix ‖ [`scope_key`] (16 B) ‖ [`EscalationTrigger::key_byte`] (1 B).
///
/// Keyed by what the row GOVERNS rather than by its own id: "at most one
/// standing policy per (scope, trigger)" is then a property of the keyspace
/// instead of an invariant something has to check, and [`standing_policy_for`]
/// — the read ES-07 runs before every ask — is a single lookup.
const STANDING_POLICY_KEY_PREFIX: &[u8] = b"edit_distance/escalation_policy/v1\0";

/// `vault_meta` key of the N dial: how many agreeing rulings earn a proposed
/// standing policy. The house per-feature key const (cf.
/// `inbox::INBOX_REVIEW_DIAL_KEY`); `settings.rs` is UI customization and owns
/// nothing here.
pub const ESCALATION_STANDING_N_KEY: &[u8] = b"edit_distance/escalation/standing_n/dial/v1";

/// Receipt-id prefix of a ruled-escalation receipt — the
/// [`is_escalation_receipt`] discriminator inside the `Gate` family.
const ESCALATION_RECEIPT_PREFIX: &str = "escalation:";

/// Receipt-id prefix of a standing-policy receipt. Disjoint from
/// [`ESCALATION_RECEIPT_PREFIX`] at the separator, so neither prefix test can
/// match the other family.
const STANDING_POLICY_RECEIPT_PREFIX: &str = "escalation_policy:";

/// Only accepted schema version for either stored row.
const ROW_VERSION: u8 = 1;

/// Domain separator for the scope digest.
const SCOPE_DIGEST_DOMAIN: &[u8] = b"oneiron.edit_distance.escalation.scope.v1";

const ESCALATION_ROW_LABEL: &str = "escalation row";
const STANDING_POLICY_ROW_LABEL: &str = "escalation standing policy row";

/// The separator joining cited receipt ids in a receipt field. A receipt id is
/// a prefix plus hex, so it never contains one.
const CITED_RECEIPTS_SEPARATOR: &str = ",";

/// Longest accepted escalation scope, borrowed from the consent bound every
/// other scope axis in the engine is measured against.
const MAX_ESCALATION_SCOPE_LEN: usize = crate::consent::MAX_CONSENT_REF_LEN;

/// How many of a `(scope, trigger)` pair's newest rulings [`EscalationStats`]
/// retains. A history is for reading a pattern, not for replaying an audit —
/// the receipt family is where the whole record lives.
pub const ESCALATION_LAST_RULINGS_BOUND: usize = 8;

/// Agreeing rulings that earn a proposed standing policy, absent a dial.
pub const DEFAULT_ESCALATION_STANDING_N: u32 = 3;

// ---------------------------------------------------------------------------
// Triggers, rulings, status
// ---------------------------------------------------------------------------

/// Why the engine stopped and asked.
///
/// Closed by canon at three arms, and deliberately without an "other": a fourth
/// reason to escalate is a canon change, and an escape hatch here would let one
/// land as data. The pattern key is `(scope, trigger)` precisely because these
/// three are not interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EscalationTrigger {
    /// The classifier was not confident enough to rule.
    Unsure,
    /// The ask fell outside standing policy.
    Policy,
    /// The ask exceeded a budget. The only trigger with a magnitude, and
    /// therefore the only one whose standing policy carries a band ceiling.
    Budget,
}

impl EscalationTrigger {
    /// Every arm — the closed enum made iterable, so a fourth trigger cannot be
    /// added without every site here seeing it.
    pub const ALL: [Self; 3] = [Self::Unsure, Self::Policy, Self::Budget];

    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsure => "unsure",
            Self::Policy => "policy",
            Self::Budget => "budget",
        }
    }

    /// Inverse of [`Self::as_str`]; `None` for a token this engine never wrote.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|arm| arm.as_str() == token)
    }

    /// The pinned key byte. Never zero, so a truncated or zero-filled key can
    /// never decode as a valid trigger.
    const fn key_byte(self) -> u8 {
        match self {
            Self::Unsure => 1,
            Self::Policy => 2,
            Self::Budget => 3,
        }
    }
}

/// What the human ruled.
///
/// [`Self::Amend`] carries ED-01's Δ rather than a second amendment encoding:
/// one delta language lane-wide, so an escalation amendment and an inbox
/// approve-with-edit are the same artifact to every downstream reader.
#[derive(Debug, Clone, PartialEq)]
pub enum EscalationRuling {
    /// Run it as asked.
    Approve,
    /// Do not run it.
    Deny,
    /// Run it changed, by this much.
    Amend(AmendmentDelta),
}

impl EscalationRuling {
    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::Amend(_) => "amend",
        }
    }

    /// The Δ an amendment carries; `None` for the other two arms.
    #[must_use]
    pub const fn delta(&self) -> Option<&AmendmentDelta> {
        match self {
            Self::Amend(delta) => Some(delta),
            Self::Approve | Self::Deny => None,
        }
    }
}

/// Whether a standing policy is merely offered or actually in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StandingPolicyStatus {
    /// Earned and surfaced; suppresses nothing until the owner taps it.
    Proposed,
    /// The owner accepted it. Only these short-circuit an ask.
    Accepted,
}

impl StandingPolicyStatus {
    /// The pinned receipt/wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Accepted => "accepted",
        }
    }
}

// ---------------------------------------------------------------------------
// The public records
// ---------------------------------------------------------------------------

/// One ruled escalation, as [`record_escalation`] takes it.
#[derive(Debug, Clone, PartialEq)]
pub struct EscalationReceipt {
    /// The task the ask was about.
    pub task_ref: EntityId,
    /// The scope the ask fell in, stamped at record time. Free-form, trimmed,
    /// and the axis every aggregation and standing policy is keyed on.
    pub scope: String,
    /// Which of the three reasons fired.
    pub trigger: EscalationTrigger,
    /// What the engine asked.
    pub question: String,
    /// What the human ruled.
    pub ruling: EscalationRuling,
    /// Why they ruled it.
    pub rationale: String,
    /// The ask's magnitude band. `Some` only on an [`EscalationTrigger::Budget`]
    /// ask; a band on any other trigger is rejected at the door, because an
    /// aggregation that silently ignored it would let a meaningless number look
    /// like evidence.
    pub budget_band: Option<u64>,
}

/// A standing answer for one `(scope, trigger)` pair.
#[derive(Debug, Clone, PartialEq)]
pub struct StandingPolicy {
    /// The row's own handle — what [`accept_standing_policy`] takes.
    pub row_ref: EntityId,
    /// The scope it governs.
    pub scope: String,
    /// The trigger it governs.
    pub trigger: EscalationTrigger,
    /// Proposed, or accepted by the owner.
    pub status: StandingPolicyStatus,
    /// The ruling every citing escalation agreed on.
    pub ruling: EscalationRuling,
    /// For an [`EscalationTrigger::Budget`] row, the largest band EVERY citing
    /// ruling covered; `None` when the row is band-less, which never covers a
    /// banded ask. Always `None` on the other triggers, which have no
    /// magnitude.
    pub budget_band_ceiling: Option<u64>,
    /// Receipt ids of the rulings that earned this row. A standing policy that
    /// could not say what it was learned from would be an assertion.
    pub cited_receipts: Vec<String>,
}

impl StandingPolicy {
    /// Whether this row answers an ask of `ask_band` without escalating.
    ///
    /// A [`StandingPolicyStatus::Proposed`] row covers nothing: it has been
    /// offered, not accepted. On `unsure` / `policy` the `(scope, trigger)` key
    /// stands and the band is not consulted. On `budget` both band-less sides
    /// fail closed — a row with no ceiling covers no banded ask, and an
    /// unmeasured ask clears no ceiling.
    #[must_use]
    pub const fn covers_ask(&self, ask_band: Option<u64>) -> bool {
        if !matches!(self.status, StandingPolicyStatus::Accepted) {
            return false;
        }
        match self.trigger {
            EscalationTrigger::Unsure | EscalationTrigger::Policy => true,
            EscalationTrigger::Budget => match (self.budget_band_ceiling, ask_band) {
                (Some(ceiling), Some(band)) => band <= ceiling,
                _ => false,
            },
        }
    }
}

/// One `(scope, trigger)` pair's ruling history.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EscalationStats {
    /// Approvals recorded.
    pub approve: u32,
    /// Denials recorded.
    pub deny: u32,
    /// Amendments recorded.
    pub amend: u32,
    /// Newest [`ESCALATION_LAST_RULINGS_BOUND`] retained, returned
    /// oldest-to-newest.
    pub last_rulings: Vec<EscalationRuling>,
}

// ---------------------------------------------------------------------------
// Stored rows
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEscalation {
    v: u8,
    task_ref: String,
    scope: String,
    trigger: String,
    question: String,
    ruling: String,
    /// Exactly the bytes [`AmendmentDelta::encode`] produced; `Some` if and
    /// only if `ruling` is `amend`.
    delta: Option<Vec<u8>>,
    rationale: String,
    budget_band: Option<u64>,
    at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredStandingPolicy {
    v: u8,
    row_ref: String,
    scope: String,
    trigger: String,
    ruling: String,
    delta: Option<Vec<u8>>,
    band_ceiling: Option<u64>,
    cited_receipts: Vec<String>,
    proposed_at: u64,
    /// Set by the acceptance door, and the whole of what
    /// [`StandingPolicyStatus`] is derived from — two spellings of one fact are
    /// two things that can disagree.
    accepted_at: Option<u64>,
}

fn encode_row<T: Serialize>(row: &T, label: &'static str) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| Error::InvariantViolation(label))
}

fn escalation_row(raw: &[u8]) -> Result<StoredEscalation> {
    let row: StoredEscalation =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex(ESCALATION_ROW_LABEL))?;
    if row.v == ROW_VERSION {
        Ok(row)
    } else {
        Err(Error::CorruptedIndex(ESCALATION_ROW_LABEL))
    }
}

fn standing_policy_row(raw: &[u8]) -> Result<StoredStandingPolicy> {
    let row: StoredStandingPolicy =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex(STANDING_POLICY_ROW_LABEL))?;
    if row.v == ROW_VERSION {
        Ok(row)
    } else {
        Err(Error::CorruptedIndex(STANDING_POLICY_ROW_LABEL))
    }
}

/// The 16-byte storage handle of a scope.
fn scope_key(scope: &str) -> [u8; ENTITY_ID_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SCOPE_DIGEST_DOMAIN);
    hasher.update(scope.as_bytes());
    let mut key = [0_u8; ENTITY_ID_LEN];
    key.copy_from_slice(&hasher.finalize().as_bytes()[..ENTITY_ID_LEN]);
    key
}

/// The ledger key range of one scope.
fn escalation_scope_prefix(scope: &str) -> Vec<u8> {
    let mut key = ESCALATION_KEY_PREFIX.to_vec();
    key.extend_from_slice(&scope_key(scope));
    key
}

fn escalation_key(scope: &str, id: &EntityId) -> Vec<u8> {
    let mut key = escalation_scope_prefix(scope);
    key.extend_from_slice(id.as_bytes());
    key
}

fn standing_policy_key(scope: &str, trigger: EscalationTrigger) -> Vec<u8> {
    let mut key = STANDING_POLICY_KEY_PREFIX.to_vec();
    key.extend_from_slice(&scope_key(scope));
    key.push(trigger.key_byte());
    key
}

/// The row id embedded in a ledger key.
fn escalation_key_id(key: &[u8]) -> Result<EntityId> {
    let tail = key
        .get(ESCALATION_KEY_PREFIX.len() + ENTITY_ID_LEN..)
        .and_then(|tail| <[u8; ENTITY_ID_LEN]>::try_from(tail).ok())
        .ok_or(Error::CorruptedIndex(ESCALATION_ROW_LABEL))?;
    EntityId::from_bytes(tail).map_err(|_| Error::CorruptedIndex(ESCALATION_ROW_LABEL))
}

fn escalation_receipt_id(id: &EntityId) -> String {
    format!("{ESCALATION_RECEIPT_PREFIX}{}", id.to_hex())
}

// ---------------------------------------------------------------------------
// Validation + the ruling codec
// ---------------------------------------------------------------------------

/// The trimmed scope, or the reason it is not one.
fn normalized_scope(scope: &str) -> Result<&str> {
    let trimmed = scope.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_ESCALATION_SCOPE_LEN {
        return Err(Error::InvalidConsentBound(
            "an escalation scope must be non-empty and within the consent-ref bound",
        ));
    }
    Ok(trimmed)
}

/// The stored `(ruling token, Δ bytes)` pair for a ruling.
fn ruling_parts(ruling: &EscalationRuling) -> Result<(String, Option<Vec<u8>>)> {
    let delta = ruling.delta().map(AmendmentDelta::encode).transpose()?;
    Ok((ruling.as_str().to_owned(), delta))
}

/// Rebuilds a ruling from its stored pair.
///
/// The token and the Δ must agree: an `amend` with no Δ, or a non-`amend`
/// carrying one, is a row this engine did not write.
fn ruling_from_parts(
    token: &str,
    delta: Option<&[u8]>,
    label: &'static str,
) -> Result<EscalationRuling> {
    match (token, delta) {
        ("approve", None) => Ok(EscalationRuling::Approve),
        ("deny", None) => Ok(EscalationRuling::Deny),
        ("amend", Some(bytes)) => AmendmentDelta::decode(bytes).map(EscalationRuling::Amend),
        _ => Err(Error::CorruptedIndex(label)),
    }
}

fn trigger_from_token(token: &str, label: &'static str) -> Result<EscalationTrigger> {
    EscalationTrigger::from_token(token).ok_or(Error::CorruptedIndex(label))
}

impl StoredEscalation {
    fn ruling(&self) -> Result<EscalationRuling> {
        ruling_from_parts(&self.ruling, self.delta.as_deref(), ESCALATION_ROW_LABEL)
    }

    fn trigger(&self) -> Result<EscalationTrigger> {
        trigger_from_token(&self.trigger, ESCALATION_ROW_LABEL)
    }
}

// ---------------------------------------------------------------------------
// The N dial
// ---------------------------------------------------------------------------

/// Agreeing rulings a `(scope, trigger)` pair owes before a standing policy is
/// proposed: the dial if one is set, else [`DEFAULT_ESCALATION_STANDING_N`].
///
/// # Errors
///
/// [`Error::CorruptedIndex`] on an unreadable dial row, plus storage failures.
pub fn escalation_standing_n(vault: &Vault) -> Result<u32> {
    let rtxn = vault.store.env.read_txn()?;
    escalation_standing_n_in_txn(&vault.store, &rtxn)
}

fn escalation_standing_n_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<u32> {
    let Some(raw) = store.vault_meta.get(txn, ESCALATION_STANDING_N_KEY)? else {
        return Ok(DEFAULT_ESCALATION_STANDING_N);
    };
    let bytes: [u8; 4] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex("escalation standing-N dial"))?;
    Ok(u32::from_le_bytes(bytes))
}

/// Sets the N dial.
///
/// # Errors
///
/// [`Error::InvalidConsentBound`] when `n` is zero — a standing policy earned
/// by no rulings at all is not a learned policy — plus storage failures.
pub fn set_escalation_standing_n(vault: &Vault, n: u32) -> Result<()> {
    if n == 0 {
        return Err(Error::InvalidConsentBound(
            "a standing-policy threshold of zero rulings is not a threshold",
        ));
    }
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, ESCALATION_STANDING_N_KEY, &n.to_le_bytes())?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// The ledger
// ---------------------------------------------------------------------------

/// Appends one ruled escalation, returning the row's handle.
///
/// # Errors
///
/// [`Error::InvalidConsentBound`] when the scope is unusable, or when a
/// magnitude band rides a trigger that has no magnitude; plus Δ encode and
/// storage failures.
pub fn record_escalation(vault: &Vault, receipt: EscalationReceipt) -> Result<EntityId> {
    record_escalation_at(vault, receipt, crate::unix_seconds_now())
}

/// [`record_escalation`] against a caller-supplied clock.
pub(crate) fn record_escalation_at(
    vault: &Vault,
    receipt: EscalationReceipt,
    at: u64,
) -> Result<EntityId> {
    let scope = normalized_scope(&receipt.scope)?.to_owned();
    if receipt.budget_band.is_some() && receipt.trigger != EscalationTrigger::Budget {
        return Err(Error::InvalidConsentBound(
            "only a budget-triggered escalation carries a magnitude band",
        ));
    }
    let (ruling, delta) = ruling_parts(&receipt.ruling)?;
    let id = EntityId::now();
    let key = escalation_key(&scope, &id);
    let row = StoredEscalation {
        v: ROW_VERSION,
        task_ref: receipt.task_ref.to_hex(),
        scope,
        trigger: receipt.trigger.as_str().to_owned(),
        question: receipt.question,
        ruling,
        delta,
        rationale: receipt.rationale,
        budget_band: receipt.budget_band,
        at,
    };
    let data = encode_row(&row, ESCALATION_ROW_LABEL)?;
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &data)?;
        Ok(())
    })?;
    Ok(id)
}

/// One `(scope, trigger)` pair's folded ruling history.
///
/// Scans that scope's whole range rather than a capped suffix: counts are not
/// derivable from a prefix of the history, and the range walked is one scope's
/// rows, not the family's.
///
/// # Errors
///
/// [`Error::InvalidConsentBound`] on an unusable scope,
/// [`Error::CorruptedIndex`] on an unreadable row, plus storage failures.
pub fn escalation_stats(
    vault: &Vault,
    scope: &str,
    trigger: EscalationTrigger,
) -> Result<EscalationStats> {
    let rtxn = vault.store.env.read_txn()?;
    let mut stats = EscalationStats::default();
    let mut recent: VecDeque<EscalationRuling> = VecDeque::new();
    for (_, row) in scope_rows_in_txn(&vault.store, &rtxn, scope, trigger)? {
        let ruling = row.ruling()?;
        match ruling {
            EscalationRuling::Approve => stats.approve = stats.approve.saturating_add(1),
            EscalationRuling::Deny => stats.deny = stats.deny.saturating_add(1),
            EscalationRuling::Amend(_) => stats.amend = stats.amend.saturating_add(1),
        }
        recent.push_back(ruling);
        if recent.len() > ESCALATION_LAST_RULINGS_BOUND {
            recent.pop_front();
        }
    }
    stats.last_rulings = recent.into();
    Ok(stats)
}

/// One `(scope, trigger)` pair's rows, with their ids, in write order.
fn scope_rows_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    scope: &str,
    trigger: EscalationTrigger,
) -> Result<Vec<(EntityId, StoredEscalation)>> {
    let scope = normalized_scope(scope)?;
    let mut rows = Vec::new();
    for entry in store
        .vault_meta
        .prefix_iter(txn, &escalation_scope_prefix(scope))?
    {
        let (key, raw) = entry?;
        let row = escalation_row(&raw)?;
        if row.trigger()? == trigger {
            rows.push((escalation_key_id(&key)?, row));
        }
    }
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Standing policy
// ---------------------------------------------------------------------------

/// Proposes a standing policy when the newest [`escalation_standing_n`] rulings
/// on `(scope, trigger)` agree, returning the new row's handle.
///
/// `None` — never an error — for every ordinary reason not to propose: too
/// little history, rulings that disagree, or a row that already governs this
/// pair. A pattern that has not formed is not a failure.
///
/// The proposed row cites the rulings that earned it and, for an
/// [`EscalationTrigger::Budget`] pair, records the band ceiling every one of
/// them covered — the MINIMUM of their bands. That is what makes the guard
/// real: N approvals of small asks mint a policy for small asks, and one
/// approval of a large one inside that window does not widen it. A single
/// band-less ruling among them leaves the ceiling `None`, which covers no
/// banded ask at all.
///
/// # Errors
///
/// [`Error::InvalidConsentBound`] on an unusable scope,
/// [`Error::CorruptedIndex`] on an unreadable row, plus storage failures.
pub fn maybe_propose_standing_policy(
    vault: &Vault,
    scope: &str,
    trigger: EscalationTrigger,
) -> Result<Option<EntityId>> {
    maybe_propose_standing_policy_at(vault, scope, trigger, crate::unix_seconds_now())
}

/// [`maybe_propose_standing_policy`] against a caller-supplied clock.
pub(crate) fn maybe_propose_standing_policy_at(
    vault: &Vault,
    scope: &str,
    trigger: EscalationTrigger,
    at: u64,
) -> Result<Option<EntityId>> {
    let scope = normalized_scope(scope)?.to_owned();
    let row_ref = EntityId::now();
    vault.with_write_txn(|wtxn| {
        let key = standing_policy_key(&scope, trigger);
        if vault.store.vault_meta.get(&*wtxn, &key)?.is_some() {
            return Ok(None);
        }
        let n = escalation_standing_n_in_txn(&vault.store, &*wtxn)?;
        let rows = scope_rows_in_txn(&vault.store, &*wtxn, &scope, trigger)?;
        let Some(window) = newest_agreeing_window(&rows, n)? else {
            return Ok(None);
        };
        let row = StoredStandingPolicy {
            v: ROW_VERSION,
            row_ref: row_ref.to_hex(),
            scope,
            trigger: trigger.as_str().to_owned(),
            ruling: window.ruling,
            delta: window.delta,
            band_ceiling: window.band_ceiling,
            cited_receipts: window.cited_receipts,
            proposed_at: at,
            accepted_at: None,
        };
        let data = encode_row(&row, STANDING_POLICY_ROW_LABEL)?;
        vault.store.vault_meta.put(wtxn, &key, &data)?;
        Ok(Some(row_ref))
    })
}

/// What a policy learned from an agreeing window would carry.
struct AgreeingWindow {
    ruling: String,
    delta: Option<Vec<u8>>,
    band_ceiling: Option<u64>,
    cited_receipts: Vec<String>,
}

/// The newest `n` rows when they rule identically, else `None`.
///
/// Agreement is on the RULING, Δ included: two amendments that changed
/// different things are two answers, not a pattern.
fn newest_agreeing_window(
    rows: &[(EntityId, StoredEscalation)],
    n: u32,
) -> Result<Option<AgreeingWindow>> {
    let n = usize::try_from(n).unwrap_or(usize::MAX);
    if n == 0 || rows.len() < n {
        return Ok(None);
    }
    let window = &rows[rows.len() - n..];
    let Some(((_, head), rest)) = window.split_first() else {
        return Ok(None);
    };
    let ruling = head.ruling()?;
    for (_, row) in rest {
        if row.ruling()? != ruling {
            return Ok(None);
        }
    }
    // Every citing ruling has to cover the ceiling, so the minimum is what the
    // window is worth — and one band-less ruling in it makes the whole window
    // band-less, which `covers_ask` reads as covering nothing.
    let band_ceiling = window.iter().try_fold(u64::MAX, |floor, (_, row)| {
        row.budget_band.map(|band| floor.min(band))
    });
    let (ruling, delta) = ruling_parts(&ruling)?;
    Ok(Some(AgreeingWindow {
        ruling,
        delta,
        band_ceiling,
        cited_receipts: window
            .iter()
            .map(|(id, _)| escalation_receipt_id(id))
            .collect(),
    }))
}

/// The standing policy governing `(scope, trigger)`, if one exists.
///
/// The read ES-07 runs before repeating an ask. Its `Err` arm is load-bearing:
/// a row this engine cannot decode is UNCERTAINTY, not absence, and the caller
/// escalates rather than substituting a guess for a policy.
///
/// # Errors
///
/// [`Error::InvalidConsentBound`] on an unusable scope,
/// [`Error::CorruptedIndex`] on an unreadable row, plus storage failures.
pub fn standing_policy_for(
    vault: &Vault,
    scope: &str,
    trigger: EscalationTrigger,
) -> Result<Option<StandingPolicy>> {
    let scope = normalized_scope(scope)?;
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, &standing_policy_key(scope, trigger))?
    else {
        return Ok(None);
    };
    standing_policy_parts(&standing_policy_row(&raw)?).map(Some)
}

fn standing_policy_parts(row: &StoredStandingPolicy) -> Result<StandingPolicy> {
    Ok(StandingPolicy {
        row_ref: EntityId::from_hex(&row.row_ref)
            .map_err(|_| Error::CorruptedIndex(STANDING_POLICY_ROW_LABEL))?,
        scope: row.scope.clone(),
        trigger: trigger_from_token(&row.trigger, STANDING_POLICY_ROW_LABEL)?,
        status: policy_status(row),
        ruling: ruling_from_parts(&row.ruling, row.delta.as_deref(), STANDING_POLICY_ROW_LABEL)?,
        budget_band_ceiling: row.band_ceiling,
        cited_receipts: row.cited_receipts.clone(),
    })
}

const fn policy_status(row: &StoredStandingPolicy) -> StandingPolicyStatus {
    if row.accepted_at.is_some() {
        StandingPolicyStatus::Accepted
    } else {
        StandingPolicyStatus::Proposed
    }
}

/// The owner's tap: flips a proposed row to [`StandingPolicyStatus::Accepted`],
/// and the only door that does.
///
/// Idempotent on a row already accepted — the act happened once, and its
/// acceptance receipt keeps the time it happened rather than the time it was
/// re-affirmed.
///
/// # Errors
///
/// [`Error::InvalidConsentBound`] when no row carries `row_ref`, plus
/// [`Error::CorruptedIndex`] on an unreadable row and storage failures.
pub fn accept_standing_policy(vault: &Vault, row_ref: &EntityId) -> Result<()> {
    accept_standing_policy_at(vault, row_ref, crate::unix_seconds_now())
}

/// [`accept_standing_policy`] against a caller-supplied clock.
pub(crate) fn accept_standing_policy_at(vault: &Vault, row_ref: &EntityId, at: u64) -> Result<()> {
    let wanted = row_ref.to_hex();
    vault.with_write_txn(|wtxn| {
        let found = find_standing_policy_in_txn(&vault.store, &*wtxn, &wanted)?;
        let Some((key, mut row)) = found else {
            return Err(Error::InvalidConsentBound(
                "no standing escalation policy carries this row ref",
            ));
        };
        if row.accepted_at.is_some() {
            return Ok(());
        }
        row.accepted_at = Some(at);
        let data = encode_row(&row, STANDING_POLICY_ROW_LABEL)?;
        vault.store.vault_meta.put(wtxn, &key, &data)?;
        Ok(())
    })
}

/// The standing-policy row carrying `row_ref`, with its key.
///
/// A scan, deliberately: the family is keyed by what a row GOVERNS so the hot
/// read is a lookup, and acceptance — an owner tap, once per row — is what pays
/// for it.
fn find_standing_policy_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    row_ref_hex: &str,
) -> Result<Option<(Vec<u8>, StoredStandingPolicy)>> {
    for entry in store
        .vault_meta
        .prefix_iter(txn, STANDING_POLICY_KEY_PREFIX)?
    {
        let (key, raw) = entry?;
        let row = standing_policy_row(&raw)?;
        if row.row_ref == row_ref_hex {
            return Ok(Some((key.to_vec(), row)));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Receipts (a projector in the `Gate` family)
// ---------------------------------------------------------------------------

/// Whether a receipt is a ruled escalation.
#[must_use]
pub fn is_escalation_receipt(record: &ReceiptRecord) -> bool {
    record.receipt_kind == ReceiptKind::Gate
        && record.receipt_id.starts_with(ESCALATION_RECEIPT_PREFIX)
}

/// Whether a receipt is a standing-policy proposal or acceptance.
#[must_use]
pub fn is_standing_policy_receipt(record: &ReceiptRecord) -> bool {
    record.receipt_kind == ReceiptKind::Gate
        && record
            .receipt_id
            .starts_with(STANDING_POLICY_RECEIPT_PREFIX)
}

/// Projects both escalation families as `Gate` receipts.
///
/// Registered in `receipt::collect_receipt_records` beside the gate-decision
/// and ramp projectors, and opens its own read txn as they do.
///
/// Both walks are EXHAUSTIVE, which is forced by the keyspace: these keys are
/// scope-major, so a bounded PREFIX of key order is not a bounded SUFFIX of
/// time order. A scan cap here would let one high-sorting scope's history hide
/// every recent decision made under a lower-sorting one — while
/// [`escalation_stats`] (which walks one scope's range, uncapped) kept counting
/// rows the receipt query could no longer return, breaking the
/// rebuild-from-receipts identity. What is bounded is the RESULT, not the walk:
/// the newest `query.limit` records, kept by
/// [`crate::receipt::retain_newest_receipt`] under the same order the query's
/// final sort uses, exactly as `receipt::gate_receipts` does with its pages.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] on an unreadable row, plus storage failures.
pub(crate) fn escalation_receipts(
    vault: &Vault,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, ESCALATION_KEY_PREFIX)?
    {
        let (key, raw) = entry?;
        retain_projected(
            query,
            &mut out,
            escalation_receipt_record(&escalation_key_id(&key)?, &escalation_row(&raw)?),
        );
    }
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, STANDING_POLICY_KEY_PREFIX)?
    {
        let (_, raw) = entry?;
        for record in standing_policy_receipt_records(&standing_policy_row(&raw)?) {
            retain_projected(query, &mut out, record);
        }
    }
    Ok(out)
}

/// Keeps one projected record if the query wants it, newest-first bounded.
///
/// One buffer serves both families: the caller's answer is the newest `limit`
/// receipts across every projector, so the newest `limit` across both of these
/// is exactly what cannot be dropped without changing it.
///
/// A `job_ref` query stays exhaustive, as `receipt::gate_receipts` does and for
/// its reason: that join runs after collection, so a record dropped here could
/// not be found again.
fn retain_projected(query: &ReceiptQuery, out: &mut Vec<ReceiptRecord>, record: ReceiptRecord) {
    if !query.matches(&record) {
        return;
    }
    if query.job_ref.is_some() {
        out.push(record);
    } else {
        retain_newest_receipt(out, record, query.limit);
    }
}

fn escalation_receipt_record(id: &EntityId, row: &StoredEscalation) -> ReceiptRecord {
    let mut fields = BTreeMap::from([
        (FIELD_TASK_REF.to_owned(), row.task_ref.clone()),
        (FIELD_ESCALATION_SCOPE.to_owned(), row.scope.clone()),
        (FIELD_ESCALATION_TRIGGER.to_owned(), row.trigger.clone()),
        (FIELD_ESCALATION_RULING.to_owned(), row.ruling.clone()),
        (FIELD_ESCALATION_QUESTION.to_owned(), row.question.clone()),
        (FIELD_ESCALATION_RATIONALE.to_owned(), row.rationale.clone()),
    ]);
    insert_delta_field(&mut fields, row.delta.as_deref());
    if let Some(band) = row.budget_band {
        fields.insert(FIELD_ESCALATION_BUDGET_BAND.to_owned(), band.to_string());
    }
    ReceiptRecord {
        receipt_id: escalation_receipt_id(id),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: row.at,
        actor: None,
        on_behalf_of: None,
        outcome: row.ruling.clone(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: vec![format!(
            "edit_distance.escalation.{}.{}",
            row.trigger, row.ruling
        )],
        fields,
    }
}

/// The proposal receipt, plus the acceptance receipt once the owner tapped.
///
/// Two records rather than one that changes: the offer and the acceptance are
/// separate acts, and a projection that rewrote the first as the second would
/// lose the fact that a proposal was ever made.
fn standing_policy_receipt_records(row: &StoredStandingPolicy) -> Vec<ReceiptRecord> {
    let mut records = vec![standing_policy_receipt_record(
        row,
        StandingPolicyStatus::Proposed,
        row.proposed_at,
    )];
    if let Some(accepted_at) = row.accepted_at {
        records.push(standing_policy_receipt_record(
            row,
            StandingPolicyStatus::Accepted,
            accepted_at,
        ));
    }
    records
}

fn standing_policy_receipt_record(
    row: &StoredStandingPolicy,
    status: StandingPolicyStatus,
    at: u64,
) -> ReceiptRecord {
    let mut fields = BTreeMap::from([
        (FIELD_ESCALATION_SCOPE.to_owned(), row.scope.clone()),
        (FIELD_ESCALATION_TRIGGER.to_owned(), row.trigger.clone()),
        (FIELD_ESCALATION_RULING.to_owned(), row.ruling.clone()),
        (
            FIELD_ESCALATION_CITED_RECEIPTS.to_owned(),
            row.cited_receipts.join(CITED_RECEIPTS_SEPARATOR),
        ),
    ]);
    insert_delta_field(&mut fields, row.delta.as_deref());
    if let Some(ceiling) = row.band_ceiling {
        fields.insert(
            FIELD_ESCALATION_BAND_CEILING.to_owned(),
            ceiling.to_string(),
        );
    }
    ReceiptRecord {
        receipt_id: format!(
            "{STANDING_POLICY_RECEIPT_PREFIX}{}.{}",
            row.row_ref,
            status.as_str()
        ),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: at,
        actor: None,
        on_behalf_of: None,
        outcome: status.as_str().to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: vec![format!(
            "edit_distance.escalation.standing.{}.{}",
            row.trigger,
            status.as_str()
        )],
        fields,
    }
}

/// Stamps a stored Δ into ED-01's reserved slot, in the same hex spelling
/// `delta::attach_amendment_deltas` writes — one delta language, down to the
/// field key.
fn insert_delta_field(fields: &mut BTreeMap<String, String>, delta: Option<&[u8]>) {
    if let Some(bytes) = delta {
        fields.insert(FIELD_AMENDMENT_DELTA.to_owned(), bytes_to_hex_lower(bytes));
    }
}

#[cfg(test)]
mod tests;
