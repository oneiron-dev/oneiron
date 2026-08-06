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
//!    are a rebuildable projection of the ARCH-0055 r7 proposal-outcome
//!    receipts (CID-7): [`Vault::rebuild_ramp_stats_from_receipts`] drops the
//!    whole table and refolds it from receipts plus this module's own demotion
//!    rows, and must land byte-identically on what incremental maintenance
//!    produced.
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
//! **Self-demotion is receipted, never silent** (oracle
//! `ms06_self_demotion_is_receipted_never_silent`). A rejection or an amendment
//! landing in a graduated scope revokes the standing grant and appends a
//! durable demotion row; the row projects as a SECOND
//! [`ReceiptKind::Gate`] receipt family, registered beside the gate-decision
//! projector in `receipt::collect_receipt_records`. It is deliberately NOT a
//! synthetic `GateDecisionRecord` in the gate-decision store: ONE-1637 made
//! that store the erasure chain's H0 index, and a ramp bookkeeping row has no
//! business in it. `ProposalOutcome` likewise stays at exactly three states
//! (`ms05_proposal_outcome_has_exactly_three_states`) — a demotion is an act on
//! a scope, not a fourth way to rule a proposal.
//!
//! ED-05 (ONE-1761) is the UX layer above this projector: it reads
//! [`Vault::scope_stats`], replaces the compiled default floor through
//! [`Vault::set_ramp_streak_floor`], and adds snooze / manual-pin states of its
//! own. The stats surface is public and stable for it.

use serde::{Deserialize, Serialize};

use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, ConsentReceipt, GrantBound,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::identity_topology::{ProposalOutcome, ProposalScope, is_identity_topology_op_kind};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use crate::store::Store;
use crate::vault::Vault;

/// `vault_meta` key prefix of the per-scope outcome-statistics projection. The
/// full key is this prefix followed by the 16-byte [`RampScope::key`].
///
/// These consts live with the family that owns the keyspace rather than in
/// `store.rs`, for the same reason `identity_redirect::REDIRECT_TABLE_META_PREFIX`
/// does: `vault_meta` readers already ignore unknown prefixes.
const RAMP_STATS_KEY_PREFIX: &[u8] = b"ramp_stats:v1:";

/// `vault_meta` key prefix of the per-scope streak-floor OVERRIDE. Absence
/// means [`DEFAULT_GRADUATION_STREAK_FLOOR`].
///
/// A floor is POLICY, not projection: it is stored apart from the stats rows
/// precisely so [`Vault::rebuild_ramp_stats_from_receipts`] — which drops and
/// refolds every stats row — cannot erase the owner's dial.
const RAMP_FLOOR_KEY_PREFIX: &[u8] = b"ramp_floor:v1:";

/// `vault_meta` key prefix of the append-only demotion log. The full key is
/// this prefix ‖ `at` (u64 big-endian) ‖ demotion id (16 bytes), so a prefix
/// scan yields demotions in time order and two demotions in the same second
/// cannot collide.
///
/// These rows are TRUTH, not projection — they record an act, and a rebuild
/// folds them rather than regenerating them.
const RAMP_DEMOTION_KEY_PREFIX: &[u8] = b"ramp_demote:v1:";

/// Receipt-id prefix of a demotion receipt, and the discriminator
/// [`is_ramp_demotion_receipt`] tests inside the `Gate` receipt family.
const RAMP_DEMOTION_RECEIPT_PREFIX: &str = "ramp_demotion:";

/// Pinned `outcome` string of a demotion receipt.
const RAMP_DEMOTION_OUTCOME: &str = "demoted";

/// Only accepted schema version for either stored row.
const RAMP_ROW_VERSION: u8 = 1;

/// Domain separator for the scope handle digest.
const RAMP_SCOPE_DIGEST_DOMAIN: &[u8] = b"oneiron.consent_graduation.scope.v1";

/// Per-field cap on a scope tuple field, matching
/// [`crate::consent::MAX_CONSENT_REF_LEN`] so a scope that validates here also
/// converts to a [`GrantBound`] without a second, looser gate.
const MAX_RAMP_SCOPE_FIELD_LEN: usize = crate::consent::MAX_CONSENT_REF_LEN;

/// The compiled default streak floor: this many consecutive approved-untouched
/// rulings in one scope surface a graduation offer.
///
/// ED-05 (ONE-1761) replaces this single constant with the legible per-scope
/// threshold table; until then [`Vault::set_ramp_streak_floor`] is the whole
/// policy surface.
pub const DEFAULT_GRADUATION_STREAK_FLOOR: u32 = 12;

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// The DEC-0006 bound tuple the ramp keys on: (op kind × target class ×
/// actor).
///
/// Identical to the [`ProposalScope`] MS-05 stamps on every proposal-outcome
/// receipt — deliberately, so a receipts-alone rebuild needs no ledger join.
///
/// `actor` is a `String` rather than an `EntityId` because the slot is
/// genuinely wider than an entity: a proposal that bound no actor stamps
/// [`crate::identity_topology::PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED`], and the
/// DEC-0006 actor axis names skills and agents that have no entity row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RampScope {
    /// The op's wire kind (`"merge"`, `"send_email"`, …).
    pub op_kind: String,
    /// The class of thing the op targets (`"PERSON"`, `"client_followup"`, …).
    pub target_class: String,
    /// The acting skill/agent reference whose autonomy the ramp measures.
    pub actor: String,
}

impl RampScope {
    /// Builds a scope from its tuple, normalizing each field (trim, reject
    /// empty, cap length) so two spellings of one scope cannot key apart.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConsentBound`] when a field is empty or oversized.
    pub fn new(
        op_kind: impl Into<String>,
        target_class: impl Into<String>,
        actor: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            op_kind: normalized_scope_field("ramp scope op kind", op_kind.into())?,
            target_class: normalized_scope_field("ramp scope target class", target_class.into())?,
            actor: normalized_scope_field("ramp scope actor", actor.into())?,
        })
    }

    /// The deterministic 16-byte storage handle for this tuple.
    ///
    /// Length-prefixed field hashing, so `("a", "bc", …)` and `("ab", "c", …)`
    /// cannot collide by concatenation.
    #[must_use]
    pub fn key(&self) -> [u8; ENTITY_ID_LEN] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(RAMP_SCOPE_DIGEST_DOMAIN);
        for field in [&self.op_kind, &self.target_class, &self.actor] {
            hasher.update(&(field.len() as u64).to_le_bytes());
            hasher.update(field.as_bytes());
        }
        let mut key = [0_u8; ENTITY_ID_LEN];
        key.copy_from_slice(&hasher.finalize().as_bytes()[..ENTITY_ID_LEN]);
        key
    }

    /// The DEC-0006 action bound this scope graduates into: the actor is the
    /// subject, the op kind is the verb class, and the target class is the
    /// envelope's single selector.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConsentBound`] when a field cannot be a bound axis.
    pub fn to_grant_bound(&self) -> Result<GrantBound> {
        GrantBound::action(
            ActorBound::new(self.actor.clone())?,
            ActionClass::new(self.op_kind.clone())?,
            ActionEnvelope::new([self.target_class.clone()])?,
        )
    }

    /// The consent registry reference of this scope's grant — the bound
    /// digest, so a grant the owner minted through the plain
    /// [`Vault::create_standing_grant`] door is the SAME row this module reads.
    /// There is no second bookkeeping table to drift.
    ///
    /// # Errors
    ///
    /// Propagates [`RampScope::to_grant_bound`].
    pub fn grant_ref(&self) -> Result<String> {
        Ok(self.to_grant_bound()?.digest().to_hex())
    }

    /// Whether this scope may ever graduate — see [`op_kind_is_ramp_eligible`].
    #[must_use]
    pub fn is_graduatable(&self) -> bool {
        op_kind_is_ramp_eligible(&self.op_kind)
    }
}

impl From<&ProposalScope> for RampScope {
    fn from(scope: &ProposalScope) -> Self {
        Self {
            op_kind: scope.op_kind.to_owned(),
            target_class: scope.target_class.clone(),
            actor: scope.actor.clone(),
        }
    }
}

/// Whether an op kind sits on the propose→auto ramp at all.
///
/// FALSE for the identity-topology family. Those ops are AUTO day one (MS-01
/// r3) and carry their own per-write consent axis, so there is no propose lane
/// for the ramp to let anyone skip: graduating one would be authority the ramp
/// invented rather than authority the owner ever withheld. The ramp is the exit
/// path for scopes that honestly START at propose — external effects,
/// cross-person reach, tinkerer dials.
#[must_use]
pub fn op_kind_is_ramp_eligible(op_kind: &str) -> bool {
    !is_identity_topology_op_kind(op_kind)
}

fn normalized_scope_field(label: &'static str, value: String) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_RAMP_SCOPE_FIELD_LEN {
        return Err(Error::InvalidConsentBound(label));
    }
    Ok(trimmed.to_owned())
}

// ---------------------------------------------------------------------------
// State + stats
// ---------------------------------------------------------------------------

/// A scope's posture on the ramp.
///
/// DERIVED on every read from the consent registry and the scope's counters,
/// never stored: the standing grant IS the authority, so a second stored copy
/// of "is this graduated" could only ever disagree with it. Marked
/// `#[non_exhaustive]` for ED-05, which adds snooze / manual-pin states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RampState {
    /// Every op still rides the propose lane. Also the inert state of a scope
    /// the ramp does not govern.
    Propose,
    /// The streak crossed the floor: an offer is surfaced, and until the owner
    /// taps it every op still rides the propose lane.
    Offered,
    /// A standing grant is live; ops in this bound run auto.
    Graduated,
}

impl RampState {
    /// The pinned wire string for this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Propose => "proposed",
            Self::Offered => "offered",
            Self::Graduated => "auto",
        }
    }

    /// Parses a pinned state string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "proposed" => Some(Self::Propose),
            "offered" => Some(Self::Offered),
            "auto" => Some(Self::Graduated),
            _ => None,
        }
    }
}

/// One scope's running outcome statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScopeOutcomeStats {
    /// The scope these counters belong to.
    pub scope: RampScope,
    /// Consecutive approved-untouched rulings. Any amendment, any rejection,
    /// and any demotion zero it: the ramp measures a CLEAN streak.
    pub untouched_streak: u32,
    /// Lifetime amended-approval count.
    pub amended: u32,
    /// Lifetime rejection count.
    pub rejected: u32,
    /// The most recent ruling, if any.
    pub last_outcome: Option<ProposalOutcome>,
    /// When the counters last moved, in the caller's clock.
    pub updated_at: u64,
    /// The derived posture.
    pub state: RampState,
}

/// Why a scope was demoted back to the propose lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DemotionReason {
    /// A ruling in the graduated scope rejected the op.
    Rejected,
    /// A ruling in the graduated scope amended the op before approving.
    Amended,
    /// The agent's own call, absent a triggering ruling.
    AgentJudgment,
}

impl DemotionReason {
    /// The pinned wire/receipt string for this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
            Self::Amended => "amended",
            Self::AgentJudgment => "agent_judgment",
        }
    }

    /// Parses a pinned reason string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "rejected" => Some(Self::Rejected),
            "amended" => Some(Self::Amended),
            "agent_judgment" => Some(Self::AgentJudgment),
            _ => None,
        }
    }

    /// The demotion a ruling triggers, or `None` when the ruling was clean.
    const fn for_outcome(outcome: ProposalOutcome) -> Option<Self> {
        match outcome {
            ProposalOutcome::ApprovedUntouched => None,
            ProposalOutcome::ApprovedAmended => Some(Self::Amended),
            ProposalOutcome::Rejected => Some(Self::Rejected),
        }
    }
}

// ---------------------------------------------------------------------------
// Stored rows
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredScopeStats {
    v: u8,
    op_kind: String,
    target_class: String,
    actor: String,
    untouched_streak: u32,
    amended: u32,
    rejected: u32,
    last_outcome: Option<String>,
    updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredDemotion {
    v: u8,
    op_kind: String,
    target_class: String,
    actor: String,
    reason: String,
    /// The grant this demotion revoked, when the scope held one.
    grant_ref: Option<String>,
    at: u64,
}

/// The counters, decoupled from the tuple that keys them, so folding is one
/// function whichever direction the rows arrive from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Counters {
    untouched_streak: u32,
    amended: u32,
    rejected: u32,
    last_outcome: Option<ProposalOutcome>,
    updated_at: u64,
}

impl Counters {
    /// Folds one ruling. Saturating because a scope ruled `u32::MAX` times has
    /// long since said whatever it had to say; wrapping would silently reset a
    /// streak into a fresh graduation offer.
    fn apply_outcome(&mut self, outcome: ProposalOutcome, at: u64) {
        match outcome {
            ProposalOutcome::ApprovedUntouched => {
                self.untouched_streak = self.untouched_streak.saturating_add(1);
            }
            ProposalOutcome::ApprovedAmended => {
                self.amended = self.amended.saturating_add(1);
                self.untouched_streak = 0;
            }
            ProposalOutcome::Rejected => {
                self.rejected = self.rejected.saturating_add(1);
                self.untouched_streak = 0;
            }
        }
        self.last_outcome = Some(outcome);
        self.updated_at = at;
    }

    /// Folds one demotion: the clean streak restarts from zero, because the
    /// evidence that earned the offer has been contradicted.
    fn apply_demotion(&mut self, at: u64) {
        self.untouched_streak = 0;
        self.updated_at = at;
    }
}

fn stats_key(scope: &RampScope) -> Vec<u8> {
    meta_key(RAMP_STATS_KEY_PREFIX, &scope.key())
}

fn floor_key(scope: &RampScope) -> Vec<u8> {
    meta_key(RAMP_FLOOR_KEY_PREFIX, &scope.key())
}

fn meta_key(prefix: &[u8], handle: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + handle.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(handle);
    key
}

fn demotion_key(at: u64, id: &EntityId) -> Vec<u8> {
    let mut handle = Vec::with_capacity(8 + ENTITY_ID_LEN);
    handle.extend_from_slice(&at.to_be_bytes());
    handle.extend_from_slice(id.as_bytes());
    meta_key(RAMP_DEMOTION_KEY_PREFIX, &handle)
}

/// The demotion id embedded in a demotion row's key.
fn demotion_key_id(key: &[u8]) -> Result<EntityId> {
    let tail = key
        .get(RAMP_DEMOTION_KEY_PREFIX.len() + 8..)
        .and_then(|tail| <[u8; ENTITY_ID_LEN]>::try_from(tail).ok())
        .ok_or(Error::CorruptedIndex("ramp demotion key"))?;
    EntityId::from_bytes(tail).map_err(|_| Error::CorruptedIndex("ramp demotion key"))
}

fn encode_row<T: Serialize>(row: &T, label: &'static str) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| Error::InvariantViolation(label))
}

fn decode_row<T: serde::de::DeserializeOwned>(raw: &[u8], label: &'static str) -> Result<T> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex(label))
}

fn stats_row_parts(row: StoredScopeStats) -> Result<(RampScope, Counters)> {
    if row.v != RAMP_ROW_VERSION {
        return Err(Error::CorruptedIndex("ramp stats row"));
    }
    let scope = RampScope::new(row.op_kind, row.target_class, row.actor)
        .map_err(|_| Error::CorruptedIndex("ramp stats row"))?;
    let counters = Counters {
        untouched_streak: row.untouched_streak,
        amended: row.amended,
        rejected: row.rejected,
        last_outcome: row.last_outcome.as_deref().and_then(ProposalOutcome::parse),
        updated_at: row.updated_at,
    };
    Ok((scope, counters))
}

fn stats_row(scope: &RampScope, counters: Counters) -> StoredScopeStats {
    StoredScopeStats {
        v: RAMP_ROW_VERSION,
        op_kind: scope.op_kind.clone(),
        target_class: scope.target_class.clone(),
        actor: scope.actor.clone(),
        untouched_streak: counters.untouched_streak,
        amended: counters.amended,
        rejected: counters.rejected,
        last_outcome: counters
            .last_outcome
            .map(|outcome| outcome.as_str().to_owned()),
        updated_at: counters.updated_at,
    }
}

// ---------------------------------------------------------------------------
// Store-level reads and writes
// ---------------------------------------------------------------------------

fn read_counters_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    scope: &RampScope,
) -> Result<Counters> {
    let Some(raw) = store.vault_meta.get(txn, &stats_key(scope))? else {
        return Ok(Counters::default());
    };
    let row: StoredScopeStats = decode_row(&raw, "ramp stats row")?;
    Ok(stats_row_parts(row)?.1)
}

fn write_counters_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    scope: &RampScope,
    counters: Counters,
) -> Result<()> {
    let data = encode_row(&stats_row(scope, counters), "ramp stats row encode failed")?;
    store.vault_meta.put(wtxn, &stats_key(scope), &data)?;
    Ok(())
}

fn read_floor_in_txn(store: &Store, txn: &heed::RoTxn<'_>, scope: &RampScope) -> Result<u32> {
    let Some(raw) = store.vault_meta.get(txn, &floor_key(scope))? else {
        return Ok(DEFAULT_GRADUATION_STREAK_FLOOR);
    };
    <[u8; 4]>::try_from(raw.as_ref())
        .map(u32::from_le_bytes)
        .map_err(|_| Error::CorruptedIndex("ramp streak floor row"))
}

/// The scope's live standing grant reference, when one is active.
fn active_grant_ref_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: &RampScope,
) -> Result<Option<String>> {
    let grant_ref = scope.grant_ref()?;
    Ok(crate::consent::standing_grant_is_active_in_txn(
        &vault.store,
        txn,
        &grant_ref,
    )?
    .then_some(grant_ref))
}

/// Derives the posture from the two things that actually decide it: whether a
/// grant is live, and whether the clean streak has earned an offer.
fn derive_state_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: &RampScope,
    counters: Counters,
) -> Result<RampState> {
    if !scope.is_graduatable() {
        return Ok(RampState::Propose);
    }
    if active_grant_ref_in_txn(vault, txn, scope)?.is_some() {
        return Ok(RampState::Graduated);
    }
    let floor = read_floor_in_txn(&vault.store, txn, scope)?;
    if counters.untouched_streak >= floor {
        return Ok(RampState::Offered);
    }
    Ok(RampState::Propose)
}

fn stats_view(scope: RampScope, counters: Counters, state: RampState) -> ScopeOutcomeStats {
    ScopeOutcomeStats {
        scope,
        untouched_streak: counters.untouched_streak,
        amended: counters.amended,
        rejected: counters.rejected,
        last_outcome: counters.last_outcome,
        updated_at: counters.updated_at,
        state,
    }
}

/// Appends one demotion row and revokes the scope's standing grant, if any.
///
/// The receipt IS the row: a demotion writes exactly one durable record, which
/// [`demotion_receipts`] projects. Revoking and recording land in the caller's
/// transaction together, so no reader can observe a revoked grant with no
/// receipt explaining it — that is what "never silent" means mechanically.
fn append_demotion_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: &RampScope,
    reason: DemotionReason,
    at: u64,
) -> Result<()> {
    let grant_ref = scope.grant_ref()?;
    let grant_ref =
        crate::consent::revoke_standing_grant_in_txn(&vault.store, wtxn, &grant_ref)?
            .then_some(grant_ref);
    let row = StoredDemotion {
        v: RAMP_ROW_VERSION,
        op_kind: scope.op_kind.clone(),
        target_class: scope.target_class.clone(),
        actor: scope.actor.clone(),
        reason: reason.as_str().to_owned(),
        grant_ref,
        at,
    };
    let data = encode_row(&row, "ramp demotion row encode failed")?;
    vault
        .store
        .vault_meta
        .put(wtxn, &demotion_key(at, &EntityId::now()), &data)?;

    let mut counters = read_counters_in_txn(&vault.store, &*wtxn, scope)?;
    counters.apply_demotion(at);
    write_counters_in_txn(&vault.store, wtxn, scope, counters)
}

// ---------------------------------------------------------------------------
// Incremental maintenance
// ---------------------------------------------------------------------------

/// Folds one resolved proposal into its scope's counters, inside the caller's
/// write txn — the incremental maintenance half of the projection, called by
/// the ONE door that rules a proposal.
///
/// A ruling that is not clean DEMOTES a graduated scope in the same
/// transaction (ARCH-0055 r7): the owner correcting the engine is exactly the
/// evidence that the engine had not earned the right to stop asking.
///
/// Replicated resolutions do not pass through here — they arrive through sync
/// admission, which owns no ramp state. [`Vault::rebuild_ramp_stats_from_receipts`]
/// is the repair door that folds them in, the same division of labour
/// `identity_redirect` draws between incremental maintenance and rebuild.
fn record_outcome_for_scope_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: &RampScope,
    outcome: ProposalOutcome,
    at: u64,
) -> Result<Counters> {
    let mut counters = read_counters_in_txn(&vault.store, &*wtxn, scope)?;
    counters.apply_outcome(outcome, at);
    write_counters_in_txn(&vault.store, wtxn, scope, counters)?;

    if let Some(reason) = DemotionReason::for_outcome(outcome)
        && active_grant_ref_in_txn(vault, &*wtxn, scope)?.is_some()
    {
        append_demotion_in_txn(vault, wtxn, scope, reason, at)?;
        counters = read_counters_in_txn(&vault.store, &*wtxn, scope)?;
    }
    Ok(counters)
}

/// [`record_outcome_for_scope_in_txn`] for callers that do not need the folded
/// counters back — the shape the identity-topology resolution door uses.
///
/// Measurement is universal and graduation is not: an identity-topology scope's
/// counters move here like any other scope's, and [`op_kind_is_ramp_eligible`]
/// is what keeps merge/split from ever reaching an offer, a grant, or an
/// apply-path check.
pub(crate) fn record_ramp_outcome_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: &RampScope,
    outcome: ProposalOutcome,
    at: u64,
) -> Result<()> {
    record_outcome_for_scope_in_txn(vault, wtxn, scope, outcome, at)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The demotion receipt family (second `ReceiptKind::Gate` projector)
// ---------------------------------------------------------------------------

/// Whether a receipt is a ramp self-demotion — the discriminator inside the
/// `Gate` family, since demotions and gate decisions share a kind but not a
/// store.
#[must_use]
pub fn is_ramp_demotion_receipt(record: &ReceiptRecord) -> bool {
    record.receipt_kind == ReceiptKind::Gate
        && record.receipt_id.starts_with(RAMP_DEMOTION_RECEIPT_PREFIX)
}

/// Projects the demotion log as `Gate` receipts. Registered beside
/// `gate_receipts` in `receipt::collect_receipt_records`.
pub(crate) fn demotion_receipts(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for (scanned, entry) in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, RAMP_DEMOTION_KEY_PREFIX)?
        .enumerate()
    {
        if scanned >= crate::receipt::MAX_RECEIPT_QUERY_SCAN {
            break;
        }
        let (key, raw) = entry?;
        let id = demotion_key_id(&key)?;
        let row: StoredDemotion = decode_row(&raw, "ramp demotion row")?;
        if row.v != RAMP_ROW_VERSION {
            return Err(Error::CorruptedIndex("ramp demotion row"));
        }
        let receipt = demotion_receipt_record(&id, &row);
        if query.matches(&receipt) {
            out.push(receipt);
        }
    }
    Ok(out)
}

fn demotion_receipt_record(id: &EntityId, row: &StoredDemotion) -> ReceiptRecord {
    let mut fields = std::collections::BTreeMap::new();
    fields.insert(crate::receipt::FIELD_OP_KIND.to_owned(), row.op_kind.clone());
    fields.insert(
        crate::receipt::FIELD_TARGET_CLASS.to_owned(),
        row.target_class.clone(),
    );
    fields.insert(
        crate::receipt::FIELD_SCOPE_ACTOR.to_owned(),
        row.actor.clone(),
    );
    fields.insert(
        crate::receipt::FIELD_DEMOTION_REASON.to_owned(),
        row.reason.clone(),
    );
    if let Some(grant_ref) = row.grant_ref.as_ref() {
        fields.insert(crate::receipt::FIELD_GRANT_REF.to_owned(), grant_ref.clone());
    }

    ReceiptRecord {
        receipt_id: format!("{RAMP_DEMOTION_RECEIPT_PREFIX}{}", id.to_hex()),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: row.at,
        actor: Some(row.actor.clone()),
        on_behalf_of: None,
        outcome: RAMP_DEMOTION_OUTCOME.to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: vec![format!("consent.ramp.demoted.{}", row.reason)],
        fields,
    }
}

// ---------------------------------------------------------------------------
// Doors
// ---------------------------------------------------------------------------

impl Vault {
    /// Resolves the ramp scope handle for one (op kind × target class × actor)
    /// tuple. Identical tuples resolve to the same scope; any difference on any
    /// axis is a different scope (oracle
    /// `ms06_ramp_scope_keys_on_op_class_agent_tuple`).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConsentBound`] when a tuple field is empty or oversized.
    pub fn ramp_scope(
        &self,
        op_kind: &str,
        target_class: &str,
        actor: &str,
    ) -> Result<RampScope> {
        RampScope::new(op_kind, target_class, actor)
    }

    /// Folds one ruling into a scope's statistics, demoting the scope if the
    /// ruling was not clean. The propose-lane door for surfaces outside
    /// identity topology.
    ///
    /// # Errors
    ///
    /// Storage failures, and [`Error::InvalidConsentBound`] when the scope
    /// cannot form a bound.
    pub fn record_proposal_outcome_for_ramp(
        &self,
        scope: &RampScope,
        outcome: ProposalOutcome,
    ) -> Result<ScopeOutcomeStats> {
        let at = crate::unix_seconds_now();
        let counters = self.with_write_txn(|wtxn| {
            record_outcome_for_scope_in_txn(self, wtxn, scope, outcome, at)
        })?;
        let rtxn = self.store.env.read_txn()?;
        let state = derive_state_in_txn(self, &rtxn, scope, counters)?;
        Ok(stats_view(scope.clone(), counters, state))
    }

    /// One scope's statistics, or `None` when nothing has ever been ruled in
    /// it.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub fn scope_stats(&self, scope: &RampScope) -> Result<Option<ScopeOutcomeStats>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.vault_meta.get(&rtxn, &stats_key(scope))? else {
            return Ok(None);
        };
        let row: StoredScopeStats = decode_row(&raw, "ramp stats row")?;
        let (stored_scope, counters) = stats_row_parts(row)?;
        let state = derive_state_in_txn(self, &rtxn, &stored_scope, counters)?;
        Ok(Some(stats_view(stored_scope, counters, state)))
    }

    /// The scope's current posture as a pinned wire string.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub fn ramp_scope_state(&self, scope: &RampScope) -> Result<RampState> {
        let rtxn = self.store.env.read_txn()?;
        let counters = read_counters_in_txn(&self.store, &rtxn, scope)?;
        derive_state_in_txn(self, &rtxn, scope, counters)
    }

    /// Every scope currently offering graduation: eligible, clean streak at or
    /// past its floor, and no grant live yet.
    ///
    /// An offer is DERIVED, never a stored row — so it cannot outlive the
    /// evidence that produced it, and a demotion retracts it by construction.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub fn graduation_offers(&self) -> Result<Vec<RampScope>> {
        let rtxn = self.store.env.read_txn()?;
        let mut offers = Vec::new();
        for entry in self
            .store
            .vault_meta
            .prefix_iter(&rtxn, RAMP_STATS_KEY_PREFIX)?
        {
            let (_, raw) = entry?;
            let row: StoredScopeStats = decode_row(&raw, "ramp stats row")?;
            let (scope, counters) = stats_row_parts(row)?;
            if derive_state_in_txn(self, &rtxn, &scope, counters)? == RampState::Offered {
                offers.push(scope);
            }
        }
        offers.sort_unstable();
        Ok(offers)
    }

    /// The owner taps a surfaced graduation offer, minting the standing grant.
    ///
    /// Requires an [`AuthenticatedOwner`] and routes through the one
    /// [`Vault::create_standing_grant`] door: no streak, however long, can
    /// produce authority on its own (DEC-0006 invariant 5, oracle
    /// `ms06_streak_offers_standing_grant_never_auto_grants`).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConsentBound`] when the scope is not on the ramp at all,
    /// plus whatever `create_standing_grant` rejects (the catastrophe floor).
    pub fn accept_graduation_offer(
        &self,
        owner: &AuthenticatedOwner,
        scope: &RampScope,
    ) -> Result<ConsentReceipt> {
        if !scope.is_graduatable() {
            return Err(Error::InvalidConsentBound(
                "op kind does not ride the propose lane; there is nothing to graduate",
            ));
        }
        self.create_standing_grant(owner, scope.to_grant_bound()?)
    }

    /// Demotes a scope back to the propose lane: revokes its standing grant if
    /// one is live, appends the demotion receipt, and zeroes the clean streak.
    ///
    /// Reducing one's own authority needs no owner authentication — only
    /// GRANTING does. What it does need is to be said out loud, which is the
    /// unconditional receipt (oracle
    /// `ms06_self_demotion_is_receipted_never_silent`): a scope with no live
    /// grant still records the act, so "I stopped trusting myself here" is
    /// never inferred from an absence.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub fn demote_scope_to_propose(
        &self,
        scope: &RampScope,
        reason: DemotionReason,
    ) -> Result<()> {
        let at = crate::unix_seconds_now();
        self.with_write_txn(|wtxn| append_demotion_in_txn(self, wtxn, scope, reason, at))
    }

    /// Overrides one scope's graduation streak floor (ED-05's seam; the
    /// compiled default is [`DEFAULT_GRADUATION_STREAK_FLOOR`]).
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub fn set_ramp_streak_floor(&self, scope: &RampScope, floor: u32) -> Result<()> {
        self.with_write_txn(|wtxn| {
            self.store
                .vault_meta
                .put(wtxn, &floor_key(scope), &floor.to_le_bytes())?;
            Ok(())
        })
    }

    /// The floor in force for one scope.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub fn ramp_streak_floor(&self, scope: &RampScope) -> Result<u32> {
        let rtxn = self.store.env.read_txn()?;
        read_floor_in_txn(&self.store, &rtxn, scope)
    }

    /// CID-7 door: drops the whole statistics projection and refolds it from
    /// truth — the ARCH-0055 r7 proposal-outcome receipts, interleaved in time
    /// order with this module's own demotion rows.
    ///
    /// Both inputs are needed and neither is optional: the receipts carry every
    /// ruling (each stamped with its own scope tuple, so no ledger join is
    /// required), and the demotion rows carry the streak resets that no ruling
    /// implies. Floors and demotions are untouched — a rebuild repairs a cache,
    /// it never rewrites policy or history.
    ///
    /// # Errors
    ///
    /// Storage failures, and [`Error::CorruptedIndex`] on an unreadable row.
    pub fn rebuild_ramp_stats_from_receipts(&self) -> Result<()> {
        let events = self.ramp_fold_events()?;
        self.with_write_txn(|wtxn| {
            let stale: Vec<Vec<u8>> = self
                .store
                .vault_meta
                .prefix_iter(&*wtxn, RAMP_STATS_KEY_PREFIX)?
                .map(|row| row.map(|(key, _)| key.to_vec()))
                .collect::<Result<_>>()?;
            for key in stale {
                self.store.vault_meta.delete(wtxn, &key)?;
            }

            let mut folded: std::collections::BTreeMap<RampScope, Counters> =
                std::collections::BTreeMap::new();
            for (at, scope, outcome) in &events {
                let counters = folded.entry(scope.clone()).or_default();
                match outcome {
                    Some(outcome) => counters.apply_outcome(*outcome, *at),
                    None => counters.apply_demotion(*at),
                }
            }
            for (scope, counters) in &folded {
                write_counters_in_txn(&self.store, wtxn, scope, *counters)?;
            }
            Ok(())
        })
    }

    /// Every fold input in time order: `(at, scope, Some(outcome))` for a
    /// ruling, `(at, scope, None)` for a demotion.
    fn ramp_fold_events(&self) -> Result<Vec<(u64, RampScope, Option<ProposalOutcome>)>> {
        let mut events = Vec::new();
        let outcome_query = ReceiptQuery::new(crate::receipt::MAX_RECEIPT_QUERY_SCAN)
            .with_kind(ReceiptKind::ProposalOutcome);
        for receipt in self.receipts(outcome_query)? {
            let Some(outcome) = ProposalOutcome::parse(&receipt.outcome) else {
                continue;
            };
            let Some(scope) = ramp_scope_from_receipt_fields(&receipt) else {
                continue;
            };
            events.push((receipt.occurred_at, scope, Some(outcome)));
        }

        let rtxn = self.store.env.read_txn()?;
        for entry in self
            .store
            .vault_meta
            .prefix_iter(&rtxn, RAMP_DEMOTION_KEY_PREFIX)?
        {
            let (_, raw) = entry?;
            let row: StoredDemotion = decode_row(&raw, "ramp demotion row")?;
            let scope = RampScope::new(row.op_kind, row.target_class, row.actor)
                .map_err(|_| Error::CorruptedIndex("ramp demotion row"))?;
            events.push((row.at, scope, None));
        }

        // A demotion caused by a ruling shares that ruling's timestamp and must
        // fold AFTER it, else the reset the ruling triggered is folded away.
        events.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| right.2.is_some().cmp(&left.2.is_some()))
        });
        Ok(events)
    }
}

/// Reads the ramp scope tuple MS-05 stamps on every proposal-outcome receipt.
fn ramp_scope_from_receipt_fields(receipt: &ReceiptRecord) -> Option<RampScope> {
    RampScope::new(
        receipt.fields.get(crate::receipt::FIELD_OP_KIND)?.clone(),
        receipt
            .fields
            .get(crate::receipt::FIELD_TARGET_CLASS)?
            .clone(),
        receipt.fields.get(crate::receipt::FIELD_SCOPE_ACTOR)?.clone(),
    )
    .ok()
}

#[cfg(test)]
mod tests;
