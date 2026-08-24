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

use serde::{Deserialize, Serialize};

use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, ConsentReceipt, GrantBound,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::identity_topology::{
    IdentityTopologyAction, IdentityTopologyRejection, ProposalOutcome, ProposalScope,
    StoredIdentityOpAction, fold_identity_topology_log, is_identity_topology_op_kind,
};
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
/// this prefix ‖ `at` (u64 big-endian) ‖ row id (16 bytes), so two demotions in
/// the same second cannot collide.
///
/// These rows are TRUTH, not projection — they record an act, and a rebuild
/// folds them rather than regenerating them.
const RAMP_DEMOTION_KEY_PREFIX: &[u8] = b"ramp_demote:v1:";

/// `vault_meta` key prefix of the append-only DOOR-RECORDED outcome log, keyed
/// like the demotion log.
///
/// A ruling that arrives through [`Vault::record_proposal_outcome_for_ramp`]
/// has no identity-topology ledger event behind it, so without this row the
/// streak it feeds would be trust nothing durable witnesses: the next rebuild
/// would delete it, and until then the engine would surface a graduation offer
/// no receipt can explain. Rulings that DO carry a ledger event never write
/// here — the type-76 row is their witness, and a second one would double-count
/// on refold.
const RAMP_OUTCOME_KEY_PREFIX: &[u8] = b"ramp_outcome:v1:";

/// Receipt-id prefix of a demotion receipt, and the discriminator
/// [`is_ramp_demotion_receipt`] tests inside the `Gate` receipt family.
const RAMP_DEMOTION_RECEIPT_PREFIX: &str = "ramp_demotion:";

/// Receipt-id prefix of a door-recorded outcome receipt — the
/// [`is_ramp_outcome_receipt`] discriminator.
const RAMP_OUTCOME_RECEIPT_PREFIX: &str = "ramp_outcome:";

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
/// rulings in one scope are the repetition half of a graduation offer.
///
/// Since ED-05 (ONE-1761) this is the streak axis of the catch-all row in
/// [`crate::edit_distance::graduation`]'s threshold table, where it is paired
/// with [`crate::edit_distance::graduation::DEFAULT_POSTERIOR_GUARD`]. The two
/// are co-designed: a SPOTLESS twelve-approval streak clears that guard and a
/// twelve-approval streak with corrections behind it does not.
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
        let (op_kind, target_class, actor) = (op_kind.into(), target_class.into(), actor.into());
        Ok(Self {
            op_kind: normalized_scope_field(SCOPE_OP_KIND_LABEL, &op_kind)?.to_owned(),
            target_class: normalized_scope_field(SCOPE_TARGET_CLASS_LABEL, &target_class)?
                .to_owned(),
            actor: normalized_scope_field(SCOPE_ACTOR_LABEL, &actor)?.to_owned(),
        })
    }

    /// Re-checks the tuple [`RampScope::new`] would have produced.
    ///
    /// The fields are `pub` (ED-05 builds scopes from its own policy rows), so
    /// [`RampScope::new`] is a door, not a gate: a caller may assemble a tuple
    /// that is empty, oversized, or merely un-normalized — and an
    /// un-normalized twin keys to a DIFFERENT row than the scope it names.
    /// Every mutating door runs this before its first write, so an unbuildable
    /// tuple can never leave a committed row behind for the all-scopes scan to
    /// choke on.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConsentBound`] when a field is empty, oversized, or
    /// carries surrounding whitespace.
    pub fn validate(&self) -> Result<()> {
        for (label, value) in [
            (SCOPE_OP_KIND_LABEL, &self.op_kind),
            (SCOPE_TARGET_CLASS_LABEL, &self.target_class),
            (SCOPE_ACTOR_LABEL, &self.actor),
        ] {
            if normalized_scope_field(label, value)? != value.as_str() {
                return Err(Error::InvalidConsentBound(label));
            }
        }
        Ok(())
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

const SCOPE_OP_KIND_LABEL: &str = "ramp scope op kind";
const SCOPE_TARGET_CLASS_LABEL: &str = "ramp scope target class";
const SCOPE_ACTOR_LABEL: &str = "ramp scope actor";

fn normalized_scope_field<'a>(label: &'static str, value: &'a str) -> Result<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_RAMP_SCOPE_FIELD_LEN {
        return Err(Error::InvalidConsentBound(label));
    }
    Ok(trimmed)
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
    /// The identity-topology causality clock at write time — see [`FoldKey`].
    after_seq: u64,
    at: u64,
}

/// One ruling recorded through the ramp door rather than through an
/// identity-topology resolution (which carries its own ledger event).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRampOutcome {
    v: u8,
    op_kind: String,
    target_class: String,
    actor: String,
    outcome: String,
    /// The identity-topology causality clock at write time — see [`FoldKey`].
    after_seq: u64,
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

/// The order a rebuild folds in — by construction the order incremental
/// maintenance wrote in.
///
/// `(watermark, rank, id)`:
/// - `watermark` is the identity-topology causality clock. A ledger ruling
///   carries its own `seq`; a ramp row stamps the clock it read at write time,
///   so it sorts after every ruling that preceded it and before every ruling
///   that followed. Caller-supplied wall time is DATA, never order — the
///   resolve door takes `now` from its caller, so two rulings in one second (or
///   a clock that steps backwards) must still fold in ledger order.
/// - `rank` separates ledger rulings from this module's rows at an equal
///   watermark: a row stamped `seq` was written AFTER ruling `seq`, which is
///   exactly the demotion a ruling triggers inside its own transaction.
/// - `id` breaks the remaining ties in mint order — the resolution event id
///   (matching `fold_identity_topology_log`'s own `(seq, event_id)` order), or
///   the time-ordered ramp row id.
type FoldKey = (u64, u8, EntityId);

const FOLD_RANK_LEDGER: u8 = 0;
const FOLD_RANK_RAMP_ROW: u8 = 1;

/// One durable act the rebuild refolds: a ruling (`outcome` present) or a
/// demotion (`outcome` absent).
#[derive(Debug, Clone)]
struct RampFoldEvent {
    key: FoldKey,
    scope: RampScope,
    /// The act's wall time — carried as DATA into `updated_at`, never as order.
    at: u64,
    outcome: Option<ProposalOutcome>,
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

fn ramp_row_key(prefix: &[u8], at: u64, id: &EntityId) -> Vec<u8> {
    let mut handle = Vec::with_capacity(8 + ENTITY_ID_LEN);
    handle.extend_from_slice(&at.to_be_bytes());
    handle.extend_from_slice(id.as_bytes());
    meta_key(prefix, &handle)
}

/// The row id embedded in a ramp row's key.
fn ramp_row_key_id(prefix: &[u8], key: &[u8], label: &'static str) -> Result<EntityId> {
    let tail = key
        .get(prefix.len() + 8..)
        .and_then(|tail| <[u8; ENTITY_ID_LEN]>::try_from(tail).ok())
        .ok_or(Error::CorruptedIndex(label))?;
    EntityId::from_bytes(tail).map_err(|_| Error::CorruptedIndex(label))
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

/// The per-scope streak override, when the owner set one.
///
/// `Option` rather than defaulted, because ED-05 composes it: an ABSENT
/// override falls through to the threshold row's own streak, whereas a present
/// one is the most specific policy statement there is and takes that axis
/// outright.
pub(crate) fn ramp_floor_override_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    scope: &RampScope,
) -> Result<Option<u32>> {
    let Some(raw) = store.vault_meta.get(txn, &floor_key(scope))? else {
        return Ok(None);
    };
    <[u8; 4]>::try_from(raw.as_ref())
        .map(|bytes| Some(u32::from_le_bytes(bytes)))
        .map_err(|_| Error::CorruptedIndex("ramp streak floor row"))
}

/// The scope's live standing grant reference, when one is active.
pub(crate) fn active_grant_ref_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: &RampScope,
) -> Result<Option<String>> {
    let grant_ref = scope.grant_ref()?;
    Ok(
        crate::consent::standing_grant_is_active_in_txn(&vault.store, txn, &grant_ref)?
            .then_some(grant_ref),
    )
}

/// Derives the posture from the two things that actually decide it: whether a
/// grant is live, and whether the ruling history has earned an offer.
///
/// The second half is ED-05's (ONE-1761): the compiled streak floor this module
/// shipped is now the catch-all row of
/// [`crate::edit_distance::graduation`]'s threshold table, which adds the
/// posterior guard that tells a spotless streak apart from an equally long one
/// with corrections behind it.
///
/// Snooze and pin do NOT appear here. They govern whether the engine ASKS,
/// which is [`Vault::graduation_offers`]'s question; this one is what authority
/// is live, and an offer the owner has declined for now is still an offer they
/// may accept. Keeping them orthogonal is why a snooze can never quietly cost
/// the owner a graduation they wanted.
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
    let policy =
        crate::edit_distance::graduation::graduation_policy_in_txn(&vault.store, txn, scope)?;
    let corrections = counters.amended.saturating_add(counters.rejected);
    if policy.is_cleared_by(counters.untouched_streak, corrections) {
        return Ok(RampState::Offered);
    }
    Ok(RampState::Propose)
}

/// Whether an offer is standing for this scope right now — ED-05's atomic
/// pre-check, so an answer cannot be recorded against an offer a ruling
/// retracted while the owner was reading it.
pub(crate) fn offer_is_standing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: &RampScope,
) -> Result<bool> {
    let counters = read_counters_in_txn(&vault.store, txn, scope)?;
    Ok(derive_state_in_txn(vault, txn, scope, counters)? == RampState::Offered)
}

/// Every scope with a statistics row, fully derived.
///
/// The enumeration behind both [`Vault::graduation_offers`] and ED-05's trust
/// table: one scan, one place the all-scopes read can be got wrong.
pub(crate) fn ramp_stats_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<ScopeOutcomeStats>> {
    let mut rows = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(txn, RAMP_STATS_KEY_PREFIX)?
    {
        let (_, raw) = entry?;
        let row: StoredScopeStats = decode_row(&raw, "ramp stats row")?;
        let (scope, counters) = stats_row_parts(row)?;
        let state = derive_state_in_txn(vault, txn, &scope, counters)?;
        rows.push(stats_view(scope, counters, state));
    }
    Ok(rows)
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
    let grant_ref = crate::consent::revoke_standing_grant_in_txn(&vault.store, wtxn, &grant_ref)?
        .then_some(grant_ref);
    let row = StoredDemotion {
        v: RAMP_ROW_VERSION,
        op_kind: scope.op_kind.clone(),
        target_class: scope.target_class.clone(),
        actor: scope.actor.clone(),
        reason: reason.as_str().to_owned(),
        grant_ref,
        after_seq: vault.read_identity_topology_seq_in_txn(&*wtxn)?,
        at,
    };
    let data = encode_row(&row, "ramp demotion row encode failed")?;
    vault.store.vault_meta.put(
        wtxn,
        &ramp_row_key(RAMP_DEMOTION_KEY_PREFIX, at, &EntityId::now()),
        &data,
    )?;

    let mut counters = read_counters_in_txn(&vault.store, &*wtxn, scope)?;
    counters.apply_demotion(at);
    write_counters_in_txn(&vault.store, wtxn, scope, counters)
}

/// Appends the durable record of a ruling that has no ledger event of its own.
///
/// The row is what makes a door-recorded streak REAL: it is the receipt the
/// offer rests on, and it is what a rebuild refolds. Rulings resolved through
/// identity topology never reach here — their type-76 event is already both.
fn append_door_outcome_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: &RampScope,
    outcome: ProposalOutcome,
    at: u64,
) -> Result<()> {
    let row = StoredRampOutcome {
        v: RAMP_ROW_VERSION,
        op_kind: scope.op_kind.clone(),
        target_class: scope.target_class.clone(),
        actor: scope.actor.clone(),
        outcome: outcome.as_str().to_owned(),
        after_seq: vault.read_identity_topology_seq_in_txn(&*wtxn)?,
        at,
    };
    let data = encode_row(&row, "ramp outcome row encode failed")?;
    vault.store.vault_meta.put(
        wtxn,
        &ramp_row_key(RAMP_OUTCOME_KEY_PREFIX, at, &EntityId::now()),
        &data,
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Incremental maintenance
// ---------------------------------------------------------------------------

/// What makes one folded ruling durable, and therefore refoldable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutcomeWitness {
    /// An identity-topology resolution event: the type-76 row IS the record,
    /// and the r7 proposal-outcome receipt projects it. Writing a ramp row too
    /// would double-count the same ruling on every refold.
    Ledger,
    /// No ledger event exists (the propose-lane door for surfaces outside
    /// identity topology), so the ramp appends its own outcome row.
    Door,
}

/// Folds one resolved proposal into its scope's counters, inside the caller's
/// write txn — the incremental maintenance half of the projection.
///
/// A ruling that is not clean DEMOTES a graduated scope in the same
/// transaction (ARCH-0055 r7): the owner correcting the engine is exactly the
/// evidence that the engine had not earned the right to stop asking.
///
/// Replicated resolutions do not pass through here — they arrive through sync
/// admission, which owns no ramp state, so a replica's counters stay behind
/// until [`Vault::rebuild_ramp_stats_from_receipts`] folds the ledger it did
/// receive. That is a deliberate boundary, not the division `identity_redirect`
/// draws: redirect rows ARE maintained at the sync reconciliation chokepoint.
/// The ramp can afford to differ because a graduated grant lives in
/// `vault_meta`, which no sync path writes — a replica holds no ramp authority
/// to be stale ABOUT, so lagging counters are fail-closed (it keeps proposing).
/// Surfacing offers on a replica from replicated rulings would be a design
/// amendment: fold at the sync reconcile chokepoint, as redirect does.
fn record_outcome_for_scope_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: &RampScope,
    outcome: ProposalOutcome,
    at: u64,
    witness: OutcomeWitness,
) -> Result<Counters> {
    if witness == OutcomeWitness::Door {
        append_door_outcome_in_txn(vault, wtxn, scope, outcome, at)?;
    }
    let mut counters = read_counters_in_txn(&vault.store, &*wtxn, scope)?;
    counters.apply_outcome(outcome, at);
    write_counters_in_txn(&vault.store, wtxn, scope, counters)?;

    if let Some(reason) = DemotionReason::for_outcome(outcome)
        && active_grant_ref_in_txn(vault, &*wtxn, scope)?.is_some()
    {
        append_demotion_in_txn(vault, wtxn, scope, reason, at)?;
        // The demotion folded exactly this into the store: our own counters,
        // demoted. No re-read needed.
        counters.apply_demotion(at);
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
    record_outcome_for_scope_in_txn(vault, wtxn, scope, outcome, at, OutcomeWitness::Ledger)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The ramp receipt family (second `ReceiptKind::Gate` projector)
// ---------------------------------------------------------------------------

/// Whether a receipt is a ramp self-demotion — the discriminator inside the
/// `Gate` family, since demotions and gate decisions share a kind but not a
/// store.
#[must_use]
pub fn is_ramp_demotion_receipt(record: &ReceiptRecord) -> bool {
    is_ramp_receipt(record, RAMP_DEMOTION_RECEIPT_PREFIX)
}

/// Whether a receipt is a ruling recorded through the ramp door — the witness
/// behind a streak that has no identity-topology event of its own.
#[must_use]
pub fn is_ramp_outcome_receipt(record: &ReceiptRecord) -> bool {
    is_ramp_receipt(record, RAMP_OUTCOME_RECEIPT_PREFIX)
}

fn is_ramp_receipt(record: &ReceiptRecord, prefix: &str) -> bool {
    record.receipt_kind == ReceiptKind::Gate && record.receipt_id.starts_with(prefix)
}

/// Projects this module's two append-only logs as `Gate` receipts. Registered
/// beside `gate_receipts` in `receipt::collect_receipt_records`.
pub(crate) fn ramp_receipts(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, RAMP_OUTCOME_KEY_PREFIX)?
        .take(crate::receipt::MAX_RECEIPT_QUERY_SCAN)
    {
        let (key, raw) = entry?;
        let row: StoredRampOutcome = decode_ramp_row(&raw, RAMP_OUTCOME_ROW_LABEL)?;
        let id = ramp_row_key_id(RAMP_OUTCOME_KEY_PREFIX, &key, RAMP_OUTCOME_ROW_LABEL)?;
        let receipt = door_outcome_receipt_record(&id, &row);
        if query.matches(&receipt) {
            out.push(receipt);
        }
    }
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, RAMP_DEMOTION_KEY_PREFIX)?
        .take(crate::receipt::MAX_RECEIPT_QUERY_SCAN)
    {
        let (key, raw) = entry?;
        let row: StoredDemotion = decode_ramp_row(&raw, RAMP_DEMOTION_ROW_LABEL)?;
        let id = ramp_row_key_id(RAMP_DEMOTION_KEY_PREFIX, &key, RAMP_DEMOTION_ROW_LABEL)?;
        let receipt = demotion_receipt_record(&id, &row);
        if query.matches(&receipt) {
            out.push(receipt);
        }
    }
    // ED-05's answered offers are the third family on this registration rather
    // than a fourth projector in `receipt::collect_receipt_records`: they are
    // the same ramp, the same `Gate` kind, and — sharing this read txn — they
    // cost no second, nested transaction.
    out.extend(crate::edit_distance::graduation::answer_receipts_in_txn(
        &vault.store,
        &rtxn,
        query,
    )?);
    Ok(out)
}

const RAMP_OUTCOME_ROW_LABEL: &str = "ramp outcome row";
const RAMP_DEMOTION_ROW_LABEL: &str = "ramp demotion row";

/// Decodes one ramp row, rejecting a version this build cannot read. Both
/// stored rows carry `v` in the same slot, so both are guarded here.
fn decode_ramp_row<T: serde::de::DeserializeOwned + RampRowVersion>(
    raw: &[u8],
    label: &'static str,
) -> Result<T> {
    let row: T = decode_row(raw, label)?;
    if row.version() != RAMP_ROW_VERSION {
        return Err(Error::CorruptedIndex(label));
    }
    Ok(row)
}

/// The one question every append-only ramp row answers before it is read.
trait RampRowVersion {
    fn version(&self) -> u8;
}

impl RampRowVersion for StoredDemotion {
    fn version(&self) -> u8 {
        self.v
    }
}

impl RampRowVersion for StoredRampOutcome {
    fn version(&self) -> u8 {
        self.v
    }
}

/// The scope tuple every ramp receipt names, in the SAME field keys the
/// proposal-outcome receipts use — one spelling, so the two families join.
fn scope_receipt_fields(
    op_kind: &str,
    target_class: &str,
    actor: &str,
) -> std::collections::BTreeMap<String, String> {
    let mut fields = std::collections::BTreeMap::new();
    fields.insert(crate::receipt::FIELD_OP_KIND.to_owned(), op_kind.to_owned());
    fields.insert(
        crate::receipt::FIELD_TARGET_CLASS.to_owned(),
        target_class.to_owned(),
    );
    fields.insert(
        crate::receipt::FIELD_SCOPE_ACTOR.to_owned(),
        actor.to_owned(),
    );
    fields
}

fn demotion_receipt_record(id: &EntityId, row: &StoredDemotion) -> ReceiptRecord {
    let mut fields = scope_receipt_fields(&row.op_kind, &row.target_class, &row.actor);
    fields.insert(
        crate::receipt::FIELD_DEMOTION_REASON.to_owned(),
        row.reason.clone(),
    );
    if let Some(grant_ref) = row.grant_ref.as_ref() {
        fields.insert(
            crate::receipt::FIELD_GRANT_REF.to_owned(),
            grant_ref.clone(),
        );
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

fn door_outcome_receipt_record(id: &EntityId, row: &StoredRampOutcome) -> ReceiptRecord {
    ReceiptRecord {
        receipt_id: format!("{RAMP_OUTCOME_RECEIPT_PREFIX}{}", id.to_hex()),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: row.at,
        actor: Some(row.actor.clone()),
        on_behalf_of: None,
        outcome: row.outcome.clone(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: vec![format!("consent.ramp.outcome.{}", row.outcome)],
        fields: scope_receipt_fields(&row.op_kind, &row.target_class, &row.actor),
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
    pub fn ramp_scope(&self, op_kind: &str, target_class: &str, actor: &str) -> Result<RampScope> {
        RampScope::new(op_kind, target_class, actor)
    }

    /// Folds one ruling into a scope's statistics, demoting the scope if the
    /// ruling was not clean. The propose-lane door for surfaces outside
    /// identity topology.
    ///
    /// The ruling lands as a durable outcome row FIRST: a counter this door
    /// moved with nothing behind it would be autonomy the ledger cannot
    /// witness, and the next rebuild would take it away again.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConsentBound`] when the scope tuple is unbuildable
    /// (checked before the first write), plus storage failures.
    pub fn record_proposal_outcome_for_ramp(
        &self,
        scope: &RampScope,
        outcome: ProposalOutcome,
    ) -> Result<ScopeOutcomeStats> {
        scope.validate()?;
        let at = crate::unix_seconds_now();
        let counters = self.with_write_txn(|wtxn| {
            record_outcome_for_scope_in_txn(self, wtxn, scope, outcome, at, OutcomeWitness::Door)
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

    /// Every scope the engine should ASK about right now: eligible, history past
    /// its threshold row, no grant live yet, and not held by ED-05's snooze or
    /// pin.
    ///
    /// An offer is DERIVED, never a stored row — so it cannot outlive the
    /// evidence that produced it, and a demotion retracts it by construction.
    ///
    /// The suppression consult is the whole of what snooze and pin do: they
    /// remove a scope from this list and from nothing else. The offer stays
    /// standing ([`RampState::Offered`]) and stays acceptable, because "stop
    /// asking me" is not "take this away from me".
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub fn graduation_offers(&self) -> Result<Vec<RampScope>> {
        let rtxn = self.store.env.read_txn()?;
        let now = crate::unix_seconds_now();
        let mut offers = Vec::new();
        for stats in ramp_stats_in_txn(self, &rtxn)? {
            if stats.state == RampState::Offered
                && !crate::edit_distance::graduation::asks_are_suppressed_in_txn(
                    &self.store,
                    &rtxn,
                    &stats.scope,
                    now,
                )?
            {
                offers.push(stats.scope);
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
    /// The offer must still be STANDING at the instant the grant is written,
    /// and that is tested in the minting transaction itself. A tap answers an
    /// offer the owner saw; between seeing it and tapping it, a rejection or an
    /// amendment may have retracted that offer and receipted the demotion. A
    /// stale tap that could still mint would let a scope walk back from
    /// demoted to graduated with no ruling in between — the exact silence this
    /// module exists to prevent.
    ///
    /// Answering here and answering through
    /// [`crate::edit_distance::graduation::answer_graduation_offer`] are the
    /// same act and leave the same durable state: both record the go-auto
    /// answer, which clears whatever snooze or pin the scope was carrying.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConsentBound`] when the scope is not on the ramp at all,
    /// when its tuple is unbuildable, or when it is not currently offering
    /// graduation; plus whatever `create_standing_grant` rejects (the
    /// catastrophe floor).
    pub fn accept_graduation_offer(
        &self,
        owner: &AuthenticatedOwner,
        scope: &RampScope,
    ) -> Result<ConsentReceipt> {
        let at = crate::unix_seconds_now();
        self.with_write_txn(|wtxn| accept_graduation_offer_in_txn(self, wtxn, owner, scope, at))
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
    /// [`Error::InvalidConsentBound`] when the scope tuple is unbuildable,
    /// plus storage failures.
    pub fn demote_scope_to_propose(&self, scope: &RampScope, reason: DemotionReason) -> Result<()> {
        scope.validate()?;
        let at = crate::unix_seconds_now();
        self.with_write_txn(|wtxn| append_demotion_in_txn(self, wtxn, scope, reason, at))
    }

    /// Overrides one scope's graduation streak floor (ED-05's seam; the
    /// compiled default is [`DEFAULT_GRADUATION_STREAK_FLOOR`]).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConsentBound`] when the scope tuple is unbuildable,
    /// plus storage failures.
    pub fn set_ramp_streak_floor(&self, scope: &RampScope, floor: u32) -> Result<()> {
        scope.validate()?;
        self.with_write_txn(|wtxn| {
            self.store
                .vault_meta
                .put(wtxn, &floor_key(scope), &floor.to_le_bytes())?;
            Ok(())
        })
    }

    /// The streak in force for one scope — this scope's own override when it
    /// has one, otherwise whatever ED-05 threshold row governs it.
    ///
    /// Reads the EFFECTIVE policy rather than only the override keyspace, so it
    /// cannot answer with the compiled default while a pattern row is the thing
    /// actually deciding. [`crate::edit_distance::graduation::
    /// graduation_policy_for`] returns the whole row, guard included.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] on an unreadable threshold row, plus storage
    /// failures.
    pub fn ramp_streak_floor(&self, scope: &RampScope) -> Result<u32> {
        Ok(crate::edit_distance::graduation::graduation_policy_for(self, scope)?.required_streak)
    }

    /// CID-7 door: drops the whole statistics projection and refolds it from
    /// truth — every identity-topology resolution event, interleaved in ledger
    /// order with this module's own outcome and demotion rows.
    ///
    /// All three inputs are needed and none is optional: the resolution events
    /// are the rulings the propose lane produced (each stamped with its own
    /// scope tuple, so no join is required), the outcome rows are the rulings
    /// recorded through the ramp door, and the demotion rows carry the streak
    /// resets no ruling implies. Floors, outcomes and demotions are untouched —
    /// a rebuild repairs a cache, it never rewrites policy or history.
    ///
    /// The scan runs INSIDE the transaction that replaces the projection.
    /// Reading truth on one transaction and overwriting the projection on a
    /// later one leaves a window in which a resolution commits between them,
    /// and the rebuild would then erase an update it never saw.
    ///
    /// # Errors
    ///
    /// Storage failures, and [`Error::CorruptedIndex`] on an unreadable row.
    pub fn rebuild_ramp_stats_from_receipts(&self) -> Result<()> {
        self.with_write_txn(|wtxn| {
            let events = self.ramp_fold_events_in_txn(&*wtxn)?;
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
            for event in &events {
                let counters = folded.entry(event.scope.clone()).or_default();
                match event.outcome {
                    Some(outcome) => counters.apply_outcome(outcome, event.at),
                    None => counters.apply_demotion(event.at),
                }
            }
            for (scope, counters) in &folded {
                write_counters_in_txn(&self.store, wtxn, scope, *counters)?;
            }
            Ok(())
        })
    }

    /// Every fold input, in [`FoldKey`] order.
    fn ramp_fold_events_in_txn(&self, rtxn: &heed::RoTxn<'_>) -> Result<Vec<RampFoldEvent>> {
        let mut events = Vec::new();
        for (event_id, record) in self.resolution_events_in_txn(rtxn)? {
            let StoredIdentityOpAction::ProposalResolution { outcome, scope, .. } = &record.action
            else {
                continue;
            };
            events.push(RampFoldEvent {
                key: (record.seq, FOLD_RANK_LEDGER, event_id),
                scope: RampScope::from(scope),
                at: record.at,
                outcome: Some(*outcome),
            });
        }

        for entry in self
            .store
            .vault_meta
            .prefix_iter(rtxn, RAMP_OUTCOME_KEY_PREFIX)?
        {
            let (key, raw) = entry?;
            let row: StoredRampOutcome = decode_ramp_row(&raw, RAMP_OUTCOME_ROW_LABEL)?;
            let id = ramp_row_key_id(RAMP_OUTCOME_KEY_PREFIX, &key, RAMP_OUTCOME_ROW_LABEL)?;
            let outcome = ProposalOutcome::parse(&row.outcome)
                .ok_or(Error::CorruptedIndex(RAMP_OUTCOME_ROW_LABEL))?;
            events.push(RampFoldEvent {
                key: (row.after_seq, FOLD_RANK_RAMP_ROW, id),
                scope: stored_row_scope(
                    row.op_kind,
                    row.target_class,
                    row.actor,
                    RAMP_OUTCOME_ROW_LABEL,
                )?,
                at: row.at,
                outcome: Some(outcome),
            });
        }

        for entry in self
            .store
            .vault_meta
            .prefix_iter(rtxn, RAMP_DEMOTION_KEY_PREFIX)?
        {
            let (key, raw) = entry?;
            let row: StoredDemotion = decode_ramp_row(&raw, RAMP_DEMOTION_ROW_LABEL)?;
            let id = ramp_row_key_id(RAMP_DEMOTION_KEY_PREFIX, &key, RAMP_DEMOTION_ROW_LABEL)?;
            events.push(RampFoldEvent {
                key: (row.after_seq, FOLD_RANK_RAMP_ROW, id),
                scope: stored_row_scope(
                    row.op_kind,
                    row.target_class,
                    row.actor,
                    RAMP_DEMOTION_ROW_LABEL,
                )?,
                at: row.at,
                outcome: None,
            });
        }

        events.sort_unstable_by_key(|event| event.key);
        Ok(events)
    }

    /// Every identity-topology RESOLUTION event, with the duplicate suppression
    /// the receipt projection applies: a ruling the fold rejected because the
    /// proposal was already resolved never happened, so it is not an outcome
    /// here either.
    ///
    /// Enumeration runs over `identity_topology_events_in_txn` — the one
    /// surface the fold, the receipt projection and any rebuild share — and is
    /// therefore complete. The public receipt query is not a substitute: it
    /// visits only the newest `MAX_RECEIPT_QUERY_SCAN` rows of the family, so a
    /// rebuild driven from it would delete a whole projection and refold a
    /// suffix of its history.
    fn resolution_events_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<Vec<(EntityId, crate::identity_topology::StoredIdentityOpEvent)>> {
        let fold =
            fold_identity_topology_log(&self.fold_effective_identity_topology_events_in_txn(rtxn)?);
        let superseded: std::collections::BTreeSet<EntityId> = fold
            .rejections
            .iter()
            .filter(|(_, reason)| {
                matches!(
                    reason,
                    IdentityTopologyRejection::ProposalAlreadyResolved { .. }
                )
            })
            .map(|(event_id, _)| *event_id)
            .collect();

        let mut resolutions = Vec::new();
        for event in self.identity_topology_events_in_txn(rtxn)? {
            if !matches!(event.action, IdentityTopologyAction::ResolveProposal { .. })
                || superseded.contains(&event.event_id)
            {
                continue;
            }
            let record = self
                .identity_topology_event_in_txn(rtxn, &event.event_id)?
                .ok_or(Error::CorruptedIndex("identity topology event index"))?;
            resolutions.push((event.event_id, record));
        }
        Ok(resolutions)
    }
}

/// [`Vault::accept_graduation_offer`] inside the caller's write txn, at `at`.
///
/// The whole door, checks included, so ED-05 — which routes its own `go-auto`
/// answer through here — cannot end up enforcing a looser version of it. The
/// public method is this function plus a transaction.
///
/// The ANSWER is recorded here rather than by either caller, for the same
/// reason: this is the only code path both public acceptance doors share, so it
/// is the only place that can guarantee they leave identical state. See
/// [`crate::edit_distance::graduation::record_go_auto_answer_in_txn`].
pub(crate) fn accept_graduation_offer_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    scope: &RampScope,
    at: u64,
) -> Result<ConsentReceipt> {
    scope.validate()?;
    if !scope.is_graduatable() {
        return Err(Error::InvalidConsentBound(
            "op kind does not ride the propose lane; there is nothing to graduate",
        ));
    }
    let bound = scope.to_grant_bound()?;
    if !offer_is_standing_in_txn(vault, &*wtxn, scope)? {
        return Err(Error::InvalidConsentBound(
            "this scope is not offering graduation; a retracted offer cannot be accepted",
        ));
    }
    crate::edit_distance::graduation::record_go_auto_answer_in_txn(vault, wtxn, scope, at)?;
    vault.create_standing_grant_in_txn(wtxn, owner, bound)
}

/// Rebuilds the scope a stored ramp row names. An engine-authored row that
/// cannot form a scope is corruption, never a row to skip past.
fn stored_row_scope(
    op_kind: String,
    target_class: String,
    actor: String,
    label: &'static str,
) -> Result<RampScope> {
    RampScope::new(op_kind, target_class, actor).map_err(|_| Error::CorruptedIndex(label))
}

#[cfg(test)]
mod tests;
