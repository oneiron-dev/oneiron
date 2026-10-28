//! Offer answers and the snooze-state machine.

use serde::{Deserialize, Serialize};

use super::{ANSWER, ANSWER_ROW_LABEL, ROW_VERSION};
use crate::consent::{AuthenticatedOwner, ConsentReceipt};
use crate::consent_graduation::RampScope;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::store::Store;
use crate::vault::Vault;

// ---------------------------------------------------------------------------
// Offer answers + snooze state
// ---------------------------------------------------------------------------

/// What the owner answered when the engine offered to stop asking.
///
/// [`Self::GoAuto`] carries the [`AuthenticatedOwner`] because it, and only it,
/// mints authority: DEC-0006 invariant 5 is enforced here by the type system.
/// The public owner door also authenticates declines and manual pins.
#[derive(Debug, Clone, Copy)]
pub enum OfferAnswer<'owner> {
    /// Accept: mint the standing grant and let this scope run auto.
    GoAuto(&'owner AuthenticatedOwner),
    /// Decline for now: hold the offer for the next backoff step, or — on the
    /// answer past the end of the ladder — pin the scope to manual.
    NotNow,
    /// Stop offering until the owner unpins the scope in settings.
    ManualPinned,
}

impl OfferAnswer<'_> {
    /// The pinned wire/receipt string for this answer.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GoAuto(_) => ANSWER_GO_AUTO,
            Self::NotNow => ANSWER_NOT_NOW,
            Self::ManualPinned => ANSWER_MANUAL_PINNED,
        }
    }
}

const ANSWER_GO_AUTO: &str = "go_auto";

pub(super) const ANSWER_NOT_NOW: &str = "not_now";

const ANSWER_UNPIN: &str = "unpin";

const ANSWER_MANUAL_PINNED: &str = "manual_pinned";

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
    fn declined_at(self, at: u64, backoffs: [u64; 2]) -> Self {
        let prior = match self {
            Self::ManualPinned => return Self::ManualPinned,
            Self::Snoozed { count, .. } => count,
            Self::None => 0,
        };
        // Indexed by declines ALREADY given, so the ladder's length is the pin
        // threshold and a decline past its end is the owner saying stop.
        match backoffs.get(usize::from(prior)) {
            Some(backoff) => Self::Snoozed {
                count: prior.saturating_add(1),
                next_eligible_at: at.saturating_add(*backoff),
            },
            None => Self::ManualPinned,
        }
    }
}

/// One answer the owner gave, and the whole of what this module stores about
/// the offer UX: [`replay_snooze`] derives the state from these rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredAnswer {
    pub(super) v: u8,
    pub(super) op_kind: String,
    pub(super) target_class: String,
    pub(super) actor: String,
    /// Authenticated owner-door provenance; the non-owner doors store neither.
    pub(super) answerer: Option<String>,
    pub(super) decision_ref: Option<String>,
    pub(super) answer: String,
    pub(super) at: u64,
    pub(super) after_seq: u64,
    pub(super) snooze_backoff_seconds: [u64; 2],
}

struct AnswerProvenance {
    answerer: String,
    decision_ref: String,
}

impl AnswerProvenance {
    fn new(owner: &AuthenticatedOwner, answerer: EntityId) -> Self {
        Self {
            answerer: answerer.to_hex(),
            decision_ref: owner.decision_id().to_hex(),
        }
    }
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

pub(super) fn snooze_state_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    scope: &RampScope,
) -> Result<SnoozeState> {
    let mut state = SnoozeState::None;
    for (_, row) in ANSWER.scan_from(store, txn, &scope.key())? {
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
        ANSWER_NOT_NOW => Ok(state.declined_at(row.at, row.snooze_backoff_seconds)),
        ANSWER_MANUAL_PINNED => Ok(SnoozeState::ManualPinned),
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
/// whenever the offer is earned and not manually pinned. A manual pin is
/// cleared only through the settings unpin door.
///
/// [`OfferAnswer::NotNow`] requires an offer that is actually being made. An
/// offer already snoozed is not being made, which is what keeps the ladder
/// meaning three separate declines spread across the backoff rather than three
/// taps in one sitting.
///
/// # Errors
///
/// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound) when the scope tuple is unbuildable, when no
/// offer is standing, or (for [`OfferAnswer::NotNow`]) when the ask is already
/// suppressed; plus whatever the grant door rejects, and storage failures.
pub fn answer_graduation_offer(
    vault: &Vault,
    scope: &RampScope,
    answer: OfferAnswer<'_>,
) -> Result<OfferAnswerOutcome> {
    answer_graduation_offer_at(vault, scope, answer, vault.store.clock.now_recorded_at())
}

/// [`answer_graduation_offer`] against a caller-supplied clock.
pub(super) fn answer_graduation_offer_at(
    vault: &Vault,
    scope: &RampScope,
    answer: OfferAnswer<'_>,
    at: u64,
) -> Result<OfferAnswerOutcome> {
    vault.with_write_txn_grouped(|wtxn| {
        answer_graduation_offer_in_txn(vault, wtxn, scope, answer, at, None)
    })
}

/// The public owner door: every answer is the owner's, not only acceptance.
pub fn answer_graduation_offer_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    scope: &RampScope,
    answer: OfferAnswer<'_>,
) -> Result<OfferAnswerOutcome> {
    let at = vault.store.clock.now_recorded_at();
    vault.with_write_txn_grouped(|wtxn| {
        let answerer = owner.revalidate_as_vault_owner_in_txn(vault, &*wtxn)?;
        let provenance = AnswerProvenance::new(owner, answerer);
        answer_graduation_offer_in_txn(vault, wtxn, scope, answer, at, Some(provenance))
    })
}

fn answer_graduation_offer_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: &RampScope,
    answer: OfferAnswer<'_>,
    at: u64,
    provenance: Option<AnswerProvenance>,
) -> Result<OfferAnswerOutcome> {
    scope.validate()?;
    if !crate::consent_graduation::offer_is_standing_in_txn(vault, &*wtxn, scope)? {
        return Err(Error::Gate(GateError::InvalidConsentBound(
            "no graduation offer is standing for this scope",
        )));
    }
    match answer {
        OfferAnswer::GoAuto(owner) => {
            let receipt = crate::consent_graduation::accept_graduation_offer_in_txn(
                vault, wtxn, owner, scope, at,
            )?;
            Ok(OfferAnswerOutcome::Graduated(receipt))
        }
        OfferAnswer::NotNow | OfferAnswer::ManualPinned => {
            let state = snooze_state_in_txn(&vault.store, &*wtxn, scope)?;
            if state.suppresses_asks_at(at) {
                return Err(Error::Gate(GateError::InvalidConsentBound(
                    "this scope's graduation offer is already held; there is nothing to decline",
                )));
            }
            let backoffs =
                super::threshold_policy::graduation_policy_in_txn(&vault.store, &*wtxn, scope)?
                    .snooze_backoff_seconds;
            append_answer_in_txn(vault, wtxn, scope, answer.as_str(), at, provenance)?;
            crate::consent_graduation::reset_ramp_streak_in_txn(vault, wtxn, scope, at)?;
            let next = match answer {
                OfferAnswer::ManualPinned => SnoozeState::ManualPinned,
                _ => state.declined_at(at, backoffs),
            };
            Ok(OfferAnswerOutcome::Snoozed(next))
        }
    }
}

/// A manual pin can only be cleared by the settings unpin door.
pub(crate) fn scope_is_manual_pinned_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    scope: &RampScope,
) -> Result<bool> {
    Ok(snooze_state_in_txn(store, txn, scope)? == SnoozeState::ManualPinned)
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
/// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound) when the scope tuple is unbuildable, plus
/// storage failures.
pub fn unpin_scope(vault: &Vault, scope: &RampScope) -> Result<()> {
    unpin_scope_at(vault, scope, vault.store.clock.now_recorded_at())
}

/// [`unpin_scope`] against a caller-supplied clock.
fn unpin_scope_at(vault: &Vault, scope: &RampScope, at: u64) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        scope.validate()?;
        append_answer_in_txn(vault, wtxn, scope, ANSWER_UNPIN, at, None)
    })
}

/// The owner's settings-only unpin, checked in the same write transaction.
pub fn unpin_scope_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    scope: &RampScope,
) -> Result<()> {
    let at = vault.store.clock.now_recorded_at();
    vault.with_write_txn_grouped(|wtxn| {
        let answerer = owner.revalidate_as_vault_owner_in_txn(vault, &*wtxn)?;
        scope.validate()?;
        let provenance = AnswerProvenance::new(owner, answerer);
        append_answer_in_txn(vault, wtxn, scope, ANSWER_UNPIN, at, Some(provenance))
    })
}

/// Declines reset the ramp projection on rebuild just as they do on write.
pub(crate) fn streak_resets_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(u64, crate::entity_id::EntityId, RampScope, u64)>> {
    let mut resets = Vec::new();
    for ((_, id), row) in ANSWER.scan(store, txn)? {
        if matches!(row.answer.as_str(), ANSWER_NOT_NOW | ANSWER_MANUAL_PINNED) {
            let scope = RampScope::new(row.op_kind, row.target_class, row.actor)?;
            resets.push((row.after_seq, id, scope, row.at));
        }
    }
    Ok(resets)
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
    owner: &AuthenticatedOwner,
    scope: &RampScope,
    at: u64,
) -> Result<()> {
    let answerer = owner.revalidate_as_vault_owner_in_txn(vault, &*wtxn)?;
    let provenance = AnswerProvenance::new(owner, answerer);
    append_answer_in_txn(vault, wtxn, scope, ANSWER_GO_AUTO, at, Some(provenance))
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
    provenance: Option<AnswerProvenance>,
) -> Result<()> {
    let (answerer, decision_ref) = match provenance {
        Some(provenance) => (Some(provenance.answerer), Some(provenance.decision_ref)),
        None => (None, None),
    };
    let row = StoredAnswer {
        v: ROW_VERSION,
        op_kind: scope.op_kind.clone(),
        target_class: scope.target_class.clone(),
        actor: scope.actor.clone(),
        answerer,
        decision_ref,
        answer: answer.to_owned(),
        at,
        after_seq: vault.read_identity_topology_seq_in_txn(&*wtxn)?,
        snooze_backoff_seconds: super::threshold_policy::graduation_policy_in_txn(
            &vault.store,
            &*wtxn,
            scope,
        )?
        .snooze_backoff_seconds,
    };
    let key = (scope.key(), vault.store.clock.entity_id()?);
    ANSWER.put(&vault.store, wtxn, &key, &row)?;
    Ok(())
}
