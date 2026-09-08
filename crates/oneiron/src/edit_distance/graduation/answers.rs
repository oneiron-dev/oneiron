//! Offer answers and the snooze-state machine.

use serde::{Deserialize, Serialize};

use super::{ANSWER_KEY_PREFIX, ANSWER_ROW_LABEL, ROW_VERSION, decode_row, encode_row, meta_key};
use crate::consent::{AuthenticatedOwner, ConsentReceipt};
use crate::consent_graduation::RampScope;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::vault::Vault;

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

pub(super) const ANSWER_NOT_NOW: &str = "not_now";

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

/// One answer the owner gave, and the whole of what this module stores about
/// the offer UX: [`replay_snooze`] derives the state from these rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredAnswer {
    pub(super) v: u8,
    pub(super) op_kind: String,
    pub(super) target_class: String,
    pub(super) actor: String,
    pub(super) answer: String,
    pub(super) at: u64,
}

/// The answer-log key range of one scope.
fn answer_scope_prefix(scope: &RampScope) -> Vec<u8> {
    meta_key(ANSWER_KEY_PREFIX, &scope.key())
}

pub(super) fn answer_key(scope: &RampScope, id: &EntityId) -> Vec<u8> {
    let mut key = answer_scope_prefix(scope);
    key.extend_from_slice(id.as_bytes());
    key
}

/// The row id embedded in an answer key.
pub(super) fn answer_key_id(key: &[u8]) -> Result<EntityId> {
    let tail = key
        .get(ANSWER_KEY_PREFIX.len() + ENTITY_ID_LEN..)
        .and_then(|tail| <[u8; ENTITY_ID_LEN]>::try_from(tail).ok())
        .ok_or(Error::CorruptedIndex(ANSWER_ROW_LABEL))?;
    EntityId::from_bytes(tail).map_err(|_| Error::CorruptedIndex(ANSWER_ROW_LABEL))
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
