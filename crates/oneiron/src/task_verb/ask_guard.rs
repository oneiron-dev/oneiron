//! One rule for who may answer or close an ask whose word is its asked
//! party's own act (UC-05).
//!
//! Each such ask kind declares, once, who it asks ([`AskedParty`]), read
//! from its own router in the transaction, and which options it still
//! offers. The checks every kind shares live here once: a word is the asked
//! party's own tap (never a word given for someone else or a soft confirm),
//! given on the node that admitted the ask, under the live proof of that
//! party revalidated in the writing transaction. A settlement cuts such an
//! ask on a word only under the same proof in the cutting transaction; its
//! deadline or staleness closes it with no proof. Every other ask passes
//! untouched.

use super::ask_record::{self, AskGroup};
use super::ask_types::{TaskAskDecision, TaskAskSettlementReason, TaskAskSource, TaskAskWord};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result};
use crate::{EntityId, Vault};

/// Who an ask kind asks, as its router reads it in the transaction.
pub(super) enum AskedParty {
    /// One named owner (training offer, training swap, contribution pair).
    Owner(EntityId),
    /// Any of these owners (live edit).
    AnyOwner(Vec<EntityId>),
    /// Any live owner of this vault (attendee answer).
    VaultOwner,
}

impl AskedParty {
    /// Whether `writer` is this party under `owner`'s proof, revalidated as
    /// the vault's owner in `txn`.
    fn proven_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
        writer: EntityId,
    ) -> Result<bool> {
        let proven = owner.revalidate_in_txn(vault, txn)?;
        Ok(proven == writer
            && match self {
                Self::Owner(asked) => proven == *asked,
                Self::AnyOwner(asked) => asked.contains(&proven),
                Self::VaultOwner => true,
            })
    }
}

/// The refusals one ask kind answers a word with; each kind keeps its own
/// words.
struct AskKindReasons {
    /// The word was given on a node other than the one that admitted the ask.
    elsewhere: &'static str,
    /// The word carries no owner proof.
    unproven: &'static str,
    /// The word is not the asked party's own under its proof.
    not_asked: &'static str,
}

/// The asked party of one ask kind, read by its router in the transaction;
/// `None` for an ask of another kind.
type AskedIn = fn(&Vault, &heed::RoTxn<'_>, EntityId, &AskGroup) -> Result<Option<AskedParty>>;

/// [`AskedIn`] once the word names an option the ask still offers; a word
/// it does not offer is refused.
type OfferedIn =
    fn(&Vault, &heed::RoTxn<'_>, EntityId, &AskGroup, &TaskAskWord) -> Result<Option<AskedParty>>;

/// An ask kind whose word is its asked party's own act.
struct AskKind {
    /// Who it asks, for the settlement's cut.
    asked_in: AskedIn,
    /// Who it asks, for word admission, after its option check.
    offered_in: OfferedIn,
    reasons: AskKindReasons,
}

/// Every ask kind whose word is its asked party's own act, in the order
/// admission and settlement check them. Each kind's intent key prefix is
/// its own, so at most one routes a given ask.
const ASK_KINDS: [AskKind; 5] = [
    AskKind {
        asked_in: super::attendee_answer::asked_in,
        offered_in: super::attendee_answer::offered_in,
        reasons: AskKindReasons {
            elsewhere: "an attendee answer is given on the node that admitted the ask",
            unproven: "an attendee answer needs the owner's own authenticated word",
            not_asked: "an attendee answer is the authenticated owner's own word",
        },
    },
    AskKind {
        asked_in: super::training_offer_ask::asked_in,
        offered_in: super::training_offer_ask::offered_in,
        reasons: AskKindReasons {
            elsewhere: "a training offer answer is given on the node that admitted the ask",
            unproven: "a training offer answer needs the owner's own authenticated word",
            not_asked: "a training offer answer is the asked owner's own word",
        },
    },
    AskKind {
        asked_in: super::training_swap_ask::asked_in,
        offered_in: super::training_swap_ask::offered_in,
        reasons: AskKindReasons {
            elsewhere: "a training swap answer is given on the node that admitted the ask",
            unproven: "a training swap answer needs the owner's own authenticated word",
            not_asked: "a training swap answer is the asked owner's own word",
        },
    },
    AskKind {
        asked_in: super::contribution_pair::asked_in,
        offered_in: super::contribution_pair::offered_in,
        reasons: AskKindReasons {
            elsewhere: "a contribution pair answer is given on the node that admitted the ask",
            unproven: "a contribution pair answer needs the owner's own authenticated word",
            not_asked: "a contribution pair answer is the asked owner's own word",
        },
    },
    AskKind {
        asked_in: live_edit_asked_in,
        offered_in: live_edit_offered_in,
        reasons: AskKindReasons {
            elsewhere: "a live-edit answer is given on the node that admitted the ask",
            unproven: "a live-edit answer needs the owner's own authenticated word",
            not_asked: "a live-edit answer is the asked owner's own word",
        },
    },
];

/// A live-edit ask asks any owner its route names (FIX 596).
fn live_edit_asked_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
) -> Result<Option<AskedParty>> {
    Ok(
        crate::office_body::live_edit_asked_owners_in(vault, txn, id, &group.requested.intent_key)?
            .map(AskedParty::AnyOwner),
    )
}

fn live_edit_offered_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    word: &TaskAskWord,
) -> Result<Option<AskedParty>> {
    Ok(crate::office_body::live_edit_offered_owners_in(
        vault,
        txn,
        id,
        &group.requested.intent_key,
        word,
    )?
    .map(AskedParty::AnyOwner))
}

/// Refuses a word on an ask of any kind in [`ASK_KINDS`] unless it is its
/// asked party's own act; any other ask passes untouched. Runs in shared
/// word admission, before the word is recorded, for `tasks_answer`, a
/// consult answer and a redeemed option link alike, so an unauthorized word
/// can never occupy First and strand the asked party's later tap.
///
/// # Errors
///
/// Storage errors, and every word it refuses.
#[expect(
    clippy::too_many_arguments,
    reason = "one admission check over the word, its writer and the owner proof"
)]
pub(super) fn admit_word_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    source: TaskAskSource,
    actor: EntityId,
    word: &TaskAskWord,
    owner: Option<&AuthenticatedOwner>,
) -> Result<()> {
    for kind in &ASK_KINDS {
        let Some(asked) = (kind.offered_in)(vault, txn, id, group, word)? else {
            continue;
        };
        // The asked party's own tap, never a word given for them or a soft
        // confirm.
        if word.companion_for.is_some() || word.inform_for.is_some() || word.confirmation.is_some()
        {
            return Err(ask_record::invalid());
        }
        // Only the admission node settles the ask, so a word anywhere else
        // could never settle under the proof that admitted it.
        if !ask_record::owns_revision(vault, txn, id, group)? {
            return Err(owner_not_authenticated(kind.reasons.elsewhere));
        }
        let Some(owner) = owner else {
            return Err(owner_not_authenticated(kind.reasons.unproven));
        };
        if source != TaskAskSource::Human || !asked.proven_in(vault, txn, owner, actor)? {
            return Err(owner_not_authenticated(kind.reasons.not_asked));
        }
    }
    Ok(())
}

/// Whether settlement may cut the ask `id` for `reason` with `decision`
/// under `owner`. Its deadline or staleness always closes it, on the hold
/// default. An ask of a kind in [`ASK_KINDS`] cuts on a first word only
/// under the live proof, in this transaction, of the asked party who gave
/// it; without that proof it stays open. Any other ask passes.
///
/// # Errors
///
/// Storage errors.
pub(super) fn may_cut_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    reason: TaskAskSettlementReason,
    decision: &TaskAskDecision,
    owner: Option<&AuthenticatedOwner>,
) -> Result<bool> {
    if matches!(
        reason,
        TaskAskSettlementReason::Deadline | TaskAskSettlementReason::Stale
    ) {
        return Ok(true);
    }
    for kind in &ASK_KINDS {
        let Some(asked) = (kind.asked_in)(vault, txn, id, group)? else {
            continue;
        };
        let TaskAskDecision::First(answer) = decision else {
            continue;
        };
        let proven = match owner {
            Some(owner) => asked.proven_in(vault, txn, owner, answer.actor_ref)?,
            None => false,
        };
        if !proven {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The refusal of a word that lacks its asked party's live proof.
fn owner_not_authenticated(reason: &'static str) -> Error {
    Error::Gate(GateError::ConsentOwnerNotAuthenticated(reason))
}
