//! One rule for who may answer or close an ask whose word is its asked
//! party's own act (UC-05).
//!
//! Each such ask kind declares, once, who it asks ([`AskedParty`]), read
//! from its own router in the transaction, and which options it still
//! offers. The checks every kind shares live here once: a word is the asked
//! party's own tap (never a word given for someone else or a soft confirm),
//! given on the node that admitted the ask, under the live proof of that
//! party revalidated in the writing transaction (UC-05-ASK-ANSWERER = A):
//! an owner's under the owner proof, a person holder's under their
//! person-tier proof, an agent's as its verified actor. A settlement cuts
//! such an ask on a person's word only under the same proof in the cutting
//! transaction; its deadline or staleness closes it with no proof. Every
//! other ask passes untouched.
//!
//! Each kind also declares which of its options approve the act the ask
//! asks for, and the line a device's prompt shows for it
//! ([`approved_act_in`]): a person's word is as important as the act it
//! approves (row OWNER-CONFIRM-SHEET), and a denial approves none. A kind
//! whose own writer refuses an approving word on a fact the store already
//! holds declares that read, too ([`approved_act_stands_in`]), so a device
//! refuses such a word before it asks for the person.

use std::collections::BTreeSet;

use super::ask_record::{self, AskGroup};
use super::ask_settlement;
use super::ask_types::{
    TaskAskDecision, TaskAskOptionId, TaskAskSettlementReason, TaskAskSource, TaskAskWord,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result};
use crate::world_keys::owner_presence_reasons;
use crate::{EntityId, Vault};

/// Who an ask kind asks, as its router reads it in the transaction.
pub(super) enum AskedParty {
    /// One named owner (training offer, training swap, contribution pair).
    Owner(EntityId),
    /// Any of these owners (live edit).
    AnyOwner(Vec<EntityId>),
    /// Any live owner of this vault (attendee answer).
    VaultOwner,
    /// An asked owner, or a frozen holder who is a person (code consent).
    OwnerOrHolder {
        owners: BTreeSet<EntityId>,
        holders: BTreeSet<EntityId>,
    },
    /// One agent (comm widen's agent recipient): its verified actor is its
    /// proof, and it carries no owner proof.
    Agent(EntityId),
}

impl AskedParty {
    /// Whether `writer` is this person party under `proof`, revalidated in
    /// `txn` at the tier the party takes: the owner tier for an owner, the
    /// person tier for a holder. A person-tier proof proves no owner (FIX
    /// 4707); an agent is never proven by a person's proof.
    fn proven_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        proof: &AuthenticatedOwner,
        writer: EntityId,
    ) -> Result<bool> {
        if proof.is_person_tier() {
            let Self::OwnerOrHolder { holders, .. } = self else {
                return Ok(false);
            };
            let proven = proof.revalidate_person_in_txn(vault, txn)?;
            return Ok(proven == writer && holders.contains(&proven));
        }
        if matches!(self, Self::Agent(_)) {
            return Ok(false);
        }
        let proven = proof.revalidate_in_txn(vault, txn)?;
        Ok(proven == writer
            && match self {
                Self::Owner(asked) => proven == *asked,
                Self::AnyOwner(asked) => asked.contains(&proven),
                Self::VaultOwner => true,
                // An owner's proof also proves the person, so a frozen
                // holder who owns the vault answers under it too.
                Self::OwnerOrHolder { owners, holders } => {
                    owners.contains(&proven) || holders.contains(&proven)
                }
                Self::Agent(_) => false,
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

/// The refusals one ask kind's own writer gives an approving word before
/// its first write, made from a read: the act the word approves no longer
/// stands.
type ActStandsIn = fn(&Vault, &heed::RoTxn<'_>, EntityId, &AskGroup, &TaskAskWord) -> Result<()>;

/// Whether an approving word on one ask can still make the kind's act run,
/// read in the transaction.
type WordActsIn = fn(&Vault, &heed::RoTxn<'_>, EntityId, &AskGroup) -> Result<bool>;

/// How one ask kind's approving word is told from its other words, and
/// what the device's prompt shows for it.
#[derive(Clone, Copy)]
struct AskApproval {
    /// Whether an option the ask offers approves the act the ask asks for.
    /// Every other option of the kind denies or abstains.
    approves: fn(&TaskAskOptionId) -> bool,
    /// The one line the device's prompt shows for an approving word
    /// ([`owner_presence_reasons`]).
    reason: &'static str,
    /// Whether an approving word can still act. The ask's own settlement
    /// applies the act of every kind but one, so their word acts while the
    /// ask's decision is open ([`ask_settlement::decision_open_in`]). A code
    /// consent word is evidence its wait's answer reads past the ask's cut,
    /// so it acts while the wait still takes its first answer
    /// ([`super::code_consent_word::answer_open_in`]).
    acts: WordActsIn,
    /// The kind's own read of whether the approved act still stands
    /// ([`approved_act_stands_in`]); `None` for a kind whose writer refuses
    /// an admitted approving word on no fact a read holds.
    stands: Option<ActStandsIn>,
}

/// An ask kind whose word is its asked party's own act.
struct AskKind {
    /// Who it asks, for the settlement's cut.
    asked_in: AskedIn,
    /// Who it asks, for word admission, after its option check.
    offered_in: OfferedIn,
    /// Its approving options; `None` for a kind whose options approve no
    /// act (a contribution pair's five options judge two answers).
    approval: Option<AskApproval>,
    reasons: AskKindReasons,
}

/// Every ask kind whose word is its asked party's own act, in the order
/// admission and settlement check them. Each kind's intent key prefix is
/// its own, so at most one routes a given ask.
const ASK_KINDS: [AskKind; 7] = [
    AskKind {
        asked_in: super::attendee_answer::asked_in,
        offered_in: super::attendee_answer::offered_in,
        approval: Some(AskApproval {
            approves: super::attendee_answer::approves,
            reason: owner_presence_reasons::ANSWER_ATTENDEE_ASK,
            acts: ask_settlement::decision_open_in,
            stands: Some(super::attendee_answer::approved_act_stands_in),
        }),
        reasons: AskKindReasons {
            elsewhere: "an attendee answer is given on the node that admitted the ask",
            unproven: "an attendee answer needs the owner's own authenticated word",
            not_asked: "an attendee answer is the authenticated owner's own word",
        },
    },
    AskKind {
        asked_in: super::training_offer_ask::asked_in,
        offered_in: super::training_offer_ask::offered_in,
        approval: Some(AskApproval {
            approves: super::training_offer_ask::approves,
            reason: owner_presence_reasons::ANSWER_TRAINING_OFFER_ASK,
            acts: ask_settlement::decision_open_in,
            stands: Some(super::training_offer_ask::approved_act_stands_in),
        }),
        reasons: AskKindReasons {
            elsewhere: "a training offer answer is given on the node that admitted the ask",
            unproven: "a training offer answer needs the owner's own authenticated word",
            not_asked: "a training offer answer is the asked owner's own word",
        },
    },
    AskKind {
        asked_in: super::training_swap_ask::asked_in,
        offered_in: super::training_swap_ask::offered_in,
        approval: Some(AskApproval {
            approves: super::training_swap_ask::approves,
            reason: owner_presence_reasons::ANSWER_TRAINING_SWAP_ASK,
            acts: ask_settlement::decision_open_in,
            stands: None,
        }),
        reasons: AskKindReasons {
            elsewhere: "a training swap answer is given on the node that admitted the ask",
            unproven: "a training swap answer needs the owner's own authenticated word",
            not_asked: "a training swap answer is the asked owner's own word",
        },
    },
    AskKind {
        asked_in: super::contribution_pair::asked_in,
        offered_in: super::contribution_pair::offered_in,
        approval: None,
        reasons: AskKindReasons {
            elsewhere: "a contribution pair answer is given on the node that admitted the ask",
            unproven: "a contribution pair answer needs the owner's own authenticated word",
            not_asked: "a contribution pair answer is the asked owner's own word",
        },
    },
    AskKind {
        asked_in: live_edit_asked_in,
        offered_in: live_edit_offered_in,
        approval: Some(AskApproval {
            approves: crate::office_body::live_edit_option_grants,
            reason: owner_presence_reasons::ANSWER_LIVE_EDIT_ASK,
            acts: ask_settlement::decision_open_in,
            stands: None,
        }),
        reasons: AskKindReasons {
            elsewhere: "a live-edit answer is given on the node that admitted the ask",
            unproven: "a live-edit answer needs the owner's own authenticated word",
            not_asked: "a live-edit answer is the asked owner's own word",
        },
    },
    AskKind {
        asked_in: super::comm_widen::asked_in,
        offered_in: super::comm_widen::offered_in,
        approval: Some(AskApproval {
            approves: super::comm_widen::approves,
            reason: owner_presence_reasons::ANSWER_COMM_WIDEN_ASK,
            acts: ask_settlement::decision_open_in,
            stands: None,
        }),
        reasons: AskKindReasons {
            elsewhere: "a comm widen answer is given on the node that admitted the ask",
            unproven: "a comm widen answer needs the owner's own authenticated word",
            not_asked: "a comm widen answer is the asked owner's own word",
        },
    },
    AskKind {
        asked_in: super::code_consent_word::asked_in,
        offered_in: super::code_consent_word::offered_in,
        approval: Some(AskApproval {
            approves: super::code_consent_word::approves,
            reason: owner_presence_reasons::ANSWER_CODE_CONSENT_ASK,
            acts: super::code_consent_word::answer_open_in,
            stands: None,
        }),
        reasons: AskKindReasons {
            elsewhere: "a code consent answer is given on the node that admitted the ask",
            unproven: "a code consent answer needs the asked person's own authenticated word",
            not_asked: "a code consent answer is the asked owner's or holder's own word",
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
        // An agent answers as itself: the verified actor the write runs as.
        if let AskedParty::Agent(agent) = &asked {
            if source != TaskAskSource::Executor
                || actor != *agent
                || !ask_record::owns_revision(vault, txn, id, group)?
            {
                return Err(ask_record::invalid());
            }
            continue;
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

enum ApprovalRoute {
    Unrouted,
    Routed(Option<AskApproval>),
}

/// The approval of the kind that routes the ask `id`, where a person's
/// `word` on it is one of that kind's approving options; `None` for a word
/// that approves no act. A word the kind does not offer is refused, as
/// [`admit_word_in`] refuses it. `Unrouted` means no registered kind takes
/// the ask.
fn approval_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    word: &TaskAskWord,
) -> Result<ApprovalRoute> {
    for kind in &ASK_KINDS {
        let Some(asked) = (kind.offered_in)(vault, txn, id, group, word)? else {
            continue;
        };
        let approval = kind.approval.filter(|approval| {
            !matches!(asked, AskedParty::Agent(_))
                && word.option.as_ref().is_some_and(approval.approves)
        });
        if let Some(approval) = approval
            && !(approval.acts)(vault, txn, id, group)?
        {
            return Ok(ApprovalRoute::Routed(Some(approval)));
        }
        return Ok(ApprovalRoute::Routed(approval));
    }
    Ok(ApprovalRoute::Unrouted)
}

/// The line a device's prompt shows for the act a person's `word` on the
/// ask `id` approves (row OWNER-CONFIRM-SHEET): an approving option of an
/// ask of a kind in [`ASK_KINDS`] that asks a person, or `proceed` on a
/// durable verb hook's open ask. `None` for a word that approves no act:
/// an option that denies or abstains, a contribution pair's judgment, a word
/// on an ask that asks an agent, or a word with no approving route. A word
/// the kind does not offer is refused, as [`admit_word_in`] refuses it.
///
/// The answer door reads this before it asks for the person at the device
/// and again in its write (`super::ask_word_presence`). The kind of an ask
/// is its intent key's, and an option's meaning is its kind's. Once the
/// ask has its result, a word of a kind whose act the ask's settlement
/// applies approves nothing. The same holds for an ask this node's
/// settlement cuts Stale on its next word
/// ([`ask_settlement::decision_open_in`]): that cut decides nothing, so a
/// word on it approves no act and releases no stopped call. A code consent
/// word approves while its wait still takes its first answer, whatever its
/// ask's result, and nothing once the wait has an answer or a settlement:
/// the wait keeps its first answer and reads no later word.
///
/// # Errors
///
/// Storage errors, and a word the ask's kind does not offer.
pub(super) fn approved_act_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    word: &TaskAskWord,
) -> Result<Option<&'static str>> {
    match approval_in(vault, txn, id, group, word)? {
        ApprovalRoute::Routed(approval) => Ok(approval.map(|approval| approval.reason)),
        ApprovalRoute::Unrouted => {
            if crate::runtime_hooks::verb_ask_word_releases_in(
                vault,
                txn,
                id,
                &group.requested.intent_key,
                word.option.as_ref(),
            )? && ask_settlement::decision_open_in(vault, txn, id, group)?
            {
                Ok(Some(owner_presence_reasons::ANSWER_VERB_HOOK_ASK))
            } else {
                Ok(None)
            }
        }
    }
}

/// Refuses an approving `word` on the ask `id` whose act the store refuses
/// now: the checks the kind's own writer makes on the word's cut before its
/// first write, made here from a read of the `selected` word (an attendee
/// ask's named contact still lives; a training offer's model switch still
/// binds). A submitted or selected word that approves no act, and a kind
/// whose writer has no such check, pass.
///
/// The answer door runs it on its read, after the word's admission and
/// before the device asks for the person (`super::ask_word_presence`), so
/// nobody is asked to approve an act its settlement then refuses. The
/// kind's writer makes each check again on the cut, through the same
/// function, so the write is as it was.
///
/// # Errors
///
/// Storage errors, a word the ask's kind does not offer, and the kind's
/// own refusal of an act that no longer stands.
pub(super) fn approved_act_stands_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    word: &TaskAskWord,
    selected: &TaskAskWord,
) -> Result<()> {
    if let ApprovalRoute::Routed(Some(approval)) = approval_in(vault, txn, id, group, word)?
        && selected.option.as_ref().is_some_and(approval.approves)
        && let Some(stands) = approval.stands
    {
        stands(vault, txn, id, group, selected)?;
    }
    Ok(())
}

/// Whether settlement may cut the ask `id` for `reason` with `decision`
/// under `owner`. Its deadline or staleness always closes it, on the hold
/// default. An ask of a kind in [`ASK_KINDS`] cuts on a person's first word
/// only under the live proof, in this transaction, of the asked party who
/// gave it; without that proof it stays open. An agent's word was admitted
/// only from its verified actor, so it cuts as it is. Any other ask passes.
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
        if matches!(asked, AskedParty::Agent(_)) {
            continue;
        }
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
