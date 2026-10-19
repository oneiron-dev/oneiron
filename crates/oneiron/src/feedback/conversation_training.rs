//! "Learn from my conversations" (FIX 4489, FIX 5502 owner rulings,
//! OF-420): the one check real conversation text passes before it may go
//! toward training the models Oneiron ships, and the only doors that send it
//! there.
//!
//! The owner's rule, in plain words ("my casa my rules", 10-19): one setting
//! per vault, set by its admin and off until the admin turns it on
//! (`Vault::set_conversation_learning`). While it is on, everything in the
//! vault counts, people, agents and guests alike. A private world never
//! counts: a world counts only while its folded privacy read is everywhere,
//! the rule code-fix exports keep. The admin may let people opt out: then a
//! person's own "leave my messages out" (`Vault::set_conversation_training`)
//! keeps their messages out ([`opted_out`]). Turning the setting off, or
//! opting out, stops new sharing; it withdraws nothing already shared, which
//! follows the intake's retention. Before anything leaves, the in-vault
//! filter runs over it (a [`TextFilter`]: the Oneironer, under OF-420's
//! in-vault redaction), and what it returns is called filtered, never more.
//! No person reads it. Otherwise real chat text never leaves, except in a
//! report the person sends (the feedback bundle's one-shot approval, not
//! this setting).
//!
//! The switch covers sharing toward the models Oneiron ships, and only that
//! (DEC-0005 #data-leaves-split; ARCH-0053 #training-opt-in). Training a
//! model of your own on your own data needs no sharing: the training pack
//! (`training_pack`), its connector and the reservoir export it reads are not
//! gated by this switch.
//!
//! Two doors in the engine hand conversation text toward a publisher, and
//! nothing else may send it there: [`share_for_publisher_training`], over a
//! sink its caller supplies, and the publisher training outbox
//! ([`Vault::offer_conversation_training`], OF-420), which selects each
//! source from the canonical rows itself and publishes only what a release
//! lets through ([`Vault::release_training_submission`]). Each judges a
//! source with [`eligible`] before filtering and again at the send or the
//! release itself: turning the switch off takes no lock a send waits on, so
//! the send-time read is the guard. With no machine-only intake configured
//! neither reads, judges or filters anything.

mod crypto;
mod custody;
mod lifecycle;
mod receipts;
mod reconcile;
mod release;
mod source;

pub use self::crypto::{IntakeReceiptKey, IntakeRecipient};
pub use self::lifecycle::{
    PublisherTrainingLifecycle, ReceiptCursor, ReceivedTrainingReceipt, ReleaseDecision,
    SealedTrainingOffer, SignedTrainingControl, TrainingControlId, TrainingQueued,
    TrainingReceiptPage, TrainingSubmissionId, TrainingUnavailable, TrainingWithheld,
};
pub use self::receipts::{
    PersonTrainingReceipts, PersonTrainingSubmission, TrainingCustody, TrainingReceiptsCursor,
    TrainingUsedRun,
};
pub use self::reconcile::TrainingUpkeep;
pub use self::release::TrainingOfferPass;

use std::collections::BTreeSet;

use crate::Vault;
use crate::authority::{AuthorityFold, EffectiveRead};
use crate::consent::person_is_live_in_txn;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::redaction::{FilteredText, TextFilter, TextFilterError};

/// Why [`share_for_publisher_training`] sent nothing at all.
pub const NO_PUBLISHER_TRAINING_INTAKE: &str =
    "no machine-only intake for conversation training is configured";

/// Where the vault's "Learn from my conversations" setting is read, and
/// each person's own opt-out while the setting lets people opt out.
///
/// Only the vault's admin turns it on. Nothing else does: not an agent, an
/// environment variable, a manifest or a hosted default.
pub trait ConversationTrainingChoice {
    /// Whether the vault's setting is on now. No choice, an off and a
    /// conflict read as off.
    ///
    /// # Errors
    /// Any read that cannot be made withholds; it never reads as on.
    fn conversation_learning_on(&self) -> Result<bool>;

    /// Whether `person`'s own messages are left out now: the vault lets
    /// people opt out, and they did.
    ///
    /// # Errors
    /// Any read that cannot be made withholds; it never lets them in.
    fn conversation_training_opted_out(&self, person: EntityId) -> Result<bool>;
}

/// The reader that says off, for a caller with no setting to read.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoChoicesYet;

impl ConversationTrainingChoice for NoChoicesYet {
    fn conversation_learning_on(&self) -> Result<bool> {
        Ok(false)
    }

    fn conversation_training_opted_out(&self, _person: EntityId) -> Result<bool> {
        Ok(true)
    }
}

/// The vault's own signed setting and each person's own signed opt-out, as
/// this vault folds them: a conflicting setting reads as off.
impl ConversationTrainingChoice for Vault {
    fn conversation_learning_on(&self) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(fold.conversation_training_vault.on())
    }

    fn conversation_training_opted_out(&self, person: EntityId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(opted_out(&fold, person))
    }
}

/// The opt-out rule (owner ruling 10-19 21:1x), the one place it is read:
/// `person`'s own messages are left out while the vault's setting is on and
/// lets people opt out, and they asked to leave them out (a conflict among
/// their choices reads as asked). Otherwise their choice is kept and
/// ignored.
fn opted_out(fold: &AuthorityFold, person: EntityId) -> bool {
    fold.conversation_training_vault.allows_opt_out()
        && fold.conversation_training.leaves_out(person)
}

/// Where one conversation text came from: whose words, and which worlds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationSource {
    /// The row the text was read from, kept for provenance.
    pub source: EntityId,
    /// Every person whose words the text carries, members and guests alike;
    /// empty for text only agents wrote.
    pub persons: BTreeSet<EntityId>,
    /// Every world the text came from; empty is unplaced.
    pub worlds: BTreeSet<EntityId>,
}

/// One conversation text and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationText {
    /// Whose words, and which worlds.
    pub source: ConversationSource,
    /// The text as stored. It reaches an intake only as the filter returns
    /// it.
    pub text: String,
}

/// Whether a source may go toward training the models Oneiron ships.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Eligibility {
    /// The vault's setting is on, every world reads everywhere, and every
    /// person named is live and has not opted out.
    Eligible,
    /// Held back, and why.
    Withheld(Withheld),
}

/// Why a source is held back. Each reason names ids, never text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Withheld {
    /// The source names no world, so whether it came from a private one is
    /// unknown.
    Unplaced,
    /// The vault's setting is off.
    Off,
    /// A world the text came from reads narrower than everywhere, or its
    /// read is conflicted or unknowable.
    PrivateWorld(EntityId),
    /// A person whose words these are is no longer a live person.
    PersonNotLive(EntityId),
    /// A person whose words these are left their own messages out, while
    /// the vault lets people opt out.
    OptedOut(EntityId),
}

/// Judges one source on the strict reading: the vault's setting is on,
/// every world the text came from reads everywhere on this vault's fold,
/// and every person named is live and has not opted out. A source naming no
/// world is withheld, as is any read short of that; one naming no person
/// (text only agents wrote) needs no person's read. The setting is read
/// now, each time this is asked.
///
/// # Errors
/// Storage faults, and any error the setting reader returns: never a yes.
pub fn eligible(
    vault: &Vault,
    choices: &dyn ConversationTrainingChoice,
    source: &ConversationSource,
) -> Result<Eligibility> {
    if source.worlds.is_empty() {
        return Ok(Eligibility::Withheld(Withheld::Unplaced));
    }
    if !choices.conversation_learning_on()? {
        return Ok(Eligibility::Withheld(Withheld::Off));
    }
    if let Some(reason) = fold_withholds(vault, source)? {
        return Ok(Eligibility::Withheld(reason));
    }
    for person in &source.persons {
        if choices.conversation_training_opted_out(*person)? {
            return Ok(Eligibility::Withheld(Withheld::OptedOut(*person)));
        }
    }
    Ok(Eligibility::Eligible)
}

/// The fold's part of [`eligible`], in one read transaction closed before
/// the setting reader opens its own: every world reads everywhere (any
/// narrower, conflicted or unknowable read is private), and every person is
/// live.
fn fold_withholds(vault: &Vault, source: &ConversationSource) -> Result<Option<Withheld>> {
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_view_readonly_in_txn(&txn)?;
    if let Some(world) = source
        .worlds
        .iter()
        .find(|world| fold.world_privacy(**world).read != EffectiveRead::Everywhere)
    {
        return Ok(Some(Withheld::PrivateWorld(*world)));
    }
    for person in &source.persons {
        if !person_is_live_in_txn(vault, &txn, person)? {
            return Ok(Some(Withheld::PersonNotLive(*person)));
        }
    }
    Ok(None)
}

/// A machine-only intake for conversation text toward training the models
/// Oneiron ships.
///
/// An implementation is the contract the owner's rule needs from the far
/// side: no person reads what it takes; it honours withdrawal, so a person's
/// deleted words, a deleted source or a world turned private are removed
/// from its store and from every later run; and it names the runs that used
/// them.
/// Nothing in this engine implements it, and the human-readable feedback
/// inbox is not one.
pub trait PublisherTrainingSink {
    /// Takes one filtered text and where it came from. The raw text never
    /// reaches it.
    ///
    /// # Errors
    /// The intake refused or could not take it; the pass stops there.
    fn accept(&self, source: &ConversationSource, text: &FilteredText) -> Result<()>;
}

/// Why one source did not go to the intake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareWithheld {
    /// The source did not pass [`eligible`], before filtering or at the send.
    Ineligible(Withheld),
    /// The filter could not run; the text was not sent unfiltered.
    FilterUnavailable(String),
    /// The filter rejected its recogniser's answer; the text was not sent.
    FilterRejected(String),
}

/// What [`share_for_publisher_training`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareOutcome {
    /// Nothing was read, judged, filtered or sent, for this reason.
    Unavailable {
        /// Why ([`NO_PUBLISHER_TRAINING_INTAKE`]).
        reason: &'static str,
    },
    /// Every source was judged: these went to the intake, these did not.
    Shared {
        /// The sources the intake took, in the order given.
        sent: Vec<EntityId>,
        /// The sources held back, and why.
        withheld: Vec<(EntityId, ShareWithheld)>,
    },
}

/// The only door that hands conversation text toward training the models
/// Oneiron ships.
///
/// With no `sink` it returns [`ShareOutcome::Unavailable`] before reading,
/// judging or filtering anything. Otherwise, for each source in order: it
/// must pass [`eligible`]; then the filter runs over its text, and a filter
/// that cannot run or rejects its answer withholds the source (it is never
/// sent unfiltered); then [`eligible`] is asked again at the send itself, so
/// a setting turned off, a person who opted out, or a world made private,
/// while the filter ran stops the send; then the filtered text and its
/// provenance go to the sink.
///
/// # Errors
/// A storage fault, a setting read that fails, or a sink that refuses stops
/// the pass; every source already taken passed every check.
pub fn share_for_publisher_training(
    vault: &Vault,
    choices: &dyn ConversationTrainingChoice,
    filter: &dyn TextFilter,
    sink: Option<&dyn PublisherTrainingSink>,
    sources: &[ConversationText],
) -> Result<ShareOutcome> {
    let Some(sink) = sink else {
        return Ok(ShareOutcome::Unavailable {
            reason: NO_PUBLISHER_TRAINING_INTAKE,
        });
    };
    let mut sent = Vec::new();
    let mut withheld = Vec::new();
    for item in sources {
        match share_one(vault, choices, filter, sink, item)? {
            None => sent.push(item.source.source),
            Some(reason) => withheld.push((item.source.source, reason)),
        }
    }
    Ok(ShareOutcome::Shared { sent, withheld })
}

/// One source through [`share_for_publisher_training`]: `None` when the
/// sink took it.
fn share_one(
    vault: &Vault,
    choices: &dyn ConversationTrainingChoice,
    filter: &dyn TextFilter,
    sink: &dyn PublisherTrainingSink,
    item: &ConversationText,
) -> Result<Option<ShareWithheld>> {
    if let Eligibility::Withheld(reason) = eligible(vault, choices, &item.source)? {
        return Ok(Some(ShareWithheld::Ineligible(reason)));
    }
    let filtered = match filter.filter(&item.text) {
        Ok(filtered) => filtered,
        Err(TextFilterError::Unavailable(reason)) => {
            return Ok(Some(ShareWithheld::FilterUnavailable(reason)));
        }
        Err(TextFilterError::Rejected(reason)) => {
            return Ok(Some(ShareWithheld::FilterRejected(reason)));
        }
    };
    // The send-time read: the setting, the opt-outs and the worlds as they
    // stand now, not as they stood before the filter ran.
    if let Eligibility::Withheld(reason) = eligible(vault, choices, &item.source)? {
        return Ok(Some(ShareWithheld::Ineligible(reason)));
    }
    sink.accept(&item.source, &filtered)?;
    Ok(None)
}
