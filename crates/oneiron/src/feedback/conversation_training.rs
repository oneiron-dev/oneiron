//! "Learn from my conversations" (FIX 4489, OF-420): the one check real
//! conversation text passes before it may go toward training the models
//! Oneiron ships, and the only door that sends it there.
//!
//! The owner's rule, in plain words: real conversation text is used for
//! training only after the person whose words they are says yes, and it stays
//! off until they do. Before anything leaves, the in-vault filter runs over it
//! (a [`TextFilter`]: the Oneironer, under OF-420's in-vault redaction), and
//! what it returns is called filtered, never more. No person reads it. A yes
//! is scoped to the worlds the person names, and a private world is never
//! included: a world counts only while its folded privacy read is
//! everywhere, the rule code-fix exports keep. Otherwise real chat text never
//! leaves, except in a report the person sends (the feedback bundle's
//! one-shot approval, not this switch).
//!
//! The switch covers sharing toward the models Oneiron ships, and only that
//! (DEC-0005 #data-leaves-split; ARCH-0053 #training-opt-in). Training a
//! model of your own on your own data needs no sharing: the training pack
//! (`training_pack`), its connector and the reservoir export it reads are not
//! gated by this switch.
//!
//! [`share_for_publisher_training`] is the only door in the engine that
//! hands conversation text toward a publisher, and nothing else may send it
//! there. It judges each source with [`eligible`] before filtering and again
//! at the send itself: turning the switch off takes no lock a send waits on,
//! so the send-time read is the guard. With no machine-only intake
//! configured it reads, judges and filters nothing.

use std::collections::BTreeSet;

use crate::Vault;
use crate::authority::EffectiveRead;
use crate::consent::person_is_live_in_txn;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::redaction::{FilteredText, TextFilter, TextFilterError};

/// Why [`share_for_publisher_training`] sent nothing at all.
pub const NO_PUBLISHER_TRAINING_INTAKE: &str =
    "no machine-only intake for conversation training is configured";

/// Where a person's "Learn from my conversations" choice is read: the worlds
/// whose conversations they said yes to, as those worlds count now.
///
/// Only the PERSON's own yes counts. Nobody else's choice opts them in: not
/// an owner's, an admin's or an agent's, and not an environment variable, a
/// manifest or a hosted default.
pub trait ConversationTrainingChoice {
    /// The worlds `person` said yes for. `Ok(None)` is off: no choice, a
    /// cleared one, or their choices in conflict. `Ok(Some(worlds))` is never
    /// empty.
    ///
    /// # Errors
    /// Any read that cannot be made withholds; it never reads as a yes.
    fn conversation_training_worlds(&self, person: EntityId) -> Result<Option<BTreeSet<EntityId>>>;
}

/// The reader that says off for everyone, for a caller with no choice
/// register to read.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoChoicesYet;

impl ConversationTrainingChoice for NoChoicesYet {
    fn conversation_training_worlds(
        &self,
        _person: EntityId,
    ) -> Result<Option<BTreeSet<EntityId>>> {
        Ok(None)
    }
}

/// Each person's own signed choice, as this vault folds it
/// (`Vault::conversation_training_worlds`): a conflict, a clear and no
/// choice read as off, and a world no longer eligible drops out.
impl ConversationTrainingChoice for Vault {
    fn conversation_training_worlds(&self, person: EntityId) -> Result<Option<BTreeSet<EntityId>>> {
        Self::conversation_training_worlds(self, person)
    }
}

/// Where one conversation text came from: whose words, and which worlds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationSource {
    /// The row the text was read from, kept for provenance.
    pub source: EntityId,
    /// Every person whose words the text carries; empty is unattributed.
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
    /// Every person named is live and said yes for every world named, and
    /// every world reads everywhere.
    Eligible,
    /// Held back, and why.
    Withheld(Withheld),
}

/// Why a source is held back. Each reason names ids, never text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Withheld {
    /// The source names no person, so whose yes it needs is unknown.
    Unattributed,
    /// The source names no world, so whether it came from a private one is
    /// unknown.
    Unplaced,
    /// A world the text came from reads narrower than everywhere, or its
    /// read is conflicted or unknowable.
    PrivateWorld(EntityId),
    /// A person whose words these are is no longer a live person.
    PersonNotLive(EntityId),
    /// A person whose words these are has no yes in force.
    Off(EntityId),
    /// A person's yes does not name a world the text came from.
    WorldNotInScope {
        /// The person whose yes is narrower.
        person: EntityId,
        /// The world it does not name.
        world: EntityId,
    },
}

/// Judges one source on the strict reading: every person named is a live
/// person whose own yes is in force and names every world the text came
/// from, and every one of those worlds reads everywhere on this vault's
/// fold. A source naming no person or no world is withheld, as is any read
/// short of that. The choice is read now, each time this is asked.
///
/// # Errors
/// Storage faults, and any error the choice reader returns: never a yes.
pub fn eligible(
    vault: &Vault,
    choices: &dyn ConversationTrainingChoice,
    source: &ConversationSource,
) -> Result<Eligibility> {
    if source.persons.is_empty() {
        return Ok(Eligibility::Withheld(Withheld::Unattributed));
    }
    if source.worlds.is_empty() {
        return Ok(Eligibility::Withheld(Withheld::Unplaced));
    }
    if let Some(reason) = fold_withholds(vault, source)? {
        return Ok(Eligibility::Withheld(reason));
    }
    for person in &source.persons {
        let Some(chosen) = choices.conversation_training_worlds(*person)? else {
            return Ok(Eligibility::Withheld(Withheld::Off(*person)));
        };
        if let Some(world) = source.worlds.iter().find(|world| !chosen.contains(*world)) {
            return Ok(Eligibility::Withheld(Withheld::WorldNotInScope {
                person: *person,
                world: *world,
            }));
        }
    }
    Ok(Eligibility::Eligible)
}

/// The fold's part of [`eligible`], in one read transaction closed before
/// the choice reader opens its own: every world reads everywhere (any
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
/// side: no person reads what it takes; it honours withdrawal, so a person
/// who turns the switch off or deletes their words has them removed from its
/// store and from every later run; and it names the runs that used them.
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
/// a person who turned the switch off, or a world made private, while the
/// filter ran stops the send; then the filtered text and its provenance go
/// to the sink.
///
/// # Errors
/// A storage fault, a choice read that fails, or a sink that refuses stops
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
    // The send-time read: the choice and the worlds as they stand now, not
    // as they stood before the filter ran.
    if let Eligibility::Withheld(reason) = eligible(vault, choices, &item.source)? {
        return Ok(Some(ShareWithheld::Ineligible(reason)));
    }
    sink.accept(&item.source, &filtered)?;
    Ok(None)
}
