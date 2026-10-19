//! Folds each person's signed "Learn from my conversations" choice (FIX
//! 4489, OF-420), and the one judge of which worlds a choice may name.
//!
//! The owner's ruling: real conversation text for training stays off until
//! the PERSON says yes, the yes can be scoped per world, and private worlds
//! are never included. The choices keep the shared owner-choice register
//! ([`super::owner_choice`]) under their own revision domain, one frontier
//! per acting PERSON: a choice supersedes exactly that person's live choices
//! its parents carry, and concurrent different choices of one person
//! conflict. A conflict reads as off, never as the last choice they agreed
//! on; so do no choice and a clear. A choice this install does not count at
//! full strength counts as not made. Choices are main-log entries, so every
//! machine the owner admits folds them.
//!
//! The register records the worlds as the person signed them. What counts
//! is judged on the fold it is read against
//! ([`Vault::conversation_training_worlds`]): a world deleted, archived, or
//! made private after the yes drops out, and a yes with no world left reads
//! as off, as does the yes of a PERSON no longer live (FIX 5116). The
//! person's own door ([`Vault::set_conversation_training`]) signs a choice.

use std::collections::{BTreeMap, BTreeSet};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::TombstoneStoreRead;
use crate::registry::ENTITY_TYPE_WORLD;

use super::machine_standing::InstallCounted;
use super::owner_choice::{
    FoldedOwnerChoice, OwnerChoiceOp, OwnerChoiceState, folded_owner_choices, owner_choice_landing,
    refused_owner_choices,
};
use super::*;

mod door;

pub use door::ConversationTrainingView;

/// Whether a person may list base reality beside their live WORLD rows: the
/// ordinary conversations live there, so a yes that could never name it
/// would scope out most of what a person says (CALLS "FIX 4489 world list
/// eligibility", open). It must still read everywhere, as every listed world
/// must.
const CONVERSATION_TRAINING_LISTS_BASE_REALITY: bool = true;

/// Every person's conversation training choices in one fold state, each
/// keyed by the acting PERSON.
pub(super) type ConversationTrainingChoiceState = OwnerChoiceState<BTreeSet<EntityId>>;

/// One person's folded choices, as this install counts them.
pub(crate) type FoldedPersonTraining = FoldedOwnerChoice<BTreeSet<EntityId>>;

/// Every person's folded conversation training choices.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct FoldedConversationTraining {
    /// Each person's choices, keyed by the PERSON; a person who never chose
    /// has no entry.
    pub(crate) persons: BTreeMap<EntityId, FoldedPersonTraining>,
    /// Well-signed choices without effect: their carrier was not admitted,
    /// or their person not live, at their parents.
    pub(crate) refused: BTreeSet<AuthorityEntryHash>,
}

impl FoldedConversationTraining {
    /// Whether any person's live choice rests on how this install counts
    /// machines.
    pub(super) fn rests_on_counting(&self) -> bool {
        self.persons.values().any(|folded| !folded.live.is_empty())
    }

    /// `person`'s choice revision: what their surface shows them and passes
    /// back as `seen`, zero while they have no live choice.
    pub(crate) fn revision(&self, person: EntityId) -> PolicyRevision {
        PolicyRevision(self.persons.get(&person).map_or([0; 32], |folded| {
            folded.revision(CONVERSATION_TRAINING_REVISION_CONTEXT)
        }))
    }

    /// The worlds `person`'s choice in force names, as signed; `None` when
    /// their choice is off, no choice of theirs counts, or their live
    /// choices conflict. A conflict never reads as the last choice they
    /// agreed on.
    pub(crate) fn chosen(&self, person: EntityId) -> Option<&BTreeSet<EntityId>> {
        let folded = self.persons.get(&person)?;
        if !folded.conflict.is_empty() {
            return None;
        }
        folded.selected()
    }

    /// The live choices `machine` carried, for its next profile revision's
    /// acknowledged set ([`super::world_privacy::live_edits_by`]).
    pub(super) fn live_choices_by(
        &self,
        machine: EntityId,
    ) -> impl Iterator<Item = AuthorityEntryHash> + '_ {
        self.persons
            .values()
            .flat_map(move |folded| super::owner_choice::live_choices_by(folded, machine))
    }
}

/// The `ConversationTrainingSet` transition ([`owner_choice_landing`]),
/// under its own revision domain, on the acting person's frontier.
pub(super) fn apply_conversation_training(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    set: &ConversationTrainingSet,
    hash: AuthorityEntryHash,
    counting: (Option<&PinnedRoot>, InstallCounted<'_>),
    restriction_only: bool,
) -> std::result::Result<(), AuthorityFoldIssue> {
    let op = OwnerChoiceOp {
        act: &set.act,
        machine: set.machine,
        choice: set.worlds.as_ref(),
        context: CONVERSATION_TRAINING_REVISION_CONTEXT,
    };
    let landing = owner_choice_landing(
        state,
        &state.conversation_training,
        entry,
        op,
        hash,
        counting,
        restriction_only,
    )?;
    state.conversation_training.land(landing);
    Ok(())
}

/// The fold's view of every person's choices, under this install's pin and
/// holds.
pub(super) fn folded_conversation_training(
    state: &FoldState,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
) -> FoldedConversationTraining {
    FoldedConversationTraining {
        persons: folded_owner_choices(state, &state.conversation_training, pin, counted),
        refused: refused_owner_choices(&state.conversation_training).clone(),
    }
}

impl Vault {
    /// The worlds whose conversations `person` said yes to training on, as
    /// they count now: their choice in force, less every world no longer
    /// eligible on this snapshot's fold (the eligibility hook,
    /// [`Self::conversation_training_world_admits`]). `None` when `person`
    /// is no longer a live PERSON of this vault (deleted, merged or split;
    /// FIX 5116), the choice is off, no choice of theirs counts, their live
    /// choices conflict, or no chosen world is still eligible.
    ///
    /// # Errors
    /// Storage faults, and history this vault lacks, as the fold reads them:
    /// never an empty or partial yes.
    pub fn conversation_training_worlds(
        &self,
        person: EntityId,
    ) -> Result<Option<BTreeSet<EntityId>>> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        self.conversation_training_effective_in_txn(&txn, &fold, person)
    }

    /// [`Self::conversation_training_worlds`] on `fold`, read in `txn`.
    pub(super) fn conversation_training_effective_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        person: EntityId,
    ) -> Result<Option<BTreeSet<EntityId>>> {
        if !crate::consent::person_is_live_in_txn(self, txn, &person)? {
            return Ok(None);
        }
        let Some(chosen) = fold.conversation_training.chosen(person) else {
            return Ok(None);
        };
        let mut worlds = BTreeSet::new();
        for world in chosen {
            if self.conversation_training_world_admits(txn, fold, *world)? {
                worlds.insert(*world);
            }
        }
        Ok((!worlds.is_empty()).then_some(worlds))
    }

    /// Whether a person's choice may name `world` (CALLS "FIX 4489 world list
    /// eligibility", open): a stored, live WORLD row, or base reality while
    /// [`CONVERSATION_TRAINING_LISTS_BASE_REALITY`] holds, that reads
    /// everywhere on `fold`. Any narrower, conflicted or unknowable read is
    /// private, and a private world is never included. It does not judge
    /// whether the person may read the world: the egress gate exports only
    /// that person's own rows.
    pub(super) fn conversation_training_world_admits(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        world: EntityId,
    ) -> Result<bool> {
        if world == crate::claim::base_world_id() {
            if !CONVERSATION_TRAINING_LISTS_BASE_REALITY {
                return Ok(false);
            }
        } else {
            if self.get_entity_type_in_txn(txn, &world)? != Some(ENTITY_TYPE_WORLD) {
                return Ok(false);
            }
            let visibility = TombstoneStoreRead::port_deletion_state(&self.store, txn, &world)?;
            if visibility.deleted || visibility.archived || visibility.stale {
                return Ok(false);
            }
        }
        Ok(fold.world_privacy(world).read == EffectiveRead::Everywhere)
    }
}
