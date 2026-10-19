//! Folds each person's signed "Learn from my conversations" opt-out (FIX
//! 4489, FIX 5502 owner rulings, OF-420).
//!
//! The owner's rulings (10-19): the vault's setting, set by its admin
//! ([`super::conversation_training_vault`]), decides whether the vault's
//! conversations count; when the admin lets people opt out, a person's own
//! "leave my messages out" keeps their messages out. The choices keep the
//! shared owner-choice register ([`super::owner_choice`]) under their own
//! revision domain, one frontier per acting PERSON: a choice supersedes
//! exactly that person's live choices its parents carry, and concurrent
//! different choices of one person conflict. A conflict reads as left out,
//! never as the last choice they agreed on; no choice reads as not left out.
//! A choice this install does not count at full strength counts as not made.
//! Choices are main-log entries, so every machine the owner admits folds
//! them. The person's own door ([`Vault::set_conversation_training`]) signs
//! a choice; it is kept, and ignored, while the vault does not let people
//! opt out.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::machine_standing::InstallCounted;
use super::owner_choice::{
    FoldedOwnerChoice, OwnerChoiceOp, OwnerChoiceState, folded_owner_choices, owner_choice_landing,
    refused_owner_choices,
};
use super::*;

mod door;

pub use door::ConversationTrainingView;

/// Every person's opt-out choices in one fold state, each keyed by the
/// acting PERSON.
pub(super) type ConversationTrainingChoiceState = OwnerChoiceState<bool>;

/// One person's folded choices, as this install counts them.
pub(crate) type FoldedPersonTraining = FoldedOwnerChoice<bool>;

/// Every person's folded opt-out choices.
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

    /// Whether `person` asked to leave their messages out: their choice in
    /// force says so, or any of their live choices in conflict does. No
    /// choice reads as not left out.
    pub(crate) fn leaves_out(&self, person: EntityId) -> bool {
        self.persons.get(&person).is_some_and(|folded| {
            folded.selected() == Some(&true)
                || folded.conflict.iter().any(|head| head.choice == Some(true))
        })
    }

    /// Whether `person`'s live choices conflict.
    pub(crate) fn conflicted(&self, person: EntityId) -> bool {
        self.persons
            .get(&person)
            .is_some_and(|folded| !folded.conflict.is_empty())
    }

    /// The authority entry of `person`'s choice in force; `None` while none
    /// counts or theirs conflict.
    pub(crate) fn act(&self, person: EntityId) -> Option<AuthorityEntryHash> {
        self.persons
            .get(&person)
            .filter(|folded| folded.conflict.is_empty())
            .and_then(|folded| folded.in_force.as_ref())
            .map(|head| head.act)
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
        choice: Some(&set.leave_out),
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
