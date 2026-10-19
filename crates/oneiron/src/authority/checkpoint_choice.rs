//! Folds the owner's signed choices of his vault's checkpoint root policy
//! (mesh PR2c, §A 06, K06; CALLS "mesh PR2-checkpoint-choice").
//!
//! The vault's choices keep the shared owner-choice register
//! ([`super::owner_choice`]) under the checkpoint policy's own revision
//! domain: a choice supersedes exactly the live choices its parents carry,
//! concurrent different choices conflict, and while they do the last
//! unconflicted choice stays in force, the owner's surface reads the
//! conflict, and checkpointing never stops. A clear (no choice) hands the
//! vault back to the policy its hosting posture fixes.
//!
//! A choice this install does not count at full strength counts as not
//! made: the choice it replaced stays in force. Choices are main-log
//! entries, so every machine the owner admits folds them, and the fold reads
//! the log alone. Pins never move with a choice: a folding install follows
//! it, and an adopting install keeps the pin its pairing gave it.

use super::machine_standing::InstallCounted;
use super::owner_choice::{
    FoldedOwnerChoice, OwnerChoiceHead, OwnerChoiceOp, OwnerChoiceState, folded_owner_choice,
    owner_choice_landing,
};
use super::*;

/// The vault's checkpoint policy choices in one fold state.
pub(super) type CheckpointChoiceState = OwnerChoiceState<CheckpointRootChoice>;

/// One choice as a surface shows it: its roots and quorum, `None` for a
/// clear.
pub type CheckpointPolicyHead = OwnerChoiceHead<CheckpointRootChoice>;

/// The vault's folded checkpoint policy choices, as this install counts
/// them.
pub(crate) type FoldedCheckpointPolicy = FoldedOwnerChoice<CheckpointRootChoice>;

/// The `CheckpointPolicySet` transition ([`owner_choice_landing`]), under the
/// checkpoint policy's revision domain.
pub(super) fn apply_checkpoint_policy(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    set: &CheckpointPolicySet,
    hash: AuthorityEntryHash,
    counting: (Option<&PinnedRoot>, InstallCounted<'_>),
    restriction_only: bool,
) -> std::result::Result<(), AuthorityFoldIssue> {
    let op = OwnerChoiceOp {
        act: &set.act,
        machine: set.machine,
        choice: set.choice.as_ref(),
        context: CHECKPOINT_POLICY_REVISION_CONTEXT,
    };
    let landing = owner_choice_landing(
        state,
        &state.checkpoint_policy,
        entry,
        op,
        hash,
        counting,
        restriction_only,
    )?;
    state.checkpoint_policy.land(landing);
    Ok(())
}

/// The fold's view of the vault's choices, under this install's pin and
/// holds.
pub(super) fn folded_checkpoint_policy(
    state: &FoldState,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
) -> FoldedCheckpointPolicy {
    folded_owner_choice(state, &state.checkpoint_policy, pin, counted)
}
