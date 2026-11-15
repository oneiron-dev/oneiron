//! Moved from `crates/oneiron/src/authority/checkpoint_choice.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::owner_choice::OwnerChoiceHead;
use crate::authority::*;

/// One choice as a surface shows it: its roots and quorum, `None` for a
/// clear.
pub type CheckpointPolicyHead = OwnerChoiceHead<CheckpointRootChoice>;
