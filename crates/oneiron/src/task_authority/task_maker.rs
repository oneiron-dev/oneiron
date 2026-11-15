//! A TASK's id commits to its maker and its owner (FIX TASK-ID-COMMITS-TO-MAKER; Engine
//! RULING 16 Nov 04:34, TASK-ID-MAKER-SHAPE = A).
//!
//! Every door that writes an Owner fact mints the TASK at
//! `derive(TASK_MAKER, maker, owner, nonce)`, and the Owner fact carries the maker and the
//! nonce. The fold recomputes the id from the fact alone and skips an Owner fact whose
//! triple derives another id. A second Owner fact that names the true maker and nonce but
//! another owner derives another id, so it cannot count, however well its carrier proves
//! it (Fable pass 28 SR-1). The nonce is the uniqueness the door already had: the id it
//! minted before (a post's or a settle's derive, an ask member's id, or a store-clock id),
//! so a retry and every device still reach one TASK.

use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::TASK_MAKER;
use crate::error::Result;

/// The maker commitment an Owner fact carries: who made the TASK, and the nonce its door
/// minted it under. With the fact's owner it derives the TASK's id
/// ([`task_ref_of_maker`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskMaker {
    /// The actor whose door minted the TASK. It is the owner unless the door named another
    /// (`tasks.create` with an `owner_ref`, an engine hook effect, a settled create).
    pub maker_ref: EntityId,
    /// The door's own uniqueness: the id it minted before this commitment.
    pub nonce: EntityId,
}

impl TaskMaker {
    /// The id of the TASK this maker mints for `owner_ref`.
    ///
    /// # Errors
    ///
    /// As [`task_ref_of_maker`].
    pub fn task_ref(&self, owner_ref: EntityId) -> Result<EntityId> {
        task_ref_of_maker(self.maker_ref, owner_ref, self.nonce)
    }
}

/// The id of the TASK `maker_ref` mints for `owner_ref` under `nonce`. Every door that
/// writes an Owner fact, and every reader that finds such a TASK from its inputs, derives
/// the id here.
///
/// # Errors
///
/// A derivation that lands in the reserved id range (`EntityId::derive`).
pub fn task_ref_of_maker(
    maker_ref: EntityId,
    owner_ref: EntityId,
    nonce: EntityId,
) -> Result<EntityId> {
    EntityId::derive(
        TASK_MAKER,
        &[maker_ref.as_bytes(), owner_ref.as_bytes(), nonce.as_bytes()],
    )
}
