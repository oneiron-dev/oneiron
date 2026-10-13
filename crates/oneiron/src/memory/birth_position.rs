//! Where a host binds a writer's TASKs to be born.

use super::Memory;
use crate::federation::record_scope::BirthPosition;

impl Memory<'_> {
    /// Binds where this surface's TASKs are born: the world and facet the
    /// writer's credential is narrowed to (ARCH-0067 §5). Every TASK minted
    /// through this surface is stamped there at birth, so the writer hears
    /// and reads its own tasks and a reader narrowed elsewhere does not.
    ///
    /// A host passes the ceiling it authenticated; nothing a caller sends
    /// reaches it. A vault-wide writer binds nothing, and its TASKs are born
    /// in base reality.
    #[must_use]
    pub fn with_birth_position(mut self, position: BirthPosition) -> Self {
        self.birth_position = position;
        self
    }

    pub(crate) const fn birth_position(&self) -> BirthPosition {
        self.birth_position
    }
}
