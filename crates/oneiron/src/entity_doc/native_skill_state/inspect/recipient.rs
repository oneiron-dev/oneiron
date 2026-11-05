//! Complete borrowed native inputs, not an accepted native state.

use super::{NativeMapInventory, NativeMapWrite};
use crate::entity_doc::native_skill_state::codec::recipient::SkillStateFactView;
use loro::ID;

pub(in crate::entity_doc) struct NativeMapFloorView<'inventory> {
    pub frontier: &'inventory [u8],
    pub fact: Option<SkillStateFactView<'inventory>>,
}

pub(in crate::entity_doc) struct NativeMapMutationView<'inventory> {
    pub id: ID,
    pub change: ID,
    pub dependencies: &'inventory [ID],
    pub write: NativeMapWriteView<'inventory>,
}

pub(in crate::entity_doc) enum NativeMapWriteView<'inventory> {
    Insert(SkillStateFactView<'inventory>),
    Delete,
}

impl NativeMapInventory {
    pub(in crate::entity_doc) fn current(&self) -> Option<SkillStateFactView<'_>> {
        self.current.as_ref().map(|fact| fact.view())
    }

    /// A real shallow floor with no fact is Some(fact: None), not no floor.
    pub(in crate::entity_doc) fn floor(&self) -> Option<NativeMapFloorView<'_>> {
        self.floor.as_ref().map(|floor| NativeMapFloorView {
            frontier: &floor.frontier,
            fact: floor.fact.as_ref().map(|fact| fact.view()),
        })
    }

    pub(in crate::entity_doc) fn mutations(
        &self,
    ) -> impl Iterator<Item = NativeMapMutationView<'_>> {
        self.mutations.iter().map(|mutation| NativeMapMutationView {
            id: mutation.id,
            change: mutation.change,
            dependencies: &mutation.dependencies,
            write: match &mutation.write {
                NativeMapWrite::Insert(fact) => NativeMapWriteView::Insert(fact.view()),
                NativeMapWrite::Delete => NativeMapWriteView::Delete,
            },
        })
    }
}
