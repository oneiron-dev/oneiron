//! The rows a Coach brief or check is gathered from (FIX 5482), ids only. A
//! set stays known only while every input names the rows it read (FIX 5760):
//! one whose producer named none leaves the set unknown, never a partial
//! list.
use oneiron::EntityId;
use oneiron::skill_optimize::union_source_rows;

pub(super) struct Sources(Option<Vec<EntityId>>);

impl Sources {
    /// Nothing read yet: a known, empty set.
    pub(super) fn new() -> Self {
        Self(Some(Vec::new()))
    }

    /// One row the brief or check read.
    pub(super) fn row(&mut self, id: EntityId) {
        if let Some(rows) = &mut self.0 {
            rows.push(id);
        }
    }

    /// An earlier snapshot's own set: an unknown one leaves this unknown.
    pub(super) fn set(&mut self, set: Option<&[EntityId]>) {
        self.0 = union_source_rows([self.0.as_deref(), set]);
    }

    /// The set, sorted and deduplicated; `None` when unknown.
    pub(super) fn rows(&self) -> Option<Vec<EntityId>> {
        union_source_rows([self.0.as_deref()])
    }
}
