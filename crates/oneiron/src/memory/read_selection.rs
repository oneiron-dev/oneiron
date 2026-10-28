//! Caller-selected world and project filters. These never grant authority.
use super::{Memory, MemoryError, MemoryResult, RecallScope};
use crate::EntityId;
use crate::corpus::CorpusScope;
use crate::pipeline::WorldAuthoritySet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecallWorlds {
    All,
    Base,
    World {
        world_ref: String,
        include_base: bool,
    },
    Worlds {
        world_refs: Vec<String>,
        include_base: bool,
    },
}

impl Memory<'_> {
    pub(super) fn selected_worlds(
        &self,
        scope: &RecallScope,
    ) -> MemoryResult<Option<WorldAuthoritySet>> {
        if scope.worlds.is_some() && scope.world_ref.is_some() {
            return Err(MemoryError::bad_request(
                "select worlds or world_ref, not both",
            ));
        }
        match &scope.worlds {
            Some(RecallWorlds::All) => Ok(None),
            Some(RecallWorlds::Base) => Ok(Some(WorldAuthoritySet::new(true, [])?)),
            Some(RecallWorlds::World {
                world_ref,
                include_base,
            }) => Ok(Some(WorldAuthoritySet::new(
                *include_base,
                [self.resolve_ref(world_ref)?],
            )?)),
            Some(RecallWorlds::Worlds {
                world_refs,
                include_base,
            }) => {
                let worlds = world_refs
                    .iter()
                    .map(|reference| self.resolve_ref(reference))
                    .collect::<MemoryResult<Vec<_>>>()?;
                // An empty requested set adds no narrowing; it never creates a grant.
                if worlds.is_empty() && !include_base {
                    return Ok(None);
                }
                Ok(Some(WorldAuthoritySet::new(*include_base, worlds)?))
            }
            None => match &scope.world_ref {
                Some(reference) => Ok(Some(WorldAuthoritySet::new(
                    true,
                    [self.resolve_ref(reference)?],
                )?)),
                None => Ok(Some(
                    self.reading_defaults(&[self.actor])?
                        .pop()
                        .expect("one default per actor"),
                )),
            },
        }
    }

    /// The projects a recall narrows to: each selected project with every
    /// project below it (FIX 7775). Selection only narrows; the caller's
    /// credential still decides what is read.
    pub(super) fn selected_projects(&self, scope: &RecallScope) -> MemoryResult<CorpusScope> {
        if scope.project_refs.is_empty() {
            return Ok(CorpusScope::All);
        }
        let selected = scope
            .project_refs
            .iter()
            .map(|reference| self.resolve_ref(reference))
            .collect::<MemoryResult<Vec<_>>>()?;
        Ok(CorpusScope::AnyOf(self.project_descendant_closure(selected)?))
    }

    /// `selected` and every PROJECT that belongs to one of them at any depth:
    /// the incoming `belongs_to` edges from PROJECT rows, followed to the
    /// end in one read, each project once however the edges loop.
    fn project_descendant_closure(&self, selected: Vec<EntityId>) -> MemoryResult<Vec<EntityId>> {
        // A vault with no project kind bound holds no project hierarchy.
        let Ok(project_type) = self.vault.project_type_byte() else {
            return Ok(selected);
        };
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        let mut closure = BTreeSet::new();
        let mut pending = selected;
        while let Some(project) = pending.pop() {
            if !closure.insert(project) {
                continue;
            }
            pending.extend(crate::vault::filtered_edge_peers_in(
                &self.vault.store,
                &txn,
                crate::ports::EdgeDirection::In,
                &project,
                crate::edge::EdgeKind::BelongsTo,
                Some(project_type),
            )?);
        }
        Ok(closure.into_iter().collect())
    }
}
