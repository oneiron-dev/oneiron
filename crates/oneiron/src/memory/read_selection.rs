//! Caller-selected world and project filters. These never grant authority.
use super::{Memory, MemoryError, MemoryResult, RecallScope};
use crate::corpus::CorpusScope;
use crate::pipeline::WorldAuthoritySet;
use serde::{Deserialize, Serialize};

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

    pub(super) fn selected_projects(&self, scope: &RecallScope) -> MemoryResult<CorpusScope> {
        if scope.project_refs.is_empty() {
            return Ok(CorpusScope::All);
        }
        Ok(CorpusScope::AnyOf(
            scope
                .project_refs
                .iter()
                .map(|reference| self.resolve_ref(reference))
                .collect::<MemoryResult<Vec<_>>>()?,
        ))
    }
}
