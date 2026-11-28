//! Caller-selected world and project filters. These never grant authority.
use super::{Memory, MemoryError, MemoryResult, RecallScope};
use crate::EntityId;
use crate::claim::world_access::WorldAuthoritySet;
use crate::corpus::CorpusScope;
use std::collections::BTreeSet;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::read_selection::RecallWorlds;

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
                None => {
                    let defaults = self
                        .reading_defaults(&[self.actor])?
                        .pop()
                        .expect("one default per actor");
                    if defaults.worlds().is_empty() {
                        return Ok(Some(defaults));
                    }
                    let txn = self
                        .vault
                        .store
                        .env
                        .read_txn()
                        .map_err(crate::error::Error::from)?;
                    let mut worlds = Vec::with_capacity(defaults.worlds().len());
                    for world in defaults.worlds() {
                        if !self.vault.is_clipboard_world_in_txn(&txn, *world)? {
                            worlds.push(*world);
                        }
                    }
                    Ok(Some(WorldAuthoritySet::new(
                        defaults.include_base(),
                        worlds,
                    )?))
                }
            },
        }
    }

    /// The projects a recall narrows to: each selected project with every
    /// project below it (FIX 7775). Selection only narrows; the caller's
    /// credential still decides what is read.
    pub(super) fn selected_projects(&self, scope: &RecallScope) -> MemoryResult<CorpusScope> {
        self.projects_at_or_below(&scope.project_refs)
    }

    /// Each of `project_refs` with every project below it, the project
    /// narrowing recall and the filtered claim reads share. Empty adds no
    /// narrowing. A ref resolves as any entity ref does, so an anchor id
    /// that names no row narrows to the claims stamped with it.
    pub(super) fn projects_at_or_below(
        &self,
        project_refs: &[String],
    ) -> MemoryResult<CorpusScope> {
        if project_refs.is_empty() {
            return Ok(CorpusScope::Unscoped);
        }
        let selected = project_refs
            .iter()
            .map(|reference| self.resolve_ref(reference))
            .collect::<MemoryResult<Vec<_>>>()?;
        Ok(CorpusScope::AnyOf(
            self.project_descendant_closure(selected)?,
        ))
    }

    /// What an attached session in the folder `folder_digests` (its own digest first) reads by
    /// default: the folder's bound project with every project below it, or
    /// [`SessionProjects::Unbound`] when no live project is bound.
    ///
    /// [`SessionProjects::Unbound`]: crate::session_project::SessionProjects::Unbound
    pub(super) fn session_projects_of(
        &self,
        folder_digests: &[String],
    ) -> MemoryResult<crate::session_project::SessionProjects> {
        Ok(self.vault.session_projects(folder_digests)?)
    }

    /// `selected` and every PROJECT that belongs to one of them at any depth:
    /// the incoming `belongs_to` edges from PROJECT rows, followed to the
    /// end in one read, each project once however the edges loop.
    fn project_descendant_closure(&self, selected: Vec<EntityId>) -> MemoryResult<Vec<EntityId>> {
        Ok(project_descendant_closure_of(self.vault, selected)?)
    }
}

/// [`Memory::project_descendant_closure`] in `vault`: `selected` and every PROJECT that belongs
/// to one of them at any depth, in one read.
pub(crate) fn project_descendant_closure_of(
    vault: &crate::Vault,
    selected: Vec<EntityId>,
) -> crate::Result<Vec<EntityId>> {
    // A vault with no project kind bound holds no project hierarchy.
    let Ok(project_type) = vault.project_type_byte() else {
        return Ok(selected);
    };
    let txn = vault.store.env.read_txn()?;
    let mut closure = BTreeSet::new();
    let mut pending = selected;
    while let Some(project) = pending.pop() {
        if !closure.insert(project) {
            continue;
        }
        pending.extend(crate::vault::filtered_edge_peers_in(
            &vault.store,
            &txn,
            crate::ports::EdgeDirection::In,
            &project,
            crate::edge::EdgeKind::BelongsTo,
            Some(project_type),
        )?);
    }
    Ok(closure.into_iter().collect())
}
