//! What one recall narrows by, resolved once from its scope (FIX 2905): the
//! worlds, projects, facet and kinds. Local recall reads these values, and an
//! opened device sends the same values to its home, which admits its
//! candidates by the same kinds rule ([`RecallKinds`]). Nothing here grants:
//! these are relevance filters inside the reader's own authority.

use super::{CONTAINER_KINDS, RecallScope, recall_kinds};
use crate::corpus::CorpusScope;
use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryResult};
use crate::pipeline::{TurnFold, WorldAuthoritySet, WorldScope};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};

/// The kinds one recall returns: `None` is the default, every kind but
/// [`CONTAINER_KINDS`]; a list is sorted and unique. Local recall and the
/// home's scoped search admit a candidate by this one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecallKinds(Option<Vec<u8>>);

impl RecallKinds {
    /// The kinds `kinds` names, sorted and unique, or the default.
    pub(crate) fn new(kinds: Option<Vec<u8>>) -> Self {
        Self(kinds.map(|mut kinds| {
            kinds.sort_unstable();
            kinds.dedup();
            kinds
        }))
    }

    /// The kinds named, or `None` for the default.
    pub(crate) fn listed(&self) -> Option<&[u8]> {
        self.0.as_deref()
    }

    /// A scope that names TURN but not MESSAGE still finds a turn by its
    /// messages' words: each message comes back as its turn or not at all.
    fn messages_only_as_turns(&self) -> bool {
        self.0.as_ref().is_some_and(|kinds| {
            kinds.contains(&ENTITY_TYPE_TURN) && !kinds.contains(&ENTITY_TYPE_MESSAGE)
        })
    }

    /// How the run treats a MESSAGE hit: as its turn, and only as its turn
    /// when the scope names TURN but not MESSAGE.
    pub(crate) fn turn_fold(&self) -> TurnFold {
        if self.messages_only_as_turns() {
            TurnFold::TurnsOnly
        } else {
            TurnFold::Fold
        }
    }

    /// Whether a candidate of `kind` enters the run.
    pub(crate) fn admits(&self, kind: u8) -> bool {
        match &self.0 {
            Some(kinds) => {
                kinds.contains(&kind)
                    || (self.messages_only_as_turns() && kind == ENTITY_TYPE_MESSAGE)
            }
            None => !CONTAINER_KINDS.contains(&kind),
        }
    }
}

/// Everything one recall narrows by, resolved once.
#[derive(Debug, Clone)]
pub(crate) struct RecallSelection {
    /// The worlds read (a bound room turn's met in); `None` reads every
    /// world, and an empty set reads none.
    pub(crate) worlds: Option<WorldAuthoritySet>,
    /// The project audiences read.
    pub(crate) projects: CorpusScope,
    /// The facet a strict facet narrowing keeps.
    pub(crate) facet: Option<EntityId>,
    /// The kinds returned.
    pub(crate) kinds: RecallKinds,
}

impl RecallSelection {
    /// The worlds as the retrieval pipeline narrows by them.
    pub(crate) fn world_scope(&self) -> WorldScope {
        match &self.worlds {
            None => WorldScope::All,
            Some(worlds) if worlds.include_base() && worlds.worlds().is_empty() => WorldScope::Base,
            Some(worlds) => WorldScope::WorldSet(worlds.clone()),
        }
    }

    /// This selection as the device sends it to its home (FIX 2905).
    #[cfg(feature = "sync")]
    pub(crate) fn resolved(&self) -> crate::sync::residence::ResolvedRecallSelection {
        let mut project_ids = match &self.projects {
            CorpusScope::All => Vec::new(),
            CorpusScope::Unscoped => vec![crate::claim::default_project_id()],
            CorpusScope::Corpus(id) => vec![*id],
            CorpusScope::AnyOf(ids) => ids.clone(),
        };
        project_ids.sort_unstable();
        project_ids.dedup();
        crate::sync::residence::ResolvedRecallSelection {
            worlds: self.worlds.as_ref().map(|worlds| {
                crate::sync::residence::ResolvedRecallWorlds {
                    include_base: worlds.include_base(),
                    world_ids: worlds.worlds().iter().copied().collect(),
                }
            }),
            project_ids,
            facet: self.facet,
            kinds: self.kinds.listed().map(<[u8]>::to_vec),
        }
    }
}

impl Memory<'_> {
    /// The one resolution of what `scope` narrows by: worlds (the actor's
    /// default when unset, met with a bound room turn's), projects, facet
    /// and kinds. Recall reads these values, and only these.
    pub(super) fn recall_selection(&self, scope: &RecallScope) -> MemoryResult<RecallSelection> {
        Ok(RecallSelection {
            worlds: self.recall_worlds(scope)?,
            projects: self.selected_projects(scope)?,
            facet: scope
                .facet
                .as_deref()
                .map(|facet| self.resolve_ref(facet))
                .transpose()?,
            kinds: RecallKinds::new(recall_kinds(scope)?),
        })
    }
}
