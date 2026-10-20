//! What one recall narrows by, resolved once from its scope (FIX 2905): the
//! worlds, projects, facet and kinds. Local recall reads these values, and an
//! opened device sends the same values to its home, which admits its
//! candidates by the same kinds rule ([`RecallKinds`]). Nothing here grants:
//! these are relevance filters inside the reader's own authority.

use std::sync::OnceLock;

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
    /// The worlds the scope names, or the actor's default, before a bound
    /// room turn's are met in: what a paid recall's later passes keep
    /// (FIX 5006).
    asked: Option<WorldAuthoritySet>,
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

/// What one recall narrows by but its facet, which is looked up only once
/// the reader is past its deny-all check ([`Memory::recall_faceted`]): a
/// reader its policy denies everything answers empty whatever its facet ref
/// names (FIX 5008).
pub(super) struct UnfacetedSelection(RecallSelection);

impl UnfacetedSelection {
    /// The worlds read; see [`RecallSelection::worlds`].
    pub(super) fn worlds(&self) -> Option<&WorldAuthoritySet> {
        self.0.worlds.as_ref()
    }

    /// The selection with no facet, for a reader its policy denies
    /// everything: it reads nothing, so its facet ref is never looked up
    /// (FIX 5008, 6694).
    pub(super) fn denied(self) -> RecallSelection {
        self.0
    }
}

/// A recall's one selection (FIX 5006, 6693). Its first pass resolves it,
/// and its later passes, its retries and its rerank text read reuse it,
/// never the scope again, so a default that changes mid-recall cannot read
/// differently between them. A recall door's cut pack and hyde ready pack
/// share it with the recall (FIX 6693): the cut pack, which runs before any
/// pass, pins the worlds the scope asks for, and the first pass the rest.
/// Only relevance is pinned: each pass still reads under a fresh read of its
/// credential, and meets the worlds the scope asked for with a bound room
/// turn's as they are then.
#[derive(Default)]
pub(crate) struct RecallPin {
    /// The worlds the scope asks for, before a bound room turn's are met in.
    asked: OnceLock<Option<WorldAuthoritySet>>,
    selection: OnceLock<RecallSelection>,
}

impl RecallPin {
    fn get(&self) -> Option<&RecallSelection> {
        self.selection.get()
    }
}

impl Memory<'_> {
    /// The one resolution of what `scope` narrows by: worlds (the actor's
    /// default when unset, met with a bound room turn's), projects and
    /// kinds, then the facet by [`Self::recall_faceted`]. Recall reads these
    /// values, and only these. A pass of a paid recall whose `pin` holds a
    /// selection reads that one, its asked worlds met with the room turn's
    /// worlds now.
    pub(super) fn recall_selection(
        &self,
        scope: &RecallScope,
        pin: Option<&RecallPin>,
    ) -> MemoryResult<UnfacetedSelection> {
        if let Some(pinned) = pin.and_then(RecallPin::get) {
            return Ok(UnfacetedSelection(RecallSelection {
                worlds: self.room_met(pinned.asked.clone())?,
                ..pinned.clone()
            }));
        }
        let asked = self.asked_worlds(scope, pin)?;
        Ok(UnfacetedSelection(RecallSelection {
            worlds: self.room_met(asked.clone())?,
            asked,
            projects: self.selected_projects(scope)?,
            facet: None,
            kinds: RecallKinds::new(recall_kinds(scope)?),
        }))
    }

    /// `selection` with its facet: `pin`'s when it holds a selection, or
    /// else `scope`'s ref looked up now, the result then pinned for the
    /// recall's later passes.
    pub(super) fn recall_faceted(
        &self,
        selection: UnfacetedSelection,
        scope: &RecallScope,
        pin: Option<&RecallPin>,
    ) -> MemoryResult<RecallSelection> {
        let UnfacetedSelection(mut selection) = selection;
        if pin.and_then(RecallPin::get).is_some() {
            return Ok(selection);
        }
        selection.facet = scope
            .facet
            .as_deref()
            .map(|facet| self.resolve_ref(facet))
            .transpose()?;
        if let Some(pin) = pin {
            let _ = pin.selection.set(selection.clone());
        }
        Ok(selection)
    }

    /// The worlds `scope` asks for, before a bound room turn's are met in:
    /// `pin`'s when it holds them, or else resolved now and pinned there.
    fn asked_worlds(
        &self,
        scope: &RecallScope,
        pin: Option<&RecallPin>,
    ) -> MemoryResult<Option<WorldAuthoritySet>> {
        if let Some(asked) = pin.and_then(|pin| pin.asked.get()) {
            return Ok(asked.clone());
        }
        let asked = self.selected_worlds(scope)?;
        if let Some(pin) = pin {
            let _ = pin.asked.set(asked.clone());
        }
        Ok(asked)
    }

    /// A fresh pin for one recall door's cut pack, hyde ready pack and
    /// recall, which share the one selection the first of them resolves
    /// (FIX 6693).
    pub(crate) fn recall_door_pin(&self) -> RecallPin {
        RecallPin::default()
    }

    /// The worlds a recall door's cut pack reads (FIX 6693): `pin`'s asked
    /// worlds, resolved and pinned now when nothing has, met with a bound
    /// room turn's now.
    pub(super) fn recall_door_worlds(
        &self,
        scope: &RecallScope,
        pin: &RecallPin,
    ) -> MemoryResult<Option<WorldAuthoritySet>> {
        let asked = match pin.get() {
            Some(pinned) => pinned.asked.clone(),
            None => self.asked_worlds(scope, Some(pin))?,
        };
        self.room_met(asked)
    }

    /// [`Self::recall_with_execution`] as one pass of a recall door that
    /// shares `pin` (FIX 6693).
    #[expect(
        clippy::too_many_arguments,
        reason = "recall_with_execution's parameter list and the door's pin"
    )]
    pub(crate) fn recall_with_execution_pinned(
        &self,
        query: &str,
        effort: super::Effort,
        scope: &RecallScope,
        limit: usize,
        format: Option<&str>,
        lease: Option<&crate::llm::BudgetLease>,
        execution: &crate::retrieval_depth::RecallExecution<'_>,
        pin: &RecallPin,
    ) -> MemoryResult<super::MemoryPack> {
        self.recall_routed(
            None,
            query,
            effort,
            scope,
            limit,
            format,
            lease,
            None,
            execution,
            Some(pin),
        )
    }

    /// The worlds a read beside a paid recall's passes reads: its pinned
    /// selection's asked worlds met with a bound room turn's now, or
    /// `scope`'s resolved now when no pass pinned one.
    pub(super) fn pinned_recall_worlds(
        &self,
        scope: &RecallScope,
        pin: &RecallPin,
    ) -> MemoryResult<Option<WorldAuthoritySet>> {
        match (pin.get(), pin.asked.get()) {
            (Some(pinned), _) => self.room_met(pinned.asked.clone()),
            (None, Some(asked)) => self.room_met(asked.clone()),
            (None, None) => self.recall_worlds(scope),
        }
    }
}
