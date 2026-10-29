//! What reading an extraction candidate needs from its branch: the pinned
//! sources, the prior heads and the listing, borrowed as one view, and an
//! owned copy with each TURN's text as verification reads it, so a checked
//! step's reply check (FIX 7274) reads exactly what the branch reads.
use std::collections::BTreeMap;

use super::{BranchResources, SourcePin};
use crate::dreamer_consolidation::PriorHead;
use crate::dreamer_consolidation::neighbourhood::Neighbourhood;
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::dreamer_consolidation::turn_text::TurnText;
use crate::llm::{Scope, ScopeResource};
use crate::{EntityId, Result};

/// A branch's pinned sources, prior heads and listing, borrowed.
#[derive(Clone, Copy)]
pub(in crate::dreamer_consolidation) struct BranchPins<'r> {
    sources: &'r BTreeMap<EntityId, SourcePin>,
    priors: &'r BTreeMap<EntityId, PriorHead>,
    known: &'r Neighbourhood,
    /// The branch's own PROJECT axis.
    project: Option<EntityId>,
    /// Each TURN's text as the branch's transcript showed it and
    /// verification cites it (FIX 7506: quotes bind against it).
    texts: PinnedTexts<'r>,
}

/// The pinned TURN texts a [`BranchPins`] reads: the branch's frozen texts
/// under its scope, or an owned copy already read so.
#[derive(Clone, Copy)]
enum PinnedTexts<'r> {
    Frozen(&'r BTreeMap<EntityId, TurnText>, &'r Scope),
    Owned(&'r BTreeMap<EntityId, String>),
}

impl<'r> BranchPins<'r> {
    /// The pinned text of TURN `id`, as its transcript line showed it and
    /// verification cites it; `None` where it has none, or the branch may
    /// not read it. Never a live reread.
    pub(in crate::dreamer_consolidation) fn cited_text(self, id: &EntityId) -> Option<&'r str> {
        match self.texts {
            PinnedTexts::Frozen(texts, scope) => texts.get(id)?.readable_text(scope).ok().flatten(),
            PinnedTexts::Owned(texts) => texts.get(id).map(String::as_str),
        }
    }

    /// The exact version the branch pinned for `id`.
    pub(in crate::dreamer_consolidation) fn source_version(
        self,
        id: &EntityId,
    ) -> Result<ScopeResource> {
        self.sources
            .get(id)
            .map(|pin| pin.resource.clone())
            .ok_or_else(|| invalid_consolidation("unadmitted evidence source"))
    }

    /// The one PROJECT a claim drawn from these sources may land in: a
    /// consolidated claim inherits its sources' exposure and never mixes
    /// scopes (ONE-1592 P3). The default project is a project like any other.
    /// A project-bound branch restricts the result to its project; it never
    /// moves a source into it. `None` when the sources span projects, lie
    /// outside the branch's project, or a project stamp does not decode.
    pub(in crate::dreamer_consolidation) fn evidence_project(
        self,
        refs: &[EntityId],
    ) -> Result<Option<EntityId>> {
        let mut project = self.project;
        for id in refs {
            let pin = self
                .sources
                .get(id)
                .ok_or_else(|| invalid_consolidation("unadmitted evidence source"))?;
            match (pin.project, project) {
                (None, _) => return Ok(None),
                (Some(source), Some(project)) if source != project => return Ok(None),
                (source, _) => project = source,
            }
        }
        Ok(Some(
            project.unwrap_or_else(crate::claim::default_project_id),
        ))
    }

    /// The listed claims about `subject` a candidate read under `scope` may
    /// be asked to correct: held as prior heads, and exactly read- and
    /// writable in `scope`.
    pub(in crate::dreamer_consolidation) fn correctable(
        self,
        subject: EntityId,
        scope: &Scope,
    ) -> impl Iterator<Item = (EntityId, &'r str, &'r str)> {
        self.known.shown_about(subject).filter(move |(claim, ..)| {
            self.priors.contains_key(claim)
                && self.source_version(claim).is_ok_and(|version| {
                    scope.allows_read(&version) && scope.allows_write(&version)
                })
        })
    }
}

/// An owned copy of what [`BranchPins`] borrows, with each TURN's text as
/// `verify_evidence_refs` cites it: what a checked step's reply check
/// holds, since that check holds no borrow.
pub(in crate::dreamer_consolidation) struct OwnedPins {
    sources: BTreeMap<EntityId, SourcePin>,
    priors: BTreeMap<EntityId, PriorHead>,
    known: Neighbourhood,
    project: Option<EntityId>,
    texts: BTreeMap<EntityId, String>,
}

impl OwnedPins {
    pub(in crate::dreamer_consolidation) fn pins(&self) -> BranchPins<'_> {
        BranchPins {
            sources: &self.sources,
            priors: &self.priors,
            known: &self.known,
            project: self.project,
            texts: PinnedTexts::Owned(&self.texts),
        }
    }

    /// The text verification cites `id` against; `None` where it has none
    /// to cite, or would refuse to read it.
    pub(in crate::dreamer_consolidation) fn cited_text(&self, id: &EntityId) -> Option<&str> {
        self.texts.get(id).map(String::as_str)
    }
}

impl BranchResources<'_> {
    pub(in crate::dreamer_consolidation) fn pins(&self) -> BranchPins<'_> {
        BranchPins {
            sources: &self.sources,
            priors: &self.priors,
            known: &self.known,
            project: self.scope.project,
            texts: PinnedTexts::Frozen(&self.texts, &self.scope),
        }
    }

    /// Every row id this branch pinned: each part's conversation, even one
    /// whose part is empty, each queued TURN and each admitted prior head,
    /// even one the listing does not show (FIX 7019).
    pub(in crate::dreamer_consolidation) fn pinned_source_ids(&self) -> Vec<EntityId> {
        self.sources.keys().copied().collect()
    }

    /// [`Self::pins`] owned, with every pinned TURN text verification could
    /// cite.
    pub(in crate::dreamer_consolidation) fn owned_pins(&self) -> OwnedPins {
        let texts = self
            .texts
            .keys()
            .filter_map(|id| Some((*id, self.cited_text(id).ok()??.to_owned())))
            .collect();
        OwnedPins {
            sources: self.sources.clone(),
            priors: self.priors.clone(),
            known: self.known.clone(),
            project: self.scope.project,
            texts,
        }
    }

    /// The text a TURN citation of `id` is verified against: its frozen
    /// text, readable under the branch's scope.
    pub(super) fn cited_text(&self, id: &EntityId) -> Result<Option<&str>> {
        Ok(self
            .texts
            .get(id)
            .map(|text| text.readable_text(&self.scope))
            .transpose()?
            .flatten())
    }
}
