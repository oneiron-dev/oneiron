//! WORKING SET (Engine ruling 21:47): this run's admitted board selection as
//! typed handles. Each family is resolved on its own, so a known scratchpad
//! says nothing of the pins or the replay bindings. A handle grants nothing
//! by itself.

use crate::entity_id::EntityId;
use crate::vault::RevisionRef;

/// One handle of the working set.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BriefWorkingHandle {
    /// The run's live scratchpad NOTE.
    ScratchpadNote { note: EntityId },
    /// A pin the board admitted, with the revision it served; `null` when
    /// the board served the row without one.
    BoardPin {
        entity: EntityId,
        served_revision: Option<RevisionRef>,
    },
    /// A name the run's program bound to one of its results: the name, the
    /// result's content handle and the occurrence path it was bound to. The
    /// handle and the path are no entity ids.
    ReplayResult {
        run_id: EntityId,
        name: String,
        handle: String,
        path: String,
    },
}

/// The working set by family. A family that is `None` is one no host
/// resolved, named unavailable; `Some` of an empty list is a family the host
/// resolved and found empty.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefWorkingSet {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scratchpad: Option<Vec<BriefWorkingHandle>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pins: Option<Vec<BriefWorkingHandle>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay: Option<Vec<BriefWorkingHandle>>,
}

impl BriefWorkingSet {
    /// Whether no host resolved any family: identity leaves the working set
    /// out, and the unavailable line names each family.
    pub(super) fn is_unavailable(&self) -> bool {
        self.scratchpad.is_none() && self.pins.is_none() && self.replay.is_none()
    }

    /// The entity rows the set's handles name: each scratchpad NOTE and each
    /// admitted pin. A replay binding names no entity row.
    pub(super) fn entity_rows(&self) -> impl Iterator<Item = EntityId> {
        [&self.scratchpad, &self.pins]
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|handle| match handle {
                BriefWorkingHandle::ScratchpadNote { note } => Some(*note),
                BriefWorkingHandle::BoardPin { entity, .. } => Some(*entity),
                BriefWorkingHandle::ReplayResult { .. } => None,
            })
    }
}
