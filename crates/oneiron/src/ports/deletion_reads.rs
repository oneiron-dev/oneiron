//! Provenance of the original deletion-state computation, not its physical read set.
use super::DeletionState;
use crate::EntityId;

/// How this call obtained its state. A memo hit performs no fresh physical reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeletionStateOrigin {
    Computed,
    Memo,
}

/// A successful original state and its provenance. Neither variant certifies
/// the canonical bodies, permission or custody of the reads behind the state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DeletionStateRead {
    pub id: EntityId,
    pub state: DeletionState,
    pub origin: DeletionStateOrigin,
}

pub(crate) type DeletionStateObserver<'observer> = dyn FnMut(DeletionStateRead) + 'observer;
