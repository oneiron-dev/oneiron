//! The targets one spawn call resolved, as its host saw them (FIX 9180,
//! Engine C1). Each dispatch opens its own frame and closes it on every
//! exit; a call nested inside another opens a frame of its own and leaves
//! the outer one as it was. The dispatch observes each seat it resolves into
//! its innermost frame, before the next step that can fail, and the closed
//! frame waits for the recorder of that call's row, which takes it at once.
//! Host-only: no guest call, outcome or other call reaches a frame.

use std::sync::{Mutex, MutexGuard, PoisonError};

use super::HostSelfDispatcher;
use crate::EntityId;
use crate::agent_dispatch::AgentDispatchTarget;

/// The open calls' frames, innermost last, and the frame of the call that
/// closed last, until its recorder takes it.
#[derive(Default)]
pub(super) struct SpawnCapture {
    frames: Mutex<Frames>,
}

#[derive(Default)]
struct Frames {
    open: Vec<Vec<EntityId>>,
    closed: Option<Vec<EntityId>>,
}

impl SpawnCapture {
    fn frames(&self) -> MutexGuard<'_, Frames> {
        self.frames.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens this call's frame; it closes when the scope drops.
    pub(super) fn open(&self) -> CaptureScope<'_> {
        self.frames().open.push(Vec::new());
        CaptureScope { capture: self }
    }

    /// Notes a seat the open call resolved. Observation only: it answers
    /// nothing and refuses nothing.
    pub(super) fn observe(&self, seat: EntityId) {
        if let Some(frame) = self.frames().open.last_mut() {
            frame.push(seat);
        }
    }

    /// Notes the AGENT_DEF `target` names; a workflow's own id seats no
    /// one (its leaves are observed as they resolve).
    pub(super) fn observe_target(&self, target: &AgentDispatchTarget) {
        if let AgentDispatchTarget::Custom(seat) = target {
            self.observe(*seat);
        }
    }
}

/// One call's open frame.
pub(super) struct CaptureScope<'c> {
    capture: &'c SpawnCapture,
}

impl Drop for CaptureScope<'_> {
    fn drop(&mut self) {
        let mut frames = self.capture.frames();
        let closed = frames.open.pop();
        frames.closed = closed;
    }
}

impl HostSelfDispatcher<'_> {
    /// The seats the call this dispatcher answered last resolved, for that
    /// call's row (FIX 9180); empty once taken, and for a call that resolved
    /// none.
    pub(crate) fn take_spawn_seats(&self) -> Vec<EntityId> {
        self.spawn_capture
            .frames()
            .closed
            .take()
            .unwrap_or_default()
    }
}
