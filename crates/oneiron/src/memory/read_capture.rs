//! Per-call evidence from the actual admitted read, not a later row lookup.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use crate::EntityId;
use crate::claim::{ReadRow, ScopedRead};
use crate::federation::Scope;

use super::Memory;

#[derive(Debug, Clone, Default)]
pub(crate) struct ReadCapture(Arc<Mutex<CaptureState>>);

impl PartialEq for ReadCapture {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

#[derive(Debug, Default)]
struct CaptureState {
    views: Vec<(EntityId, ServedView)>,
    changed: bool,
    closed: bool,
}

#[derive(Debug)]
pub(crate) struct ServedView {
    pub(crate) worlds: Option<BTreeSet<EntityId>>,
    pub(crate) scope: Option<Scope>,
}

pub(crate) struct CapturedRead {
    pub(crate) views: Vec<(EntityId, ServedView)>,
    pub(crate) changed: bool,
}

/// A candidate becomes evidence only after the original projection succeeds.
pub(crate) struct ReadCandidate {
    capture: ReadCapture,
    id: EntityId,
    view: ServedView,
}

impl ReadCandidate {
    pub(crate) fn served(self) {
        if let Ok(mut state) = self.capture.0.lock()
            && !state.closed
        {
            state.views.push((self.id, self.view));
        }
    }
}

impl ReadCapture {
    pub(crate) fn changed(&self) {
        if let Ok(mut state) = self.0.lock()
            && !state.closed
        {
            state.changed = true;
        }
    }

    pub(crate) fn finish(&self) -> Option<CapturedRead> {
        let mut state = self.0.lock().ok()?;
        if state.closed {
            return None;
        }
        state.closed = true;
        Some(CapturedRead {
            views: std::mem::take(&mut state.views),
            changed: state.changed,
        })
    }
}

impl Memory<'_> {
    pub(crate) fn read_capture(&self) -> Option<ReadCapture> {
        self.host_origin.as_ref()?.read_capture()
    }

    pub(super) fn read_world_candidate(
        &self,
        lane: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        row: &ReadRow,
    ) -> Option<ReadCandidate> {
        let capture = self.read_capture()?;
        let body = row.body.as_deref()?;
        let store = lane.store_read();
        let worlds = crate::federation::record_scope::note_world::served_worlds_in(
            &store,
            txn,
            row.id,
            row.entity_type,
            body,
        )
        .ok()
        .flatten();
        let scope = crate::federation::record_scope::scope_for_parts(
            &store,
            txn,
            row.id,
            row.entity_type,
            body,
        )
        .ok()
        .flatten();
        Some(ReadCandidate {
            capture,
            id: row.id,
            view: ServedView { worlds, scope },
        })
    }
}
