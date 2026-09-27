//! Txn segment install, leases, commit/apply guards.
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use crate::error::{Error, Result};

use super::super::journal::JournalEntry;
use super::super::keyspace::{OverlayMutation, OverlayState, project_mutation};
use super::ACTIVE_SEGMENT;
use super::lifecycle::{Lease, OverlayLifecycleState, SessionOverlay};
use crate::error::OffRecordError;

pub(in crate::session_overlay) struct TxnSegment {
    pub(super) overlay: Arc<SessionOverlay>,
    pub(super) generation: u64,
    pub(super) preview: Arc<OverlayState>,
    pub(in crate::session_overlay) mutations: Vec<OverlayMutation>,
    #[allow(
        dead_code,
        reason = "typed journal staging is consumed by ONE-1730 promotion"
    )]
    pub(super) journal: Vec<JournalEntry>,
    pub(super) journal_bytes: usize,
    _lease: Lease,
}

pub(super) static NEXT_OVERLAY_GENERATION: AtomicU64 = AtomicU64::new(1);

/// RAII owner of the thread-local segment installed for one base write txn.
#[allow(
    dead_code,
    reason = "ONE-1728 witness is the first lib-target owner of a session write segment"
)]
pub(crate) struct TxnSegmentGuard {
    overlay: Arc<SessionOverlay>,
    finished: bool,
    _not_send: PhantomData<Rc<()>>,
}

#[allow(
    dead_code,
    reason = "ONE-1728 witness is the first lib-target committer of a session write segment"
)]
impl TxnSegmentGuard {
    /// Applies staged rows and typed journal entries after base commit.
    pub(crate) fn commit(mut self) -> Result<()> {
        let segment = ACTIVE_SEGMENT.with(|slot| slot.borrow_mut().take());
        let Some(segment) = segment else {
            return Err(Error::InvariantViolation(
                "session txn segment disappeared before commit",
            ));
        };
        if !Arc::ptr_eq(&segment.overlay, &self.overlay) {
            return Err(Error::InvariantViolation(
                "another session txn segment replaced the installed segment",
            ));
        }
        let result = self.overlay.apply_segment(&segment);
        self.finished = true;
        result
    }
}

impl Drop for TxnSegmentGuard {
    fn drop(&mut self) {
        if !self.finished {
            ACTIVE_SEGMENT.with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot
                    .as_ref()
                    .is_some_and(|segment| Arc::ptr_eq(&segment.overlay, &self.overlay))
                {
                    slot.take();
                }
            });
        }
        self.overlay.release_segment_writer();
    }
}

impl SessionOverlay {
    #[allow(
        dead_code,
        reason = "ONE-1728 witness is the first lib-target session write transaction"
    )]
    pub(crate) fn install_txn_segment(self: &Arc<Self>) -> Result<TxnSegmentGuard> {
        ACTIVE_SEGMENT.with(|slot| {
            if slot.borrow().is_some() {
                return Err(Error::InvariantViolation(
                    "a session txn segment is already installed on this thread",
                ));
            }
            Ok(())
        })?;

        let lease = self.acquire_segment_lease()?;
        let generation = lease.generation;
        let snapshot = self.state.load_full();
        let segment = TxnSegment {
            overlay: self.clone(),
            generation,
            preview: snapshot,
            mutations: Vec::new(),
            journal: Vec::new(),
            journal_bytes: 0,
            _lease: lease,
        };
        let install_result = ACTIVE_SEGMENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_some() {
                return Err(Error::InvariantViolation(
                    "a session txn segment is already installed on this thread",
                ));
            }
            *slot = Some(segment);
            Ok(())
        });
        if let Err(error) = install_result {
            self.release_segment_writer();
            return Err(error);
        }
        Ok(TxnSegmentGuard {
            overlay: self.clone(),
            finished: false,
            _not_send: PhantomData,
        })
    }

    #[allow(
        dead_code,
        reason = "reachable through the ONE-1728 production session write path"
    )]
    fn acquire_segment_lease(self: &Arc<Self>) -> Result<Lease> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        while lifecycle.segment_active {
            if lifecycle.state != OverlayLifecycleState::Live {
                return Err(Error::OffRecord(
                    OffRecordError::OffRecordOverlayLeaseClosed {
                        generation: lifecycle.generation,
                    },
                ));
            }
            // Base writers are acquired before this permit (base -> segment). Commit
            // releases the base writer before applying/releasing this permit and never
            // reacquires it, so there is no reverse-order path and waiters make progress.
            lifecycle = self.segment_available.wait(lifecycle).map_err(|_| {
                Error::InvariantViolation("session overlay lifecycle mutex poisoned")
            })?;
        }
        if lifecycle.state != OverlayLifecycleState::Live {
            return Err(Error::OffRecord(
                OffRecordError::OffRecordOverlayLeaseClosed {
                    generation: lifecycle.generation,
                },
            ));
        }
        lifecycle.leases = lifecycle
            .leases
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("session overlay lease count"))?;
        lifecycle.segment_active = true;
        Ok(Lease {
            overlay: self.clone(),
            generation: lifecycle.generation,
        })
    }

    #[allow(
        dead_code,
        reason = "reachable through the ONE-1728 production session write path"
    )]
    fn release_segment_writer(&self) {
        if let Ok(mut lifecycle) = self.lifecycle.lock() {
            lifecycle.segment_active = false;
            self.segment_available.notify_all();
        }
    }

    #[allow(
        dead_code,
        reason = "reachable through the ONE-1728 production session write path"
    )]
    fn apply_segment(&self, segment: &TxnSegment) -> Result<()> {
        let lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if lifecycle.state == OverlayLifecycleState::Gone
            || lifecycle.generation != segment.generation
        {
            return Err(Error::OffRecord(
                OffRecordError::OffRecordOverlayLeaseClosed {
                    generation: segment.generation,
                },
            ));
        }
        let state = self.state.load_full();
        let next = Self::apply_preflighted_to_state(state, &segment.mutations, &segment.journal)?;
        self.state.store(next);
        Ok(())
    }

    // Budget failures belong exclusively to preflight, before the base commit.
    // This apply helper deliberately has no budget input or budget-error branch.
    pub(super) fn apply_preflighted_to_state(
        state: Arc<OverlayState>,
        mutations: &[OverlayMutation],
        journal: &[JournalEntry],
    ) -> Result<Arc<OverlayState>> {
        let mut next = state.as_ref().clone();
        for mutation in mutations {
            next = project_mutation(&next, mutation)?;
        }
        for entry in journal {
            Arc::make_mut(&mut next.journal).push(entry.clone());
            next.recalculate_bytes();
        }
        Ok(Arc::new(next))
    }
}

#[cfg(test)]
mod hygiene_tests {
    use super::*;
    use crate::batch::BatchOp;
    use crate::entity_id::EntityId;
    use crate::session_overlay::hygiene_tests::{allocation, observe_drop};
    use crate::session_overlay::{JournalRole, JournalScope, OverlayKeyspace};
    use crate::temporal::TimeRange;

    #[test]
    fn aborted_segment_scrubs_its_owned_mutation_and_journal_buffers() -> Result<()> {
        let overlay = SessionOverlay::new(4096);
        let segment = overlay.install_txn_segment()?;
        overlay.put(OverlayKeyspace::Entities, b"key", b"mutation-private")?;
        let watched = ACTIVE_SEGMENT.with(|slot| {
            let borrow = slot.borrow();
            let OverlayMutation::Put { value, .. } = &borrow.as_ref().unwrap().mutations[0] else {
                panic!("staged put");
            };
            allocation(value)
        });
        observe_drop(watched, true, || drop(segment));

        let segment = overlay.install_txn_segment()?;
        let scope = JournalScope::new(EntityId::now(), EntityId::now());
        overlay.stage_journal_entry(JournalEntry {
            scope,
            role: JournalRole::TurnPut,
            learned_at: 1,
            occurred: TimeRange { start: 1, end: 1 },
            op: BatchOp::Put {
                id: scope.turn(),
                entity_type: 1,
                occurred: TimeRange { start: 1, end: 1 },
                learned_at: 1,
                data: b"journal-private".to_vec(),
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            },
        })?;
        let watched = ACTIVE_SEGMENT.with(|slot| {
            let borrow = slot.borrow();
            let BatchOp::Put { data, .. } = &borrow.as_ref().unwrap().journal[0].op else {
                panic!("staged journal put");
            };
            allocation(data)
        });
        observe_drop(watched, true, || drop(segment));
        Ok(())
    }
}
