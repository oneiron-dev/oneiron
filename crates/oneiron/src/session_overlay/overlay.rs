use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use arc_swap::ArcSwap;

use crate::batch::{BatchOp, LONG_INTERVAL_THRESHOLD_SECS};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;

use super::journal::{JournalEntry, PromotePlan, journal_entry_in_closure};
use super::keyspace::{
    KeyspaceState, OverlayKeyspace, OverlayMutation, OverlayState, OverlayValue, drop_overlay_row,
    project_mutation,
};
use super::snapshot::OverlaySnapshot;

/// Write-transaction entry points that a session write path must wrap.
///
/// ONE-1726 supplies the segment mechanism only. Future session paths must
/// install it around `Vault::try_with_write_txn`/`with_write_txn`,
/// `BatchBuilder::commit`, facade `with_verified_actor_write_txn`/`witness`,
/// and the direct `env.write_txn()` clusters in `dreamer_runner`,
/// `attempt_queue`, `claim`, `deletion`, `connector_key`, `companion`,
/// `code_run`, and the remaining store/vault feature modules.
pub(crate) const SESSION_WRITE_TXN_ENTRY_POINTS: &[&str] = &[
    "Vault::try_with_write_txn / Vault::with_write_txn",
    "BatchBuilder::commit",
    "Memory::with_verified_actor_write_txn / Memory::witness",
    "direct env.write_txn(): dreamer_runner, attempt_queue, claim, deletion, connector_key, companion, code_run, and remaining feature modules",
];

const _: () = assert!(!SESSION_WRITE_TXN_ENTRY_POINTS.is_empty());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OverlayLifecycleState {
    Live,
    Sealing,
    Sealed,
    Closing,
    Gone,
}

pub(super) struct Lifecycle {
    pub(super) state: OverlayLifecycleState,
    generation: u64,
    /// Monotonic counter bumped by every MODE publication — `seal_writes`
    /// (Live -> Sealed, the flip on-record) and `rearm` (Sealed -> Live, the
    /// K10 flip-back). A [`SessionWriteRoute`] records the value it was minted
    /// under and [`SessionWriteRoute::revalidate`] refuses a mismatch, so a
    /// route minted before the most recent flip can never stage or commit.
    /// Distinct from `generation`, which stamps LEASES and bumps at close.
    mode_generation: u64,
    leases: usize,
    segment_active: bool,
}

pub(super) struct Lease {
    overlay: Arc<SessionOverlay>,
    #[allow(
        dead_code,
        reason = "segment generation is consumed once ONE-1728 installs production session writes"
    )]
    generation: u64,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut lifecycle) = self.overlay.lifecycle.lock() {
            lifecycle.leases = lifecycle.leases.saturating_sub(1);
            if lifecycle.leases == 0 {
                self.overlay.lease_drained.notify_all();
            }
        }
    }
}

pub(super) struct TxnSegment {
    overlay: Arc<SessionOverlay>,
    generation: u64,
    preview: Arc<OverlayState>,
    pub(super) mutations: Vec<OverlayMutation>,
    #[allow(
        dead_code,
        reason = "typed journal staging is consumed by ONE-1730 promotion"
    )]
    journal: Vec<JournalEntry>,
    journal_bytes: usize,
    _lease: Lease,
}

thread_local! {
    pub(super) static ACTIVE_SEGMENT: RefCell<Option<TxnSegment>> = const { RefCell::new(None) };
}

static NEXT_OVERLAY_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Persistent-COW in-memory overlay shared by one live session.
pub(crate) struct SessionOverlay {
    state: ArcSwap<OverlayState>,
    pub(super) lifecycle: Mutex<Lifecycle>,
    lease_drained: Condvar,
    segment_available: Condvar,
    budget_bytes: usize,
}

impl SessionOverlay {
    pub(crate) fn new(budget_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            state: ArcSwap::from_pointee(OverlayState::empty()),
            lifecycle: Mutex::new(Lifecycle {
                state: OverlayLifecycleState::Live,
                generation: NEXT_OVERLAY_GENERATION.fetch_add(1, Ordering::Relaxed),
                mode_generation: 0,
                leases: 0,
                segment_active: false,
            }),
            lease_drained: Condvar::new(),
            segment_available: Condvar::new(),
            budget_bytes,
        })
    }

    #[allow(
        dead_code,
        reason = "ONE-1726 budget oracle introspection; production admission uses the private field"
    )]
    pub(crate) const fn budget_bytes(&self) -> usize {
        self.budget_bytes
    }

    /// Lock-free taint-set membership exported through the registry's
    /// immutable session snapshot. Closed overlays retain this immutable
    /// state until the registry drops them, so close cannot create a false
    /// negative between classification and the write-door decision.
    pub(crate) fn contains_entity(&self, id: &EntityId) -> Result<bool> {
        let state = self.state.load();
        let KeyspaceState::Single { rows, .. } =
            state.keyspaces[OverlayKeyspace::Entities.slot()].as_ref()
        else {
            return Err(Error::InvariantViolation(
                "entities overlay keyspace unexpectedly uses DUP_SORT",
            ));
        };
        Ok(matches!(
            rows.get(id.as_bytes().as_slice()),
            Some(OverlayValue::Present(_))
        ))
    }

    pub(crate) fn has_entities(&self) -> Result<bool> {
        let state = self.state.load();
        let KeyspaceState::Single { rows, .. } =
            state.keyspaces[OverlayKeyspace::Entities.slot()].as_ref()
        else {
            return Err(Error::InvariantViolation(
                "entities overlay keyspace unexpectedly uses DUP_SORT",
            ));
        };
        Ok(rows
            .values()
            .any(|value| matches!(value, OverlayValue::Present(_))))
    }

    /// The currently published mode generation, read under the state lock.
    /// [`SessionWriteRoute`] is the only consumer.
    pub(super) fn mode_generation(&self) -> Result<u64> {
        Ok(self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?
            .mode_generation)
    }

    /// Seals the overlay write path while leaving composed reads available.
    /// The transition first blocks new segment installers, then drains the one
    /// permitted active writer before publishing `Sealed`.
    ///
    /// The seal is permanent EXCEPT for the K10 flip-back: [`Self::rearm`]
    /// transitions `Sealed` -> `Live` when a session flips back to
    /// `OffRecord`. Every other state stays terminal.
    pub(crate) fn seal_writes(self: &Arc<Self>) -> Result<()> {
        let holds_active_segment = ACTIVE_SEGMENT.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|segment| Arc::ptr_eq(&segment.overlay, self))
        });
        if holds_active_segment {
            return Err(Error::InvariantViolation(
                "session overlay seal called while this thread holds an active txn segment",
            ));
        }

        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        match lifecycle.state {
            OverlayLifecycleState::Live => {
                lifecycle.state = OverlayLifecycleState::Sealing;
                self.segment_available.notify_all();
            }
            OverlayLifecycleState::Sealed => return Ok(()),
            OverlayLifecycleState::Sealing
            | OverlayLifecycleState::Closing
            | OverlayLifecycleState::Gone => {
                return Err(Error::OffRecordOverlayLeaseClosed {
                    generation: lifecycle.generation,
                });
            }
        }
        while lifecycle.segment_active {
            lifecycle = self.segment_available.wait(lifecycle).map_err(|_| {
                Error::InvariantViolation("session overlay lifecycle mutex poisoned")
            })?;
        }
        lifecycle.state = OverlayLifecycleState::Sealed;
        lifecycle.mode_generation = next_mode_generation(lifecycle.mode_generation)?;
        Ok(())
    }

    /// K10 flip-back: re-enables overlay writes when a session returns to
    /// `OffRecord` mode. The ONLY legal transition is `Sealed` -> `Live`
    /// (`Live` IS the landed write-enabled state — no `Armed` variant exists;
    /// K10's "armed" prose names `Live`). Every other state — including a
    /// `Live` overlay that was never sealed — is refused, so rearm can never
    /// resurrect a closing or closed overlay.
    ///
    /// Publishing bumps the mode generation, so any [`SessionWriteRoute`]
    /// minted before the flip-back is refused by [`SessionWriteRoute::revalidate`]
    /// before it can stage. The room's earlier turns stay visible in-session
    /// and unextractable through base: rearm reopens the write door only, and
    /// touches no row.
    pub(crate) fn rearm(self: &Arc<Self>) -> Result<()> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if lifecycle.state != OverlayLifecycleState::Sealed {
            return Err(Error::OffRecordOverlayLeaseClosed {
                generation: lifecycle.generation,
            });
        }
        lifecycle.state = OverlayLifecycleState::Live;
        lifecycle.mode_generation = next_mode_generation(lifecycle.mode_generation)?;
        Ok(())
    }

    pub(crate) fn snapshot(self: &Arc<Self>) -> Result<OverlaySnapshot> {
        let active = ACTIVE_SEGMENT.with(|slot| {
            let slot = slot.borrow();
            slot.as_ref().and_then(|segment| {
                Arc::ptr_eq(&segment.overlay, self)
                    .then(|| (segment.generation, segment.preview.clone()))
            })
        });

        if let Some((generation, state)) = active {
            let lease = self.acquire_existing_lease(generation)?;
            return Ok(OverlaySnapshot {
                state,
                _lease: lease,
            });
        }

        let lease = self.acquire_read_lease()?;
        let state = self.state.load_full();
        Ok(OverlaySnapshot {
            state,
            _lease: lease,
        })
    }

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

    pub(crate) fn put(
        self: &Arc<Self>,
        keyspace: OverlayKeyspace,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        self.reject_unbudgetable_payload(key, value)?;
        let mutation = OverlayMutation::Put {
            keyspace,
            key: key.to_vec(),
            value: value.to_vec(),
        };
        self.preflight_segment_mutation(&mutation)?;
        self.stage_mutation(mutation)
    }

    #[allow(
        dead_code,
        reason = "ONE-1728 witness/retrieval supplies the first lib-target overlay delete"
    )]
    pub(crate) fn delete(self: &Arc<Self>, keyspace: OverlayKeyspace, key: &[u8]) -> Result<()> {
        self.delete_with_base_backing(keyspace, key, true)
    }

    pub(crate) fn delete_with_base_backing(
        self: &Arc<Self>,
        keyspace: OverlayKeyspace,
        key: &[u8],
        base_backed: bool,
    ) -> Result<()> {
        let mutation = OverlayMutation::Delete {
            keyspace,
            key: key.to_vec(),
            base_backed,
        };
        self.preflight_segment_mutation(&mutation)?;
        self.stage_mutation(mutation)
    }

    pub(crate) fn delete_duplicate(
        self: &Arc<Self>,
        keyspace: OverlayKeyspace,
        key: &[u8],
        value: &[u8],
        base_backed: bool,
    ) -> Result<()> {
        self.reject_unbudgetable_payload(key, value)?;
        let mutation = OverlayMutation::DeleteDuplicate {
            keyspace,
            key: key.to_vec(),
            value: value.to_vec(),
            base_backed,
        };
        self.preflight_segment_mutation(&mutation)?;
        self.stage_mutation(mutation)
    }

    pub(crate) fn clear(self: &Arc<Self>, keyspace: OverlayKeyspace) -> Result<()> {
        let mutation = OverlayMutation::Clear { keyspace };
        self.preflight_segment_mutation(&mutation)?;
        self.stage_mutation(mutation)
    }

    /// Stages one typed, role-tagged journal op into the active txn segment.
    ///
    /// The ONLY journal staging surface: every staged op carries its
    /// [`JournalRole`] and the witnessing write's own `learned_at`/`occurred`,
    /// so promote can never fall back on inferring ownership from index keys
    /// or on restamping the room clock.
    pub(crate) fn stage_journal_entry(self: &Arc<Self>, entry: JournalEntry) -> Result<()> {
        let incoming_bytes = entry.byte_size();
        ACTIVE_SEGMENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(segment) = slot.as_mut() else {
                return Err(Error::InvariantViolation(
                    "session overlay write requires an active txn segment",
                ));
            };
            if !Arc::ptr_eq(&segment.overlay, self) {
                return Err(Error::InvariantViolation(
                    "the active txn segment belongs to another session overlay",
                ));
            }
            let current_bytes = segment
                .preview
                .bytes_used
                .checked_add(segment.journal_bytes)
                .ok_or(Error::ArithmeticOverflow("overlay staged byte count"))?;
            self.ensure_budget(current_bytes, incoming_bytes)?;
            segment.journal.push(entry);
            segment.journal_bytes = segment.journal_bytes.checked_add(incoming_bytes).ok_or(
                Error::ArithmeticOverflow("overlay staged journal byte count"),
            )?;
            Ok(())
        })
    }

    /// Retires a promoted closure from the live overlay (ARCH-0052 D4,
    /// ONE-1730). Called ONLY after the promote transaction commits.
    ///
    /// Every retired row is removed OUTRIGHT, never tombstoned. A tombstone
    /// masks the base row underneath, and the row underneath is now the
    /// promoted one — masking it would make the room lose sight of the turn it
    /// just published. Removal is therefore conditional on the key being
    /// PRESENT in the overlay: a delete of an absent key is exactly what the
    /// mutation path turns into a mask.
    ///
    /// Rows whose overlay copy is byte-identical to the base copy the replay
    /// just wrote — BM25 postings/stats, vector and HNSW rows — are left in
    /// place deliberately. Their keys and duplicate identities are the same on
    /// both sides, so the composed read returns one row either way, and the
    /// accumulator halves (`total_docs`, per-field lengths) are room-scoped
    /// counts that must keep answering for the room until it evaporates.
    ///
    /// The journal entries go with them, so a later close counts the promoted
    /// turn as published rather than as transcript that stopped existing.
    pub(crate) fn retire_promoted_closure(self: &Arc<Self>, plan: &PromotePlan) -> Result<()> {
        let lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if lifecycle.state == OverlayLifecycleState::Gone {
            return Err(Error::OffRecordOverlayLeaseClosed {
                generation: lifecycle.generation,
            });
        }
        let mut next = self.state.load_full().as_ref().clone();

        for op in &plan.ops {
            match op {
                BatchOp::Put {
                    id,
                    entity_type,
                    occurred,
                    learned_at,
                    ..
                } => {
                    drop_overlay_row(&mut next, OverlayKeyspace::Entities, id.as_bytes());
                    drop_overlay_row(
                        &mut next,
                        OverlayKeyspace::TypeIndex,
                        &Store::encode_type_key(*entity_type, id),
                    );
                    drop_overlay_row(
                        &mut next,
                        OverlayKeyspace::TemporalOccurredStart,
                        &Store::encode_temporal_key(occurred.start, id),
                    );
                    if occurred.start != occurred.end {
                        drop_overlay_row(
                            &mut next,
                            OverlayKeyspace::TemporalOccurredEnd,
                            &Store::encode_temporal_key(occurred.end, id),
                        );
                    }
                    drop_overlay_row(
                        &mut next,
                        OverlayKeyspace::TemporalLearned,
                        &Store::encode_temporal_key(*learned_at, id),
                    );
                    if occurred.end.saturating_sub(occurred.start) > LONG_INTERVAL_THRESHOLD_SECS {
                        drop_overlay_row(
                            &mut next,
                            OverlayKeyspace::TemporalLongIntervals,
                            &Store::encode_temporal_key(occurred.end, id),
                        );
                    }
                }
                BatchOp::PublicEdgeWithCreatedAt { src, kind, tgt, .. } => {
                    drop_overlay_row(
                        &mut next,
                        OverlayKeyspace::EdgesOut,
                        &Store::encode_edge_key(src, *kind, tgt),
                    );
                    drop_overlay_row(
                        &mut next,
                        OverlayKeyspace::EdgesIn,
                        &Store::encode_edge_key(tgt, *kind, src),
                    );
                }
                _ => {}
            }
        }

        // The in-room alias pair. The forward key is stored verbatim as the
        // reverse row's VALUE, so the pair retires without re-deriving a
        // content hash that the body may have moved past.
        for id in &plan.replayed {
            let forward_key = match next.keyspaces[OverlayKeyspace::ShortIdsReverse.slot()].as_ref()
            {
                KeyspaceState::Single { rows, .. } => match rows.get(id.as_bytes().as_slice()) {
                    Some(OverlayValue::Present(value)) => Some(value.clone()),
                    Some(OverlayValue::Tombstone) | None => None,
                },
                KeyspaceState::DupSort { .. } => None,
            };
            if let Some(forward_key) = forward_key {
                drop_overlay_row(&mut next, OverlayKeyspace::ShortIds, &forward_key);
                drop_overlay_row(&mut next, OverlayKeyspace::ShortIdsReverse, id.as_bytes());
            }
        }

        let turn = plan.turn;
        let conversation = plan.conversation;
        Arc::make_mut(&mut next.journal)
            .retain(|entry| !journal_entry_in_closure(entry, turn, conversation));
        next.recalculate_bytes();
        self.state.store(Arc::new(next));
        drop(lifecycle);
        Ok(())
    }

    pub(crate) fn close(self: &Arc<Self>) -> Result<()> {
        // A close nested inside this thread's own active segment would wait on a lease
        // that only this stack can release (the guard drops when it unwinds past here).
        // Fail fast — in the single-writer model close is a session-lifecycle op, never
        // nested inside an active write segment — leaving the overlay Live and usable.
        let holds_active_segment = ACTIVE_SEGMENT.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|segment| Arc::ptr_eq(&segment.overlay, self))
        });
        if holds_active_segment {
            return Err(Error::InvariantViolation(
                "session overlay close called while this thread holds an active txn segment",
            ));
        }

        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        match lifecycle.state {
            OverlayLifecycleState::Live | OverlayLifecycleState::Sealed => {
                lifecycle.state = OverlayLifecycleState::Closing;
                // Wake every installer parked on the segment permit so each re-checks the
                // terminal lifecycle state and returns the closed error instead of sleeping;
                // release_segment_writer's notify_one only ever wakes a single waiter.
                self.segment_available.notify_all();
            }
            OverlayLifecycleState::Sealing
            | OverlayLifecycleState::Closing
            | OverlayLifecycleState::Gone => {
                return Err(Error::OffRecordOverlayLeaseClosed {
                    generation: lifecycle.generation,
                });
            }
        }
        while lifecycle.leases != 0 {
            lifecycle = self.lease_drained.wait(lifecycle).map_err(|_| {
                Error::InvariantViolation("session overlay lifecycle mutex poisoned")
            })?;
        }
        // Retain the immutable state as the registry's fail-closed membership
        // snapshot until the entry itself is unpublished. No read lease can
        // observe it after the lifecycle reaches Gone.
        lifecycle.generation = lifecycle
            .generation
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("session overlay generation"))?;
        lifecycle.state = OverlayLifecycleState::Gone;
        Ok(())
    }

    fn preflight_segment_mutation(self: &Arc<Self>, mutation: &OverlayMutation) -> Result<()> {
        ACTIVE_SEGMENT.with(|slot| {
            let slot = slot.borrow();
            let Some(segment) = slot.as_ref() else {
                return Err(Error::InvariantViolation(
                    "session overlay write requires an active txn segment",
                ));
            };
            if !Arc::ptr_eq(&segment.overlay, self) {
                return Err(Error::InvariantViolation(
                    "the active txn segment belongs to another session overlay",
                ));
            }
            let current_bytes = segment
                .preview
                .bytes_used
                .checked_add(segment.journal_bytes)
                .ok_or(Error::ArithmeticOverflow("overlay staged byte count"))?;
            let projected = project_mutation(&segment.preview, mutation)?;
            self.ensure_mutation_budget(
                current_bytes,
                segment.preview.bytes_used,
                projected.bytes_used,
            )
        })
    }

    fn stage_mutation(self: &Arc<Self>, mutation: OverlayMutation) -> Result<()> {
        ACTIVE_SEGMENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(segment) = slot.as_mut() else {
                return Err(Error::InvariantViolation(
                    "session overlay write requires an active txn segment",
                ));
            };
            if !Arc::ptr_eq(&segment.overlay, self) {
                return Err(Error::InvariantViolation(
                    "the active txn segment belongs to another session overlay",
                ));
            }
            segment.preview = Self::apply_preflighted_to_state(
                segment.preview.clone(),
                std::slice::from_ref(&mutation),
                &[],
            )?;
            segment.mutations.push(mutation);
            Ok(())
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
                return Err(Error::OffRecordOverlayLeaseClosed {
                    generation: lifecycle.generation,
                });
            }
            // Base writers are acquired before this permit (base -> segment). Commit
            // releases the base writer before applying/releasing this permit and never
            // reacquires it, so there is no reverse-order path and waiters make progress.
            lifecycle = self.segment_available.wait(lifecycle).map_err(|_| {
                Error::InvariantViolation("session overlay lifecycle mutex poisoned")
            })?;
        }
        if lifecycle.state != OverlayLifecycleState::Live {
            return Err(Error::OffRecordOverlayLeaseClosed {
                generation: lifecycle.generation,
            });
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

    fn acquire_read_lease(self: &Arc<Self>) -> Result<Lease> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if !matches!(
            lifecycle.state,
            OverlayLifecycleState::Live | OverlayLifecycleState::Sealed
        ) {
            return Err(Error::OffRecordOverlayLeaseClosed {
                generation: lifecycle.generation,
            });
        }
        lifecycle.leases = lifecycle
            .leases
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("session overlay lease count"))?;
        Ok(Lease {
            overlay: self.clone(),
            generation: lifecycle.generation,
        })
    }

    fn acquire_existing_lease(self: &Arc<Self>, generation: u64) -> Result<Lease> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if lifecycle.state == OverlayLifecycleState::Gone || lifecycle.generation != generation {
            return Err(Error::OffRecordOverlayLeaseClosed { generation });
        }
        lifecycle.leases = lifecycle
            .leases
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("session overlay lease count"))?;
        Ok(Lease {
            overlay: self.clone(),
            generation,
        })
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
            return Err(Error::OffRecordOverlayLeaseClosed {
                generation: segment.generation,
            });
        }
        let state = self.state.load_full();
        let next = Self::apply_preflighted_to_state(state, &segment.mutations, &segment.journal)?;
        self.state.store(next);
        Ok(())
    }

    // Budget failures belong exclusively to preflight, before the base commit.
    // This apply helper deliberately has no budget input or budget-error branch.
    fn apply_preflighted_to_state(
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

    fn ensure_mutation_budget(
        &self,
        current_bytes: usize,
        old_mutation_bytes: usize,
        new_mutation_bytes: usize,
    ) -> Result<()> {
        let Some(net_increase) = new_mutation_bytes.checked_sub(old_mutation_bytes) else {
            return Ok(());
        };
        if net_increase == 0 {
            return Ok(());
        }
        self.ensure_budget(current_bytes, net_increase)
    }

    /// Reject a payload whose own bytes exceed the entire budget before it is cloned
    /// into an owned mutation. Any such mutation is unconditionally rejected by the
    /// net-delta preflight anyway (a single key of that size alone exceeds the budget),
    /// so this only fast-paths the guaranteed rejection while capping transient
    /// allocation at the budget. Admittable mutations have payload <= budget and are
    /// unaffected, so shrink/overwrite-at-cap admission is preserved.
    fn reject_unbudgetable_payload(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let payload_bytes = key
            .len()
            .checked_add(value.len())
            .ok_or(Error::ArithmeticOverflow("overlay payload byte count"))?;
        if payload_bytes > self.budget_bytes {
            return Err(Error::OffRecordOverlayFull {
                budget_bytes: self.budget_bytes,
                attempted_bytes: payload_bytes,
            });
        }
        Ok(())
    }

    fn ensure_budget(&self, current_bytes: usize, incoming_bytes: usize) -> Result<()> {
        let attempted_bytes = current_bytes
            .checked_add(incoming_bytes)
            .ok_or(Error::ArithmeticOverflow("overlay attempted byte count"))?;
        if attempted_bytes > self.budget_bytes {
            return Err(Error::OffRecordOverlayFull {
                budget_bytes: self.budget_bytes,
                attempted_bytes,
            });
        }
        Ok(())
    }
}

/// Advances the mode-publication counter. Overflow is a hard error rather than
/// a wrap: a wrapped counter could make a stale route revalidate.
fn next_mode_generation(current: u64) -> Result<u64> {
    current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("session overlay mode generation"))
}

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
