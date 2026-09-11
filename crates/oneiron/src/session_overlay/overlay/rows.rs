//! Row staging, preflight, budget checks, read probes.
use std::sync::Arc;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::super::journal::JournalEntry;
use super::super::keyspace::{
    KeyspaceState, OverlayKeyspace, OverlayMutation, OverlayValue, project_mutation,
};
use super::super::snapshot::OverlaySnapshot;
use super::ACTIVE_SEGMENT;
use super::lifecycle::SessionOverlay;
use crate::error::OffRecordError;

impl SessionOverlay {
    // Budget failures belong exclusively to preflight, before the base commit.
    // This apply helper deliberately has no budget input or budget-error branch.
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
            return Err(Error::OffRecord(OffRecordError::OffRecordOverlayFull {
                budget_bytes: self.budget_bytes,
                attempted_bytes: payload_bytes,
            }));
        }
        Ok(())
    }

    fn ensure_budget(&self, current_bytes: usize, incoming_bytes: usize) -> Result<()> {
        let attempted_bytes = current_bytes
            .checked_add(incoming_bytes)
            .ok_or(Error::ArithmeticOverflow("overlay attempted byte count"))?;
        if attempted_bytes > self.budget_bytes {
            return Err(Error::OffRecord(OffRecordError::OffRecordOverlayFull {
                budget_bytes: self.budget_bytes,
                attempted_bytes,
            }));
        }
        Ok(())
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
        reason = "ONE-1726 budget oracle introspection; production admission uses the private field"
    )]
    pub(crate) const fn budget_bytes(&self) -> usize {
        self.budget_bytes
    }
}
