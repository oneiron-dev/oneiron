//! Promoted-closure retirement reusing Store key builders.
use std::sync::Arc;

use crate::batch::{BatchOp, LONG_INTERVAL_THRESHOLD_SECS};
use crate::error::{Error, Result};
use crate::store::Store;

use super::super::journal::{PromotePlan, journal_entry_in_closure};
use super::super::keyspace::{KeyspaceState, OverlayKeyspace, OverlayValue, drop_overlay_row};
use super::lifecycle::{OverlayLifecycleState, SessionOverlay};

impl SessionOverlay {
    // Budget failures belong exclusively to preflight, before the base commit.
    // This apply helper deliberately has no budget input or budget-error branch.
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
}
