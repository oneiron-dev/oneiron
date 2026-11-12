//! `connector.call_source_rows`'s lane read: one held call's source rows the caller's lane admits.

use super::*;
use crate::claim::ClaimReadStatus;
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND, MemoryError};

/// The verb a Grant lists to name a connector source-rows read: the row's own name.
const CONNECTOR_CALL_SOURCE_ROWS_VERB: &str = "connector.call_source_rows";

impl Memory<'_> {
    /// Reads `call_ref`'s source rows the caller's lane admits, in one snapshot under one
    /// receipt that stays inside: what the call's passes picked (FIX 5455), filtered to the
    /// rows the caller's ordinary read lane admits at `Recorded`, ids only. The caller's live
    /// owner Grant naming the verb is checked first in the same snapshot; without one the
    /// read is refused. A ref this vault never held, and a call another actor made that the
    /// caller does not own, read the same not-found as `connector.call_status`, so a ref
    /// discloses nothing. `None` is a call whose rows are unknown, and an acknowledged call
    /// whose rows ride its wait's reply instead; `Some` keeps an empty set distinct from
    /// unknown, and a filtered-empty set distinct too. Every id is judged by the lane in the
    /// same snapshot; a withheld id is dropped silently, never an error, and adds no public
    /// count. Only admitted ids list as producers.
    pub(crate) fn connector_call_source_rows(
        &self,
        call_ref: &EntityId,
    ) -> MemoryResult<Option<Vec<EntityId>>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        Ok(lane
            .read_projected(&[], None, |txn, _rows| {
                self.prove_read_authority_in_txn(txn)?;
                let standing = crate::authority::principal_standing_in_txn(
                    self.vault(),
                    txn,
                    self.actor(),
                    self.actor_class(),
                    CONNECTOR_CALL_SOURCE_ROWS_VERB,
                )?;
                if standing.is_none() {
                    return Err(MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        format!(
                            "{CONNECTOR_CALL_SOURCE_ROWS_VERB} takes a live Grant listing {CONNECTOR_CALL_SOURCE_ROWS_VERB}: no live Grant from a live owner names this caller and lists the verb"
                        ),
                        &["Have the owner grant this caller the verb by name."],
                    ));
                }
                let not_found = || {
                    MemoryError::new(
                        MEMORY_CODE_NOT_FOUND,
                        "no connector call with this ref is yours to read",
                        &[
                            "Pass the call_ref a held or pending_delivery connector.call reply named, as the caller that made the call or as the vault's owner.",
                        ],
                    )
                };
                let state = self
                    .vault()
                    .connector_call_state_in_txn(txn, call_ref)?
                    .ok_or_else(not_found)?;
                if state.principal_ref != self.actor().to_hex()
                    && !self.is_vault_owner_in_txn(txn)?
                {
                    return Err(not_found());
                }
                if state.acknowledged {
                    return Ok(None);
                }
                let Some(ids) = state.source_rows else {
                    return Ok(None);
                };
                if ids.is_empty() {
                    return Ok(Some(Vec::new()));
                }
                let reads: Vec<_> = ids
                    .iter()
                    .map(|id| crate::claim::PointRead::id(*id))
                    .collect();
                let filtered = lane
                    .read_projected_in_txn(txn, &reads, None, |txn, rows| {
                        let mut filtered = Vec::new();
                        for row in rows.into_iter().flatten() {
                            if let Some(candidate) =
                                self.read_world_candidate(&lane, txn, &row)
                            {
                                candidate.served();
                            }
                            filtered.push(row.id);
                        }
                        Ok::<_, MemoryError>(filtered)
                    })?
                    .value;
                self.produced_from(filtered.clone());
                Ok(Some(filtered))
            })?
            .value)
    }
}
