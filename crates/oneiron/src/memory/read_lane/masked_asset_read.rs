//! `vault.assets.masked_read`'s lane read: one admitted ASSET's bytes, always masked.

use super::*;

/// The verb a Grant lists to name a masked asset read: the row's own name. This
/// method exists only for that row, so the check names it directly.
const MASKED_ASSET_READ_VERB: &str = "vault.assets.masked_read";

impl Memory<'_> {
    /// Reads `entity_ref` as its ASSET bytes, always masked, in the lane's
    /// snapshot: the caller's live owner Grant naming the verb is checked in
    /// the same snapshot, and without one the read is refused. Readability is
    /// judged before the type: a ref that resolves to nothing, a row the lane
    /// withholds, a deleted shell, and a row that is no ASSET answer `None`,
    /// exactly like a missing target; the receipt counts only rows the key
    /// could read. An admitted ASSET answers its bytes as a masked reader
    /// reads them in that same snapshot
    /// ([`repo_asset_body_known_in_txn`](crate::memory::repo_secret_reads::repo_asset_body_known_in_txn)):
    /// a repo file a mark covers, or a value custody knows reads in, answers
    /// its projection; every other ASSET answers its stored bytes unchanged.
    /// There is no cap and no pin: the row is read live. Record verbs serve
    /// every claim status, so the lane is `Recorded` as `vault.get` opens it.
    pub(crate) fn masked_asset_read(
        &self,
        entity_ref: &str,
    ) -> MemoryResult<ScopedReadResult<Option<(EntityId, Vec<u8>)>>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let target = self.read_target(entity_ref, ReadMode::Live)?;
        lane.read_projected(&point_reads(&[target]), None, |txn, rows| {
            let standing = crate::authority::principal_standing_in_txn(
                self.vault(),
                txn,
                self.actor(),
                self.actor_class(),
                MASKED_ASSET_READ_VERB,
            )?;
            if standing.is_none() {
                return Err(masked_asset_read_refused());
            }
            let Some(row) = rows.into_iter().next().flatten() else {
                return Ok::<_, MemoryError>(None);
            };
            if row.entity_type != crate::registry::ENTITY_TYPE_ASSET {
                return Ok(None);
            }
            let candidate = self.read_world_candidate(&lane, txn, &row);
            let Some(body) = row.body else {
                return Ok(None);
            };
            let id = row.id;
            let served = crate::memory::repo_secret_reads::repo_asset_body_known_in_txn(
                self.vault(),
                txn,
                &id,
                row.entity_type,
                &body,
            )?
            .unwrap_or(body);
            if let Some(candidate) = candidate {
                candidate.served();
            }
            self.produced_from([id]);
            Ok(Some((id, served)))
        })
    }
}

/// The read's refusal of a caller with no live Grant naming the verb.
fn masked_asset_read_refused() -> MemoryError {
    MemoryError::new(
        crate::memory::MEMORY_CODE_FORBIDDEN,
        format!(
            "{MASKED_ASSET_READ_VERB} takes a live Grant naming the verb: no live Grant from a live owner names this caller and lists the verb"
        ),
        &["Have the owner grant this caller the verb by name."],
    )
}
