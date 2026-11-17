//! The lexical query hint CLAIMs by target (FIX-LIST row 24676).
//!
//! Every claim write used to look up the hints of the claim it wrote by
//! reading every CLAIM row of the vault
//! ([`super::lexical_query_hints::lexical_query_hint_claim_ids_for_target`]),
//! so each Put cost O(the vault's claim count). This derived index names,
//! per target, the hint CLAIM rows whose body is a canonical lexical query
//! hint of that target, so the lookup reads only that target's hints.
//!
//! It is a prefilter only: the lookup runs its own per-row checks on each
//! hit, in hint id order, so it serves exactly what the walk of every CLAIM
//! row serves. Any doubt (flag unset, a hit the CLAIM type index does not
//! hold, a read error) makes the lookup walk every CLAIM row, which answers
//! exactly as it does today. Every entity body write passes the body stage
//! (`batch::put_apply::stage_entity_body_row`), which moves the row's key
//! here, every in-place scrub to a shell
//! (`EntityStoreMaintenance::port_entity_scrub`, which every erase runs)
//! drops it, and every entity row removal drops it.
//!
//! [`INDEX_VERSION`] is the decoder's version too: a change to what the
//! hint body decoder accepts bumps it, so the next open rebuilds the index
//! under the new decoder.

use super::*;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::side_table::{self, Raw, SideTable};
use crate::store::ManifestDbs;
use crate::store::Store;
use crate::store::scan_count::ScanCount;

/// Keys are `(target, hint)`; the value is an empty marker.
const HINT_INDEX: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::LEXICAL_QUERY_HINT_INDEX);

/// `Some(INDEX_VERSION)` once a whole rebuild of the index has committed.
const INDEX_STATE: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::LEXICAL_QUERY_HINT_INDEX_STATE);

const INDEX_VERSION: u64 = 1;

/// What the index holds for one stored row.
#[derive(Clone, Copy, PartialEq, Eq)]
enum IndexedRow {
    /// A canonical lexical query hint of `target`: the hint predicate, a
    /// subject equal to the encoded target, and an id derived from that
    /// target and query.
    Hint { target: EntityId },
    /// Anything else: another kind, a shell, another predicate, a hint body
    /// under any other id, or a body no claim decoder reads. The walk skips
    /// every one of these too.
    Outside,
}

/// The index entry of the `kind` row `id` holding `body` (without its
/// header). A header-only body is a shell, which the walk skips while its
/// row is deleted.
fn indexed_row(id: &EntityId, kind: u8, body: &[u8]) -> IndexedRow {
    if kind != ENTITY_TYPE_CLAIM || body.is_empty() {
        return IndexedRow::Outside;
    }
    let Ok(decoded) = crate::write_envelope::claim_body::decode_claim_body(body, true) else {
        return IndexedRow::Outside;
    };
    match crate::write_envelope::claim_body::lexical_query_hint::canonical_lexical_query_hint(
        id, &decoded,
    ) {
        Ok(Some(hint)) => IndexedRow::Hint {
            target: hint.target,
        },
        _ => IndexedRow::Outside,
    }
}

fn index_complete_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> bool {
    matches!(INDEX_STATE.get(store, txn, &()), Ok(Some(INDEX_VERSION)))
}

/// Moves entity `id`'s index entry from its stored row to `replacement`
/// (the kind and body about to be stored), in the writing transaction;
/// `None` removes the row. Runs before the row itself is written or
/// removed, as the identity hint and named-entity indexes beside it do.
///
/// # Errors
///
/// The `entities` read's and the index write's own store errors.
pub(crate) fn reindex_lexical_query_hint(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    replacement: Option<(u8, &[u8])>,
) -> Result<()> {
    let prior = EntityStoreRead::port_entity_raw_wiped(store, txn, id)?.map_or(
        IndexedRow::Outside,
        |raw| match EntityMetadataHeader::parse(&raw) {
            Some(header) => indexed_row(id, header.entity_type, &raw[ENTITY_METADATA_HEADER_LEN..]),
            None => IndexedRow::Outside,
        },
    );
    let next = replacement.map_or(IndexedRow::Outside, |(kind, body)| {
        indexed_row(id, kind, body)
    });
    if prior != next
        && let IndexedRow::Hint { target } = prior
    {
        HINT_INDEX.delete(store, txn, &(target, *id))?;
    }
    if let IndexedRow::Hint { target } = next {
        HINT_INDEX.put(store, txn, &(target, *id), &())?;
    }
    Ok(())
}

/// The hint CLAIM ids the index names for `target`, in hint id order, when
/// the index can answer for a lookup in `txn`. `None` means any doubt at
/// all: the caller walks every CLAIM row. Each hit is verified against its
/// stored body, so a stale index row is skipped, never served.
pub(crate) fn indexed_lexical_query_hint_claim_ids_for_target(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    target: &EntityId,
    rows: &mut ScanCount,
) -> Result<Option<Vec<EntityId>>> {
    if !index_complete_in_txn(store, txn) {
        return Ok(None);
    }
    let Ok(keys) = HINT_INDEX.scan_keys(store, txn, target.as_bytes().as_slice()) else {
        return Ok(None);
    };
    let mut hint_ids = Vec::with_capacity(keys.len());
    for (indexed_target, hint_id) in keys {
        if indexed_target != *target {
            return Ok(None);
        }
        rows.row();
        // The walk reads the CLAIM type index: a hit it does not hold is
        // doubt, never an answer the walk would not give.
        if !EntityStoreRead::port_entity_type_indexed(store, txn, ENTITY_TYPE_CLAIM, &hint_id)
            .unwrap_or(false)
        {
            return Ok(None);
        }
        let Some(body) = super::lexical_query_hints::stored_claim_body(store, txn, &hint_id)?
        else {
            continue;
        };
        let Ok(Some(hint)) =
            crate::write_envelope::claim_body::lexical_query_hint::canonical_lexical_query_hint(
                &hint_id, &body,
            )
        else {
            continue;
        };
        if hint.target == *target {
            hint_ids.push(hint_id);
        }
    }
    hint_ids.sort_unstable();
    hint_ids.dedup();
    Ok(Some(hint_ids))
}

impl Vault {
    /// Rebuilds the hint index from the CLAIM rows when it is missing or
    /// stale, in one write transaction (a crash leaves nothing or
    /// everything). Runs at writable open and after a checkpoint restore
    /// (`force`); a complete index is left alone.
    ///
    /// # Errors
    ///
    /// At open (`force` false) none: a failed rebuild of this Derived index
    /// never refuses the open; the flag stays unset and the lookups keep the
    /// walk. The restore rebuild (`force`) propagates its store errors like
    /// its sibling backfills.
    pub(crate) fn backfill_lexical_query_hint_index(&self, force: bool) -> Result<()> {
        match self.rebuild_lexical_query_hint_index(force) {
            Err(error) if !force => {
                tracing::warn!(
                    %error,
                    "lexical query hint index rebuild failed; hint lookups keep the walk"
                );
                Ok(())
            }
            other => other,
        }
    }

    fn rebuild_lexical_query_hint_index(&self, force: bool) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        if !force && index_complete_in_txn(&self.store, &wtxn) {
            return Ok(());
        }
        let ids =
            EntityStoreRead::port_entity_ids_by_type(&self.store, &wtxn, ENTITY_TYPE_CLAIM, None)?
                .collect::<Result<Vec<_>>>()?;
        let mut hints = Vec::new();
        for id in ids {
            let Some(row) = EntityStoreRead::port_entity_record(&self.store, &wtxn, &id)? else {
                continue;
            };
            if let IndexedRow::Hint { target } = indexed_row(&id, row.entity_type, &row.body) {
                hints.push((target, id));
            }
        }
        HINT_INDEX.delete_from(&self.store, &mut wtxn, &[])?;
        for key in &hints {
            HINT_INDEX.put(&self.store, &mut wtxn, key, &())?;
        }
        INDEX_STATE.put(&self.store, &mut wtxn, &(), &INDEX_VERSION)?;
        wtxn.commit()?;
        Ok(())
    }
}

/// The door `scan_check::table_tests` uses.
#[cfg(test)]
impl Vault {
    /// Drops the index and its completeness flag, as a vault older than the
    /// index holds them, so the lookups walk until the next open rebuilds it.
    pub(crate) fn drop_lexical_query_hint_index_for_test(&self) -> Result<()> {
        self.with_write_txn(|wtxn| {
            HINT_INDEX.delete_from(&self.store, wtxn, &[])?;
            INDEX_STATE.delete(&self.store, wtxn, &())?;
            Ok(())
        })
    }
}
