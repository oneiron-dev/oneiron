//! The buckets a MACRO run holds once its preparation narrowed it (FIX
//! 7729). A multi-part child whose parts split off as owed siblings (FIX
//! 7524, FIX 7728) runs the rest only, so admission holds the rest only
//! while that run lasts, and the split-off conversations' other work is not
//! kept waiting on it. The run records its narrowed set as it starts, under
//! its lease generation: a later lease of the same try holds its full
//! queued set again until its own run narrows it. The all-or-none rule and
//! every held-set wait stay as they were.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

use super::ConsolidationPartitionKey;

/// The narrowed bucket set of a run, keyed by its try.
const RUNNING_BUCKETS: SideTable<AttemptId, RunningBuckets, Named> =
    SideTable::new(&side_table::DREAMER_CONSOLIDATION_RUNNING_BUCKETS);

/// The buckets one lease of a try runs: each part partition's
/// conversation, world and facet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunningBuckets {
    /// The lease generation of the run that narrowed them.
    attempt_count: u32,
    buckets: Vec<(EntityId, Option<EntityId>, Option<EntityId>)>,
}

/// Records, as the run of `attempt` leased at `attempt_count` starts, that
/// it holds `buckets` only.
pub(super) fn record_running_buckets(
    vault: &Vault,
    attempt: AttemptId,
    attempt_count: u32,
    buckets: &[ConsolidationPartitionKey],
) -> Result<()> {
    let row = RunningBuckets {
        attempt_count,
        buckets: buckets
            .iter()
            .map(|key| (key.conversation_ref, key.world_ref, key.facet_ref))
            .collect(),
    };
    vault.with_write_txn_grouped(|txn| RUNNING_BUCKETS.put(vault, txn, &attempt, &row))
}

/// The buckets the running `record` holds when its run narrowed them at its
/// current lease; `None` when it holds its full queued set.
pub(crate) fn running_bucket_set_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &AttemptRecord,
) -> Result<Option<Vec<ConsolidationPartitionKey>>> {
    Ok(RUNNING_BUCKETS
        .get_lenient(vault, txn, &record.id)?
        .filter(|row| row.attempt_count == record.attempt_count)
        .map(|row| {
            row.buckets
                .into_iter()
                .map(
                    |(conversation_ref, world_ref, facet_ref)| ConsolidationPartitionKey {
                        conversation_ref,
                        world_ref,
                        facet_ref,
                    },
                )
                .collect()
        }))
}
