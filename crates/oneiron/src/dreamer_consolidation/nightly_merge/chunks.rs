//! Which unlisted siblings a nightly merge fans in beside its listed children
//! (FIX 7495, FIX 7524): a retry of a listed child, which queues that child's
//! own input, and every sibling a preparation owed (a retry's overflow
//! chunk, or a multi-part child's part that could not be read whole), which
//! names its originating attempt. Lineage is explicit, never the equality of
//! a whole multi-part set or a mere overlap of parts.

use std::collections::BTreeSet;

use rmpv::Value;

use super::{ATTEMPT, MERGED, MergeInput};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::dreamer_consolidation::partition::{decode_branch_origin, decode_partition_payload};
use crate::dreamer_runner::{DreamerAttemptStatus, DreamerConsolidationScope, DreamerRunnerStore};
use crate::{Result, Vault};

/// The retry chunks of `listed`: the consolidation attempts under this
/// merge's parent whose lineage is a listed child's. One that another merge
/// under that parent lists, or has read, is that merge's. A lineage that
/// does not read leaves the listed children alone, as before: nothing here
/// refuses a merge.
pub(super) fn retry_chunks_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    merge: &DreamerAttemptStatus,
    listed: &[AttemptId],
) -> Vec<AttemptId> {
    let Some(parent) = merge.payload.parent_attempt else {
        return Vec::new();
    };
    chunks_under_in_txn(vault, txn, merge.attempt.id, parent, listed).unwrap_or_else(|error| {
        tracing::warn!(
            merge = %crate::entity_id::bytes_to_hex_lower(merge.attempt.id.as_bytes()),
            kind = ?error.kind(),
            "nightly merge retry chunks did not read; it fans in its listed children"
        );
        Vec::new()
    })
}

/// The listed children's queued inputs and ids: what a sibling's lineage
/// is matched against.
struct Listed {
    ids: BTreeSet<AttemptId>,
    inputs: Vec<Value>,
}

impl Listed {
    /// Whether a consolidation sibling queued with `input` is a listed
    /// child's: its retry (the same queued input), or work owed by a listed
    /// child or by one of their retries (its `origin`).
    fn owns(&self, queue: &AttemptQueue<'_>, txn: &heed::RoTxn<'_>, input: &Value) -> Result<bool> {
        if self.inputs.contains(input) {
            return Ok(true);
        }
        let Some(origin) = decode_branch_origin(input) else {
            return Ok(false);
        };
        if self.ids.contains(&origin) {
            return Ok(true);
        }
        Ok(queue
            .get_in_txn(txn, origin)?
            .and_then(|record| {
                crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload).ok()
            })
            .is_some_and(|payload| self.inputs.contains(&payload.input)))
    }
}

/// [`retry_chunks_in_txn`] over `parent`'s run-tree children.
fn chunks_under_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    merge: AttemptId,
    parent: AttemptId,
    listed: &[AttemptId],
) -> Result<Vec<AttemptId>> {
    let queue = AttemptQueue::new(vault);
    let mut owners = Listed {
        ids: listed.iter().copied().collect(),
        inputs: Vec::new(),
    };
    for id in listed {
        if let Some(record) = queue.get_in_txn(txn, *id)?
            && let Ok(payload) =
                crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload)
            && decode_partition_payload(&payload.input).is_ok()
        {
            owners.inputs.push(payload.input);
        }
    }
    let mut claimed = owners.ids.clone();
    let mut candidates = Vec::new();
    for sibling in DreamerRunnerStore::new(vault).child_attempts_in_txn(txn, parent)? {
        if sibling == merge {
            continue;
        }
        let Some(record) = queue.get_in_txn(txn, sibling)? else {
            continue;
        };
        let Ok(payload) = crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload)
        else {
            continue;
        };
        if payload.attempt_type == ATTEMPT {
            if let Some(input) = payload
                .input
                .as_str()
                .and_then(|raw| serde_json::from_str::<MergeInput>(raw).ok())
            {
                claimed.extend(input.children);
            }
            if let Some(result) = MERGED.get(&vault.store, txn, &sibling)? {
                claimed.extend(result.chunks);
            }
        } else if payload.attempt_type == DreamerConsolidationScope::Macro.as_str()
            && decode_partition_payload(&payload.input).is_ok()
            && owners.owns(&queue, txn, &payload.input)?
        {
            candidates.push(sibling);
        }
    }
    candidates.retain(|id| !claimed.contains(id));
    Ok(candidates)
}
