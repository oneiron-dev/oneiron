//! A profile read's source ids, read in fair bounded batches (FIX 10054,
//! Rule 5). A size bound is pacing, never a refusal: any number of ids is
//! read, each batch in its own turn on the vault's task-work line, which it
//! gives back at the batch's end so other callers' work runs between.

use std::collections::HashSet;

use crate::api::parse_entity_id_param;
use crate::error::ApiError;
use crate::server::SyncServer;

/// Source ids read per task-work turn (CALLS "OF-10054 source work batch",
/// open): pacing only, never a limit on how many a request names.
const PROFILE_SOURCE_WORK_BATCH_IDS: usize = 4096;

/// The distinct source ids `values` names, in submitted order, or None when
/// it names none. Blank entries are skipped; a malformed id is today's 400.
pub(super) async fn source_revision_ids(
    server: &SyncServer,
    caller: oneiron::EntityId,
    values: Option<Vec<String>>,
) -> Result<Option<Vec<oneiron::EntityId>>, ApiError> {
    let Some(values) = values else {
        return Ok(None);
    };
    let mut ids = Vec::new();
    let mut seen = HashSet::new();
    for batch in values.chunks(PROFILE_SOURCE_WORK_BATCH_IDS) {
        let _turn = server.admit_task_work(caller).await;
        for value in batch {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            let id = parse_entity_id_param(value, "sourceRevisionIds")?;
            if seen.insert(id) {
                ids.push(id);
            }
        }
    }
    Ok(super::non_empty_source_revision_ids(ids))
}
