//! An erased row out of a research campaign's kept confirmation release
//! (FIX 6933): the source rows of its released cases and their labels.

use super::ResearchContinuation;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// The continuations as their pass keeps them. Key: id16 (root attempt) +
/// u64be (work).
const CONTINUATION: SideTable<([u8; 16], u64), ResearchContinuation, Named> =
    SideTable::new(&side_table::AUTORESEARCH_CONTINUATION);

/// Drops an erased row `id` from the source rows of every case, and every
/// label on one, that a continuation keeps in its running confirmation's
/// release (FIX 6933), rewriting only the continuations that named it. The
/// release keeps its exposure and its cases, and the continuation its
/// tasks, reservation, run, state and times: a restart still re-briefs the
/// referee and never spends a second shot. Registered on the continuation
/// table's declaration; a source may be any row, so this reads every
/// continuation for each erased id.
///
/// # Errors
///
/// Storage errors, or a continuation that does not decode.
pub(crate) fn erase_release_source_rows_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let mut named = Vec::new();
    for (key, mut continuation) in CONTINUATION.scan(&vault.store, wtxn)? {
        let Some(running) = continuation.running.as_mut() else {
            continue;
        };
        let Some(release) = running.release.as_mut() else {
            continue;
        };
        let mut changed = false;
        for case in &mut release.cases {
            changed |= crate::skill_optimize::forget_eval_case_source_rows(case, id);
        }
        if changed {
            named.push((key, continuation));
        }
    }
    for (key, continuation) in named {
        CONTINUATION.put(&vault.store, wtxn, &key, &continuation)?;
    }
    Ok(())
}
