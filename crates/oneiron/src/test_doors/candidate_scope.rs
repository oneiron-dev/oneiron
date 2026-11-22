//! Door for `tests/scoped_temporal_scan_caps.rs`: a query whose candidate
//! filter admits only some rows, as a scoped read's admission refuses each
//! row its reader may not read. The builder's candidate filter is
//! crate-private; no `made_by` slice joins it.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::error::Result;
use crate::{EntityId, PipelineBuilder, ScoredEntity, Vault};

/// Runs `configure`'s query on `vault` under a candidate filter that admits
/// only `readable`, counting each time the filter is asked in `asked`.
///
/// # Errors
///
/// The query's error.
#[doc(hidden)]
pub fn run_reading_only(
    vault: &Vault,
    readable: &[EntityId],
    asked: &AtomicUsize,
    configure: impl for<'q> FnOnce(PipelineBuilder<'q>) -> PipelineBuilder<'q>,
) -> Result<Vec<ScoredEntity>> {
    let admits =
        |_: &crate::store::StoreRead<'_>, _: &heed::RoTxn<'_>, id: &EntityId| -> Result<bool> {
            asked.fetch_add(1, Ordering::Relaxed);
            Ok(readable.contains(id))
        };
    configure(vault.query().filter_candidates(&admits)).run()
}
