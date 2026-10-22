//! One mount wrapper for every graph-FS door (FIX 7608 slice 2b-ii-A, FIX
//! 8964): it mounts on the caller's own admitted scoped read, exactly as
//! the doors do today, and carries this handle's repo byte-recipient hint
//! into the mount, so `cat`, `head`, `grep` and `wc` share one projection.
//! No request field sets it.

use super::super::{Memory, MemoryResult};
use crate::claim::ScopedRead;
use crate::graph_fs::{GraphFsOptions, GraphFsReference, GraphFsResolver};

impl Memory<'_> {
    /// `lane.mount_graph_fs(reference, options)`, carrying whether this
    /// handle reads repo bytes masked.
    ///
    /// # Errors
    /// The mount's own, or a failed recipient check.
    pub(crate) fn mount_repo_graph_fs<'r, 'v>(
        &self,
        lane: &'r ScopedRead<'v>,
        reference: &GraphFsReference,
        options: GraphFsOptions,
    ) -> MemoryResult<GraphFsResolver<'r, 'v>> {
        let masked = self.repo_reads_masked()?;
        Ok(lane
            .mount_graph_fs(reference, options)?
            .with_repo_masked(masked))
    }
}
