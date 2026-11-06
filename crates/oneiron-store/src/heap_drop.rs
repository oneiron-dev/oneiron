//! Counts reported by rebuildable index and window heap drops.

/// Counts of concrete work one shed performed.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
pub struct HeapDropReport {
    pub sync_windows: u64,
    pub ppr_cache_rows: u64,
    pub ppr_dependency_rows: u64,
    pub hnsw_nodes: u64,
    /// Lower-bound proxy from persisted snapshot lengths. The heap actually
    /// freed — chiefly Loro op history — is typically much larger and is not
    /// cheaply measurable. Nonzero means the shed did concrete work; it is
    /// never an RSS-delta predictor.
    pub estimated_reclaimed_bytes: u64,
}

impl HeapDropReport {
    /// Field-wise merge of the sync, PPR and HNSW reports. Every count field
    /// is disjoint across producers and sums into its matching output field;
    /// no max/overwrite rule is permitted.
    #[must_use]
    pub fn merged(self, other: Self) -> Self {
        Self {
            sync_windows: self.sync_windows.saturating_add(other.sync_windows),
            ppr_cache_rows: self.ppr_cache_rows.saturating_add(other.ppr_cache_rows),
            ppr_dependency_rows: self
                .ppr_dependency_rows
                .saturating_add(other.ppr_dependency_rows),
            hnsw_nodes: self.hnsw_nodes.saturating_add(other.hnsw_nodes),
            estimated_reclaimed_bytes: self
                .estimated_reclaimed_bytes
                .saturating_add(other.estimated_reclaimed_bytes),
        }
    }
}
