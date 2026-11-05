//! Commit-bound materialization revisions and read invalidation data.

use oneiron_contracts::entity_id::EntityId;

/// Transport correlation only; never actor authority.
#[derive(Clone, Debug, Default)]
pub struct OriginMark {
    /// Parsed only from the server's existing `conn:<id>` import marker.
    pub conn_id: Option<u32>,
    /// Exact Loro origin, when present.
    pub origin: Option<String>,
}
