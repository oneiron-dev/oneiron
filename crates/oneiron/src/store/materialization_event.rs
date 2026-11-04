//! Commit-bound materialization revisions and read invalidation data.

use crate::EntityId;
use crate::store::revision_ref::RevisionRef;

/// A committed original or the exact source revision of a mirrored carrier.
/// A mirror without a source is an independent, foreign local contribution.
#[derive(Clone, Debug)]
pub enum RevisionEvent {
    Original(crate::vault::EntityRevisionChange),
    Mirror {
        entity: EntityId,
        source_revision: Option<RevisionRef>,
    },
}

/// Post-commit notification consumer. Implementations must not write to the
/// observed Loro document or re-enter materialization from this callback.
pub trait LiveQueryTee: Send + Sync {
    /// Called once per committed container batch, never for an aborted batch.
    fn on_materialized(
        &self,
        container_path: &str,
        diff: &MaterializedDiffSummary,
        by: &OriginMark,
    );
}

/// Coarse read dependencies invalidated by one committed container batch.
#[derive(Clone, Debug)]
pub struct MaterializedDiffSummary {
    /// Changed paths (`w:<window>/<container>/<key>`), not entity bodies.
    pub containers: Vec<String>,
    /// Total changed key and binary-value bytes, for accounting only.
    pub bytes: usize,
    /// Revision identities captured at the transaction or bridge-commit door.
    pub revision_events: Vec<RevisionEvent>,
}

/// Transport correlation only; never actor authority.
#[derive(Clone, Debug, Default)]
pub struct OriginMark {
    /// Parsed only from the server's existing `conn:<id>` import marker.
    pub conn_id: Option<u32>,
    /// Exact Loro origin, when present.
    pub origin: Option<String>,
}
