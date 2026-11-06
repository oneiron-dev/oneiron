//! Query execution options for retrieval ports, independent of storage handles.
use super::Transactions;
use crate::EntityId;
use crate::error::Result;
use heed::RoTxn;
use oneiron_retrieval::pipeline::ScoredEntity;
/// Scope probes are evaluated inside the caller's existing snapshot.
pub(crate) struct TextQuery<'a> {
    pub query: &'a str,
    pub limit: usize,
    pub rank: &'a crate::config::bm25::Bm25Config,
    /// True gates every posting before ranking; false gates prefix expansion only.
    pub filter_all: bool,
    pub matches_scope: &'a mut dyn FnMut(&EntityId) -> Result<bool>,
    /// Authenticated private diary ids from this query's read snapshot only.
    pub private_note_ids: Option<&'a crate::claim::ScopedDiaryCandidates>,
    /// Caller-carried recency blend (FIX 9096); None preserves today's scores.
    pub recency: Option<crate::config::bm25::Bm25RecencyConfig>,
}
pub(crate) trait RetrievalIndexExecution: Transactions {
    fn port_retrieval_text_scoped(
        &self,
        txn: &Self::Read<'_>,
        query: TextQuery<'_>,
    ) -> Result<Vec<ScoredEntity>>;
}

/// Per-node read visibility for an ACTOR-SCOPED walk (ONE-1608 / ARCH-0050
/// R6 L2).
///
/// The walk consults this before a node may hold or carry mass, so policy
/// decides STRUCTURE rather than being applied to a ranking that already
/// crossed hidden nodes. Filtering results afterwards cannot undo that: mass
/// which already flowed through a denied bridge has changed which permitted
/// items rank where, and at [`MAX_PPR_DEPTH`] hops a caller can read the
/// hidden graph off the scores of the nodes it IS allowed to see.
///
/// Implementations answer for one actor and must be pure with respect to the
/// caller's transaction: the walk hands them the SAME `RoTxn` it is reading
/// from, and an error is propagated (fail closed), never treated as "visible".
pub(crate) trait PprNodeVisibility {
    fn ppr_node_visible(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool>;
}
