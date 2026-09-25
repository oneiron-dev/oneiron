//! Query execution options for retrieval ports, independent of storage handles.
use super::Transactions;
use crate::{EntityId, error::Result, pipeline::ScoredEntity};
/// Scope probes are evaluated inside the caller's existing snapshot.
pub(crate) struct TextQuery<'a> {
    pub query: &'a str,
    pub limit: usize,
    pub rank: &'a crate::bm25::Bm25Config,
    /// True gates every posting before ranking; false gates prefix expansion only.
    pub filter_all: bool,
    pub matches_scope: &'a mut dyn FnMut(&EntityId) -> Result<bool>,
}
pub(crate) trait RetrievalIndexExecution: Transactions {
    fn port_retrieval_text_scoped(
        &self,
        txn: &Self::Read<'_>,
        query: TextQuery<'_>,
    ) -> Result<Vec<ScoredEntity>>;
}
