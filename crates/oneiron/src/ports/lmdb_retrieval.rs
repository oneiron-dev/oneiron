//! Configured text-query adapter, including composed session targets.
use super::{RetrievalIndexExecution, TextQuery, Transactions};
use crate::{
    analyzer::MultilingualAnalyzer, error::Result, pipeline::ScoredEntity, store::ManifestDbs,
};
use heed::RoTxn;
pub(crate) struct TextIndexView<'a, T> {
    target: &'a T,
    analyzer: &'a MultilingualAnalyzer,
}
pub(crate) fn text_index<'a, T: ManifestDbs>(
    target: &'a T,
    analyzer: &'a MultilingualAnalyzer,
) -> TextIndexView<'a, T> {
    TextIndexView { target, analyzer }
}
impl<T: ManifestDbs> Transactions for TextIndexView<'_, T> {
    type Read<'a> = heed::RoTxn<'a>;
    type Write<'a> = heed::RwTxn<'a>;
}
impl<T: ManifestDbs> RetrievalIndexExecution for TextIndexView<'_, T> {
    fn port_retrieval_text_scoped(
        &self,
        txn: &RoTxn<'_>,
        query: TextQuery<'_>,
    ) -> Result<Vec<ScoredEntity>> {
        let mut scope = query.matches_scope;
        let options = crate::bm25::Bm25SearchOptions {
            recency: None,
            exact_posting_matches_scope: &mut scope,
        };
        let rows = if query.filter_all {
            crate::bm25::search_text_filtered_with_recency(
                self.target,
                txn,
                self.analyzer,
                query.rank,
                query.query,
                query.limit,
                options,
            )?
        } else {
            crate::bm25::search_text_scoped_with_recency(
                self.target,
                txn,
                self.analyzer,
                query.rank,
                query.query,
                query.limit,
                options,
            )?
        };
        let mut visible = Vec::with_capacity(rows.len());
        for row in rows {
            let state = super::TombstoneStoreRead::port_deletion_state(self.target, txn, &row.id)?;
            if !state.deleted && !state.stale {
                visible.push(row);
            }
        }
        Ok(visible)
    }
}
impl RetrievalIndexExecution for crate::Vault {
    fn port_retrieval_text_scoped(
        &self,
        txn: &RoTxn<'_>,
        query: TextQuery<'_>,
    ) -> Result<Vec<ScoredEntity>> {
        self.ensure_text_index_trusted()?;
        text_index(&self.store, &self.analyzer).port_retrieval_text_scoped(txn, query)
    }
}
