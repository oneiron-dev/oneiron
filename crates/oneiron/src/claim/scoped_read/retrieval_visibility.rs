//! The retrieval authority floor for graph channels on a scoped read.

use super::*;

pub(crate) struct RetrievalVisibility<'read, 'vault> {
    scoped: &'read ScopedRead<'vault>,
    policy: PolicyManifestResolution,
    filter: ResolvedRetrievalFilter,
}

impl<'vault> ScopedRead<'vault> {
    /// Conjoins retrieval constraints with the existing actor-read traversal
    /// gate. Resolve against the walk's transaction; an absent request inherits
    /// the actor's floor, never the unscoped owner's authority.
    pub(crate) fn retrieval_visibility_in(
        &self,
        txn: &heed::RoTxn<'_>,
        requested: Option<&RetrievalFilter>,
    ) -> Result<RetrievalVisibility<'_, 'vault>> {
        let (filter, policy) = self.resolve_retrieval_filter_in(txn, requested)?;
        Ok(RetrievalVisibility {
            scoped: self,
            policy,
            filter,
        })
    }

    /// The same final retrieval predicate for direct hits and graph nodes.
    pub(super) fn is_entity_retrievable_with_policy_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        id: &EntityId,
    ) -> Result<bool> {
        // Audience, NOTE privacy, relationship grants and type/scalar ceilings
        // all live in the shared row predicate; graph traversal must not fork it.
        self.is_entity_readable_with_filter_in(txn, policy, id, filter)
    }
}

impl crate::ppr::PprNodeVisibility for RetrievalVisibility<'_, '_> {
    fn ppr_node_visible(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        self.scoped
            .is_entity_retrievable_with_policy_in(txn, &self.policy, &self.filter, id)
    }
}
