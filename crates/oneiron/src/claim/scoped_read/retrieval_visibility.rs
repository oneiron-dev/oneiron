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
        if filter.deny_all {
            return Ok(false);
        }
        let Some(raw) = self.entities().get(txn, id.as_bytes())? else {
            return Ok(false);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if self
            .vault
            .store
            .validate_entity_type(header.entity_type)
            .is_err()
            || filter
                .entity_types
                .as_ref()
                .is_some_and(|types| !types.contains(&header.entity_type))
        {
            return Ok(false);
        }
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Ok(true);
        }
        let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        let facets = self.claim_facet_refs_in(txn, id)?;
        Ok(crate::pipeline::retrieval_claim_allowed(filter, &body)
            && crate::gate::scoped_read_claim_allowed(policy, &self.actor_key, &body, &facets))
    }
}

impl crate::ppr::PprNodeVisibility for RetrievalVisibility<'_, '_> {
    fn ppr_node_visible(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        if !self
            .scoped
            .is_entity_retrievable_with_policy_in(txn, &self.policy, &self.filter, id)?
        {
            return Ok(false);
        }
        self.scoped
            .is_entity_readable_with_policy_in(txn, &self.policy, id)
    }
}
