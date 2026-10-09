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
        // Audience, NOTE privacy, relationship grants, credential scope and
        // type/scalar ceilings all live in the shared row predicate; graph
        // traversal must not fork it.
        let Some(row) = self.entity_record_in(txn, id)? else {
            return Ok(false);
        };
        if !self.is_entity_raw_readable_with_filter_in(txn, policy, id, &row.encode(), filter)? {
            return Ok(false);
        }
        if row.entity_type != crate::registry::ENTITY_TYPE_TURN {
            return Ok(true);
        }
        self.turn_messages_readable_in(txn, policy, id)
    }

    /// A TURN's text, and so its vector, is its messages' text
    /// (`embed::turn_text_in_txn`): a reader retrieves the turn only when it
    /// may read every message in it, or the vector would match it by the
    /// meaning of words it may not read. Checked here, against the grants and
    /// messages of this read, so a grant revoked or a message added after the
    /// turn embedded counts at once. An erased message is a shell whose words
    /// left the turn's vector in its erasing write
    /// (`embed::erase_turn_vectors_in_txn`), so it no longer counts.
    ///
    /// Each message is read under the actor's own floor, not the request's
    /// narrowing: a scope that asks for TURNs alone still may read messages.
    fn turn_messages_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        turn: &EntityId,
    ) -> Result<bool> {
        let floor = crate::gate::narrow_retrieval_filter(
            &policy.retrieval_floor_for_actor(Some(&self.actor_key)),
            None,
        )?;
        let parts = match self.session_view {
            Some(view) => {
                view.port_edges(txn, turn, EdgeDirection::In, Some(EdgeKind::PartOf), None)?
            }
            None => {
                self.vault
                    .port_edges(txn, turn, EdgeDirection::In, Some(EdgeKind::PartOf), None)?
            }
        };
        for part in parts {
            let message = part?.target;
            let Some(row) = self.entity_record_in(txn, &message)? else {
                continue;
            };
            if row.entity_type != crate::registry::ENTITY_TYPE_MESSAGE || row.body.is_empty() {
                continue;
            }
            if !self.is_entity_readable_with_filter_in(txn, policy, &message, &floor)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl crate::ppr::PprNodeVisibility for RetrievalVisibility<'_, '_> {
    fn ppr_node_visible(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        self.scoped
            .is_entity_retrievable_with_policy_in(txn, &self.policy, &self.filter, id)
    }
}
