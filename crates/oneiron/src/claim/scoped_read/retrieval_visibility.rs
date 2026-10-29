//! The retrieval authority floor for graph channels on a scoped read.

use super::access_gate::HeldAuthority;
use super::*;

pub(crate) struct RetrievalVisibility<'read, 'vault> {
    scoped: &'read ScopedRead<'vault>,
    policy: PolicyManifestResolution,
    filter: ResolvedRetrievalFilter,
    /// The walk's transaction: borrowed, so it outlives this value and no
    /// other transaction can stand at its address while `held` is in use.
    txn: &'read heed::RoTxn<'read>,
    /// One relationship authority for every node the walk checks in `txn`,
    /// so the grants and relationship claims load once per walk, not once
    /// per node (FIX 11648).
    held: HeldAuthority<'vault>,
}

impl<'vault> ScopedRead<'vault> {
    /// Conjoins retrieval constraints with the existing actor-read traversal
    /// gate. Resolve against the walk's transaction; an absent request inherits
    /// the actor's floor, never the unscoped owner's authority.
    pub(crate) fn retrieval_visibility_in<'read>(
        &'read self,
        txn: &'read heed::RoTxn<'_>,
        requested: Option<&RetrievalFilter>,
    ) -> Result<RetrievalVisibility<'read, 'vault>> {
        let (filter, policy) = self.resolve_retrieval_filter_in(txn, requested)?;
        Ok(RetrievalVisibility {
            scoped: self,
            policy,
            filter,
            txn,
            held: HeldAuthority::default(),
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
        self.is_entity_retrievable_held_in(txn, policy, filter, id, &HeldAuthority::default())
    }

    /// [`Self::is_entity_retrievable_with_policy_in`] under the authority one
    /// serving txn holds for all its rows (FIX 7462).
    pub(super) fn is_entity_retrievable_held_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        id: &EntityId,
        authority: &HeldAuthority<'vault>,
    ) -> Result<bool> {
        // Audience, NOTE privacy, relationship grants, credential scope and
        // type/scalar ceilings all live in the shared row predicate; graph
        // traversal must not fork it.
        let Some(row) = self.entity_record_in(txn, id)? else {
            return Ok(false);
        };
        if !self.is_entity_raw_readable_held_in(
            txn,
            policy,
            id,
            &row.encode(),
            filter,
            authority,
        )? {
            return Ok(false);
        }
        if row.entity_type != crate::registry::ENTITY_TYPE_TURN {
            return Ok(true);
        }
        self.turn_messages_readable_in(txn, policy, id, authority)
    }

    /// A TURN's text, and so its vector, is its messages' text
    /// (`embed::turn_text_in_txn`): a reader retrieves the turn only when it
    /// may read every message in it, or the vector would match it by the
    /// meaning of words it may not read. Checked here, against the grants and
    /// messages of this read, so a grant revoked or a message added after the
    /// turn embedded counts at once. An erased message is a shell whose words
    /// left the turn's vector in its erasing write
    /// (`embed::erase_turn_vectors_in_txn`), so it no longer counts. A read by
    /// id finds nothing by meaning: it takes the turn's row alone
    /// (`entity_raw_with_mode_in`, `is_entity_readable_with_policy_in`), whose
    /// text is the messages it may read.
    ///
    /// Each message is read under the actor's own floor, not the request's
    /// narrowing: a scope that asks for TURNs alone still may read messages.
    fn turn_messages_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        turn: &EntityId,
        authority: &HeldAuthority<'vault>,
    ) -> Result<bool> {
        let floor = self.actor_retrieval_floor(policy)?;
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
            if !self.is_entity_readable_held_in(txn, policy, &message, &floor, authority)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl crate::ppr::PprNodeVisibility for RetrievalVisibility<'_, '_> {
    fn ppr_node_visible(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        // The held authority is the walk's transaction's; a node checked in
        // any other transaction loads its own.
        if std::ptr::eq(txn, self.txn) {
            return self.scoped.is_entity_retrievable_held_in(
                txn,
                &self.policy,
                &self.filter,
                id,
                &self.held,
            );
        }
        self.scoped
            .is_entity_retrievable_with_policy_in(txn, &self.policy, &self.filter, id)
    }
}
