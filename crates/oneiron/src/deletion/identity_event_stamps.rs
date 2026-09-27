//! Scrub author stamps on the exact topology events an erasure touches.

use std::collections::BTreeSet;

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::identity_topology::{
    StoredIdentityOpAction, decode_identity_topology_event_body,
    encode_identity_topology_event_body,
};
use crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT;

/// Whether a stored type-76 action names any of `touched` in the redirect
/// topology it declares — the exact reach of the ARCH-0055 §9 erase walk.
///
/// ONLY the two shell-edge families answer yes: merge and split are the ops
/// the redirect walk reads, so they are the ops whose payloads it touches.
/// Facet, assert_distinct, undo and proposal resolution are outside that
/// reach and stay untouched, which is what keeps the author-stamp rider from
/// becoming a family-wide sweep.
fn identity_op_event_touches(
    action: &StoredIdentityOpAction,
    touched: &BTreeSet<EntityId>,
) -> bool {
    match action {
        StoredIdentityOpAction::Merge { sources, survivor } => {
            touched.contains(survivor) || sources.iter().any(|source| touched.contains(source))
        }
        StoredIdentityOpAction::Split { entity, heads, .. } => {
            touched.contains(entity) || heads.iter().any(|head| touched.contains(head))
        }
        StoredIdentityOpAction::Facet { .. }
        | StoredIdentityOpAction::AssertDistinct { .. }
        | StoredIdentityOpAction::Undo { .. }
        | StoredIdentityOpAction::ProposalResolution { .. }
        | StoredIdentityOpAction::ProposalCancellation { .. } => false,
    }
}

impl Vault {
    /// ARCH-0055 §9 author-stamp rider, STRICTLY scoped: drop the deciding
    /// actor's stamp from the type-76 merge/split events whose payloads this
    /// erase walk touched — the records that bound the erased head to the
    /// shells this transaction just emptied. Erasing the subjects of a
    /// decision while the ledger keeps reading "X decided this about them"
    /// leaves the erasure half-done.
    ///
    /// The boundary is the walk's own reach and nothing wider. A general
    /// participant-deletion sweep over the family is a separate obligation
    /// with its own ticket; a rider that grew into it would erase authorship
    /// of decisions this erase never read, on a path with no receipt for
    /// having done so.
    ///
    /// Fail-closed on an undecodable body, like every other reader of this
    /// engine-authored family — and reached only when the head actually had
    /// shells, so an ordinary delete never enumerates the ledger at all.
    pub(super) fn scrub_identity_op_author_stamps_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        touched: &BTreeSet<EntityId>,
    ) -> Result<()> {
        self.scrub_identity_op_stamps_matching_in_txn(wtxn, |event| {
            identity_op_event_touches(&event.action, touched)
        })
    }

    /// Explicit erasure of an author removes the stamp without deleting the
    /// self-contained decision. This is distinct from the redirect walk's
    /// participant-scoped stamp scrub above.
    pub(super) fn scrub_identity_op_actor_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        self.scrub_identity_op_stamps_matching_in_txn(wtxn, |event| {
            event
                .actor
                .is_some_and(|stamp| stamp.entity_ref() == *actor)
        })
    }

    fn scrub_identity_op_stamps_matching_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        matches: impl Fn(&crate::identity_topology::StoredIdentityOpEvent) -> bool,
    ) -> Result<()> {
        let mut scrubbed: Vec<(EntityId, Vec<u8>)> = Vec::new();
        for entry in self
            .store
            .type_index
            .prefix_iter(&*wtxn, &[ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT])?
        {
            let (key, _) = entry?;
            let event_id = crate::vault::entity_id_from_type_index_key(&key)?;
            let Some(raw) = self.store.entities.get(&*wtxn, event_id.as_bytes())? else {
                continue;
            };
            if raw.len() < ENTITY_METADATA_HEADER_LEN {
                return Err(Error::CorruptedIndex("entity metadata"));
            }
            let event = decode_identity_topology_event_body(&raw[ENTITY_METADATA_HEADER_LEN..])
                .map_err(|_| Error::CorruptedIndex("identity topology event body"))?;
            if !matches(&event) {
                continue;
            }
            let Some(event) = event.without_author_stamp() else {
                continue;
            };
            let mut record = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
            record.extend_from_slice(&encode_identity_topology_event_body(&event)?);
            scrubbed.push((event_id, record));
        }
        for (event_id, record) in &scrubbed {
            // Erasure must remove the old author stamp from retained history too.
            crate::vault::entity_revision::remove_entity_revisions(&self.store, wtxn, event_id)?;
            self.store.entities.put(wtxn, event_id.as_bytes(), record)?;
        }
        Ok(())
    }
}
