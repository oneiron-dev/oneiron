//! Erase independent author-attribution carriers without changing decisions.

use std::collections::BTreeSet;

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::identity_topology::{StoredIdentityOpAction, decode_identity_topology_event_body};
use crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT;

/// Exactly the merge/split decisions reached by the redirect erasure walk.
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
        _ => false,
    }
}

impl Vault {
    /// Redact the authors of decisions reached by the redirect walk. The
    /// decision stays immutable; only separate personal carriers are erased.
    /// Returns the redacted events and their scrubbed carriers, for
    /// post-commit local invalidation.
    pub(super) fn scrub_identity_op_author_stamps_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        touched: &BTreeSet<EntityId>,
    ) -> Result<Vec<EntityId>> {
        let mut targets = Vec::new();
        for entry in self
            .store
            .type_index
            .prefix_iter(&*wtxn, &[ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT])?
        {
            let (key, _) = entry?;
            let id = crate::vault::entity_id_from_type_index_key(&key)?;
            let raw = self
                .store
                .entities
                .get(&*wtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("identity topology event index"))?;
            if raw.len() < ENTITY_METADATA_HEADER_LEN {
                return Err(Error::CorruptedIndex("identity topology event header"));
            }
            let record = decode_identity_topology_event_body(&raw[ENTITY_METADATA_HEADER_LEN..])
                .map_err(|_| Error::CorruptedIndex("identity topology event body"))?;
            if identity_op_event_touches(&record.action, touched) {
                targets.push(id);
            }
        }
        let mut scrubbed = Vec::new();
        for target in targets {
            scrubbed.push(target);
            scrubbed.extend(crate::identity_topology::redact_author_attribution_in_txn(
                self,
                wtxn,
                target,
                self.store.clock.now_recorded_at(),
            )?);
        }
        Ok(scrubbed)
    }

    /// Erase one actor's independent carriers across the entire decision
    /// family, even when the actor is not a decision participant.
    pub(super) fn scrub_identity_op_actor_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        crate::identity_topology::redact_actor_in_txn(
            self,
            wtxn,
            *actor,
            self.store.clock.now_recorded_at(),
        )?;
        Ok(())
    }
}
