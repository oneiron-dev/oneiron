//! Actor and class checks for private NOTE bodies in scoped reads.

use super::*;

impl ScopedRead<'_> {
    /// Scoped actor keys are asserted by a trusted host, not bearer secrets.
    /// A private NOTE additionally requires an exact entity id and a live,
    /// class-valid actor row in the same snapshot as its body.
    pub(super) fn note_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        bytes: &[u8],
    ) -> Result<bool> {
        // A migrated NOTE retains author metadata but stores markdown on its
        // document plane. Apply the same privacy rule to that logical body.
        #[cfg(feature = "sync")]
        let resolved = crate::entity_doc::resolve_record_body(&self.vault.store, txn, id, bytes)?;
        #[cfg(feature = "sync")]
        let bytes = resolved.as_slice();
        #[cfg(not(feature = "sync"))]
        let _ = id;
        let Ok(body) = crate::note::decode_note_body_in_txn(&self.vault.store, txn, bytes) else {
            return Ok(false);
        };
        if crate::note::note_body_readable(&self.vault.store, txn, bytes, None)? {
            return Ok(true);
        }
        let Ok(actor) = EntityId::from_hex(self.actor_key.actor_ref()) else {
            return Ok(false);
        };
        if actor != body.author_ref {
            return Ok(false);
        }
        let Some(class) = self.actor_key.actor_class().and_then(|class| match class {
            "human" => Some(crate::edge::EdgeActorClass::Human),
            "agent" => Some(crate::edge::EdgeActorClass::Agent),
            "system" => Some(crate::edge::EdgeActorClass::System),
            _ => None,
        }) else {
            return Ok(false);
        };
        let crate::vault::LiveEntityRow::Live { entity_type, .. } =
            crate::vault::live_entity_row_in_txn(&self.vault.store, txn, &actor)?
        else {
            return Ok(false);
        };
        Ok(crate::provenance::validate_actor_class(entity_type, class).is_ok())
    }
}
