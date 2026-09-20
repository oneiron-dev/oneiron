//! Actor-private NOTE admission on the scoped read snapshot.

use super::*;

impl ScopedRead<'_> {
    /// Scoped actor keys are asserted by a trusted host, not bearer secrets.
    /// A private NOTE additionally requires an exact entity id and a live,
    /// class-valid actor row in the same snapshot as its body.
    pub(super) fn note_readable_in(&self, txn: &heed::RoTxn<'_>, bytes: &[u8]) -> Result<bool> {
        let Ok(body) = crate::note::decode_note_body(bytes) else {
            return Ok(false);
        };
        if body.kind != crate::note::NoteKind::Diary {
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
