//! `vault.esign.fields.place` (ARCH-0064 SGN-07): the fields of a signing
//! document still in Draft, placed again. Canon's DRAFT rung (ARCH-0064
//! section 4): "The agent prepares the document + places fields; a human
//! sends", so the human who sends may move a field the agent placed before
//! sending. The door takes `vault.esign.create`'s authority: the verb's
//! Grant, the project membership a draft for a project asks of its drafter,
//! and, for a narrowed credential, its lane's reach to the document and every
//! item the draft pins (FIX 6403), judged before the write and again in it.
//! The draft lands again whole with the new fields in place of its own, as
//! one more `esign.drafted` event by the caller. Once the document has left
//! Draft its content is frozen and the door is refused.
use super::super::lane_scope::{self, EsignScope};
use super::super::ledger::{place_fields_in, state_in};
use super::super::model::EsignAuditActor;
use super::draft::draft_view;
use super::{EsignDraftView, document_id};
use crate::EntityId;
use crate::claim::ScopedRead;
use crate::memory::Memory;
use oneiron_contracts::memory::MemoryResult;

#[doc(hidden)]
pub use oneiron_verb_wire::blob_artifact::esign::door::EsignFieldsPlaceRequest;

impl Memory<'_> {
    /// `vault.esign.fields.place`: replaces the fields of the draft on
    /// `document_ref` with `fields`, as the bound actor, whose id the new
    /// draft event names. A narrowed credential places fields only on a
    /// document and items its lane reaches (FIX 6403).
    /// # Errors
    /// A `document_ref` that is no id, or the vault's refusal: a document
    /// that is unknown, out of a narrowed caller's lane or no longer in Draft,
    /// fields that do not validate against the draft (an item, page,
    /// recipient or geometry it does not hold), a project the caller is no
    /// member of, or a draft that names commitments.
    pub fn esign_place_fields(
        &self,
        input: &EsignFieldsPlaceRequest,
    ) -> MemoryResult<EsignDraftView> {
        let document = document_id(&input.document_ref)?;
        if let EsignScope::Credential(lane) = self.esign_scope()? {
            return self.esign_place_fields_in_lane(&lane, document, input);
        }
        let vault = self.vault();
        let actor = self.esign_audit_actor();
        let now = vault.now_recorded_at();
        vault.try_with_write_txn_grouped(|txn| -> MemoryResult<()> {
            place_fields_in(vault, txn, document, &input.fields, actor, now)?;
            Ok(())
        })?;
        Ok(draft_view(document, vault.esign_document(document)?))
    }

    /// [`Self::esign_place_fields`] for a narrowed credential: the document
    /// and every item its draft pins judged by `lane` before the write and
    /// again in it, the draft landing through the document's own content
    /// writer. The view is read in a snapshot that judges the document again.
    fn esign_place_fields_in_lane(
        &self,
        lane: &ScopedRead<'_>,
        document: EntityId,
        input: &EsignFieldsPlaceRequest,
    ) -> MemoryResult<EsignDraftView> {
        let vault = self.vault();
        {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            if !lane_scope::reaches_signing_document(lane, vault, &txn, document, false)? {
                return Err(lane_scope::unreached().into());
            }
        }
        let actor = self.esign_audit_actor();
        let now = vault.now_recorded_at();
        lane_scope::write_artifact(lane, self, document, |txn| {
            if !lane_scope::reaches_signing_document(lane, vault, txn, document, false)? {
                return Err(lane_scope::unreached().into());
            }
            place_fields_in(vault, txn, document, &input.fields, actor, now)?;
            Ok(())
        })?;
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        lane_scope::reaches_in(lane, &txn, document)?;
        Ok(draft_view(document, state_in(vault, &txn, document)?))
    }

    /// The bound actor as a draft event names it: its id, with no network
    /// origin (a verb call carries none).
    fn esign_audit_actor(&self) -> EsignAuditActor {
        EsignAuditActor {
            actor: self.actor().to_hex(),
            ip: None,
            user_agent: None,
        }
    }
}
