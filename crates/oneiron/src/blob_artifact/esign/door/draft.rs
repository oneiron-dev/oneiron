//! `vault.esign.create`. FIX 6403: a world-, facet- or record-scoped
//! credential drafts a signing document on an overlay and PDFs its own read
//! lane reaches ([`super::super::lane_scope`]), through the overlay's own
//! content writer; an unrestricted caller drafts as before. The QR PDF
//! download switch (`qr_pdf_download`) lands in the draft's own transaction,
//! and only the vault owner turns it on, on the owner's own live credential
//! or none (the embedded owner), never one handed to another key.
use super::super::lane_scope::{self, EsignScope};
use super::super::ledger::{create_document_in, state_in};
use super::super::lifecycle::with_lifecycle;
use super::super::model::{EsignAuditActor, EsignState, validate_document};
use super::super::qr_capability::set_pdf_download_in_txn;
use super::{EsignCreateRequest, EsignDraftView, document_id};
use crate::EntityId;
use crate::claim::ScopedRead;
use crate::memory::Memory;
use oneiron_contracts::memory::{MemoryError, MemoryResult};

impl Memory<'_> {
    /// `vault.esign.create`: drafts a signing document on `document_ref` as
    /// the bound actor, whose id the draft's trail names. A narrowed
    /// credential drafts only on an overlay and items its lane reaches
    /// (FIX 6403).
    /// # Errors
    /// A `document_ref` that is no id, a QR PDF download asked for by anyone
    /// but the vault owner, or the vault's refusal: a draft that does not
    /// validate, an item whose PDF moved past its pinned version, a project
    /// the caller is no member of, or a document already drafted.
    pub fn esign_create(&self, input: &EsignCreateRequest) -> MemoryResult<EsignDraftView> {
        let document = document_id(&input.document_ref)?;
        // Every envelope is sensitive unless the owner says otherwise
        // (ARCH-0064a section 6): no other caller loosens it. Judged before
        // the draft and again in its write.
        if input.qr_pdf_download {
            let txn = self
                .vault()
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            self.admit_qr_pdf_download_in(&txn)?;
        }
        if let EsignScope::Credential(lane) = self.esign_scope()? {
            return self.esign_create_in_lane(&lane, document, input);
        }
        let vault = self.vault();
        let actor = EsignAuditActor {
            actor: self.actor().to_hex(),
            ip: None,
            user_agent: None,
        };
        let now = vault.now_recorded_at();
        let body = match &input.draft.lifecycle {
            Some(rules) => with_lifecycle(&input.draft, now, rules)?,
            None => input.draft.clone(),
        };
        validate_document(&body, now)?;
        vault.try_with_write_txn_grouped(|txn| -> MemoryResult<()> {
            create_document_in(vault, txn, document, &body, actor, now)?;
            if input.qr_pdf_download {
                self.admit_qr_pdf_download_in(txn)?;
                set_pdf_download_in_txn(vault, txn, document, true)?;
            }
            Ok(())
        })?;
        let state = vault.esign_document(document)?;
        Ok(draft_view(document, state))
    }

    /// [`Self::esign_create`] for a narrowed credential: the overlay and
    /// every item judged by `lane` before the write and again in it, the
    /// draft landing through the overlay's own content writer. A draft whose
    /// project takes its overlay out of the lane rolls back whole, never
    /// lands unreadable to its drafter (CALLS `FIX 6403 draft destination
    /// stays readable`, proposed). The view is read in a snapshot that
    /// judges the overlay again.
    fn esign_create_in_lane(
        &self,
        lane: &ScopedRead<'_>,
        document: EntityId,
        input: &EsignCreateRequest,
    ) -> MemoryResult<EsignDraftView> {
        let vault = self.vault();
        {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            lane_scope::reaches_in(lane, &txn, document)?;
            lane_scope::reaches_draft_in(lane, &txn, &input.draft)?;
        }
        let actor = EsignAuditActor {
            actor: self.actor().to_hex(),
            ip: None,
            user_agent: None,
        };
        let now = vault.now_recorded_at();
        let body = match &input.draft.lifecycle {
            Some(rules) => with_lifecycle(&input.draft, now, rules)?,
            None => input.draft.clone(),
        };
        validate_document(&body, now)?;
        lane_scope::write_artifact(lane, self, document, |txn| {
            lane_scope::reaches_draft_in(lane, txn, &body)?;
            create_document_in(vault, txn, document, &body, actor, now)?;
            if input.qr_pdf_download {
                self.admit_qr_pdf_download_in(txn)?;
                set_pdf_download_in_txn(vault, txn, document, true)?;
            }
            lane_scope::reaches_in(lane, txn, document)?;
            Ok(())
        })?;
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        lane_scope::reaches_in(lane, &txn, document)?;
        Ok(draft_view(document, state_in(vault, &txn, document)?))
    }

    /// Admits the caller to turn on a document's QR PDF download in `txn`
    /// (REVIEW-7856 P1): the bound actor is the vault owner, and the
    /// credential it presented, if any, is the owner's own, live and still
    /// held by the owner (as [`crate::Vault::credential_owner_held`] judges).
    /// An owner credential handed to another key (`attenuate_to`) keeps the
    /// owner's holder and class, so the owner check alone admits it.
    /// # Errors
    /// The refusal for any other caller, or the store's failure.
    fn admit_qr_pdf_download_in(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
        let vault = self.vault();
        let owner = crate::memory::actor_is_vault_owner_in_txn(
            vault,
            txn,
            self.actor(),
            self.actor_class(),
        )?;
        let held = match self.presented_credential() {
            None => true,
            Some(proof) => {
                !proof.is_transferred()
                    && vault.capability_slip_is_live_in_txn(txn, proof)?
                    && match vault.credential_target_key_in_txn(txn, proof)? {
                        Some(key) => key.facets_owner_exempt_in(vault, txn)?,
                        None => false,
                    }
            }
        };
        if owner && held {
            return Ok(());
        }
        Err(MemoryError::bad_request(
            "only the vault owner turns on a document's QR PDF download",
        ))
    }
}

/// The view of `document`'s draft as `state` folds it.
fn draft_view(document: EntityId, state: EsignState) -> EsignDraftView {
    EsignDraftView {
        document_ref: document.to_hex(),
        status: state.status,
        title: state.document.title,
        expires_at: state.document.expires_at,
        project_ref: state.document.project.map(|project| project.to_hex()),
        recipients: state
            .document
            .recipients
            .into_iter()
            .map(|recipient| recipient.id)
            .collect(),
        fields: state.document.fields.len(),
    }
}
