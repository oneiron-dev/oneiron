//! Capability-scoped PDF bytes. Canonical reads never follow a mutable blob head.
use super::{
    SigningAction,
    capability::{EsignCapability, binding},
    ledger::state_in,
    model::*,
};
use crate::{EntityId, Result, Vault};
use sha2::{Digest, Sha256};
impl Vault {
    /// During signing this returns the pinned original, and after sealing the
    /// pinned, hash-checked output (verified at seal time). The HTTP carrier serves it as an attachment.
    pub fn esign_pdf_for_capability(
        &self,
        token: &EsignCapability,
        item: usize,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<Vec<u8>> {
        self.esign_pdf_for_capability_within(token, item, ip, user_agent, &|_, _| Ok(true))
    }
    /// [`Self::esign_pdf_for_capability`] under a narrowed caller's
    /// credential ceiling (FIX 6403): the ceremony Load and the read judge
    /// the document the capability binds as soon as the binding names it.
    /// The capability authorizes the item it names, original or sealed.
    pub(super) fn esign_pdf_for_capability_within(
        &self,
        token: &EsignCapability,
        item: usize,
        ip: Option<String>,
        user_agent: Option<String>,
        ceiling: &dyn Fn(&heed::RoTxn<'_>, EntityId) -> Result<bool>,
    ) -> Result<Vec<u8>> {
        self.execute_signing_action_within(
            token,
            &SigningAction::Load,
            super::SigningCaller::Bearer,
            ip,
            user_agent,
            ceiling,
        )?;
        self.esign_pdf_after_admission(token, item, ceiling)
    }
    /// One capability admission for a page and its pinned PDF, for preview callers.
    pub fn esign_preview_for_capability(
        &self,
        token: &EsignCapability,
        item: usize,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(super::SigningPage, Vec<u8>)> {
        let super::SigningOutcome::Page(page) =
            self.execute_signing_action(token, &SigningAction::Load, ip, user_agent)?
        else {
            return Err(invalid("preview is unavailable"));
        };
        let bytes = self.esign_pdf_after_admission(token, item, &|_, _| Ok(true))?;
        Ok((page, bytes))
    }
    /// [`Self::esign_preview_for_capability`] with no byte of the PDF read
    /// (FIX 12304): the page, and the length of the PDF the item reads now,
    /// measured without reading it, so its reader can admit that memory
    /// before [`Self::esign_preview_pdf_within`] reads it.
    pub fn esign_preview_page_for_capability(
        &self,
        token: &EsignCapability,
        item: usize,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(super::SigningPage, u64)> {
        let super::SigningOutcome::Page(page) =
            self.execute_signing_action(token, &SigningAction::Load, ip, user_agent)?
        else {
            return Err(invalid("preview is unavailable"));
        };
        let txn = self.store.env.read_txn()?;
        let pdf = self.pinned_pdf_in(&txn, token, item, &|_, _| Ok(true))?;
        Ok((page, self.pinned_pdf_len_in(&txn, &pdf)?))
    }
    /// The preview's PDF (FIX 12304), found under the checks of
    /// [`Self::esign_preview_for_capability`]'s read, in one snapshot, and
    /// read only when its length is at most `admitted`, the bytes its reader
    /// admitted. A longer one is `Err` with its length, unread.
    pub fn esign_preview_pdf_within(
        &self,
        token: &EsignCapability,
        item: usize,
        admitted: u64,
    ) -> Result<std::result::Result<Vec<u8>, u64>> {
        let txn = self.store.env.read_txn()?;
        let pdf = self.pinned_pdf_in(&txn, token, item, &|_, _| Ok(true))?;
        let len = self.pinned_pdf_len_in(&txn, &pdf)?;
        if len > admitted {
            return Ok(Err(len));
        }
        self.pinned_pdf_bytes_in(&txn, &pdf).map(Ok)
    }
    fn esign_pdf_after_admission(
        &self,
        token: &EsignCapability,
        item: usize,
        ceiling: &dyn Fn(&heed::RoTxn<'_>, EntityId) -> Result<bool>,
    ) -> Result<Vec<u8>> {
        let txn = self.store.env.read_txn()?;
        let pdf = self.pinned_pdf_in(&txn, token, item, ceiling)?;
        self.pinned_pdf_bytes_in(&txn, &pdf)
    }
    /// The PDF version `token`'s item reads in `txn`: during signing the
    /// pinned original, after sealing the pinned output.
    fn pinned_pdf_in(
        &self,
        txn: &heed::RoTxn<'_>,
        token: &EsignCapability,
        item: usize,
        ceiling: &dyn Fn(&heed::RoTxn<'_>, EntityId) -> Result<bool>,
    ) -> Result<PinnedPdf> {
        let now = self.now_recorded_at();
        let cap = binding(self, txn, token)?;
        super::lane_scope::ceiling_admits_in(ceiling, txn, &cap.document)?;
        let id = EntityId::from_hex(&cap.document)?;
        let state = state_in(self, txn, id)?;
        let recipient = state
            .recipients
            .get(&cap.recipient)
            .ok_or_else(|| invalid("invalid capability"))?;
        if cap.revoked_at.is_some()
            || now >= cap.hard_expires_at
            || now >= recipient.expires_at
            || (state.status == DocumentStatus::Pending
                && recipient.signing == SigningStatus::Waiting)
            || matches!(
                state.status,
                DocumentStatus::Draft | DocumentStatus::Voided | DocumentStatus::Expired
            )
        {
            return Err(invalid("PDF is unavailable"));
        }
        if matches!(
            state.status,
            DocumentStatus::Completed | DocumentStatus::Rejected
        ) {
            // Read the canonical swap in THIS snapshot, then the immutable version.
            let manifest = super::seal::CANONICAL
                .get(&self.store, txn, &id)?
                .ok_or_else(|| invalid("sealed manifest missing"))?;
            let item = manifest
                .items
                .get(item)
                .ok_or_else(|| invalid("item missing"))?;
            Ok(PinnedPdf {
                artifact: EntityId::from_hex(&item.sealed_artifact)?,
                version: item.sealed_version,
                sealed_sha256: Some(item.sha256),
            })
        } else {
            let item = state
                .document
                .items
                .get(item)
                .ok_or_else(|| invalid("item missing"))?;
            Ok(PinnedPdf {
                artifact: EntityId::from_hex(&item.artifact_ref)?,
                version: item.original_version,
                sealed_sha256: None,
            })
        }
    }
    /// `pdf`'s length, measured without reading its bytes.
    fn pinned_pdf_len_in(&self, txn: &heed::RoTxn<'_>, pdf: &PinnedPdf) -> Result<u64> {
        self.blob_artifact_version_len_in_txn(txn, &pdf.artifact, pdf.version)?
            .ok_or_else(|| invalid(pdf.missing()))
    }
    /// `pdf`'s bytes; a sealed output's are checked against its hash.
    fn pinned_pdf_bytes_in(&self, txn: &heed::RoTxn<'_>, pdf: &PinnedPdf) -> Result<Vec<u8>> {
        let bytes = self
            .read_blob_artifact_version_in_txn(txn, &pdf.artifact, pdf.version)?
            .ok_or_else(|| invalid(pdf.missing()))?;
        if let Some(sha256) = pdf.sealed_sha256
            && <[u8; 32]>::from(Sha256::digest(&bytes)) != sha256
        {
            return Err(invalid("sealed artifact hash mismatch"));
        }
        Ok(bytes)
    }
}

/// The PDF version a capability's item reads, and, for a sealed output, the
/// SHA-256 its bytes are checked against.
struct PinnedPdf {
    artifact: EntityId,
    version: u64,
    sealed_sha256: Option<[u8; 32]>,
}

impl PinnedPdf {
    /// What a version no longer stored is refused as.
    fn missing(&self) -> &'static str {
        if self.sealed_sha256.is_some() {
            "sealed artifact missing"
        } else {
            "original missing"
        }
    }
}
