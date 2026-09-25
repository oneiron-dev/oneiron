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
        self.execute_signing_action(token, &SigningAction::Load, ip, user_agent)?;
        self.esign_pdf_after_admission(token, item)
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
        let bytes = self.esign_pdf_after_admission(token, item)?;
        Ok((page, bytes))
    }
    fn esign_pdf_after_admission(&self, token: &EsignCapability, item: usize) -> Result<Vec<u8>> {
        let now = crate::unix_seconds_now();
        let txn = self.store.env.read_txn()?;
        let cap = binding(self, &txn, token)?;
        let id = EntityId::from_hex(&cap.document)?;
        let state = state_in(self, &txn, id)?;
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
                .get(&self.store, &txn, &id)?
                .ok_or_else(|| invalid("sealed manifest missing"))?;
            let item = manifest
                .items
                .get(item)
                .ok_or_else(|| invalid("item missing"))?;
            let bytes = self
                .read_blob_artifact_version_in_txn(
                    &txn,
                    &EntityId::from_hex(&item.sealed_artifact)?,
                    item.sealed_version,
                )?
                .ok_or_else(|| invalid("sealed artifact missing"))?;
            if <[u8; 32]>::from(Sha256::digest(&bytes)) != item.sha256 {
                return Err(invalid("sealed artifact hash mismatch"));
            }
            Ok(bytes)
        } else {
            let item = state
                .document
                .items
                .get(item)
                .ok_or_else(|| invalid("item missing"))?;
            self.read_blob_artifact_version_in_txn(
                &txn,
                &EntityId::from_hex(&item.artifact_ref)?,
                item.original_version,
            )?
            .ok_or_else(|| invalid("original missing"))
        }
    }
}
