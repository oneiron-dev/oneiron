//! `vault.esign.create` (ARCH-0064 D3, D5): a signing document's draft from
//! outside Rust. The upload floor: the caller names PDF artifacts it already
//! registered (`vault.artifacts.create`), places recipients and fields, and
//! the draft lands as the caller, person or agent. Drafting sends nothing:
//! `send_for_signature` stays its own act through the dispatch gate, where
//! the signing principal's autonomy dial rules it.
use super::model::{DocumentStatus, EsignAuditActor, EsignDocument};
use crate::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult};
use serde::{Deserialize, Serialize};

/// A signing document to draft on an existing artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignCreateRequest {
    /// The artifact the signing overlay lives on, already registered: for a
    /// one-PDF document, that PDF's own artifact.
    pub document_ref: String,
    /// The draft: its items pin each PDF's current version. With
    /// `lifecycle` set, a zero document or recipient expiry is set from its
    /// window now; without it, every expiry is explicit. A `project` binds
    /// the document, its trail and its held sign acts to that project, for
    /// one of its members or a vault owner only.
    pub draft: EsignDocument,
}

/// A drafted signing document, as it landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsignDraftView {
    pub document_ref: String,
    pub status: DocumentStatus,
    pub title: String,
    pub expires_at: u64,
    pub project_ref: Option<String>,
    /// The recipients' ids, in the draft's order.
    pub recipients: Vec<String>,
    /// How many fields the draft places.
    pub fields: usize,
}

impl Memory<'_> {
    /// `vault.esign.create`: drafts a signing document on `document_ref` as
    /// the bound actor, whose id the draft's trail names.
    /// # Errors
    /// A `document_ref` that is no id, or the vault's refusal: a draft that
    /// does not validate, an item whose PDF moved past its pinned version, a
    /// project the caller is no member of, or a document already drafted.
    pub fn esign_create(&self, input: &EsignCreateRequest) -> MemoryResult<EsignDraftView> {
        let document = EntityId::from_hex(&input.document_ref)
            .map_err(|_| MemoryError::bad_request("document_ref is not an artifact id"))?;
        let vault = self.vault();
        let actor = EsignAuditActor {
            actor: self.actor().to_hex(),
            ip: None,
            user_agent: None,
        };
        let now = vault.now_recorded_at();
        match &input.draft.lifecycle {
            Some(rules) => vault.create_esign_document_with_lifecycle(
                document,
                &input.draft,
                actor,
                now,
                rules,
            )?,
            None => vault.create_esign_document(document, &input.draft, actor, now)?,
        }
        let state = vault.esign_document(document)?;
        Ok(EsignDraftView {
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
        })
    }
}
