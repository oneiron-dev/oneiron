//! The e-sign doors outside Rust (ARCH-0064 D3, D5, SGN-02).
//!
//! - `vault.esign.create`: a signing document's draft. The upload floor: the
//!   caller names PDF artifacts it already registered
//!   (`vault.artifacts.create`), places recipients and fields, and the draft
//!   lands as the caller, person or agent. Drafting sends nothing.
//! - `vault.esign.get`: the document's state and its audit trail.
//! - `vault.esign.links.issue`: the owner mints the recipients' signing
//!   capabilities in DRAFT and receives them, once, to deliver.
//! - `vault.esign.send_for_signature`, `vault.esign.remind`,
//!   `vault.esign.void`: the outbound verbs, each one dispatch through the
//!   OF-327 gate as the caller ([`Vault::dispatch_esign`]); the gate's grants
//!   and ceilings rule a person's send, and the signing principal's autonomy
//!   dial an agent's.
//! - `vault.esign.signing.act`, `vault.esign.signing.pdf`,
//!   `vault.esign.signing.image`, `vault.esign.signing.signature`: the
//!   recipient ceremony, typed twins of the public `/sign/*` doors. The
//!   capability in the request is the authority (the public doors carry it
//!   in the `x-oneiron-esign-capability` header, these rows in their
//!   input); the bound caller only classes the act.
//! - `vault.esign.seal.get`: the seal task's receipts for one document
//!   and its sealed manifest once sealing lands.
use super::delivery_settlement::EsignDeliveryReceipt;
use super::model::{
    DocumentStatus, EsignAuditActor, EsignDocument, EsignEventRow, RecipientState, SignatureRow,
};
use super::outbound::{EsignOutboundCommand, EsignOutboundVerb};
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
        let document = document_id(&input.document_ref)?;
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

fn document_id(document_ref: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(document_ref)
        .map_err(|_| MemoryError::bad_request("document_ref is not an artifact id"))
}

/// A signing document to read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignGetRequest {
    /// The artifact the signing overlay lives on.
    pub document_ref: String,
}

/// A signing document as its trail folds, with the trail itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EsignDocumentView {
    pub document_ref: String,
    pub status: DocumentStatus,
    /// An event of the document awaits its owner's answer (a held sign
    /// act); the state shows it folded in, and other acts wait for it.
    pub awaits_owner_answer: bool,
    /// The draft as it was sent: items, recipients, fields, expiry.
    pub document: EsignDocument,
    /// Each recipient's delivery, signing and access status, by id.
    pub recipients: BTreeMap<String, RecipientState>,
    /// The current value of each filled field.
    pub signatures: Vec<SignatureRow>,
    /// A recipient's decline reason, once one declined.
    pub rejection: Option<String>,
    /// SHA-256 of each sealed item, hex, once sealed.
    pub sealed_sha256: Vec<String>,
    /// The hash-chained trail, oldest first: every event, its actor and time.
    pub audit: Vec<EsignEventRow>,
    /// The invitations and reminders that ended unsent, oldest first (FIX 6363).
    pub delivery_receipts: Vec<EsignDeliveryReceipt>,
}

/// The document whose recipients' signing links to mint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignLinksIssueRequest {
    /// The drafted document, not yet sent.
    pub document_ref: String,
    /// Revoke every live link of the draft first and mint all afresh, for
    /// links lost before the send. Without it, only recipients holding no
    /// usable link get one.
    #[serde(default)]
    pub rotate: bool,
}

/// One recipient's new signing link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsignIssuedLink {
    pub recipient: String,
    pub email: String,
    /// The bearer capability, shown this once: the recipient opens the
    /// host's signing page with it as the fragment (`/sign#<capability>`).
    /// The vault keeps only its digest.
    pub capability: String,
}

/// The signing links a draft holds after the issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsignLinksView {
    pub document_ref: String,
    /// The links minted now, in the draft's recipient order.
    pub issued: Vec<EsignIssuedLink>,
    /// The recipients whose earlier link still holds, and is not shown again.
    pub unchanged: Vec<String>,
}

/// One send or reminder of a signing document through the dispatch gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignDispatchRequest {
    /// The signing document.
    pub document_ref: String,
    /// The recipient count the caller reviewed; a document whose recipients
    /// changed since is refused.
    pub recipient_count: usize,
    /// The signing principal an agent acts for: its autonomy dial must be
    /// `autonomous_in_envelope` for an agent's dispatch to land.
    #[serde(default)]
    pub on_behalf_of: Option<String>,
    /// A retry under the same key answers the first dispatch's receipt.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

/// One void of a signing document through the dispatch gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignVoidRequest {
    /// The signing document, drafted or pending.
    pub document_ref: String,
    /// The recipient count the caller reviewed.
    pub recipient_count: usize,
    /// Why the sender withdraws it; the trail and the void notice carry it.
    pub reason: String,
    /// The signing principal an agent acts for.
    #[serde(default)]
    pub on_behalf_of: Option<String>,
    /// A retry under the same key answers the first dispatch's receipt.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

/// One recipient ceremony act (`vault.esign.signing.act`): the signing
/// link's capability and the act it asks for. The public `POST /sign/action`
/// door takes the act alone; its capability rides in the
/// `x-oneiron-esign-capability` header, admitted before the body is read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSigningRequest {
    /// The recipient's Bearer [REDACTED] from their signing link. It is the
    /// ceremony's authority; a credential the call also presents only
    /// classes the caller (an agent's Complete is an automated sign act).
    pub token: String,
    /// Load, save one field, complete with consent, or reject.
    pub action: super::SigningAction,
}

/// One ceremony document item to download (`vault.esign.signing.pdf`):
/// the pinned original while signing, the sealed output after sealing.
/// The public `POST /sign/pdf` door takes the item alone, under the
/// `x-oneiron-esign-capability` header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSigningPdfRequest {
    /// The recipient's Bearer [REDACTED].
    pub token: String,
    /// Which of the document's items, by position.
    pub item: usize,
}

/// One downloaded ceremony item, as base64 PDF bytes. The public
/// `POST /sign/pdf` door serves the same bytes as an attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSigningPdfView {
    pub item: usize,
    pub pdf_base64: String,
}

/// One signature image to upload for a signature field
/// (`vault.esign.signing.image`), bound to the capability's recipient.
/// The public `POST /sign/image` door takes the raw PNG or JPEG bytes as
/// its body, under the `x-oneiron-esign-capability` header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSigningImageRequest {
    /// The recipient's Bearer [REDACTED].
    pub token: String,
    /// The PNG or JPEG signature image, base64.
    pub png_or_jpeg_base64: String,
}

/// The stored signature image's ref, for a signature field's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSigningImageView {
    pub image_ref: String,
}

/// One stored signature image to read back (`vault.esign.signing.signature`),
/// under the capability that uploaded it. The public `POST /sign/signature`
/// door takes the image ref alone, under the `x-oneiron-esign-capability`
/// header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSigningSignatureRequest {
    /// The recipient's Bearer [REDACTED].
    pub token: String,
    pub image_ref: String,
}

/// One stored signature image, as base64 bytes. The public
/// `POST /sign/signature` door serves the same bytes as an image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSigningSignatureView {
    pub image_ref: String,
    pub image_base64: String,
}

/// A signing document whose seal task to observe (`vault.esign.seal.get`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSealGetRequest {
    /// The artifact the signing overlay lives on.
    pub document_ref: String,
}

/// One queued or finished seal attempt of a document: the seal task's
/// receipt row, in creation order beside its siblings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSealAttemptView {
    /// The attempt's id, hex; a sealed document's manifest names the
    /// attempt that sealed it by this same ref.
    pub attempt_ref: String,
    /// The attempt kind, `esign.seal`.
    pub kind: String,
    /// `queued`, `leased`, `completed`, `failed`, or another attempt state.
    pub state: String,
    /// The seal generation the attempt was queued for: the document and
    /// its generation, as the dedupe key spells them, while it is kept.
    pub dedupe_key: Option<String>,
    /// The worker holding or last holding the attempt's lease.
    pub lease_owner: Option<String>,
    /// Lease generations taken within this one try.
    pub attempt_count: u32,
    pub created_at: u64,
    pub updated_at: u64,
    /// The failure a failed attempt kept; the backstop queues it again.
    pub last_error: Option<String>,
}

/// One sealed item's provenance: the frozen original it came from and the
/// sealed version that replaced it, with the sealed bytes' SHA-256, hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSealedItemView {
    pub original_artifact: String,
    pub original_version: u64,
    pub sealed_artifact: String,
    pub sealed_version: u64,
    pub sha256: String,
}

/// A sealed document's manifest: which attempt sealed it, over which
/// audit chain, and what each item became.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSealedView {
    /// The seal attempt that produced this manifest, by its attempt ref.
    pub attempt_ref: String,
    /// SHA-256 of the audit trail the seal covered, hex.
    pub audit_chain_sha256: String,
    /// Sealed on a rejection rather than a completion.
    pub rejected: bool,
    pub items: Vec<EsignSealedItemView>,
}

/// Where one document's seal stands: its folded status, every seal
/// attempt the queue still holds for it, and its sealed manifest once
/// one attempt sealed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSealView {
    pub document_ref: String,
    pub status: DocumentStatus,
    pub attempts: Vec<EsignSealAttemptView>,
    pub sealed: Option<EsignSealedView>,
}

/// What the gate made of one e-sign dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsignDispatchView {
    pub document_ref: String,
    /// `send_for_signature`, `remind` or `void`.
    pub verb: String,
    /// The dispatch's intent ref; its retry key is the tail.
    pub intent_ref: String,
    /// The pipeline outcome: `delivered_to_channel` when the act landed,
    /// `held`, `suppressed` or `failed` otherwise.
    pub outcome: String,
    /// The gate's outcome (`allow`, `pending`, `deny`).
    pub gate_outcome: String,
    /// The persisted gate decision, readable with `vault.receipts.get`.
    pub gate_decision_ref: Option<String>,
    pub gate_reason_codes: Vec<String>,
}

impl Memory<'_> {
    /// `vault.esign.get`: the document's folded state and its trail. The
    /// row's refs admission reads `document_ref` under the caller's scope
    /// first, so a project's document reads only in its audience.
    /// # Errors
    /// A `document_ref` that is no id or names no signing document, or a
    /// broken trail.
    pub fn esign_get(&self, input: &EsignGetRequest) -> MemoryResult<EsignDocumentView> {
        let document = document_id(&input.document_ref)?;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let (state, audit, held) = super::ledger::read_in(vault, &txn, document)?;
        let delivery_receipts =
            super::delivery_settlement::delivery_receipts_in(vault, &txn, document)?;
        Ok(EsignDocumentView {
            document_ref: document.to_hex(),
            status: state.status,
            awaits_owner_answer: held,
            document: state.document,
            recipients: state.recipients,
            signatures: state.signatures.into_values().collect(),
            rejection: state.rejection,
            sealed_sha256: state
                .sealed_sha256
                .iter()
                .map(|digest| crate::entity_id::bytes_to_hex_lower(digest.as_slice()))
                .collect(),
            audit,
            delivery_receipts,
        })
    }

    /// `vault.esign.signing.act`: one recipient ceremony act under the
    /// capability in the request body, the typed twin of the public
    /// `POST /sign/action` door. The capability is the authority; the
    /// bound caller only classes the act, as on that door: a human signs
    /// in person, any other class's Complete is an automated sign act.
    /// # Errors
    /// A capability that does not parse or no longer admits its
    /// recipient, or the ceremony's own refusal. No refusal echoes the
    /// capability.
    pub fn esign_signing_act(
        &self,
        input: &EsignSigningRequest,
    ) -> MemoryResult<super::SigningOutcome> {
        let token = super::EsignCapability::parse(&input.token)?;
        let caller = match self.actor_class() {
            crate::edge::EdgeActorClass::Human => super::SigningCaller::Person,
            _ => super::SigningCaller::Agent,
        };
        Ok(self
            .vault()
            .execute_signing_action_as(&token, &input.action, caller, None, None)?)
    }

    /// `vault.esign.signing.pdf`: one ceremony item's bytes under its
    /// capability, the typed twin of `POST /sign/pdf`: the pinned
    /// original while signing, the hash-checked sealed output after
    /// sealing. Loading the item is a ceremony Load, so a first download
    /// marks the recipient viewed, as on the public door.
    /// # Errors
    /// A capability that does not admit the item.
    pub fn esign_signing_pdf(
        &self,
        input: &EsignSigningPdfRequest,
    ) -> MemoryResult<EsignSigningPdfView> {
        use base64::Engine;
        let token = super::EsignCapability::parse(&input.token)?;
        let bytes = self
            .vault()
            .esign_pdf_for_capability(&token, input.item, None, None)?;
        Ok(EsignSigningPdfView {
            item: input.item,
            pdf_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        })
    }

    /// `vault.esign.signing.image`: stores one signature image bound to
    /// the capability's recipient, the typed twin of `POST /sign/image`,
    /// and answers the ref a signature field's value names.
    /// # Errors
    /// A capability that does not admit an upload, image bytes that are
    /// not base64, or an image the store refuses.
    pub fn esign_signing_image(
        &self,
        input: &EsignSigningImageRequest,
    ) -> MemoryResult<EsignSigningImageView> {
        use base64::Engine;
        let token = super::EsignCapability::parse(&input.token)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&input.png_or_jpeg_base64)
            .map_err(|_| MemoryError::bad_request("png_or_jpeg_base64 is not base64"))?;
        let image_ref = self.vault().upload_esign_signature_image(&token, &bytes)?;
        Ok(EsignSigningImageView { image_ref })
    }

    /// `vault.esign.signing.signature`: reads back one stored signature
    /// image under the capability that uploaded it, the typed twin of
    /// `POST /sign/signature`.
    /// # Errors
    /// A capability that does not own the named image.
    pub fn esign_signing_signature(
        &self,
        input: &EsignSigningSignatureRequest,
    ) -> MemoryResult<EsignSigningSignatureView> {
        use base64::Engine;
        let token = super::EsignCapability::parse(&input.token)?;
        let bytes = self
            .vault()
            .esign_signature_image_for_capability(&token, &input.image_ref)?;
        Ok(EsignSigningSignatureView {
            image_ref: input.image_ref.clone(),
            image_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        })
    }

    /// `vault.esign.seal.get`: where the document's seal task stands:
    /// its folded status, every `esign.seal` attempt the queue holds
    /// for it in creation order, and the sealed manifest once one
    /// attempt sealed it. The row's refs admission reads `document_ref`
    /// under the caller's scope first, as `vault.esign.get` does.
    /// # Errors
    /// A `document_ref` that is no id or names no signing document.
    pub fn esign_seal_get(&self, input: &EsignSealGetRequest) -> MemoryResult<EsignSealView> {
        let document = document_id(&input.document_ref)?;
        let vault = self.vault();
        let attempts = crate::attempt_queue::AttemptQueue::new(vault)
            .list_kind_bounded(super::ESIGN_SEAL_ATTEMPT_KIND, usize::MAX)?
            .into_iter()
            .filter(|record| record.payload.as_slice() == document.as_bytes().as_slice())
            .map(|record| EsignSealAttemptView {
                attempt_ref: crate::entity_id::bytes_to_hex_lower(record.id.as_bytes()),
                kind: record.kind,
                state: record.state.as_str().to_owned(),
                dedupe_key: record.dedupe_key,
                lease_owner: record.lease_owner,
                attempt_count: record.attempt_count,
                created_at: record.created_at,
                updated_at: record.updated_at,
                last_error: record.last_error,
            })
            .collect();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let (state, _, _) = super::ledger::read_in(vault, &txn, document)?;
        let sealed = super::seal::CANONICAL
            .get(&vault.store, &txn, &document)?
            .map(|manifest| EsignSealedView {
                attempt_ref: manifest.attempt_ref,
                audit_chain_sha256: crate::entity_id::bytes_to_hex_lower(
                    manifest.audit_chain_sha256.as_slice(),
                ),
                rejected: manifest.rejected,
                items: manifest
                    .items
                    .into_iter()
                    .map(|item| EsignSealedItemView {
                        original_artifact: item.original_artifact,
                        original_version: item.original_version,
                        sealed_artifact: item.sealed_artifact,
                        sealed_version: item.sealed_version,
                        sha256: crate::entity_id::bytes_to_hex_lower(item.sha256.as_slice()),
                    })
                    .collect(),
            });
        Ok(EsignSealView {
            document_ref: document.to_hex(),
            status: state.status,
            attempts,
            sealed,
        })
    }

    /// `vault.esign.links.issue`: the vault owner mints the draft's signing
    /// capabilities and receives each new one once, to deliver. Only the
    /// owner's proof mints: the one the host bound to this request, else the
    /// embedded owner's own.
    /// # Errors
    /// A caller that is not the vault owner, a document already sent, or no
    /// such document.
    pub fn esign_links_issue(
        &self,
        input: &EsignLinksIssueRequest,
    ) -> MemoryResult<EsignLinksView> {
        const VERB: &str = "vault.esign.links.issue";
        let document = document_id(&input.document_ref)?;
        let embedded: AuthenticatedOwner;
        let owner = match self.owner_authorship() {
            Some(owner) => owner,
            None => {
                embedded = self.embedded_owner(VERB)?;
                &embedded
            }
        };
        let vault = self.vault();
        let minted = if input.rotate {
            vault.reissue_esign_capabilities(owner, document)?
        } else {
            vault.issue_esign_capabilities(owner, document)?
        };
        let state = vault.esign_document(document)?;
        let mut minted: BTreeMap<String, super::EsignCapability> = minted.into_iter().collect();
        let mut issued = Vec::new();
        let mut unchanged = Vec::new();
        for recipient in state.document.recipients {
            match minted.remove(&recipient.id) {
                Some(capability) => issued.push(EsignIssuedLink {
                    capability: capability.expose_for_delivery().to_owned(),
                    recipient: recipient.id,
                    email: recipient.email,
                }),
                None => unchanged.push(recipient.id),
            }
        }
        Ok(EsignLinksView {
            document_ref: document.to_hex(),
            issued,
            unchanged,
        })
    }

    /// `vault.esign.send_for_signature`: sends the drafted document to its
    /// recipients through the dispatch gate, as the caller.
    /// # Errors
    /// See [`Memory::esign_void`].
    pub fn esign_send_for_signature(
        &self,
        input: &EsignDispatchRequest,
    ) -> MemoryResult<EsignDispatchView> {
        self.esign_dispatch(
            EsignOutboundVerb::SendForSignature,
            &input.document_ref,
            input.recipient_count,
            None,
            input.on_behalf_of.as_deref(),
            input.idempotency_key.as_deref(),
        )
    }

    /// `vault.esign.remind`: reminds every recipient whose turn it is of the
    /// pending document, through the dispatch gate, as the caller.
    /// # Errors
    /// See [`Memory::esign_void`].
    pub fn esign_remind(&self, input: &EsignDispatchRequest) -> MemoryResult<EsignDispatchView> {
        self.esign_dispatch(
            EsignOutboundVerb::Remind,
            &input.document_ref,
            input.recipient_count,
            None,
            input.on_behalf_of.as_deref(),
            input.idempotency_key.as_deref(),
        )
    }

    /// `vault.esign.void`: withdraws a drafted or pending document, unsealed,
    /// and tells its recipients, through the dispatch gate, as the caller.
    /// # Errors
    /// A `document_ref` or `on_behalf_of` that is no id, an empty reason or
    /// retry key, a caller whose binding no longer holds, a document whose
    /// recipients changed since the reviewed count, or the dispatch's own
    /// refusal. A gate that holds or denies the act, or a document that
    /// cannot take it, is an outcome in the view, not an error.
    pub fn esign_void(&self, input: &EsignVoidRequest) -> MemoryResult<EsignDispatchView> {
        if input.reason.trim().is_empty() {
            return Err(MemoryError::bad_request("a void names its reason"));
        }
        self.esign_dispatch(
            EsignOutboundVerb::Void,
            &input.document_ref,
            input.recipient_count,
            Some(&input.reason),
            input.on_behalf_of.as_deref(),
            input.idempotency_key.as_deref(),
        )
    }

    fn esign_dispatch(
        &self,
        verb: EsignOutboundVerb,
        document_ref: &str,
        recipient_count: usize,
        reason: Option<&str>,
        on_behalf_of: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> MemoryResult<EsignDispatchView> {
        let document = document_id(document_ref)?;
        if let Some(principal) = on_behalf_of {
            EntityId::from_hex(principal)
                .map_err(|_| MemoryError::bad_request("on_behalf_of is not an entity id"))?;
        }
        let vault = self.vault();
        let (actor, class) = (self.actor(), self.actor_class());
        crate::memory::verify_actor_binding(vault, actor, class)?;
        let request = esign_dispatch_request(
            vault,
            verb,
            document,
            actor,
            class,
            on_behalf_of,
            idempotency_key,
        )?;
        let intent_ref = request.intent_ref.clone();
        let command = EsignOutboundCommand {
            document: document.to_hex(),
            recipient_count,
            verb,
            reason: reason.map(str::to_owned),
        };
        // The owner's own act carries his proof into the send, so each
        // delivery it queues mints its signing link (FIX 5238).
        let embedded = match self.owner_authorship() {
            Some(_) => None,
            None => self.embedded_owner(verb.as_str()).ok(),
        };
        let result = match self.owner_authorship().or(embedded.as_ref()) {
            Some(owner) => vault.dispatch_esign_as_owner(request, &command, owner),
            None => vault.dispatch_esign(request, &command, None, None),
        }
        .map_err(crate::memory::facade_error_from_outbound_dispatch)?;
        Ok(EsignDispatchView {
            document_ref: document.to_hex(),
            verb: verb.as_str().to_owned(),
            intent_ref,
            outcome: result.outcome.as_str().to_owned(),
            gate_outcome: result.gate_outcome,
            gate_decision_ref: result.gate_decision_id,
            gate_reason_codes: result.gate_reason_codes,
        })
    }
}

/// The OF-327 request for one e-sign act by the bound caller: channel
/// `esign`, the act's verb, the document as target, sent now. Its intent ref
/// carries the retry key, so a retry replays the first receipt.
fn esign_dispatch_request(
    vault: &Vault,
    verb: EsignOutboundVerb,
    document: EntityId,
    actor: EntityId,
    class: crate::edge::EdgeActorClass,
    on_behalf_of: Option<&str>,
    idempotency_key: Option<&str>,
) -> MemoryResult<OutboundDispatchRequest> {
    let key = match idempotency_key {
        Some(key) if key.trim().is_empty() => {
            return Err(MemoryError::bad_request("idempotency_key is empty"));
        }
        Some(key) => key.to_owned(),
        None => vault.new_entity_id()?.to_hex(),
    };
    let intent_ref = format!("esign:{}:{}:{key}", verb.as_str(), document.to_hex());
    let mut draft =
        OutboundIntentDraft::new(actor.to_hex(), verb.as_str(), "esign", document.to_hex())
            .idempotency_key(key)
            .dedupe_key(intent_ref.clone());
    if let Some(principal) = on_behalf_of {
        draft = draft.on_behalf_of(principal);
    }
    let intent = OutboundIntent::from_trigger(
        draft,
        OutboundIntentTrigger::agent_immediate(intent_ref.clone()),
    );
    Ok(OutboundDispatchRequest::new(
        format!("receipt:{intent_ref}"),
        intent_ref,
        intent,
        OutboundDispatchActor {
            actor_class: class.gate_actor_class().to_owned(),
            actor_ref: Some(actor.to_hex()),
            actor_entity_ref: Some(actor),
        },
        OutboundDispatchGate::allow_when_policy_grants(),
        vault.now_recorded_at(),
        OutboundDeliveryWindowDecision::DeliverNow,
    ))
}
