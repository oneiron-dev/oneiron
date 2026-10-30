//! The e-sign doors outside Rust (ARCH-0064 D3, D5, SGN-02).
//!
//! - `vault.esign.create`: a signing document's draft. The upload floor: the
//!   caller names PDF artifacts it already registered
//!   (`vault.artifacts.create`), places recipients and fields, and the draft
//!   lands as the caller, person or agent. Drafting sends nothing.
//! - `vault.esign.get`: the document's state and its audit trail, or why
//!   its trail does not read, with its delivery receipts either way.
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
//!   input); the bound caller only classes the act, and a narrowed
//!   credential's lane bounds it to the documents that lane reaches.
//! - `vault.esign.seal.get`: the seal task's receipts for one document
//!   and its sealed manifest once sealing lands.
//!
//! FIX 6403: every row admits a world-, facet- or record-scoped credential
//! within its own read lane ([`super::lane_scope`]); an unrestricted caller
//! keeps each row's own path.
use super::delivery_settlement::EsignDeliveryReceipt;
use super::document_view::EsignSealTrail;
use super::lane_scope::{self, EsignScope};
use super::model::{DocumentStatus, EsignDocument};
use super::outbound::{EsignActScope, EsignOutboundCommand, EsignOutboundVerb};
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

mod draft;
mod links;
mod read;

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
    /// A retry under the same key answers the first dispatch's receipt. A
    /// call with none is its own send, keyed on the call's invocation id when
    /// it names one, else a fresh key; its view's `intent_ref` ends in that
    /// key, and a retry of a held call passes it here.
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
    /// A retry under the same key answers the first dispatch's receipt. A
    /// call with none is its own send, keyed on the call's invocation id when
    /// it names one, else a fresh key; its view's `intent_ref` ends in that
    /// key, and a retry of a held call passes it here.
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

/// Where one document's seal stands: every seal attempt the queue still
/// holds for it, its sealed manifest once one attempt sealed it, its
/// delivery receipts, and its folded status, or why its trail does not read
/// (FIX 6554).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EsignSealView {
    pub document_ref: String,
    pub attempts: Vec<EsignSealAttemptView>,
    pub sealed: Option<EsignSealedView>,
    /// The document's delivery receipts, as `vault.esign.get` lists them,
    /// read whether or not its trail reads.
    pub delivery_receipts: Vec<EsignDeliveryReceipt>,
    /// `trail`, `readable` with the folded `status`, or `unreadable` with
    /// its error.
    #[serde(flatten)]
    pub trail: EsignSealTrail,
}

/// What the gate made of one e-sign dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsignDispatchView {
    pub document_ref: String,
    /// `send_for_signature`, `remind` or `void`.
    pub verb: String,
    /// The dispatch's intent ref; its retry key is the tail, the key a
    /// retry of a call that named none passes as `idempotency_key`.
    pub intent_ref: String,
    /// The pipeline outcome: `delivered_to_channel` when the act landed,
    /// `held`, `suppressed` or `failed` otherwise.
    pub outcome: String,
    /// The gate's outcome (`allow`, `pending`, `deny`).
    pub gate_outcome: String,
    /// The persisted gate decision, readable with `vault.receipts.get`.
    pub gate_decision_ref: Option<String>,
    pub gate_reason_codes: Vec<String>,
    /// While the gate holds the act for the owner (`gate_outcome`
    /// `pending`), the approve-once digest his one-time press must name to
    /// release it, 64 lower-hex (FIX 6424): it pins this document, this
    /// command and this act's send ref, so the retry that spends it carries
    /// this view's retry key.
    pub approval_digest: Option<String>,
}

impl Memory<'_> {
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
        let vault = self.vault();
        Ok(match self.esign_scope()? {
            EsignScope::Unrestricted => {
                vault.execute_signing_action_as(&token, &input.action, caller, None, None)?
            }
            EsignScope::Credential(lane) => vault.execute_signing_action_within(
                &token,
                &input.action,
                caller,
                None,
                None,
                &|txn: &heed::RoTxn<'_>, document: EntityId| {
                    lane_scope::reaches(&lane, txn, document)
                },
            )?,
        })
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
        let vault = self.vault();
        let bytes = match self.esign_scope()? {
            EsignScope::Unrestricted => {
                vault.esign_pdf_for_capability(&token, input.item, None, None)?
            }
            EsignScope::Credential(lane) => vault.esign_pdf_for_capability_within(
                &token,
                input.item,
                None,
                None,
                &|txn: &heed::RoTxn<'_>, document: EntityId| {
                    lane_scope::reaches(&lane, txn, document)
                },
            )?,
        };
        Ok(EsignSigningPdfView {
            item: input.item,
            pdf_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        })
    }

    /// `vault.esign.signing.image`: stores one signature image bound to
    /// the capability's recipient, the typed twin of `POST /sign/image`,
    /// and answers the ref a signature field's value names. Its memory is
    /// reserved from the host's machine memory before it is allocated
    /// (`admitted_signature_image`, FIX 8064).
    /// # Errors
    /// A capability that does not admit an upload, image bytes that are
    /// not base64, an image the store refuses, or memory the host's floor
    /// or wait refused.
    pub fn esign_signing_image(
        &self,
        input: &EsignSigningImageRequest,
    ) -> MemoryResult<EsignSigningImageView> {
        let token = super::EsignCapability::parse(&input.token)?;
        let (_memory, bytes) = admitted_signature_image(&input.png_or_jpeg_base64)?;
        let vault = self.vault();
        let image_ref = match self.esign_scope()? {
            EsignScope::Unrestricted => vault.upload_esign_signature_image(&token, &bytes)?,
            EsignScope::Credential(lane) => vault.upload_esign_signature_image_within(
                &token,
                &bytes,
                &|txn: &heed::RoTxn<'_>, document: EntityId| {
                    lane_scope::reaches(&lane, txn, document)
                },
            )?,
        };
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
        let vault = self.vault();
        let bytes = match self.esign_scope()? {
            EsignScope::Unrestricted => {
                vault.esign_signature_image_for_capability(&token, &input.image_ref)?
            }
            EsignScope::Credential(lane) => vault.esign_signature_image_for_capability_within(
                &token,
                &input.image_ref,
                &|txn: &heed::RoTxn<'_>, document: EntityId| {
                    lane_scope::reaches(&lane, txn, document)
                },
            )?,
        };
        Ok(EsignSigningSignatureView {
            image_ref: input.image_ref.clone(),
            image_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        })
    }

    /// `vault.esign.links.issue`: the vault owner mints the draft's signing
    /// capabilities and receives each new one once, to deliver. Only the
    /// owner's proof mints: the one the host bound to this request, else the
    /// embedded owner's own. A narrowed credential mints only as the vault
    /// owner's own, on a draft its lane reaches (FIX 6403).
    /// # Errors
    /// A caller that is not the vault owner, a document already sent, or no
    /// such document.
    pub fn esign_links_issue(
        &self,
        input: &EsignLinksIssueRequest,
    ) -> MemoryResult<EsignLinksView> {
        const VERB: &str = "vault.esign.links.issue";
        let document = document_id(&input.document_ref)?;
        if let EsignScope::Credential(lane) = self.esign_scope()? {
            return self.esign_links_issue_in_lane(&lane, document, input.rotate);
        }
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
        Ok(links::links_view(document, state, minted))
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
        let scope = self.esign_scope()?;
        let vault = self.vault();
        let (actor, class) = (self.actor(), self.actor_class());
        crate::memory::verify_actor_binding(vault, actor, class)?;
        // FIX 6403: a narrowed caller's lane judges the document and its
        // originals before the act is built, a void on the whole chain, and
        // again in the gate's writer and in the act's own write.
        let restrictive = verb == EsignOutboundVerb::Void;
        scope.admit_signing_document(vault, document, restrictive)?;
        // FIX 6424: a call with no key is keyed on its own invocation.
        let key = super::dispatch_key::esign_dispatch_key(
            vault,
            verb,
            document,
            actor,
            on_behalf_of,
            idempotency_key,
            self.invocation(),
        )?;
        let request =
            esign_dispatch_request(vault, verb, document, actor, class, on_behalf_of, key);
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
        let result = match (&scope, self.owner_authorship().or(embedded.as_ref())) {
            (EsignScope::Credential(lane), owner) => vault.dispatch_esign_in_scope(
                request,
                &command,
                owner,
                EsignActScope {
                    writer: crate::WriteActor::new(actor, class),
                    reaches: &|txn: &heed::RoTxn<'_>| {
                        lane_scope::reaches_signing_document(
                            lane,
                            vault,
                            txn,
                            document,
                            restrictive,
                        )
                    },
                },
            ),
            (EsignScope::Unrestricted, Some(owner)) => {
                vault.dispatch_esign_as_owner(request, &command, owner)
            }
            (EsignScope::Unrestricted, None) => vault.dispatch_esign(request, &command, None, None),
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
            approval_digest: result.approval_digest,
        })
    }
}

/// The OF-327 request for one e-sign act by the bound caller: channel
/// `esign`, the act's verb, the document as target, sent now. Its intent ref
/// carries the retry key, so a retry replays the first receipt. A call with
/// no key is keyed on its own call (FIX 6424).
fn esign_dispatch_request(
    vault: &Vault,
    verb: EsignOutboundVerb,
    document: EntityId,
    actor: EntityId,
    class: crate::edge::EdgeActorClass,
    on_behalf_of: Option<&str>,
    key: String,
) -> OutboundDispatchRequest {
    let intent_ref = super::dispatch_key::esign_intent_ref(verb, document, &key);
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
    OutboundDispatchRequest::new(
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
    )
}

/// The signature image a typed door carries as base64, its memory reserved
/// from the host's machine memory before it is allocated (FIX 8064), as
/// `POST /sign/image` leases its spool's: first the decoded bytes, then the
/// peak its decode and re-encode hold, planned from its header over a cursor
/// ([`super::plan_signature_image`]). The hold returned keeps both until the
/// upload returns. The host's port waits its queue wait and refuses only at
/// the machine's floor or that wait; a process with no registered host
/// reserves nothing, as before.
fn admitted_signature_image(
    encoded: &str,
) -> MemoryResult<(oneiron_docedit::resource::Hold, Vec<u8>)> {
    use base64::Engine;
    let refused = |refusal| MemoryError::from(crate::office_body::document_refused(refusal));
    let decoded = u64::try_from(base64::decoded_len_estimate(encoded.len())).unwrap_or(u64::MAX);
    let mut hold = crate::office_body::document_resources()
        .reserve(decoded)
        .map_err(refused)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| MemoryError::bad_request("png_or_jpeg_base64 is not base64"))?;
    let plan = super::plan_signature_image(&mut std::io::Cursor::new(bytes.as_slice()))?;
    // A peak past u64 fits no machine: the host's floor refuses it.
    let peak = plan
        .peak_bytes(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
        .unwrap_or(u64::MAX);
    hold.take(peak.saturating_sub(decoded)).map_err(refused)?;
    Ok((hold, bytes))
}
