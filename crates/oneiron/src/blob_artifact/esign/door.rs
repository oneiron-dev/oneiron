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
use super::model::DocumentStatus;
use super::outbound::{EsignActScope, EsignOutboundCommand, EsignOutboundVerb};
use crate::consent::AuthenticatedOwner;
use crate::memory::Memory;
use crate::outbound::{OutboundDispatchRequest, OutboundIntent, OutboundIntentDraft};
use crate::store::outbound_actor::OutboundDispatchActor;
use crate::store::outbound_actor::OutboundDispatchGate;
use crate::store::outbound_trigger::OutboundIntentTrigger;
use crate::{EntityId, Vault};
use oneiron_contracts::memory::{MemoryError, MemoryResult};
use oneiron_delivery_vocabulary::delivery_window::types::DeliveryWindowDecision as OutboundDeliveryWindowDecision;
use serde::{Deserialize, Serialize};

mod draft;
mod links;
mod preview;
mod read;

pub use preview::{EsignSigningPreviewRequest, EsignSigningPreviewView, layout_esign_preview};

#[doc(hidden)]
pub use oneiron_verb_wire::blob_artifact::esign::door::{
    EsignCreateRequest, EsignDispatchRequest, EsignGetRequest, EsignLinksIssueRequest,
    EsignSealAttemptView, EsignSealGetRequest, EsignSealedItemView, EsignSealedView,
    EsignSigningImageRequest, EsignSigningImageView, EsignSigningPdfRequest, EsignSigningPdfView,
    EsignSigningSignatureRequest, EsignSigningSignatureView, EsignVoidRequest,
};

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
    fn signing_caller(&self) -> super::SigningCaller {
        match self.actor_class() {
            crate::edge::EdgeActorClass::Human => super::SigningCaller::Person,
            _ => super::SigningCaller::Agent,
        }
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
        let caller = self.signing_caller();
        let vault = self.vault();
        let verified_actor = Some(self.actor());
        let (ip, user_agent) = self.signing_request_transport();
        Ok(match self.esign_scope()? {
            EsignScope::Unrestricted => vault.execute_signing_action_as(
                &token,
                &input.action,
                caller,
                verified_actor,
                ip,
                user_agent,
            )?,
            EsignScope::Credential(lane) => vault.execute_signing_action_within(
                &token,
                &input.action,
                caller,
                verified_actor,
                ip,
                user_agent,
                &|txn: &heed::RoTxn<'_>, document: EntityId| {
                    lane_scope::reaches(&lane, txn, document)
                },
            )?,
        })
    }

    /// `vault.esign.signing.pdf`: one ceremony item's bytes under its
    /// capability, the typed twin of `POST /sign/pdf`: the pinned
    /// original while signing, the hash-checked sealed output after
    /// sealing. Loading the item is a ceremony Load and never records Viewed;
    /// only a later explicit human action does.
    /// # Errors
    /// A capability that does not admit the item.
    pub fn esign_signing_pdf(
        &self,
        input: &EsignSigningPdfRequest,
    ) -> MemoryResult<EsignSigningPdfView> {
        use base64::Engine;
        let token = super::EsignCapability::parse(&input.token)?;
        let caller = self.signing_caller();
        let verified_actor = Some(self.actor());
        let (ip, user_agent) = self.signing_request_transport();
        let vault = self.vault();
        let bytes = match self.esign_scope()? {
            EsignScope::Unrestricted => vault.esign_pdf_for_capability_as(
                &token,
                input.item,
                caller,
                verified_actor,
                ip,
                user_agent,
            )?,
            EsignScope::Credential(lane) => vault.esign_pdf_for_capability_within(
                &token,
                input.item,
                caller,
                verified_actor,
                ip,
                user_agent,
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
        let caller = self.signing_caller();
        let verified_actor = Some(self.actor());
        let vault = self.vault();
        let image_ref = match self.esign_scope()? {
            EsignScope::Unrestricted => {
                vault.upload_esign_signature_image_as(&token, &bytes, caller, verified_actor)?
            }
            EsignScope::Credential(lane) => vault.upload_esign_signature_image_within(
                &token,
                &bytes,
                caller,
                verified_actor,
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
        let caller = self.signing_caller();
        let verified_actor = Some(self.actor());
        let vault = self.vault();
        let bytes = match self.esign_scope()? {
            EsignScope::Unrestricted => vault.esign_signature_image_for_capability_as(
                &token,
                &input.image_ref,
                caller,
                verified_actor,
            )?,
            EsignScope::Credential(lane) => vault.esign_signature_image_for_capability_within(
                &token,
                &input.image_ref,
                caller,
                verified_actor,
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
    let refused = |refusal| {
        MemoryError::from(crate::entity_doc::document_resources::machine_memory_refused(refusal))
    };
    let decoded = u64::try_from(base64::decoded_len_estimate(encoded.len())).unwrap_or(u64::MAX);
    let mut hold = crate::entity_doc::document_resources::document_resources()
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
