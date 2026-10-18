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
        let result = vault
            .dispatch_esign(request, &command, None, None)
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
