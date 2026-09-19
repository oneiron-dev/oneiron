//! Gmail send-as: one human-approved immutable message, one attempted provider call.
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::channel_identity::{
    ChannelIdentityState, DelegatedGrantScope, decode_channel_identity_body,
    verify_delegated_custody_in_txn,
};
use crate::outbound::{OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink};
use crate::{
    EntityId, Vault,
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Typed message, not caller-supplied RFC headers. The wire encodes MIME.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GmailSendMessage {
    pub to: String,
    pub subject: String,
    pub body: String,
}
impl GmailSendMessage {
    pub fn validate(&self) -> Result<()> {
        super::split_email_address(&self.to)?;
        if self.to.contains(['\r', '\n'])
            || self.subject.contains(['\r', '\n'])
            || self.subject.len() > 998
            || self.body.len() > 10 * 1024 * 1024
        {
            return Err(Error::InvalidConfig(
                "Invalid Gmail message bounds or headers".into(),
            ));
        }
        Ok(())
    }
    pub(crate) fn digest(&self, identity: EntityId) -> Result<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(&(identity.to_hex(), self))
            .map_err(|_| Error::InvalidConfig("Invalid Gmail message".into()))?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }
}

/// Gmail API `users.messages.send`. The wire resolves the custody name at egress;
/// it receives neither reusable approval nor token bytes.
pub trait GmailSendWire {
    fn send_message(
        &mut self,
        secret_ref: &str,
        mailbox: &str,
        message: &GmailSendMessage,
    ) -> Result<String>;
}

#[derive(Serialize, Deserialize)]
pub(crate) struct GmailMessageApproval {
    pub(crate) identity: String,
    pub(crate) approver: String,
    pub(crate) digest: String,
    pub(crate) consumed: bool,
}
pub(crate) fn approval_key(intent_ref: &str) -> Result<Vec<u8>> {
    if intent_ref.trim().is_empty() || intent_ref.len() > 512 {
        return Err(Error::InvalidConfig("Invalid Gmail intent ref".into()));
    }
    Ok(format!(
        "gmail:send:approval:v1:{}",
        blake3::hash(intent_ref.as_bytes()).to_hex()
    )
    .into_bytes())
}

/// Re-proves both the stored active row and the custody scope in the consuming transaction.
pub(crate) fn send_binding(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    identity: EntityId,
) -> Result<(String, String)> {
    let raw = vault
        .store
        .entities
        .get(txn, identity.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("identity header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY {
        return Err(Error::InvalidEntityType(header.entity_type));
    }
    let row = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    let grant = row
        .grant
        .as_ref()
        .ok_or_else(|| Error::InvalidConfig("Gmail send requires delegated custody".into()))?;
    if row.channel != "email"
        || row.state != ChannelIdentityState::Active
        || !grant.scopes.contains(&DelegatedGrantScope::MailSend)
    {
        return Err(Error::InvalidConfig(
            "Gmail send requires an active MailSend grant".into(),
        ));
    }
    verify_delegated_custody_in_txn(&vault.store, txn, "email", &row.address_or_handle, grant)?;
    Ok((grant.custody_record_ref.clone(), row.address_or_handle))
}

pub struct GmailDelegatedSendSink<'a, W> {
    vault: &'a Vault,
    wire: W,
    plans: BTreeMap<String, (EntityId, GmailSendMessage)>,
}
impl<'a, W> GmailDelegatedSendSink<'a, W> {
    pub fn new(vault: &'a Vault, wire: W) -> Self {
        Self {
            vault,
            wire,
            plans: BTreeMap::new(),
        }
    }
    pub fn wire(&self) -> &W {
        &self.wire
    }
    pub fn with_message(
        mut self,
        intent_ref: String,
        identity: EntityId,
        message: GmailSendMessage,
    ) -> Result<Self> {
        approval_key(&intent_ref)?;
        message.validate()?;
        if self.plans.insert(intent_ref, (identity, message)).is_some() {
            return Err(Error::InvalidConfig("Gmail intent is already bound".into()));
        }
        Ok(self)
    }
    fn consume(
        &self,
        intent_ref: &str,
        identity: EntityId,
        message: &GmailSendMessage,
    ) -> Result<(String, String, EntityId)> {
        let key = approval_key(intent_ref)?;
        let digest = message.digest(identity)?;
        self.vault.with_write_txn(|txn| {
            let bytes = self.vault.store.vault_meta.get(txn, &key)?.ok_or_else(|| {
                Error::InvalidConfig("Gmail message has no human approval".into())
            })?;
            let mut approval: GmailMessageApproval = serde_json::from_slice(&bytes)
                .map_err(|_| Error::InvalidConfig("Invalid Gmail approval".into()))?;
            if approval.consumed
                || approval.identity != identity.to_hex()
                || approval.digest != digest
            {
                return Err(Error::InvalidConfig(
                    "Gmail approval does not authorize this message".into(),
                ));
            }
            let approver = EntityId::from_hex(&approval.approver)?;
            crate::memory::verify_deletion_authority_in_txn(
                self.vault,
                txn,
                approver,
                crate::edge::EdgeActorClass::Human,
            )
            .map_err(|_| Error::InvalidConfig("Gmail approver is no longer authorized".into()))?;
            let (secret, mailbox) = send_binding(self.vault, txn, identity)?;
            approval.consumed = true;
            let bytes = serde_json::to_vec(&approval)
                .map_err(|_| Error::InvalidConfig("Invalid Gmail approval".into()))?;
            self.vault.store.vault_meta.put(txn, &key, &bytes)?;
            Ok((secret, mailbox, approver))
        })
    }
}
impl<W: GmailSendWire> OutboundExecutionSink for GmailDelegatedSendSink<'_, W> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        if request.intent.channel != "email" || request.verb_contract.kind != "send" {
            return OutboundExecutionOutcome::failed("gmail_send_requires_email_send");
        }
        let Some((identity, message)) = self.plans.get(request.intent_ref).cloned() else {
            return OutboundExecutionOutcome::failed("gmail_send_message_missing");
        };
        if request.channel_identity_ref != Some(identity)
            || request.intent.target != message.to
            || request
                .counterparty_ref
                .is_some_and(|target| target != message.to)
        {
            return OutboundExecutionOutcome::failed("gmail_send_binding_mismatch");
        }
        let (secret, mailbox, approver) = match self.consume(request.intent_ref, identity, &message)
        {
            Ok(binding) => binding,
            Err(_) => {
                return OutboundExecutionOutcome::failed("gmail_send_approval_or_grant_denied");
            }
        };
        let result = match self.wire.send_message(&secret, &mailbox, &message) {
            Ok(id) if !id.trim().is_empty() && id.len() <= 128 => {
                OutboundExecutionOutcome::delivered_to_channel(id)
            }
            _ => OutboundExecutionOutcome::failed("gmail_send_provider_failed")
                .with_possible_delivery(),
        };
        result
            .with_receipt_field("gmail_approval_by", approver.to_hex())
            .with_receipt_field(
                "gmail_message_digest",
                message.digest(identity).expect("validated message"),
            )
    }
}
