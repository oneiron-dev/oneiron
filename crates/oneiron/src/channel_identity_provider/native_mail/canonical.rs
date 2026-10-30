//! The canonical mail operation: the one logical send both the owner's
//! approve-once tap and the Gate's mail lane compose their digest from.
use super::canonical_recipient;
use crate::gate::{
    ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateProvenanceHandles,
};
use crate::outbound::OutboundDispatchRequest;
use crate::{EntityId, Error, Result};

/// One stable logical mail send, independent of approval availability and
/// current sender lifecycle. Both owner tap and Gate compose their digest from
/// this operation; the dispatcher freezes its canonical recipient into the
/// ordinary intent that the sink receives and the ledger compares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalMailSend {
    pub(crate) actor: EntityId,
    pub(crate) identity: EntityId,
    pub(crate) recipient: String,
    pub(crate) logical_ref: String,
    pub(crate) content_ref: Option<String>,
    pub(crate) brief_ref: Option<String>,
}

impl CanonicalMailSend {
    pub(crate) fn from_request(request: &OutboundDispatchRequest) -> Result<Self> {
        if !request.intent.channel.trim().eq_ignore_ascii_case("email")
            || !request.intent.verb.trim().eq_ignore_ascii_case("send")
        {
            return Err(Error::InvalidConfig("invalid native-mail operation".into()));
        }
        let identity = request
            .channel_identity_ref
            .ok_or_else(|| Error::InvalidConfig("missing native-mail sender".into()))?;
        let actor = request
            .actor
            .actor_entity_ref
            .ok_or_else(|| Error::InvalidConfig("missing native-mail actor".into()))?;
        let recipient = canonical_recipient(&request.intent.target)?;
        if let Some(contact) = request.counterparty_ref.as_deref()
            && canonical_recipient(contact)? != recipient
        {
            return Err(Error::InvalidConfig(
                "native-mail target and counterparty differ".into(),
            ));
        }
        if request.intent_ref.trim().is_empty() {
            return Err(Error::InvalidConfig("missing native-mail send ref".into()));
        }
        Ok(Self {
            actor,
            identity,
            recipient,
            logical_ref: request.intent_ref.clone(),
            content_ref: request.intent.content_ref.clone(),
            brief_ref: request.intent.job_ref.clone(),
        })
    }

    pub(crate) fn from_effect(effect: &ExternalEffectGateInput) -> Option<Self> {
        let actor = effect.provenance.actor_entity_ref?;
        if effect.channel != "email"
            || effect.verb != "send"
            || effect.actor.actor_ref.as_deref() != Some(actor.to_hex().as_str())
        {
            return None;
        }
        Some(Self {
            actor,
            identity: effect.channel_identity_ref?,
            recipient: canonical_recipient(effect.counterparty.as_deref()?).ok()?,
            logical_ref: effect.send_ref.as_ref()?.clone(),
            content_ref: effect.provenance.mail_content_ref.clone(),
            brief_ref: effect.brief_ref.clone(),
        })
    }

    fn optional_string(value: &serde_json::Value, key: &str) -> Option<Option<String>> {
        match value.get(key) {
            None | Some(serde_json::Value::Null) => Some(None),
            Some(serde_json::Value::String(text)) => Some(Some(text.clone())),
            _ => None,
        }
    }
    /// Decode only canonical axes needed to verify a typed admission proof.
    pub(crate) fn from_frozen_payload(bytes: &[u8]) -> Option<Self> {
        let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
        if !value.get("native_mail_recipient")?.as_bool()?
            || value.get("channel")?.as_str()? != "email"
            || !value
                .get("verb")?
                .as_str()?
                .trim()
                .eq_ignore_ascii_case("send")
        {
            return None;
        }
        let identity = EntityId::from_hex(value.get("channel_identity_ref")?.as_str()?).ok()?;
        let actor = EntityId::from_hex(value.get("actor_entity_ref")?.as_str()?).ok()?;
        if value.get("actor_ref")?.as_str()? != actor.to_hex() {
            return None;
        }
        let recipient = canonical_recipient(value.get("target")?.as_str()?).ok()?;
        if value.get("target")?.as_str()? != recipient
            || value.get("counterparty_ref")?.as_str()? != recipient
        {
            return None;
        }
        let logical_ref = value.get("native_mail_logical_ref")?.as_str()?.to_owned();
        if logical_ref.trim().is_empty() {
            return None;
        }
        Some(Self {
            actor,
            identity,
            recipient,
            logical_ref,
            content_ref: Self::optional_string(&value, "content_ref")?,
            brief_ref: Self::optional_string(&value, "job_ref")?,
        })
    }

    pub(crate) fn approval_kind(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.native_mail.cold_send.approve_once.v1");
        let identity_hex = self.identity.to_hex();
        for part in [
            identity_hex.as_str(),
            self.recipient.as_str(),
            self.logical_ref.as_str(),
        ] {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part.as_bytes());
        }
        match self.content_ref.as_deref() {
            Some(content) => {
                hasher.update(&[1]);
                hasher.update(&(content.len() as u64).to_le_bytes());
                hasher.update(content.as_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
        format!("external:email:send:once:{}", hasher.finalize().to_hex())
    }
}

/// Recompose the immutable operation, not a caller-supplied proof string.
/// Ledger validation checks its digest before accepting a replayable row.
pub(crate) fn approval_digest_from_frozen_payload(
    payload: &[u8],
) -> Option<crate::consent::EffectDigest> {
    let operation = CanonicalMailSend::from_frozen_payload(payload)?;
    let actor_ref = operation.actor.to_hex();
    let effect = ExternalEffectGateInput {
        actor: GateActor {
            actor_class: "agent".into(),
            actor_ref: Some(actor_ref),
            delegation_grant_ref: None,
        },
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(operation.actor),
            mail_content_ref: operation.content_ref,
            ..GateProvenanceHandles::default()
        },
        verb: "send".into(),
        channel: "email".into(),
        channel_identity_ref: Some(operation.identity),
        counterparty: Some(operation.recipient),
        brief_ref: operation.brief_ref,
        send_ref: Some(operation.logical_ref),
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: true,
        has_permission: true,
        policy_risk: ExternalEffectPolicyRisk::HoldToProposal,
        send_autonomy: None,
    };
    crate::gate::native_mail_cold_approval_digest(&effect)
}
