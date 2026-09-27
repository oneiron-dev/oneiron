//! Native mail fulfillment adapter. MTA, JMAP, DNS and DKIM stay in the host.
use super::shared_validate::{
    normalize_domain, normalize_email_address, split_email_address,
    validate_email_inbound_metadata, validate_provision_intent,
};
use super::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound,
    ChannelIdentityProviderProvision, EmailProviderInbound,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, SelfHeldShape,
    decode_channel_identity_body,
};
use crate::channel_identity_lifecycle::{ChannelIdentityLifecycleVerb, ProvisionIntent};
use crate::consent::{AuthenticatedOwner, ConsentReceipt};
use crate::consent_graduation::{RampScope, RampState};
use crate::gate::{
    ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateProvenanceHandles,
};
use crate::outbound::{
    OutboundDispatchError, OutboundDispatchRequest, OutboundDispatchResult, OutboundExecutionSink,
};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use crate::store::Store;
use crate::surface_event::{
    InboundSurfaceEventInput, SurfaceCounterpartyStamp, SurfaceEventAdmission,
};
use crate::{EntityId, Error, Result, Vault};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeMailRunMode {
    SelfRun,
    CloudRun,
}
/// The host implementation uses its embedded Stalwart >=0.16 JMAP driver.
/// It must enforce domain isolation and Track-B key custody there; the engine
/// does not replace those controls with an SMTP client or a SaaS inbox.
pub trait NativeMailHost {
    fn provision(&self, intent: &ProvisionIntent, mode: NativeMailRunMode) -> Result<String>;
    /// Verify the signature over the ORIGINAL bytes before parsing, deduping
    /// or routing. Verification failure must not return an inbound envelope.
    fn verify_webhook(
        &self,
        body: &[u8],
        headers: &BTreeMap<String, String>,
    ) -> Result<EmailProviderInbound>;
}
pub struct NativeMailAdapter<H> {
    domain: String,
    mode: NativeMailRunMode,
    host: H,
}
impl<H: NativeMailHost> NativeMailAdapter<H> {
    pub fn new(domain: &str, mode: NativeMailRunMode, host: H) -> Result<Self> {
        Ok(Self {
            domain: normalize_domain(domain)?,
            mode,
            host,
        })
    }
    pub fn address_for_identity(&self, id: EntityId) -> String {
        format!("mail-{}@{}", id.to_hex(), self.domain)
    }
    pub fn requested_identity(&self, id: EntityId, agent: EntityId, now: u64) -> ChannelIdentity {
        ChannelIdentity::requested(
            "email",
            self.address_for_identity(id),
            SelfHeldShape::DedicatedAddress,
            ChannelIdentityBinding::agent(agent),
            now,
        )
    }
    /// Native-mail send door. The host supplies the sink; the engine owns the
    /// sender/recipient check, gate, intent ledger and receipt. No SMTP or
    /// cloud-send implementation lives here. Other email dispatch callers
    /// reach the same mail-recipient floor at the common external-effect gate.
    pub fn dispatch_send<S: OutboundExecutionSink>(
        &self,
        vault: &Vault,
        request: OutboundDispatchRequest,
        sink: &mut S,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        let invalid = || Error::InvalidConfig("invalid native-mail send envelope".into());
        let identity_ref = request.channel_identity_ref.ok_or_else(invalid)?;
        let identity = vault
            .get_channel_identity(&identity_ref)?
            .ok_or_else(invalid)?;
        if request.intent.channel != "email"
            || request.intent.verb != "send"
            || identity.address_or_handle != self.address_for_identity(identity_ref)
            || !identity.may_send()
            || identity.binding.actor_ref() != request.actor.actor_entity_ref
        {
            return Err(invalid().into());
        }
        // The common dispatch door canonicalizes and binds the recipient
        // before freezing the intent. This adapter cannot authorize a second
        // delivery path or normalize only the Gate's counterparty copy.
        vault.dispatch_outbound_intent(request, sink)
    }

    /// Owner approval for exactly one cold send. This mints no standing
    /// authority; dispatch still rechecks recipient, sender and Gate policy.
    /// A changed recipient or logical send reference gets a different digest.
    pub fn approve_send_once(
        &self,
        vault: &Vault,
        owner: &AuthenticatedOwner,
        request: &OutboundDispatchRequest,
    ) -> Result<ConsentReceipt> {
        let invalid = || Error::InvalidConfig("invalid native-mail send envelope".into());
        let identity_ref = request.channel_identity_ref.ok_or_else(invalid)?;
        let identity = vault
            .get_channel_identity(&identity_ref)?
            .ok_or_else(invalid)?;
        let Some(actor) = request.actor.actor_entity_ref else {
            return Err(invalid());
        };
        if request.intent.channel != "email"
            || request.intent.verb != "send"
            || request.intent_ref.trim().is_empty()
            || identity.address_or_handle != self.address_for_identity(identity_ref)
            || !identity.may_send()
            || identity.binding.actor_ref() != Some(actor)
            || request.actor.actor_ref.as_deref() != Some(actor.to_hex().as_str())
        {
            return Err(invalid());
        }
        let recipient = canonical_recipient(&request.intent.target)?;
        if let Some(contact) = request.counterparty_ref.as_deref()
            && canonical_recipient(contact)? != recipient
        {
            return Err(invalid());
        }
        let effect = ExternalEffectGateInput {
            actor: GateActor {
                actor_class: request.actor.actor_class.clone(),
                actor_ref: request.actor.actor_ref.clone(),
                delegation_grant_ref: None,
            },
            provenance: GateProvenanceHandles {
                actor_entity_ref: Some(actor),
                ..GateProvenanceHandles::default()
            },
            verb: "send".into(),
            channel: "email".into(),
            channel_identity_ref: Some(identity_ref),
            counterparty: Some(recipient),
            brief_ref: request.intent.job_ref.clone(),
            send_ref: Some(request.intent_ref.clone()),
            standing_grant_ref: None,
            scoped_mcp_call: None,
            counterparty_first_touch: None,
            counterparty_opted_out: false,
            counterparty_opt_out_receipt_reason: None,
            has_opted_in: request.gate.has_opted_in,
            has_permission: request.gate.has_permission,
            policy_risk: ExternalEffectPolicyRisk::HoldToProposal,
        };
        let digest = crate::gate::native_mail_cold_approval_digest(&effect).ok_or_else(invalid)?;
        vault.approve_once(owner, digest)
    }

    /// CID-5 health is a prerequisite for OFFERING cold-recipient autonomy,
    /// not a new prohibition on an owner's already granted send authority.
    /// The OF-399 ramp supplies the approval streak; the owner alone accepts
    /// the offer and mints the standing action grant.
    pub fn cold_send_graduation_offer(
        &self,
        vault: &Vault,
        identity_ref: EntityId,
    ) -> Result<Option<RampScope>> {
        let txn = vault.store.env.read_txn()?;
        let identity = vault.get_channel_identity_in_txn(&txn, &identity_ref)?;
        let Some(identity) = identity else {
            return Ok(None);
        };
        if identity.address_or_handle != self.address_for_identity(identity_ref)
            || !identity.may_send()
        {
            return Ok(None);
        }
        let Some(actor) = identity.binding.actor_ref() else {
            return Ok(None);
        };
        if !native_mail_reputation_earned(vault, &txn, identity_ref)? {
            return Ok(None);
        }
        let scope = RampScope::new(
            "send",
            format!("recipient:cold_external:{}", identity_ref.to_hex()),
            actor.to_hex(),
        )?;
        drop(txn);
        if vault.ramp_scope_state(&scope)? == RampState::Offered {
            Ok(Some(scope))
        } else {
            Ok(None)
        }
    }

    /// Production ingress: verified bytes -> untrusted semantic envelope ->
    /// identity quarantine gate -> durable, idempotent surface-event handoff.
    pub fn accept_webhook(
        &self,
        vault: &Vault,
        body: &[u8],
        headers: &BTreeMap<String, String>,
        now: u64,
    ) -> Result<SurfaceEventAdmission> {
        if body.len() > 16 * 1024 * 1024 {
            return Err(Error::InvalidConfig("mail webhook too large".into()));
        }
        let verified = self.host.verify_webhook(body, headers)?;
        let input = self.parse_inbound(ChannelIdentityProviderInbound::Email(verified))?;
        vault.enqueue_inbound_surface_event(input, now)
    }
}
impl<H: NativeMailHost> ChannelIdentityProviderAdapter for NativeMailAdapter<H> {
    fn provider_key(&self) -> &'static str {
        "native_mail"
    }
    fn fulfillment_mode(
        &self,
        verb: ChannelIdentityLifecycleVerb,
    ) -> Option<ChannelIdentityFulfillment> {
        match verb {
            ChannelIdentityLifecycleVerb::Provision => Some(ChannelIdentityFulfillment::Api),
            _ => None,
        }
    }
    fn provision(
        &self,
        intent: &ProvisionIntent,
        fulfilled_at: u64,
    ) -> Result<ChannelIdentityProviderProvision> {
        let address = self.address_for_identity(intent.identity_id);
        validate_provision_intent(intent, "email", &address, ChannelIdentityFulfillment::Api)?;
        let provider_identity_ref = self.host.provision(intent, self.mode)?;
        if provider_identity_ref.is_empty() || provider_identity_ref.len() > 512 {
            return Err(Error::InvalidConfig(
                "invalid native mailbox receipt".into(),
            ));
        }
        Ok(ChannelIdentityProviderProvision {
            provider_key: self.provider_key().into(),
            identity_id: intent.identity_id,
            channel: "email".into(),
            address_or_handle: address,
            fulfillment_mode: ChannelIdentityFulfillment::Api,
            provider_identity_ref,
            fulfilled_at,
        })
    }
    /// Semantic adapter entry point for an already-authenticated host event.
    /// HTTP callers must use accept_webhook, not construct trusted envelopes.
    fn parse_inbound(
        &self,
        input: ChannelIdentityProviderInbound,
    ) -> Result<InboundSurfaceEventInput> {
        let ChannelIdentityProviderInbound::Email(mail) = input else {
            return Err(Error::InvalidConfig(
                "native mail requires an email envelope".into(),
            ));
        };
        validate_email_inbound_metadata(&mail)?;
        let (local, domain) = split_email_address(&mail.envelope_to)?;
        if domain != self.domain {
            return Err(Error::InvalidConfig(
                "mail recipient outside managed domain".into(),
            ));
        }
        let id = EntityId::from_hex(
            local
                .strip_prefix("mail-")
                .ok_or_else(|| Error::InvalidConfig("unknown mailbox".into()))?,
        )?;
        if self.address_for_identity(id) != format!("{local}@{domain}") {
            return Err(Error::InvalidConfig("noncanonical mailbox".into()));
        }
        let (_, sender_domain) = split_email_address(&mail.envelope_from)?;
        let sender = normalize_email_address(&mail.envelope_from, &sender_domain)?;
        let mut event = InboundSurfaceEventInput::new(
            mail.provider_event_id,
            "email",
            self.address_for_identity(id),
            SurfaceCounterpartyStamp::unknown(format!("email:{sender}")),
            mail.received_at,
            true,
        );
        event.payload_ref = mail.payload_ref;
        Ok(event)
    }
}

/// Canonical recipient used by both the Gate and the frozen transport intent.
/// Kept in the pack so every path uses the same strict address parser.
pub(crate) fn canonical_recipient(address: &str) -> Result<String> {
    let (_, domain) = split_email_address(address)?;
    normalize_email_address(address, &domain)
}

/// The recipient posture is only for active native-mail identities. Plain
/// `email` connectors keep their pre-existing gate semantics; an explicit
/// native-mail dispatch cannot evade this test because its send door requires
/// the same active, identity-shaped sender.
pub(crate) fn is_native_mail_sender_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: EntityId,
) -> Result<bool> {
    Ok(native_mail_identity_in_txn(store, txn, identity_ref)?.is_some())
}

fn native_mail_identity_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: EntityId,
) -> Result<Option<ChannelIdentity>> {
    let Some(raw) = store
        .port_entity_record(txn, &identity_ref)?
        .map(|row| row.encode())
    else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("native-mail identity entity header"))?;
    if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
        return Ok(None);
    }
    let identity = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    if identity.channel != "email"
        || !identity.may_send()
        || !identity
            .address_or_handle
            .starts_with(&format!("mail-{}@", identity_ref.to_hex()))
    {
        return Ok(None);
    }
    Ok(Some(identity))
}

/// Called only by the external-effect Gate on its own transaction. The
/// graduation grant is both DEC-0006 consent and outbound authority, but
/// only for the exact actor × native-mail identity × cold-recipient class.
/// Missing or malformed identity/grant rows cannot authorize an effect.
pub(crate) fn native_mail_cold_send_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
) -> Result<bool> {
    if effect.channel != "email"
        || effect.verb != "send"
        || effect.counterparty.as_deref().is_none_or(str::is_empty)
        || matches!(
            effect.counterparty_first_touch,
            Some(
                crate::counterparty_contact::CounterpartyFirstTouch::UserIntroduction
                    | crate::counterparty_contact::CounterpartyFirstTouch::InboundFirst
            )
        )
    {
        return Ok(false);
    }
    let Some(identity_ref) = effect.channel_identity_ref else {
        return Ok(false);
    };
    let Some(actor) = effect.provenance.actor_entity_ref else {
        return Ok(false);
    };
    if effect.actor.actor_ref.as_deref() != Some(actor.to_hex().as_str()) {
        return Ok(false);
    }
    let Some(identity) = native_mail_identity_in_txn(store, txn, identity_ref)? else {
        return Ok(false);
    };
    if identity.binding.actor_ref() != Some(actor) {
        return Ok(false);
    }
    Ok(true)
}

/// A cold send may borrow the graduated owner grant only after the current
/// counterparty and sender were classified on this Gate transaction.
pub(crate) fn mail_graduated_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
) -> Result<bool> {
    if !native_mail_cold_send_in_txn(store, txn, effect)? {
        return Ok(false);
    }
    let (Some(identity_ref), Some(actor)) = (
        effect.channel_identity_ref,
        effect.provenance.actor_entity_ref,
    ) else {
        return Ok(false);
    };
    let scope = RampScope::new(
        "send",
        format!("recipient:cold_external:{}", identity_ref.to_hex()),
        actor.to_hex(),
    )?;
    crate::consent::standing_grant_is_active_in_txn(store, txn, &scope.grant_ref()?)
}

/// Only current, observed CID-5 evidence earns a ramp offer. Missing or
/// conflicting heads do not prove a healthy established sender. A weak sender
/// may still receive explicit owner authority through the ordinary gate.
pub(crate) fn native_mail_reputation_earned(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    identity_ref: EntityId,
) -> Result<bool> {
    use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
    use crate::identity_reputation::{
        BOUNCE_CONSTRAINED_THRESHOLD, COMPLAINT_CONSTRAINED_THRESHOLD,
        PREDICATE_IDENTITY_REPUTATION_ATTESTATION_TIER, PREDICATE_IDENTITY_REPUTATION_BOUNCE_RATE,
        PREDICATE_IDENTITY_REPUTATION_COMPLAINT_RATE,
        PREDICATE_IDENTITY_REPUTATION_SPAM_LABEL_OBSERVATIONS,
        PREDICATE_IDENTITY_REPUTATION_WARMUP_STAGE,
    };
    use crate::ports::TombstoneStore;
    let mut seen = [false; 5];
    for id in vault.claims_for_subject_in_txn(txn, &identity_ref)? {
        let Some(claim) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if claim.lifecycle != ClaimLifecycleStatus::Active
            || claim.stale
            || crate::ports::stale_in_txn(&vault.store, txn, &id)?
            || vault.port_tombstone_is_deleted(txn, &id)?
            || !matches!(
                claim.approval,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
            )
            || claim.source != Some(ClaimSource::Observed)
        {
            continue;
        }
        let index = match claim.predicate.as_str() {
            PREDICATE_IDENTITY_REPUTATION_WARMUP_STAGE => 0,
            PREDICATE_IDENTITY_REPUTATION_COMPLAINT_RATE => 1,
            PREDICATE_IDENTITY_REPUTATION_BOUNCE_RATE => 2,
            PREDICATE_IDENTITY_REPUTATION_SPAM_LABEL_OBSERVATIONS => 3,
            PREDICATE_IDENTITY_REPUTATION_ATTESTATION_TIER => 4,
            _ => continue,
        };
        crate::identity_reputation::validate_identity_reputation_claim_structure(&claim)?;
        let safe = match index {
            0 => claim.value.as_str() == Some("established"),
            1 => claim
                .value
                .as_f64()
                .is_some_and(|n| n < COMPLAINT_CONSTRAINED_THRESHOLD),
            2 => claim
                .value
                .as_f64()
                .is_some_and(|n| n < BOUNCE_CONSTRAINED_THRESHOLD),
            3 => claim.value.as_u64() == Some(0),
            4 => matches!(claim.value.as_str(), Some("a" | "b")),
            _ => unreachable!(),
        };
        if !safe {
            return Ok(false);
        }
        seen[index] = true;
    }
    Ok(seen.into_iter().all(|present| present))
}

#[cfg(test)]
#[path = "native_mail/tests.rs"]
mod tests;
