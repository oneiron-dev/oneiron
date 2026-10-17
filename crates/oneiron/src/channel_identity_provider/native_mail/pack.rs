//! Native mail pack runtime: one Stalwart instance, both run modes, one gate.
use std::collections::BTreeMap;

use super::NativeMailAdapter;
use crate::channel_identity::ChannelIdentityState;
use crate::channel_identity_lifecycle::{
    ChannelIdentityFulfillmentInput, ChannelIdentityLifecycleActor, ChannelIdentityLifecycleIntent,
    ChannelIdentityLifecycleRequest, ChannelIdentityLifecycleResult, ProvisionIntent,
};
use crate::channel_identity_provider::mail_placement::PlacementPolicy;
use crate::channel_identity_provider::shared_validate::validate_provision_intent;
use crate::channel_identity_provider::stalwart::{
    NativeMailMessage, StalwartClient, StalwartInboxCursor, StalwartInboxOutcome,
    StalwartQuarantine, StalwartSendSink,
};
use crate::channel_identity_provider::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderProvision,
};
use crate::outbound::{OutboundDispatchError, OutboundDispatchRequest, OutboundDispatchResult};
use crate::surface_event::SurfaceEventAdmission;
use crate::{EntityId, Error, Result, Vault};

/// An immutable message and its approval/dispatch envelope. The agent cannot
/// supply From or route selection. Persist the message on the host if the
/// approval is asynchronous; its content ref verifies it on replay.
#[derive(Debug, Clone)]
pub struct PreparedNativeMailSend {
    request: OutboundDispatchRequest,
    message: NativeMailMessage,
}

impl PreparedNativeMailSend {
    pub fn request(&self) -> &OutboundDispatchRequest {
        &self.request
    }
    pub fn message(&self) -> &NativeMailMessage {
        &self.message
    }
}

/// The same runtime serves a self-run instance or a cloud-owned instance.
/// Installing its built-in pack is inert: it grants no send authority and
/// starts no network listener. The host drives these provision/poll/send doors.
pub struct NativeMailPack {
    client: StalwartClient,
    adapter: NativeMailAdapter<StalwartClient>,
}

impl NativeMailPack {
    pub fn new(client: StalwartClient) -> Result<Self> {
        let adapter = NativeMailAdapter::new(
            client.config().domain(),
            client.config().run_mode(),
            client.clone(),
        )?;
        Ok(Self { client, adapter })
    }

    pub fn adapter(&self) -> &NativeMailAdapter<StalwartClient> {
        &self.adapter
    }
    pub fn client(&self) -> &StalwartClient {
        &self.client
    }

    /// No account is created when the existing ExternalEffect door holds or
    /// denies provisioning. Failed MTA work leaves PendingFulfillment for the
    /// host to retry through complete_provision, without reissuing authority.
    pub fn provision_identity(
        &self,
        vault: &Vault,
        request: ChannelIdentityLifecycleRequest,
    ) -> Result<ChannelIdentityLifecycleResult> {
        vault.require_builtin_channel_pack("native_mail")?;
        let ChannelIdentityLifecycleIntent::Provision(intent) = &request.intent else {
            return Err(Error::InvalidConfig(
                "native mail pack requires a provision intent".into(),
            ));
        };
        self.validate_intent(intent)?;
        let intent = intent.clone();
        let actor = request.actor.clone();
        let at = request.requested_at;
        let result = vault.apply_channel_identity_lifecycle_intent(request)?;
        if result
            .identity
            .as_ref()
            .is_some_and(|row| row.state() == ChannelIdentityState::PendingFulfillment)
            && result.outcome == ChannelIdentityState::PendingFulfillment.as_str()
        {
            self.complete_provision(vault, &intent, actor, at)
                .map(|(_, lifecycle)| lifecycle)
        } else {
            Ok(result)
        }
    }

    /// Retry provider fulfillment only for the exact row the gate already
    /// admitted. A foreign or rebound row cannot reuse another actor's intent.
    pub fn complete_provision(
        &self,
        vault: &Vault,
        intent: &ProvisionIntent,
        actor: ChannelIdentityLifecycleActor,
        fulfilled_at: u64,
    ) -> Result<(
        ChannelIdentityProviderProvision,
        ChannelIdentityLifecycleResult,
    )> {
        vault.require_builtin_channel_pack("native_mail")?;
        self.validate_intent(intent)?;
        // The admitted identity is compared against its facts, read from its
        // `channel_identity.*` heads (OF-272), not the row's own copy.
        let facts = vault
            .channel_identity_facts(&intent.identity_id)?
            .ok_or(Error::EntityNotFound)?;
        if facts.state != ChannelIdentityState::PendingFulfillment
            || facts.address_or_handle != intent.identity.address_or_handle()
            || facts.binding != intent.identity.binding()
            || facts.pending_fulfillment.as_deref() != Some(intent.fulfillment_mode.as_str())
            || actor.actor_entity_ref != facts.binding.actor_ref()
        {
            return Err(Error::InvalidConfig(
                "native mail fulfillment differs from admitted identity".into(),
            ));
        }
        let provision = self.adapter.provision(intent, fulfilled_at)?;
        let lifecycle = vault.fulfill_channel_identity(ChannelIdentityFulfillmentInput {
            actor,
            identity_id: intent.identity_id,
            fulfilled_at,
        })?;
        Ok((provision, lifecycle))
    }

    fn validate_intent(&self, intent: &ProvisionIntent) -> Result<()> {
        validate_provision_intent(
            intent,
            "email",
            &self.adapter.address_for_identity(intent.identity_id),
            crate::channel_identity::ChannelIdentityFulfillment::Api,
        )
    }

    /// Call before displaying a one-send approval. The digest includes this
    /// content ref; later dispatch cannot swap the subject, body or recipient.
    pub fn prepare_send(
        &self,
        mut request: OutboundDispatchRequest,
        message: NativeMailMessage,
    ) -> Result<PreparedNativeMailSend> {
        message.validate()?;
        if request.intent.channel != "email"
            || request.intent.verb != "send"
            || request.intent.target != message.to
            || request.calendar_invite.is_some()
            || request.intent_ref.trim().is_empty()
        {
            return Err(Error::InvalidConfig(
                "unsupported or inconsistent native mail send".into(),
            ));
        }
        request.intent.content_ref = Some(message.content_ref()?);
        if request.intent.idempotency_key.is_none() {
            request.intent.idempotency_key = Some(request.intent_ref.clone());
        }
        Ok(PreparedNativeMailSend { request, message })
    }

    /// Sends use the pre-existing native-mail recipient policy and OF-327
    /// spine: cold recipients hold for the owner's approval; standing grants
    /// and transactional/known-recipient policy retain their normal behavior.
    pub fn dispatch_send(
        &self,
        vault: &Vault,
        prepared: PreparedNativeMailSend,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        vault.require_builtin_channel_pack("native_mail")?;
        let mut sink = StalwartSendSink::new(&self.client, &prepared.message)?;
        self.adapter
            .dispatch_send(vault, prepared.request, &mut sink)
    }

    pub fn poll_inbox(
        &self,
        vault: &Vault,
        identity_ref: EntityId,
        policy: PlacementPolicy,
        cursor: Option<&StalwartInboxCursor>,
        quarantine: &StalwartQuarantine,
        now: u64,
    ) -> Result<StalwartInboxOutcome> {
        self.client.poll_inbox(
            vault,
            &self.adapter,
            identity_ref,
            policy,
            cursor,
            quarantine,
            now,
        )
    }

    /// Cloud hosts supply the original-body verifier when constructing the
    /// client. Verified webhooks and authenticated polls share CID-6 admission.
    pub fn accept_webhook(
        &self,
        vault: &Vault,
        body: &[u8],
        headers: &BTreeMap<String, String>,
        now: u64,
    ) -> Result<SurfaceEventAdmission> {
        vault.require_builtin_channel_pack("native_mail")?;
        self.adapter.accept_webhook(vault, body, headers, now)
    }
}
