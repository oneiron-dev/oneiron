//! Native mail fulfillment adapter. MTA, JMAP, DNS and DKIM stay in the host.
use super::shared_validate::{
    normalize_domain, normalize_email_address, split_email_address,
    validate_email_inbound_metadata, validate_provision_intent,
};
use super::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound,
    ChannelIdentityProviderProvision, EmailProviderInbound,
};
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, SelfHeldShape,
};
use crate::channel_identity_lifecycle::{ChannelIdentityLifecycleVerb, ProvisionIntent};
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

#[cfg(test)]
mod tests {
    use super::*;
    struct Host {
        inbound: EmailProviderInbound,
    }
    impl NativeMailHost for Host {
        fn provision(&self, intent: &ProvisionIntent, _: NativeMailRunMode) -> Result<String> {
            Ok(format!("mailbox:{}", intent.identity_id.to_hex()))
        }
        fn verify_webhook(
            &self,
            body: &[u8],
            _: &BTreeMap<String, String>,
        ) -> Result<EmailProviderInbound> {
            if body != b"authenticated fixture" {
                return Err(Error::InvalidConfig("webhook signature refused".into()));
            }
            Ok(self.inbound.clone())
        }
    }
    #[test]
    fn native_modes_conform_and_unauthenticated_ingress_writes_nothing() -> Result<()> {
        for mode in [NativeMailRunMode::SelfRun, NativeMailRunMode::CloudRun] {
            let id = EntityId::now();
            let agent = EntityId::now();
            let adapter = NativeMailAdapter::new(
                "side.example.test",
                mode,
                Host {
                    inbound: EmailProviderInbound::new(
                        "native-mail-event",
                        format!("mail-{}@side.example.test", id.to_hex()),
                        "sender@example.test",
                        10,
                    ),
                },
            )?;
            let intent = ProvisionIntent {
                identity_id: id,
                identity: adapter.requested_identity(id, agent, 1),
                fulfillment_mode: ChannelIdentityFulfillment::Api,
            };
            let fulfilled = adapter.provision(&intent, 2)?;
            assert_eq!(
                fulfilled.address_or_handle,
                intent.identity.address_or_handle
            );
            assert_eq!(fulfilled.provider_key, "native_mail");
            let input = adapter.parse_inbound(ChannelIdentityProviderInbound::Email(
                adapter.host.inbound.clone(),
            ))?;
            assert!(input.foreign_inbound);
            let dir = tempfile::tempdir()?;
            let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
            assert!(
                adapter
                    .accept_webhook(&vault, b"forged", &BTreeMap::new(), 10)
                    .is_err()
            );
            assert!(
                crate::attempt_queue::AttemptQueue::new(&vault)
                    .list()?
                    .is_empty()
            );
        }
        Ok(())
    }
}
