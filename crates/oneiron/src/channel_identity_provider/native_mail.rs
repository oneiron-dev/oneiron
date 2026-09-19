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
    use crate::channel_identity::ChannelIdentityState;
    use crate::channel_identity_lifecycle::ChannelIdentityLifecycleActor;
    use crate::surface_event::SurfaceEventHandoffState;

    struct Host {
        inbound: EmailProviderInbound,
    }
    impl NativeMailHost for Host {
        fn provision(&self, intent: &ProvisionIntent, mode: NativeMailRunMode) -> Result<String> {
            Ok(format!("{mode:?}:{}", intent.identity_id.to_hex()))
        }
        fn verify_webhook(
            &self,
            body: &[u8],
            headers: &BTreeMap<String, String>,
        ) -> Result<EmailProviderInbound> {
            if body != b"authenticated fixture"
                || headers.get("signature").map(String::as_str) != Some("fixture")
            {
                return Err(Error::InvalidConfig("webhook signature refused".into()));
            }
            Ok(self.inbound.clone())
        }
    }
    #[test]
    fn native_modes_conform_and_unauthenticated_ingress_writes_nothing() -> Result<()> {
        let id = EntityId::from_hex("abababababababababababababababab")?;
        let address = "mail-abababababababababababababababab@side.example.test";
        for mode in [NativeMailRunMode::SelfRun, NativeMailRunMode::CloudRun] {
            let agent = EntityId::now();
            let adapter = NativeMailAdapter::new(
                "SIDE.EXAMPLE.TEST",
                mode,
                Host {
                    inbound: EmailProviderInbound::new(
                        "native-mail-event",
                        address,
                        "Sender@EXAMPLE.TEST",
                        10,
                    )
                    .with_payload_ref("mail:body"),
                },
            )?;
            assert_eq!(adapter.address_for_identity(id), address);
            assert_eq!(adapter.provider_key(), "native_mail");
            assert_eq!(
                adapter.fulfillment_mode(ChannelIdentityLifecycleVerb::Provision),
                Some(ChannelIdentityFulfillment::Api)
            );
            assert_eq!(
                adapter.fulfillment_mode(ChannelIdentityLifecycleVerb::Bind),
                None
            );
            let intent = ProvisionIntent {
                identity_id: id,
                identity: adapter.requested_identity(id, agent, 1),
                fulfillment_mode: ChannelIdentityFulfillment::Api,
            };
            let fulfilled = adapter.provision(&intent, 2)?;
            assert_eq!(fulfilled.address_or_handle, address);
            assert_eq!(fulfilled.channel, "email");
            assert_eq!(
                fulfilled.provider_identity_ref,
                format!("{mode:?}:abababababababababababababababab")
            );
            let fulfillment =
                fulfilled.fulfillment_input(ChannelIdentityLifecycleActor::agent(agent));
            assert_eq!(fulfillment.identity_id, id);
            let input = adapter.parse_inbound(ChannelIdentityProviderInbound::Email(
                adapter.host.inbound.clone(),
            ))?;
            assert_eq!(input.receiving_address_or_handle, address);
            assert_eq!(input.channel, "email");
            assert_eq!(
                input.counterparty,
                SurfaceCounterpartyStamp::unknown("email:sender@example.test")
            );
            assert_eq!(input.payload_ref.as_deref(), Some("mail:body"));
            assert!(input.foreign_inbound);
            let dir = tempfile::tempdir()?;
            let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
            vault.create_channel_identity(&id, &intent.identity)?;
            vault.transition_channel_identity(
                &id,
                ChannelIdentityState::PendingFulfillment,
                Some(ChannelIdentityFulfillment::Api),
                2,
                None,
            )?;
            vault.fulfill_channel_identity(fulfillment)?;
            let headers = BTreeMap::from([("signature".into(), "fixture".into())]);
            assert!(
                adapter
                    .accept_webhook(&vault, b"forged", &headers, 10)
                    .is_err()
            );
            assert!(
                adapter
                    .accept_webhook(&vault, b"authenticated fixture", &BTreeMap::new(), 10)
                    .is_err()
            );
            assert!(
                crate::attempt_queue::AttemptQueue::new(&vault)
                    .list()?
                    .is_empty()
            );
            let SurfaceEventAdmission::Accepted(ack) =
                adapter.accept_webhook(&vault, b"authenticated fixture", &headers, 10)?
            else {
                panic!("live identity must accept verified ingress")
            };
            assert_eq!(ack.state, SurfaceEventHandoffState::Queued);
            assert!(!ack.replayed);
            let SurfaceEventAdmission::Accepted(replay) =
                adapter.accept_webhook(&vault, b"authenticated fixture", &headers, 11)?
            else {
                panic!("verified retry must be acknowledged")
            };
            assert!(replay.replayed);
            assert_eq!(ack.attempt_ref, replay.attempt_ref);
            assert_eq!(
                crate::attempt_queue::AttemptQueue::new(&vault)
                    .list()?
                    .len(),
                1
            );
        }
        Ok(())
    }
    #[test]
    fn native_mail_refuses_foreign_malformed_and_non_email_envelopes() -> Result<()> {
        let adapter = NativeMailAdapter::new(
            "side.example.test",
            NativeMailRunMode::SelfRun,
            Host {
                inbound: EmailProviderInbound::new("unused", "unused", "unused", 10),
            },
        )?;
        let normalized = adapter.parse_inbound(ChannelIdentityProviderInbound::Email(
            EmailProviderInbound::new(
                "case",
                "mail-ABABABABABABABABABABABABABABABAB@SIDE.EXAMPLE.TEST",
                "Sender@EXAMPLE.TEST",
                10,
            ),
        ))?;
        assert_eq!(
            normalized.receiving_address_or_handle,
            "mail-abababababababababababababababab@side.example.test"
        );
        for address in [
            "mail-abababababababababababababababab@foreign.example.test",
            "other-abababababababababababababababab@side.example.test",
            "mail-not-a-uuid@side.example.test",
        ] {
            assert!(
                adapter
                    .parse_inbound(ChannelIdentityProviderInbound::Email(
                        EmailProviderInbound::new("event", address, "sender@example.test", 10)
                    ))
                    .is_err()
            );
        }
        assert!(
            adapter
                .parse_inbound(ChannelIdentityProviderInbound::Slack(
                    super::super::SlackProviderInbound::new("event", "T1", "C1", "U1", "agent", 10)
                ))
                .is_err()
        );
        Ok(())
    }
}
