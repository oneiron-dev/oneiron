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
use crate::consent_graduation::{RampScope, RampState};
use crate::gate::ExternalEffectGateInput;
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
        mut request: OutboundDispatchRequest,
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
        let (_, domain) = split_email_address(&request.intent.target)?;
        let recipient = normalize_email_address(&request.intent.target, &domain)?;
        if request
            .counterparty_ref
            .as_deref()
            .is_some_and(|ref_| ref_ != recipient)
        {
            return Err(invalid().into());
        }
        request.counterparty_ref = Some(recipient);
        vault.dispatch_outbound_intent(request, sink)
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
pub(crate) fn mail_graduated_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
) -> Result<bool> {
    if effect.channel != "email" || effect.verb != "send" {
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
    let mut seen = [false; 5];
    for id in vault.claims_for_subject_in_txn(txn, &identity_ref)? {
        let Some(claim) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if claim.lifecycle != ClaimLifecycleStatus::Active
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
    #[test]
    fn mail_09_native_send_and_cid5_offer_require_real_identity_and_health() -> Result<()> {
        use crate::claim::ClaimSource;
        use crate::identity_reputation::{
            IdentityAttestationTier, IdentityReputation, IdentityWarmupStage,
        };
        use crate::identity_topology::ProposalOutcome;
        use crate::outbound::{
            OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
            OutboundDispatchOutcome, OutboundExecutionOutcome, OutboundExecutionRequest,
            OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
        };
        use crate::temporal::TimeRange;
        struct Sink(usize);
        impl OutboundExecutionSink for Sink {
            fn execute(&mut self, _: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
                self.0 += 1;
                OutboundExecutionOutcome::delivered_to_channel("host:mail")
            }
        }
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let id = EntityId::now();
        let actor = EntityId::now();
        vault.put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"mail actor",
        )?;
        let adapter = NativeMailAdapter::new(
            "side.example.test",
            NativeMailRunMode::SelfRun,
            Host {
                inbound: EmailProviderInbound::new("event", "unused", "unused", 1),
            },
        )?;
        let requested = adapter.requested_identity(id, actor, 1);
        vault.create_channel_identity(&id, &requested)?;
        vault.transition_channel_identity(
            &id,
            ChannelIdentityState::PendingFulfillment,
            Some(ChannelIdentityFulfillment::Api),
            2,
            None,
        )?;
        let provision = adapter.provision(
            &ProvisionIntent {
                identity_id: id,
                identity: requested,
                fulfillment_mode: ChannelIdentityFulfillment::Api,
            },
            3,
        )?;
        vault.fulfill_channel_identity(
            provision.fulfillment_input(ChannelIdentityLifecycleActor::agent(actor)),
        )?;

        let scope = RampScope::new(
            "send",
            format!("recipient:cold_external:{}", id.to_hex()),
            actor.to_hex(),
        )?;
        for _ in 0..crate::consent_graduation::DEFAULT_GRADUATION_STREAK_FLOOR {
            vault.record_proposal_outcome_for_ramp(&scope, ProposalOutcome::ApprovedUntouched)?;
        }
        assert_eq!(vault.ramp_scope_state(&scope)?, RampState::Offered);
        assert!(adapter.cold_send_graduation_offer(&vault, id)?.is_none());
        assert!(!vault.graduation_offers()?.contains(&scope));
        let owner_id = EntityId::now();
        vault.put_entity(
            &owner_id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )?;
        let owner = vault.authenticate_owner(
            owner_id,
            "principal:owner",
            true,
            crate::store::GateDecisionId::now(),
        )?;
        assert!(vault.accept_graduation_offer(&owner, &scope).is_err());

        let reputation = IdentityReputation {
            complaint_rate: 0.0,
            bounce_rate: 0.0,
            spam_label_observations: 0,
            attestation_tier: IdentityAttestationTier::A,
            warmup_stage: IdentityWarmupStage::Established,
            updated_at: 10,
        };
        for (n, mut body) in reputation.claim_bodies(id).into_iter().enumerate() {
            if body.approval == crate::claim::ClaimApprovalStatus::Proposed {
                continue;
            }
            body.source = Some(ClaimSource::Observed);
            vault.put_claim(
                &EntityId::now(),
                &body,
                TimeRange {
                    start: n as u64 + 1,
                    end: n as u64 + 1,
                },
                n as u64 + 1,
            )?;
        }
        assert_eq!(
            adapter.cold_send_graduation_offer(&vault, id)?,
            Some(scope.clone())
        );
        assert!(vault.graduation_offers()?.contains(&scope));

        // A normal policy manifest allows the DEC-0006/OF-399 grant to be
        // the actual authority; no scoped send grant is hidden in this fixture.
        let v = rmpv::Value::from;
        let manifest = rmpv::Value::Map(vec![
            (v("schema_version"), v("1.2")),
            (v("pack_id"), v("native-mail-test")),
            (v("pack_version"), v("v1")),
            (v("min_engine_version"), v(env!("CARGO_PKG_VERSION"))),
            (
                v("defaults"),
                rmpv::Value::Map(vec![
                    (v("criticality"), v("normal")),
                    (v("sensitivity"), v("normal")),
                ]),
            ),
            (v("rules"), rmpv::Value::Array(vec![])),
            (
                v("actor_ceilings"),
                rmpv::Value::Array(vec![rmpv::Value::Map(vec![
                    (v("actor_class"), v("agent")),
                    (v("actor_ref"), rmpv::Value::from(actor.to_hex())),
                    (v("ceiling"), v("auto")),
                ])]),
            ),
            (v("scoped_grants"), rmpv::Value::Array(vec![])),
        ]);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &manifest).expect("manifest fixture encoding");
        crate::test_util::put_policy_manifest_bytes(
            &vault,
            crate::gate::default_policy_manifest_id()?,
            &bytes,
        )?;
        let intent = OutboundIntent::from_trigger(
            OutboundIntentDraft::new("actor", "send", "email", "new@example.test"),
            OutboundIntentTrigger::agent_immediate("session:mail-09"),
        );
        let request = OutboundDispatchRequest::new(
            "mail-09:receipt",
            "mail-09:intent",
            intent,
            OutboundDispatchActor::agent(actor),
            OutboundDispatchGate::allow_when_policy_grants(),
            20,
            OutboundDeliveryWindowDecision::DeliverNow,
        )
        .channel_identity_ref(id);
        let mut sink = Sink(0);
        let result = adapter
            .dispatch_send(&vault, request.clone(), &mut sink)
            .expect("native send reaches the gate");
        assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
        assert_eq!(sink.0, 0);
        vault.accept_graduation_offer(&owner, &scope)?;
        let mut graduated = request.clone();
        graduated.receipt_id = "mail-09:graduated-receipt".into();
        graduated.intent_ref = "mail-09:graduated-intent".into();
        let result = adapter
            .dispatch_send(&vault, graduated, &mut sink)
            .expect("graduated send reaches the gate");
        assert_eq!(
            result.outcome,
            OutboundDispatchOutcome::DeliveredToChannel,
            "{result:?}"
        );
        assert_eq!(sink.0, 1);
        let mut forged = request;
        forged.channel_identity_ref = Some(EntityId::now());
        assert!(adapter.dispatch_send(&vault, forged, &mut sink).is_err());
        assert_eq!(sink.0, 1);
        Ok(())
    }
}
