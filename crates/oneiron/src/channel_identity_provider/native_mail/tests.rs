//! Native-mail adapter and send-autonomy integration tests.

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
        let fulfillment = fulfilled.fulfillment_input(ChannelIdentityLifecycleActor::agent(agent));
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
    use crate::ports::RetrievalIndex;
    use crate::temporal::TimeRange;
    struct Sink(Vec<String>);
    impl OutboundExecutionSink for Sink {
        fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
            self.0.push(request.intent.target.clone());
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
    let mut warmup_claim = None;
    for (n, mut body) in reputation.claim_bodies(id).into_iter().enumerate() {
        if body.approval == crate::claim::ClaimApprovalStatus::Proposed {
            continue;
        }
        body.source = Some(ClaimSource::Observed);
        let claim_id = EntityId::now();
        if body.predicate == crate::identity_reputation::PREDICATE_IDENTITY_REPUTATION_WARMUP_STAGE
        {
            warmup_claim = Some((claim_id, body.clone()));
        }
        vault.put_claim(
            &claim_id,
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
    let (stale_id, fresh_body) = warmup_claim.expect("warmup evidence");
    vault.with_write_txn(|txn| vault.port_retrieval_mark_stale(txn, &stale_id))?;
    assert!(adapter.cold_send_graduation_offer(&vault, id)?.is_none());
    assert!(!vault.graduation_offers()?.contains(&scope));
    assert!(vault.accept_graduation_offer(&owner, &scope).is_err());
    vault.put_claim(
        &EntityId::now(),
        &fresh_body,
        TimeRange { start: 12, end: 12 },
        12,
    )?;
    assert_eq!(
        adapter.cold_send_graduation_offer(&vault, id)?,
        Some(scope.clone())
    );
    let known = crate::counterparty_contact::CounterpartyContactRecord::user_introduction(
        id,
        "known@example.test",
        20,
    )?;
    vault.create_counterparty_contact(&EntityId::now(), &known)?;
    let inbound = crate::counterparty_contact::CounterpartyContactRecord::inbound_first(
        id,
        "inbound@example.test",
        20,
    )?;
    vault.create_counterparty_contact(&EntityId::now(), &inbound)?;

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
    let mut sink = Sink(Vec::new());
    let result = adapter
        .dispatch_send(&vault, request.clone(), &mut sink)
        .expect("native send reaches the gate");
    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(sink.0.is_empty());
    vault.accept_graduation_offer(&owner, &scope)?;
    // The public dispatch door cannot classify a known contact and
    // deliver to a different cold address, even with a normal grant.
    let mut mismatched = request.clone();
    mismatched.receipt_id = "mail-09:mismatch-receipt".into();
    mismatched.intent_ref = "mail-09:mismatch-intent".into();
    mismatched.intent.target = "COLD@EXAMPLE.TEST".into();
    mismatched.counterparty_ref = Some("known@example.test".into());
    assert!(
        vault
            .dispatch_outbound_intent(mismatched, &mut sink)
            .is_err()
    );
    assert!(sink.0.is_empty());
    let mut graduated = request.clone();
    graduated.receipt_id = "mail-09:graduated-receipt".into();
    graduated.intent_ref = "mail-09:graduated-intent".into();
    graduated.intent.target = "NEW@EXAMPLE.TEST".into();
    let completed_replay = graduated.clone();
    let result = adapter
        .dispatch_send(&vault, graduated, &mut sink)
        .expect("graduated send reaches the gate");
    assert_eq!(
        result.outcome,
        OutboundDispatchOutcome::DeliveredToChannel,
        "{result:?}"
    );
    assert_eq!(sink.0, ["new@example.test"]);
    let mut linked = request.clone();
    linked.receipt_id = "mail-09:linked-receipt".into();
    linked.intent_ref = "mail-09:linked-intent".into();
    linked.intent.job_ref = Some("brief:followup".into());
    let linked_result = adapter
        .dispatch_send(&vault, linked, &mut sink)
        .expect("graduation also covers job-linked sends");
    assert_eq!(
        linked_result.outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    assert_eq!(sink.0.len(), 2);
    for (n, target) in ["known@example.test", "inbound@example.test"]
        .iter()
        .enumerate()
    {
        let mut other = request.clone();
        other.receipt_id = format!("mail-09:known-{n}-receipt");
        other.intent_ref = format!("mail-09:known-{n}-intent");
        other.intent.target = (*target).into();
        let answer = adapter
            .dispatch_send(&vault, other, &mut sink)
            .expect("known recipient reaches the gate");
        assert_eq!(answer.outcome, OutboundDispatchOutcome::Held);
        assert_eq!(sink.0.len(), 2, "cold-only grant must not send to {target}");
    }
    let mut forged = request;
    forged.channel_identity_ref = Some(EntityId::now());
    assert!(adapter.dispatch_send(&vault, forged, &mut sink).is_err());
    assert_eq!(sink.0.len(), 2);
    vault.transition_channel_identity(&id, ChannelIdentityState::Released, None, 30, None)?;
    let replayed = adapter
        .dispatch_send(&vault, completed_replay, &mut sink)
        .expect("adapter completed replay must validate from frozen admission");
    assert_eq!(
        replayed.outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    assert_eq!(
        sink.0.len(),
        2,
        "completed replay cannot call the sink again"
    );
    Ok(())
}

#[test]
fn mail_09_owner_approve_once_releases_only_one_cold_send() -> Result<()> {
    use crate::outbound::{
        OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
        OutboundDispatchOutcome, OutboundExecutionOutcome, OutboundExecutionRequest,
        OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
    };
    use crate::temporal::TimeRange;
    struct Sink {
        calls: usize,
        fail_next: bool,
    }
    impl OutboundExecutionSink for Sink {
        fn execute(&mut self, _: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
            self.calls += 1;
            if std::mem::take(&mut self.fail_next) {
                OutboundExecutionOutcome::failed("definite non-delivery")
            } else {
                OutboundExecutionOutcome::delivered_to_channel("host:once")
            }
        }
    }
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let actor = EntityId::now();
    let owner_id = EntityId::now();
    for id in [actor, owner_id] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"mail principal",
        )?;
    }
    let owner = vault.authenticate_owner(
        owner_id,
        "principal:owner",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let identity = EntityId::now();
    let adapter = NativeMailAdapter::new(
        "side.example.test",
        NativeMailRunMode::SelfRun,
        Host {
            inbound: EmailProviderInbound::new("event", "unused", "unused", 1),
        },
    )?;
    let requested = adapter.requested_identity(identity, actor, 1);
    vault.create_channel_identity(&identity, &requested)?;
    vault.transition_channel_identity(
        &identity,
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Api),
        2,
        None,
    )?;
    let provision = adapter.provision(
        &ProvisionIntent {
            identity_id: identity,
            identity: requested,
            fulfillment_mode: ChannelIdentityFulfillment::Api,
        },
        3,
    )?;
    vault.fulfill_channel_identity(
        provision.fulfillment_input(ChannelIdentityLifecycleActor::agent(actor)),
    )?;

    let v = rmpv::Value::from;
    let manifest = rmpv::Value::Map(vec![
        (v("schema_version"), v("1.2")),
        (v("pack_id"), v("native-mail-once")),
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
    rmpv::encode::write_value(&mut bytes, &manifest).expect("manifest encoding");
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )?;
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("actor", "send", "email", "NEW@EXAMPLE.TEST")
            .content_ref("draft:approved"),
        OutboundIntentTrigger::agent_immediate("session:once"),
    );
    let request = crate::outbound::OutboundDispatchRequest::new(
        "mail-09:once-receipt",
        "mail-09:once-intent",
        intent,
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        20,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .channel_identity_ref(identity);
    let mut sink = Sink {
        calls: 0,
        fail_next: false,
    };
    let held = adapter
        .dispatch_send(&vault, request.clone(), &mut sink)
        .expect("cold send reaches gate");
    assert_eq!(held.outcome, OutboundDispatchOutcome::Held);
    assert_eq!(sink.calls, 0);
    adapter.approve_send_once(&vault, &owner, &request)?;
    let mut replacement = request.clone();
    replacement.intent.content_ref = Some("draft:replacement".into());
    let refused = adapter
        .dispatch_send(&vault, replacement, &mut sink)
        .expect("replacement goes to Gate, not transport");
    assert_eq!(refused.outcome, OutboundDispatchOutcome::Held);
    assert_eq!(sink.calls, 0);
    let mut windowed = request.clone();
    windowed.window_decision = OutboundDeliveryWindowDecision::Hold {
        reason: "quiet_window".into(),
        retry_at: Some(30),
    };
    let parked = adapter
        .dispatch_send(&vault, windowed, &mut sink)
        .expect("window hold keeps the one-send tap available");
    assert_eq!(parked.outcome, OutboundDispatchOutcome::Held);
    assert_eq!(sink.calls, 0);
    let sent = adapter
        .dispatch_send(&vault, request.clone(), &mut sink)
        .expect("owner one-shot releases this send");
    assert_eq!(sent.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(sink.calls, 1);
    assert!(adapter.approve_send_once(&vault, &owner, &request).is_err());
    let mut other = request;
    other.receipt_id = "mail-09:other-receipt".into();
    other.intent_ref = "mail-09:other-intent".into();
    let held = adapter
        .dispatch_send(&vault, other.clone(), &mut sink)
        .expect("other cold send reaches gate");
    assert_eq!(held.outcome, OutboundDispatchOutcome::Held);
    assert_eq!(sink.calls, 1);
    adapter.approve_send_once(&vault, &owner, &other)?;
    sink.fail_next = true;
    let failed = adapter
        .dispatch_send(&vault, other.clone(), &mut sink)
        .expect("definite non-delivery retains the admitted one-send approval");
    assert_eq!(failed.outcome, OutboundDispatchOutcome::Failed);
    assert_eq!(sink.calls, 2);
    let retried = adapter
        .dispatch_send(&vault, other.clone(), &mut sink)
        .expect("same frozen send retries under its spent approval");
    assert_eq!(retried.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(sink.calls, 3);
    let mut third = other;
    third.intent_ref = "mail-09:third-intent".into();
    third.receipt_id = "mail-09:third-receipt".into();
    let held = adapter
        .dispatch_send(&vault, third, &mut sink)
        .expect("third send has no approval");
    assert_eq!(held.outcome, OutboundDispatchOutcome::Held);
    assert_eq!(sink.calls, 3);
    Ok(())
}
