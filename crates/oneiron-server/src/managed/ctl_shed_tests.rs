use super::*;
use oneiron::genui::{GrantMintIntent, GrantMintIntentScope};
use oneiron::outbound::*;
use oneiron_vault_contract::{Credentials, CtlRequest, CtlResponse, ShedCause, ShedStatus};
use std::sync::Arc;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ctl_shed_enters_during_real_outbound_dispatch_and_preserves_journal() -> anyhow::Result<()>
{
    struct Sink {
        state: Arc<ManagedState>,
        vault: Arc<oneiron::Vault>,
        runtime: tokio::runtime::Handle,
    }
    impl OutboundExecutionSink for Sink {
        fn execute(&mut self, _: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
            let before =
                oneiron::outbound_intent_ledger::intent_ledger_records(&self.vault).unwrap();
            assert_eq!(before.records.len(), 1);
            assert_eq!(
                before.records[0].state,
                oneiron::outbound_intent_ledger::IntentState::Pending
            );
            let response = self
                .runtime
                .block_on(self.state.handle_request(CtlRequest::Shed {
                    cause: ShedCause::LongOutboundWait,
                    waited_secs: 2,
                }))
                .unwrap();
            assert!(matches!(
                response,
                CtlResponse::Slim {
                    status: ShedStatus::Entered,
                    slim: true,
                    ..
                }
            ));
            let after =
                oneiron::outbound_intent_ledger::intent_ledger_records(&self.vault).unwrap();
            assert_eq!(before.records, after.records);
            OutboundExecutionOutcome::delivered_to_channel("test-reply")
        }
    }
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(oneiron::Vault::open(
        dir.path(),
        oneiron::VaultConfig::default(),
    )?);
    let actor_id = oneiron::EntityId::from_bytes([0xE1; 16])?;
    vault.put_entity(
        &actor_id,
        oneiron::registry::ENTITY_TYPE_PERSON,
        oneiron::TimeRange { start: 1, end: 1 },
        1,
        b"sender",
    )?;
    let actor = OutboundDispatchActor::agent(actor_id);
    // The seeded first-party actor ceiling plus a real owner grant authorizes
    // the send. Maintenance policy bytes remain forbidden at the public put door.
    vault.mint_standing_outbound_grant(
        &oneiron::EntityId::from_bytes([0xBC; 16])?,
        &GrantMintIntent {
            principal_ref: actor_id.to_hex(),
            origin_component_id: "ctl-test".into(),
            origin_action_id: "escalate_always_this_verb_class".into(),
            origin_receipt_ref: None,
            scope: GrantMintIntentScope::VerbClass {
                verb_class: "send".into(),
            },
        },
        2,
    )?;
    let server = Arc::new(crate::SyncServer::new(
        vault.clone(),
        crate::config::SyncServerConfig::default(),
    )?);
    let credentials = Credentials {
        dek: [1; 32],
        token: [2; 32],
    };
    let ledger = WakeLedger::load(
        vault.clone(),
        "ctl-test".into(),
        dir.path().join("supervisor.sock"),
        &credentials,
    )?;
    let state = Arc::new(ManagedState::new("ctl-test".into(), server, ledger));
    let runtime = tokio::runtime::Handle::current();
    let job = tokio::task::spawn_blocking(move || {
        let intent = OutboundIntent::from_trigger(
            OutboundIntentDraft::new(
                actor.actor_ref.as_deref().unwrap(),
                "send",
                "feedback_collector",
                "https://example.test/feedback",
            ),
            OutboundIntentTrigger::agent_immediate("approval"),
        );
        let request = OutboundDispatchRequest::new(
            "ctl-send",
            "ctl-send",
            intent,
            actor,
            OutboundDispatchGate::allow_when_policy_grants(),
            1000,
            OutboundDeliveryWindowDecision::DeliverNow,
        );
        let outcome = vault.dispatch_outbound_intent(
            request,
            &mut Sink {
                state,
                vault: vault.clone(),
                runtime,
            },
        )?;
        assert_eq!(outcome.outcome, OutboundDispatchOutcome::DeliveredToChannel);
        assert_eq!(vault.residency(), oneiron::VaultResidency::Full);
        Ok::<(), oneiron::outbound::OutboundDispatchError>(())
    });
    job.await??;
    Ok(())
}
