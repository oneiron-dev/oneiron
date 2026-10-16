use super::*;
use crate::connector_key::{ConnectorDispatchTelemetry, ConnectorKeyRecord, EffectorBudget};
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};
#[test]
fn subscriptions_roundtrip_revoke_and_wake_only_matching_non_depleted_keys() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = vault.ensure_embedded_owner_actor().unwrap();
    let agent_a = entity(0x72);
    let agent_b = entity(0x73);
    for id in [owner_id, agent_a, agent_b] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"actor",
        )?;
    }
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    let key_a = entity(0x74);
    let key_b = entity(0x75);
    vault.register_connector_key(
        &key_a,
        ConnectorKeyRecord::active("calendar", Some(agent_a), Vec::new(), 1),
    )?;
    let mut budget = EffectorBudget::rate(1, 600);
    budget.on_exhaust = EffectorBudgetOnExhaust::Suspend;
    vault.register_connector_key(
        &key_b,
        ConnectorKeyRecord::active("calendar", Some(agent_b), vec![budget], 1),
    )?;
    let filter = ConnectorEventFilter {
        connector: "calendar".into(),
        event_kind: Some("updated".into()),
        predicate: Some("calendar.event".into()),
    };
    let a = vault.subscribe_connector_event(&owner, agent_a, key_a, filter.clone())?;
    let b = vault.subscribe_connector_event(&owner, agent_b, key_b, filter.clone())?;
    vault.subscribe_connector_event(
        &owner,
        agent_a,
        key_a,
        ConnectorEventFilter {
            event_kind: Some("created".into()),
            ..filter
        },
    )?;
    let listed = vault.connector_event_subscriptions(agent_a)?;
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().any(|(id, row)| *id == a && row.active));
    let spent = vault.admit_connector_key_dispatches(
        &key_b,
        "calendar",
        1,
        ConnectorDispatchTelemetry::default(),
    )?;
    assert_eq!(spent.admitted, 1);
    let event = ConnectorEvent {
        event_id: "event-1".into(),
        connector: "calendar".into(),
        event_kind: "updated".into(),
        predicate: "calendar.event".into(),
        payload: serde_json::json!({"ref":"source-record"}),
    };
    let decisions = vault.ingest_connector_event(&event)?;
    assert_eq!(decisions.len(), 2);
    assert!(decisions.iter().any(|d| d.subscription == a
        && d.status == ConnectorWakeStatus::Enqueued
        && d.attempt_id.is_some()));
    assert!(decisions.iter().any(|d| d.subscription == b
        && d.status == ConnectorWakeStatus::BudgetExhausted
        && d.attempt_id.is_none()));
    let txn = vault.store.env.read_txn()?;
    assert_eq!(
        read_connector_key_in_txn(&vault.store, &txn, &key_b)?
            .unwrap()
            .status,
        ConnectorKeyStatus::Suspended
    );
    drop(txn);
    assert_eq!(vault.ingest_connector_event(&event)?, decisions);
    assert!(
        vault
            .store
            .gate_decisions(100)?
            .iter()
            .any(|r| r.content_kind == "connector_wake" && r.claim_id == Some(*a.as_bytes()))
    );
    let mut delivered = EventConsumer::default();
    deliver_queued_event(&vault, &mut delivered)?;
    assert_eq!(delivered.events.len(), 1);
    assert_eq!(delivered.events[0].agent, agent_a);
    assert_eq!(delivered.events[0].event, event);
    assert_eq!(delivered.events[0].source(), ClaimSource::ToolOutput);
    vault.revoke_connector_event_subscription(&owner, a)?;
    assert!(
        vault
            .connector_event_subscriptions(agent_a)?
            .iter()
            .any(|(id, row)| *id == a && !row.active)
    );
    let next = ConnectorEvent {
        event_id: "event-2".into(),
        ..event
    };
    let after = vault.ingest_connector_event(&next)?;
    assert!(
        after
            .iter()
            .all(|d| d.status == ConnectorWakeStatus::KeyInactive && d.subscription == b)
    );
    Ok(())
}
#[test]
fn corrupt_subscription_claim_fails_closed() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = vault.ensure_embedded_owner_actor().unwrap();
    let actor = entity(0x62);
    let key_id = entity(0x63);
    for id in [owner_id, actor] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"actor",
        )?;
    }
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    vault.register_connector_key(
        &key_id,
        ConnectorKeyRecord::active("calendar", Some(actor), Vec::new(), 1),
    )?;
    let id = vault.subscribe_connector_event(
        &owner,
        actor,
        key_id,
        ConnectorEventFilter {
            connector: "calendar".into(),
            event_kind: None,
            predicate: None,
        },
    )?;
    let mut body = vault.get_claim(&id)?.unwrap();
    body.value = Value::from("not a subscription row");
    vault.put_claim(&id, &body, TimeRange { start: 1, end: 1 }, 1)?;
    assert!(vault.connector_event_subscriptions(actor).is_err());
    assert!(
        vault
            .ingest_connector_event(&ConnectorEvent {
                event_id: "event".into(),
                connector: "calendar".into(),
                event_kind: "updated".into(),
                predicate: "calendar.event".into(),
                payload: Json::Null
            })
            .is_err()
    );
    Ok(())
}

#[derive(Default)]
struct EventConsumer {
    events: Vec<crate::dreamer_runner::connector_event::ConnectorEventWake>,
}
impl crate::dreamer_wake::DreamerAttemptExecutor for EventConsumer {
    async fn execute(
        &mut self,
        attempt: &crate::dreamer_runner::DreamerAdmittedAttempt,
        _ctx: &mut crate::dreamer_wake::WakeAttemptContext<'_>,
    ) -> Result<crate::dreamer_wake::DreamerAttemptExecution> {
        self.events.push(
            crate::dreamer_runner::connector_event::ConnectorEventWake::from_attempt(attempt)?,
        );
        Ok(crate::dreamer_wake::DreamerAttemptExecution::Completed { completed_units: 0 })
    }
}
fn deliver_queued_event(vault: &Vault, exec: &mut EventConsumer) -> Result<()> {
    use crate::dreamer_wake::{
        DreamerWakeDriver, RunWakePass, WakeCancellation, WakePassDeadline, WakeTrigger,
    };
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    let mut driver = DreamerWakeDriver::new(
        vault,
        "connector-event-fixture",
        WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0)),
    );
    let cancel = WakeCancellation::new();
    let future = driver.run_wake_pass(
        RunWakePass {
            trigger: WakeTrigger::Event,
            scope: crate::dreamer_runner::DreamerConsolidationScope::Micro,
            local_node_id: 1,
            lease_owner: "connector-event-consumer".into(),
            budget_total_units: 1000,
            reserve_units: 10,
            now: crate::unix_seconds_now() + 1,
            host_scope: None,
        },
        exec,
        &cancel,
    );
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..100 {
        if let Poll::Ready(report) = future.as_mut().poll(&mut context) {
            assert_eq!(report?.completed, 1);
            return Ok(());
        }
    }
    Err(invalid())
}

/// F18 (H397): owner doors take their actor from a proof this vault
/// authenticated. Another vault's proof for the same PERSON id acts on nothing.
mod foreign_owner_proof {
    use super::*;

    #[test]
    fn a_foreign_owner_proof_subscribes_no_agent() -> Result<()> {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let owner_id = vault.ensure_embedded_owner_actor().unwrap();
        let agent = entity(0x72);
        for id in [owner_id, agent] {
            vault.put_entity(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"actor",
            )?;
        }
        let owner =
            vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
        let (_other_dir, _other, foreign) =
            crate::test_util::foreign_owner_proof(owner_id, &owner_id.to_hex());
        let key = entity(0x74);
        vault.register_connector_key(
            &key,
            ConnectorKeyRecord::active("calendar", Some(agent), Vec::new(), 1),
        )?;
        let filter = ConnectorEventFilter {
            connector: "calendar".into(),
            event_kind: Some("updated".into()),
            predicate: Some("calendar.event".into()),
        };

        assert_eq!(
            vault
                .subscribe_connector_event(&foreign, agent, key, filter.clone())
                .unwrap_err()
                .kind(),
            crate::ErrorKind::ConsentOwnerNotAuthenticated
        );
        assert!(vault.connector_event_subscriptions(agent)?.is_empty());
        vault.subscribe_connector_event(&owner, agent, key, filter)?;
        assert_eq!(vault.connector_event_subscriptions(agent)?.len(), 1);
        Ok(())
    }
}

mod revoked_owner_credential {
    use super::*;

    /// Astra r1 on #1458: the owner's credential is revoked while the
    /// subscription waits for the writer. The writer's snapshot refuses it.
    #[test]
    fn a_credential_revoked_while_the_subscription_waits_subscribes_no_agent() -> Result<()> {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let agent = entity(0x72);
        vault.put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"actor",
        )?;
        let key = entity(0x74);
        vault.register_connector_key(
            &key,
            ConnectorKeyRecord::active("calendar", Some(agent), Vec::new(), 1),
        )?;
        let filter = ConnectorEventFilter {
            connector: "calendar".into(),
            event_kind: Some("updated".into()),
            predicate: Some("calendar.event".into()),
        };
        let vault = std::rc::Rc::new(vault);
        let (owner, slip) = crate::test_util::credentialed_owner_proof(&vault, b"subscription");
        crate::test_util::revoke_before_the_next_write(&vault, slip);

        assert_eq!(
            vault
                .subscribe_connector_event(&owner, agent, key, filter.clone())
                .unwrap_err()
                .kind(),
            crate::ErrorKind::ConsentOwnerNotAuthenticated
        );
        assert!(vault.connector_event_subscriptions(agent)?.is_empty());
        let (fresh, _) = crate::test_util::credentialed_owner_proof(&vault, b"subscription again");
        vault.subscribe_connector_event(&fresh, agent, key, filter)?;
        assert_eq!(vault.connector_event_subscriptions(agent)?.len(), 1);
        Ok(())
    }
}
