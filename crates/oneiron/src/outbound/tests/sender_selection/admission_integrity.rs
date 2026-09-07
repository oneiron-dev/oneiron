use super::*;

#[derive(Clone)]
struct SharedRetrySink(std::sync::Arc<std::sync::Mutex<RetrySenderSink>>);

impl OutboundExecutionSink for SharedRetrySink {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.0.lock().expect("provider lock").execute(request)
    }
}

#[test]
fn concurrent_first_admissions_bind_one_sender_principal_and_request()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::outbound_chokepoint::BEFORE_NEW_ADMISSION;
    use crate::outbound_intent_ledger::{IntentLedgerError, IntentState};
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::Duration;

    for axis in [
        "sender",
        "actor",
        "target",
        "permission",
        "risk",
        "verb",
        "same",
    ] {
        let (_tmp, vault) = temp_vault();
        let actor = auto_agent_actor(&vault)?;
        let actor_ref = actor.actor_entity_ref.expect("actor");
        install_sender_retry_policy(&vault, actor_ref)?;
        for sender in [entity(0x93), entity(0x94)] {
            put_sending_identity(&vault, sender, ChannelIdentityBinding::actor(actor_ref))?;
        }
        let mut request = email_send_dispatch_request(actor, 0).channel_identity_ref(entity(0x93));
        request.intent.verb = "replace".to_owned();
        request.ledger_identity_ref = Some("intent:concurrent-first-admission".to_owned());
        let mut competing = request.clone();
        match axis {
            "sender" => competing.channel_identity_ref = Some(entity(0x94)),
            "actor" => {
                competing.actor = crate::outbound::OutboundDispatchActor::agent(entity(0x95));
            }
            "target" => competing.intent.target = "other@example.com".to_owned(),
            "permission" => competing.gate.has_permission = false,
            "risk" => {
                competing.gate.policy_risk =
                    crate::outbound::OutboundDispatchPolicyRisk::HoldToProposal;
            }
            "verb" => competing.intent.verb = "send".to_owned(),
            "same" => {}
            _ => unreachable!(),
        }
        let provider = Arc::new(Mutex::new(RetrySenderSink {
            uncertain_first: true,
            ..Default::default()
        }));
        let mut sink = SharedRetrySink(Arc::clone(&provider));
        let gates_before = vault.gate_decisions(100)?.len();
        let (first, second, admitted) = std::thread::scope(|scope| {
            let vault = &vault;
            let (ready_tx, ready_rx) = mpsc::channel();
            let (first_tx, first_rx) = mpsc::channel();
            let (second_tx, second_rx) = mpsc::channel();
            let ready_first = ready_tx.clone();
            let first_request = request.clone();
            let mut first_sink = sink.clone();
            let first = scope.spawn(move || {
                BEFORE_NEW_ADMISSION.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        ready_first.send(()).expect("first prepared");
                        first_rx
                            .recv_timeout(Duration::from_secs(10))
                            .expect("release first");
                    }));
                });
                vault.dispatch_outbound_intent(first_request, &mut first_sink)
            });
            let mut second_sink = sink.clone();
            let second = scope.spawn(move || {
                BEFORE_NEW_ADMISSION.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        ready_tx.send(()).expect("second prepared");
                        second_rx
                            .recv_timeout(Duration::from_secs(10))
                            .expect("release second");
                    }));
                });
                vault.dispatch_outbound_intent(competing, &mut second_sink)
            });
            // Both calls have read an EMPTY ledger and frozen their bindings.
            // Release one writer, then the other with its now-stale preparation.
            // No timing sleeps: the old payload-id-only admission admits both.
            for _ in 0..2 {
                ready_rx
                    .recv_timeout(Duration::from_secs(10))
                    .expect("both prepared");
            }
            first_tx.send(()).expect("admit first");
            let first = first.join().expect("first dispatch thread");
            let admitted = intent_ledger_records(vault).expect("first durable row");
            second_tx.send(()).expect("admit second");
            (
                first,
                second.join().expect("second dispatch thread"),
                admitted,
            )
        });
        assert_eq!(first?.outcome, OutboundDispatchOutcome::Failed);
        assert_eq!(admitted.records.len(), 1);
        assert_eq!(admitted[0].state, IntentState::Pending);
        assert_eq!(admitted[0].recorded_outcome, None);
        if axis == "same" {
            let replay = second?;
            assert_eq!(replay.outcome, OutboundDispatchOutcome::DeliveredToChannel);
            assert!(replay.gate_decision_id.is_none());
            assert!(replay.effector_budget.is_none());
        } else {
            assert!(
                matches!(
                    second,
                    Err(OutboundDispatchError::Chokepoint(
                        IntentLedgerError::InvalidRecord(_)
                    ))
                ),
                "{axis}"
            );
            assert_eq!(
                provider.lock().expect("provider").senders.len(),
                1,
                "{axis}"
            );
            assert_eq!(intent_ledger_records(&vault)?.records, admitted.records);
            let replay = vault.dispatch_outbound_intent(request.clone(), &mut sink)?;
            assert_eq!(replay.outcome, OutboundDispatchOutcome::DeliveredToChannel);
        }
        let done = intent_ledger_records(&vault)?;
        assert!(done.corrupt.is_empty());
        assert_eq!(done.records.len(), 1);
        assert_eq!(done[0].id, admitted[0].id);
        assert_eq!(done[0].payload(), admitted[0].payload());
        assert_eq!(done[0].budget_accounting, admitted[0].budget_accounting);
        assert_eq!(done[0].state, IntentState::Done);
        let deduped = vault.dispatch_outbound_intent(request, &mut sink)?;
        assert_eq!(deduped.outcome, OutboundDispatchOutcome::DeliveredToChannel);
        let provider = provider.lock().expect("provider");
        assert_eq!(provider.senders, vec![Some(entity(0x93)); 2]);
        assert_eq!(provider.keys[0], provider.keys[1]);
        assert!(provider.keys[0].is_some());
        assert_eq!(provider.effects.len(), 1);
        assert_eq!(vault.gate_decisions(100)?.len(), gates_before + 1);
        assert_eq!(
            vault
                .effector_budget_read("email", Some(&actor_ref))?
                .expect("budget")
                .rows[0]
                .used,
            1
        );
    }
    Ok(())
}

#[test]
fn exact_attempt_lookup_isolates_corruption_and_refuses_unindexed_ledger()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::outbound_intent_ledger::IntentLedgerError;

    let (_tmp, vault) = temp_vault();
    let actor = auto_agent_actor(&vault)?;
    install_sender_retry_policy(&vault, actor.actor_entity_ref.expect("actor"))?;
    let request = email_send_dispatch_request(actor.clone(), 0);
    let mut sink = SenderRecordingSink::default();
    vault.dispatch_outbound_intent(request.clone(), &mut sink)?;
    let admitted = intent_ledger_records(&vault)?;
    let mut key = b"outbound:intent_ledger:v2:".to_vec();
    key.extend_from_slice(&admitted[0].id);
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .vault_meta
        .put(&mut wtxn, &key, b"corrupt row")?;
    wtxn.commit()?;
    let error = vault
        .dispatch_outbound_intent(request, &mut sink)
        .expect_err("corrupt target");
    assert!(matches!(
        error,
        OutboundDispatchError::Chokepoint(IntentLedgerError::InvalidRecord(_))
    ));
    assert_eq!(sink.senders.len(), 1);
    let fresh = email_send_dispatch_request(actor.clone(), 1);
    let delivered = vault.dispatch_outbound_intent(fresh.clone(), &mut sink)?;
    assert_eq!(
        delivered.outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    assert_eq!(
        sink.senders.len(),
        2,
        "unrelated corruption must not block a fresh call"
    );
    let healthy = intent_ledger_records(&vault)?.records.remove(0);
    let mut index_key = b"outbound:intent_attempt:v1:".to_vec();
    index_key.extend_from_slice(healthy.attempt_id.as_bytes());
    index_key.extend_from_slice(&healthy.call_seq.to_be_bytes());
    for bad_pointer in [b"bad index".to_vec(), vec![0xEE; 32]] {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .vault_meta
            .put(&mut wtxn, &index_key, &bad_pointer)?;
        wtxn.commit()?;
        let error = vault
            .dispatch_outbound_intent(fresh.clone(), &mut sink)
            .expect_err("invalid or dangling index pointer must fail closed");
        assert!(matches!(
            error,
            OutboundDispatchError::Chokepoint(IntentLedgerError::InvalidRecord(_))
        ));
        assert_eq!(sink.senders.len(), 2);
    }
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .vault_meta
        .delete(&mut wtxn, b"outbound:intent_attempt_format")?;
    wtxn.commit()?;
    let error = vault
        .dispatch_outbound_intent(email_send_dispatch_request(actor, 2), &mut sink)
        .expect_err("nonempty ledger without index format must fail closed");
    assert!(matches!(
        error,
        OutboundDispatchError::Chokepoint(IntentLedgerError::InvalidRecord(_))
    ));
    assert_eq!(sink.senders.len(), 2);
    Ok(())
}
