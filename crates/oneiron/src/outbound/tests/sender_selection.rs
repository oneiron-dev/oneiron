use super::{
    auto_agent_actor, connector_task_draft, email_send_dispatch_request, entity, policy_manifest,
    put_connector_task_actor, put_policy_manifest_bytes, temp_vault,
};
use crate::Vault;
use crate::attempt_queue::AttemptQueue;
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape,
};
use crate::connector_key::{
    ConnectorKeyRecord, EffectorBudget, EffectorBudgetOnExhaust, EffectorBudgetWindow,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound::{
    OutboundDispatchError, OutboundDispatchOutcome, OutboundExecutionOutcome,
    OutboundExecutionRequest, OutboundExecutionSink,
};
use crate::outbound_intent_ledger::intent_ledger_records;
use crate::receipt::ReceiptQuery;
use crate::temporal::TimeRange;

mod admission_integrity;
mod replay;

#[derive(Default)]
struct SenderRecordingSink {
    senders: Vec<Option<EntityId>>,
}

impl OutboundExecutionSink for SenderRecordingSink {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.senders.push(request.channel_identity_ref);
        OutboundExecutionOutcome::delivered_to_channel("provider:sender-selection")
    }
}

fn put_sending_identity(
    vault: &Vault,
    id: EntityId,
    binding: ChannelIdentityBinding,
) -> crate::Result<()> {
    let mut identity = ChannelIdentity::requested(
        "email",
        format!("sender-{}@example.com", id.to_hex()),
        SelfHeldShape::DedicatedAddress,
        binding,
        1_000,
    );
    identity.state = ChannelIdentityState::Active;
    vault.create_channel_identity(&id, &identity)
}

#[test]
fn ambiguous_automatic_sender_refuses_before_dispatch_effects()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for second_is_faceted in [false, true] {
        let (_tmp, vault) = temp_vault();
        let actor = auto_agent_actor(&vault)?;
        let actor_ref = actor.actor_entity_ref.expect("actor entity");
        put_policy_manifest_bytes(
            &vault,
            entity(0xD0),
            &policy_manifest(&actor_ref.to_hex(), "email", &["send"]),
        )?;
        let key_ref = entity(0xB7);
        vault.register_connector_key(
            &key_ref,
            ConnectorKeyRecord::active(
                "email",
                Some(actor_ref),
                vec![EffectorBudget::sends(
                    10,
                    EffectorBudgetWindow::Rolling { duration_s: 86_400 },
                    EffectorBudgetOnExhaust::Suspend,
                )],
                1_000,
            ),
        )?;
        for facet in [entity(0x91), entity(0x92)] {
            vault.put_entity(
                &facet,
                crate::registry::ENTITY_TYPE_FACET,
                TimeRange {
                    start: 1_000,
                    end: 1_000,
                },
                1_000,
                b"sender facet",
            )?;
        }
        let first = entity(0x93);
        let second = entity(0x94);
        put_sending_identity(
            &vault,
            first,
            ChannelIdentityBinding::actor_with_facet(actor_ref, entity(0x91)),
        )?;
        put_sending_identity(
            &vault,
            second,
            if second_is_faceted {
                ChannelIdentityBinding::actor_with_facet(actor_ref, entity(0x92))
            } else {
                ChannelIdentityBinding::actor(actor_ref)
            },
        )?;
        let receipts_before = vault.receipts(ReceiptQuery::new(100))?;
        let key_before = vault.get_connector_key(&key_ref)?;
        let request = email_send_dispatch_request(actor.clone(), 0);
        let mut sink = SenderRecordingSink::default();
        let error = vault
            .dispatch_outbound_intent(request.clone(), &mut sink)
            .expect_err("multiple eligible senders must refuse automatic dispatch");
        assert!(matches!(
            error,
            OutboundDispatchError::Engine(Error::InvalidConfig(reason))
                if reason.starts_with("ambiguous outbound sender:")
        ));
        assert!(
            sink.senders.is_empty(),
            "ambiguous dispatch must not call the sink"
        );
        assert_eq!(vault.receipts(ReceiptQuery::new(100))?, receipts_before);
        assert_eq!(vault.get_connector_key(&key_ref)?, key_before);
        let budget = vault
            .effector_budget_read("email", Some(&actor_ref))?
            .expect("governing budget");
        assert_eq!(budget.rows.len(), 1);
        assert_eq!(
            budget.rows[0].used, 0,
            "ambiguity must not debit the budget"
        );
        let ledger = intent_ledger_records(&vault)?;
        assert!(
            ledger.records.is_empty(),
            "ambiguity must not journal an intent"
        );
        assert!(ledger.corrupt.is_empty());
        assert_eq!(vault.standalone_outbound_intent_count()?, 0);
        assert!(AttemptQueue::new(&vault).list()?.is_empty());

        // The same request is valid when the caller selects one of the senders.
        let explicit =
            vault.dispatch_outbound_intent(request.channel_identity_ref(first), &mut sink)?;
        assert_eq!(
            explicit.outcome,
            OutboundDispatchOutcome::DeliveredToChannel
        );
        assert_eq!(explicit.gate_outcome, "allow");
        assert_eq!(sink.senders, vec![Some(first)]);
        assert_eq!(
            explicit.effector_budget.expect("budget debit").rows[0].used,
            1
        );

        // Removing only the competing sender makes automatic faceted sending valid.
        vault.transition_channel_identity(
            &second,
            ChannelIdentityState::Released,
            None,
            1_001,
            None,
        )?;
        let automatic =
            vault.dispatch_outbound_intent(email_send_dispatch_request(actor, 2), &mut sink)?;
        assert_eq!(
            automatic.outcome,
            OutboundDispatchOutcome::DeliveredToChannel
        );
        assert_eq!(automatic.gate_outcome, "allow");
        assert_eq!(sink.senders, vec![Some(first), Some(first)]);
        assert_eq!(
            automatic.effector_budget.expect("budget debit").rows[0].used,
            2
        );
    }
    Ok(())
}

#[test]
fn absent_optional_sender_still_dispatches_with_and_without_a_connector_key()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for with_key in [false, true] {
        let (_tmp, vault) = temp_vault();
        let actor = auto_agent_actor(&vault)?;
        let actor_ref = actor.actor_entity_ref.expect("actor entity");
        put_policy_manifest_bytes(
            &vault,
            entity(0xD0),
            &policy_manifest(&actor_ref.to_hex(), "email", &["send"]),
        )?;
        if with_key {
            vault.register_connector_key(
                &entity(0xB7),
                ConnectorKeyRecord::active("email", Some(actor_ref), Vec::new(), 1_000),
            )?;
        }
        let mut sink = SenderRecordingSink::default();
        let result =
            vault.dispatch_outbound_intent(email_send_dispatch_request(actor, 0), &mut sink)?;
        assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
        assert_eq!(result.gate_outcome, "allow");
        assert_eq!(sink.senders, vec![None]);
    }
    Ok(())
}

// A provider double that applies an uncertain first call, then deduplicates a
// retry by the key the real pipeline supplies. A definite failure applies nothing.
#[derive(Default)]
struct RetrySenderSink {
    uncertain_first: bool,
    senders: Vec<Option<EntityId>>,
    keys: Vec<Option<String>>,
    effects: std::collections::BTreeSet<String>,
}

impl OutboundExecutionSink for RetrySenderSink {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.senders.push(request.channel_identity_ref);
        self.keys.push(request.idempotency_key.map(str::to_owned));
        let first = self.senders.len() == 1;
        if !first || self.uncertain_first {
            self.effects.insert(
                request
                    .idempotency_key
                    .map_or_else(|| format!("call:{}", self.senders.len()), str::to_owned),
            );
        }
        if first {
            let failed = OutboundExecutionOutcome::failed("sender-retry:first-call");
            if self.uncertain_first {
                failed.with_possible_delivery()
            } else {
                failed
            }
        } else {
            OutboundExecutionOutcome::delivered_to_channel("provider:sender-retry")
        }
    }
}

fn install_sender_retry_policy(vault: &Vault, actor: EntityId) -> crate::Result<()> {
    put_policy_manifest_bytes(
        vault,
        entity(0xD0),
        &policy_manifest(&actor.to_hex(), "email", &["send", "replace"]),
    )?;
    vault.register_connector_key(
        &entity(0xB7),
        ConnectorKeyRecord::active(
            "email",
            Some(actor),
            vec![EffectorBudget::sends(
                10,
                EffectorBudgetWindow::Rolling { duration_s: 86_400 },
                EffectorBudgetOnExhaust::Suspend,
            )],
            1_000,
        ),
    )?;
    vault.put_entity(
        &entity(0x91),
        crate::registry::ENTITY_TYPE_FACET,
        TimeRange {
            start: 1_000,
            end: 1_000,
        },
        1_000,
        b"retry sender facet",
    )
}
