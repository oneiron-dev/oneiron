//! OF-393 facade oracles: paused plans create no TASKs; rulings bind exact work.

use super::support::*;
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::edit_distance::escalation::{EscalationTrigger, escalation_stats, standing_policy_for};
use crate::fanout_auto::{
    FanoutAskClassifier, FanoutAskContext, FanoutAskVerdict, FanoutClassifierView,
    FanoutDecisionHistory,
};
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::store::GateDecisionId;

fn owner(vault: &Vault) -> AuthenticatedOwner {
    let actor = consult_peer(vault, 0xF0);
    vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .expect("human proof")
}

fn plan(vault: &Vault, count: u8) -> ConsultFanOutSpec {
    ConsultFanOutSpec {
        question_ref: consult_turn(vault, 0x7A),
        context_refs: Vec::new(),
        assignees: (1..=count).map(|seed| consult_peer(vault, seed)).collect(),
        deadline_at: unix_seconds_now() + 3600,
        label: Some("consult".into()),
        now: None,
    }
}

fn scope(actor: EntityId, input: &ConsultFanOutSpec) -> String {
    format!(
        "consult:{}:{}",
        actor.to_hex(),
        input.question_ref.short_ref()
    )
}

#[test]
fn fanout_submit_estimate_gate_tick_dispatched_paused_threshold() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let input = plan(&vault, 25);
    let facade = vault.memory(actor, EdgeActorClass::Agent);
    let allowed = facade
        .fan_out_consults(&input)
        .expect("threshold is inclusive");
    assert_eq!(allowed.task_refs.len(), 25);
    assert_eq!(allowed.meter.total_count, 25);
    assert_eq!(allowed.meter.per_peer.values().copied().sum::<u32>(), 25);
    assert!(allowed.paused.is_none());
    let input = plan(&vault, 26);
    let paused = facade
        .fan_out_consults(&input)
        .expect("uncertain AUTO surfaces");
    assert!(paused.paused.is_some());
    assert_eq!(paused.meter.total_count, 26);
    assert!(paused.task_refs.is_empty());
    assert_eq!(task_entity_census(&vault), 25);
    // No node-local attempts are dispatched while waiting; consults remain
    // peer TASKs and a runner tick has nothing to accidentally start.
    assert!(
        AttemptQueue::new(&vault)
            .list()
            .expect("attempts")
            .is_empty()
    );
    assert_eq!(
        facade
            .consult_fanout_status(paused.correlation_ref)
            .unwrap(),
        paused
    );
}

#[test]
fn fanout_approve_policy_deny_resume_exact_digest_and_gate_receipts() {
    let (dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let human = owner(&vault);
    let mut input = plan(&vault, 26);
    let approved_at = unix_seconds_now() - 120;
    input.now = Some(approved_at);
    let facade = vault.memory(actor, EdgeActorClass::Agent);
    let paused = facade.fan_out_consults(&input).unwrap();
    let mut wrong = paused.meter.plan_digest;
    wrong[0] ^= 1;
    let stale = facade
        .resume_fan_out_consults(
            paused.correlation_ref,
            wrong,
            ConsultFanOutChoice::ApproveOnce,
            &human,
        )
        .expect_err("stale digest");
    assert_eq!(stale.code, MEMORY_CODE_INVALID_STATE);
    assert_eq!(task_entity_census(&vault), 0);
    let denied = facade
        .resume_fan_out_consults(
            paused.correlation_ref,
            paused.meter.plan_digest,
            ConsultFanOutChoice::Deny,
            &human,
        )
        .expect("deny parks");
    assert!(denied.paused.as_ref().unwrap().denied);
    assert!(denied.task_refs.is_empty());
    let gate = vault
        .receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))
        .unwrap();
    let deny_receipt = gate
        .iter()
        .find(|row| Some(&row.receipt_id) == denied.choice_receipt_ref.as_ref())
        .unwrap();
    assert_eq!(deny_receipt.outcome, "kept_paused");
    assert_eq!(
        deny_receipt.fields["diff_handle"],
        crate::entity_id::bytes_to_hex_lower(&paused.meter.plan_digest)
    );
    assert_eq!(
        escalation_stats(&vault, &scope(actor, &input), EscalationTrigger::Budget)
            .unwrap()
            .deny,
        1
    );
    // Visible after process loss, not only present in an in-memory sink.
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("reopen paused run");
    let facade = vault.memory(actor, EdgeActorClass::Agent);
    assert_eq!(
        facade
            .consult_fanout_status(paused.correlation_ref)
            .unwrap(),
        denied
    );
    let resumed = facade
        .resume_fan_out_consults(
            paused.correlation_ref,
            paused.meter.plan_digest,
            ConsultFanOutChoice::ApproveAndRemember,
            &human,
        )
        .expect("authenticated resume");
    assert_eq!(resumed.task_refs.len(), 26);
    for task in &resumed.task_refs {
        let body = task_verb_body(&vault, *task).unwrap().unwrap();
        assert_eq!(body.created_at, approved_at);
        assert_eq!(body.ttl.unwrap().deadline_at, input.deadline_at);
    }
    assert!(resumed.paused.is_none());
    let repeated = facade
        .resume_fan_out_consults(
            paused.correlation_ref,
            paused.meter.plan_digest,
            ConsultFanOutChoice::ApproveAndRemember,
            &human,
        )
        .unwrap();
    assert_eq!(repeated, resumed);
    assert_eq!(task_entity_census(&vault), 26);
    let standing = standing_policy_for(&vault, &scope(actor, &input), EscalationTrigger::Budget)
        .unwrap()
        .unwrap();
    assert_eq!(standing.budget_band_ceiling, Some(26));
    assert!(standing.covers_ask(Some(26)));
    assert!(!standing.covers_ask(Some(27)));
    let stats = escalation_stats(&vault, &scope(actor, &input), EscalationTrigger::Budget).unwrap();
    assert_eq!((stats.approve, stats.deny), (1, 1));
    assert!(!standing.cited_receipts.is_empty());
    let gate = vault
        .receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))
        .unwrap();
    assert!(gate.iter().any(
        |row| Some(&row.receipt_id) == resumed.choice_receipt_ref.as_ref()
            && row.fields.get("diff_handle")
                == Some(&crate::entity_id::bytes_to_hex_lower(
                    &paused.meter.plan_digest
                ))
    ));
    // Accepted cap is read by the real AUTO admission, even without a classifier.
    let covered = facade.fan_out_consults(&input).expect("remembered cap");
    assert_eq!(covered.task_refs.len(), 26);
    let wider = plan(&vault, 27);
    let refused = facade.fan_out_consults(&wider).expect("above cap surfaces");
    assert!(refused.paused.is_some());
    assert!(refused.task_refs.is_empty());
    let mut other_scope = input;
    other_scope.question_ref = consult_turn(&vault, 0x7B);
    assert!(
        facade
            .fan_out_consults(&other_scope)
            .unwrap()
            .paused
            .is_some()
    );
    // No separate, unbounded outbound grant was minted as a semantic twin.
    assert!(
        vault
            .entities_by_type_page(crate::registry::ENTITY_TYPE_OUTBOUND_GRANT, None, 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn fanout_pathologies_park_with_count_fan_out_board_rows_and_evidence() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let human = owner(&vault);
    let mut input = plan(&vault, 1);
    let peer = input.assignees[0];
    // The reverse leg is a real peer actor, not the first-party actor preset.
    // Give that peer an explicit Auto ceiling before testing cycle admission.
    let bytes = crate::gate::default_policy_manifest().unwrap();
    let Value::Map(mut manifest) = rmpv::decode::read_value(&mut bytes.as_slice()).unwrap() else {
        panic!("manifest");
    };
    let (_, Value::Array(ceilings)) = manifest
        .iter_mut()
        .find(|(k, _)| k.as_str() == Some("actor_ceilings"))
        .unwrap()
    else {
        panic!("ceilings");
    };
    ceilings.push(Value::Map(vec![
        (Value::from("actor_class"), Value::from("agent")),
        (Value::from("actor_ref"), Value::from(peer.to_hex())),
        (Value::from("ceiling"), Value::from("auto")),
    ]));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(manifest)).unwrap();
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id().unwrap(),
        &bytes,
    )
    .unwrap();
    let facade = vault.memory(actor, EdgeActorClass::Agent);
    let first = facade.fan_out_consults(&input).unwrap();
    assert_eq!(first.task_refs.len(), 1);
    input.assignees = vec![actor];
    let reverse = vault
        .memory(peer, EdgeActorClass::Agent)
        .fan_out_consults(&input)
        .unwrap();
    assert!(reverse.paused.is_some());
    assert!(reverse.task_refs.is_empty());
    assert!(
        reverse
            .meter
            .board_rows
            .iter()
            .any(|row| row.line.ends_with("evidence=consult_cycle"))
    );
    let peer_facade = vault.memory(peer, EdgeActorClass::Agent);
    let board = peer_facade.fan_out_agents_section(&[], &[]).unwrap();
    assert_eq!(board.rows, reverse.meter.board_rows);
    assert!(
        board
            .rows
            .iter()
            .any(|row| row.line.contains("consults=1 paused"))
    );
    assert!(board.rows.iter().any(|row| {
        row.line
            .contains(&format!("peer={} consults=1", actor.to_hex()))
    }));
    assert!(board.rows.iter().any(|row| row.line.contains("cycle_hop=")));
    assert!(
        board
            .rows
            .iter()
            .all(|row| row.lane == crate::context_board::AgentLane::Fanout)
    );
    facade
        .set_consult_fanout_policy(
            &human,
            &ConsultFanOutPolicy {
                peer_rate: Some(ConsultFanOutRate {
                    window_secs: 60,
                    spike_at: 2,
                }),
                ..ConsultFanOutPolicy::default()
            },
        )
        .unwrap();
    input.assignees = vec![peer];
    let spike = facade.fan_out_consults(&input).unwrap();
    assert!(spike.paused.is_some());
    assert!(
        spike
            .meter
            .board_rows
            .iter()
            .any(|row| row.line.contains("projected=2 spike_at=2 window_secs=60"))
    );
    assert_eq!(task_entity_census(&vault), 1);
    // A human can release a pathology once; remembering cannot suppress the
    // pathology check on the next run, even below the count threshold.
    facade
        .resume_fan_out_consults(
            spike.correlation_ref,
            spike.meter.plan_digest,
            ConsultFanOutChoice::ApproveAndRemember,
            &human,
        )
        .unwrap();
    assert!(facade.fan_out_consults(&input).unwrap().paused.is_some());
}

struct HistoryClassifier;
impl FanoutAskClassifier for HistoryClassifier {
    fn classify(
        &self,
        _: &FanoutAskContext,
        view: &FanoutClassifierView<'_>,
        history: &FanoutDecisionHistory,
    ) -> Result<FanoutAskVerdict> {
        assert_eq!(view.total_count(), 2);
        assert_eq!(history.deny, 1);
        Ok(FanoutAskVerdict::Allow)
    }
}

#[test]
fn fanout_tunable_threshold_auto_history_and_human_authentication() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let human = owner(&vault);
    assert!(
        vault
            .authenticate_owner(
                human.actor(),
                human.principal_ref(),
                false,
                GateDecisionId::now()
            )
            .is_err()
    );
    let input = plan(&vault, 2);
    let facade = vault.memory(actor, EdgeActorClass::Agent);
    facade
        .set_consult_fanout_policy(
            &human,
            &ConsultFanOutPolicy {
                approval_threshold: 1,
                ..ConsultFanOutPolicy::default()
            },
        )
        .unwrap();
    let paused = facade.fan_out_consults(&input).unwrap();
    let stranger = consult_peer(&vault, 0xF1);
    let denied = vault
        .memory(stranger, EdgeActorClass::Agent)
        .resume_fan_out_consults(
            paused.correlation_ref,
            paused.meter.plan_digest,
            ConsultFanOutChoice::ApproveOnce,
            &human,
        )
        .unwrap_err();
    assert_eq!(denied.code, MEMORY_CODE_FORBIDDEN);
    facade
        .resume_fan_out_consults(
            paused.correlation_ref,
            paused.meter.plan_digest,
            ConsultFanOutChoice::Deny,
            &human,
        )
        .unwrap();
    let classified = facade
        .fan_out_consults_with_classifier(&input, Some(&HistoryClassifier))
        .unwrap();
    assert_eq!(classified.task_refs.len(), 2);
    facade
        .set_consult_fanout_policy(
            &human,
            &ConsultFanOutPolicy {
                approval_threshold: 1,
                mode: ConsultFanOutMode::Manual,
                peer_rate: None,
            },
        )
        .unwrap();
    assert!(
        facade
            .fan_out_consults_with_classifier(&input, Some(&HistoryClassifier))
            .unwrap()
            .paused
            .is_some()
    );
    facade
        .set_consult_fanout_policy(
            &human,
            &ConsultFanOutPolicy {
                approval_threshold: 1,
                mode: ConsultFanOutMode::FullAccess,
                peer_rate: None,
            },
        )
        .unwrap();
    assert_eq!(facade.fan_out_consults(&input).unwrap().task_refs.len(), 2);
}

#[test]
fn fanout_corrupt_standing_policy_refuses_even_below_threshold() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let human = owner(&vault);
    let input = plan(&vault, 1);
    let facade = vault.memory(actor, EdgeActorClass::Agent);
    facade
        .set_consult_fanout_policy(
            &human,
            &ConsultFanOutPolicy {
                approval_threshold: 0,
                ..ConsultFanOutPolicy::default()
            },
        )
        .unwrap();
    let paused = facade.fan_out_consults(&input).unwrap();
    facade
        .resume_fan_out_consults(
            paused.correlation_ref,
            paused.meter.plan_digest,
            ConsultFanOutChoice::ApproveAndRemember,
            &human,
        )
        .unwrap();
    facade
        .set_consult_fanout_policy(&human, &ConsultFanOutPolicy::default())
        .unwrap();
    vault
        .with_write_txn(|txn| {
            let key = vault
                .store
                .vault_meta
                .prefix_iter(txn, b"edit_distance/escalation_policy/v1\0")?
                .next()
                .expect("remembered policy")?
                .0
                .to_vec();
            vault.store.vault_meta.put(txn, &key, b"corrupt policy")?;
            Ok(())
        })
        .unwrap();
    let error = facade
        .fan_out_consults(&input)
        .expect_err("corruption is not absence");
    assert_eq!(error.code, crate::memory::MEMORY_CODE_INTERNAL);
    assert_eq!(task_entity_census(&vault), 1);
}
