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
fn fanout_rulings_use_the_vault_id_source_and_replay_the_same_receipt() {
    let clock = crate::ports::ManualClock::new(100);
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(
        dir.path(),
        VaultConfig {
            store_clock: clock.bundle(),
            ..VaultConfig::default()
        },
    )
    .expect("open vault");
    let actor = own_agent(&vault);
    let human = owner(&vault);
    let mut input = plan(&vault, 26);
    input.now = Some(100);
    input.deadline_at = 300;
    let facade = vault.memory(actor, EdgeActorClass::Agent);
    let paused = facade.fan_out_consults(&input).expect("paused plan");
    assert!(paused.paused.is_some());
    let denied = facade
        .resume_fan_out_consults(
            paused.correlation_ref,
            paused.meter.plan_digest,
            ConsultFanOutChoice::Deny,
            &human,
        )
        .expect("denied ruling");
    let denied_ref = denied.choice_receipt_ref.as_deref().expect("deny receipt");
    let denied_id = EntityId::from_hex(denied_ref.strip_prefix("gate:").expect("typed gate ref"))
        .expect("valid receipt id");
    assert_eq!(denied_id.as_bytes()[0], 0x71);
    let approved = facade
        .resume_fan_out_consults(
            paused.correlation_ref,
            paused.meter.plan_digest,
            ConsultFanOutChoice::ApproveAndRemember,
            &human,
        )
        .expect("approval ruling");
    let approved_ref = approved
        .choice_receipt_ref
        .as_deref()
        .expect("approve receipt");
    let approved_id =
        EntityId::from_hex(approved_ref.strip_prefix("gate:").expect("typed gate ref"))
            .expect("valid receipt id");
    assert_eq!(approved_id.as_bytes()[0], 0x71);
    assert_ne!(denied_id, approved_id);
    let before_replay = vault
        .store
        .gate_decisions(100)
        .expect("durable gate decisions")
        .into_iter()
        .filter(|row| row.content_kind == "consult_fanout")
        .collect::<Vec<_>>();
    assert_eq!(before_replay.len(), 2);
    assert!(
        before_replay
            .iter()
            .any(|row| row.decision_id.as_bytes() == *denied_id.as_bytes()
                && row.outcome == "kept_paused")
    );
    assert!(
        before_replay
            .iter()
            .any(|row| row.decision_id.as_bytes() == *approved_id.as_bytes())
    );
    // The same operation writes two escalation rulings and a remembered cap.
    // They are public Gate receipts and must follow this vault's ID source too.
    let standing = standing_policy_for(&vault, &scope(actor, &input), EscalationTrigger::Budget)
        .expect("standing policy read")
        .expect("remembered cap");
    assert_eq!(standing.row_ref.as_bytes()[0], 0x71);
    let projected = vault
        .receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))
        .expect("projected receipts");
    let escalation_receipts: Vec<_> = projected
        .iter()
        .filter(|row| {
            crate::edit_distance::escalation::is_escalation_receipt(row)
                && row.fields.get(crate::receipt::FIELD_TASK_REF)
                    == Some(&paused.correlation_ref.to_hex())
        })
        .collect();
    assert_eq!(escalation_receipts.len(), 2);
    let escalation_ids: Vec<_> = escalation_receipts
        .iter()
        .map(|row| {
            EntityId::from_hex(
                row.receipt_id
                    .strip_prefix("escalation:")
                    .expect("escalation ref"),
            )
            .expect("valid escalation ID")
        })
        .collect();
    assert!(escalation_ids.iter().all(|id| id.as_bytes()[0] == 0x71));
    assert_ne!(escalation_ids[0], escalation_ids[1]);
    assert!(escalation_receipts.iter().any(|row| row.outcome == "deny"));
    assert!(
        escalation_receipts
            .iter()
            .any(|row| row.outcome == "approve")
    );
    let cited = standing.cited_receipts.clone();
    assert_eq!(cited.len(), 1);
    assert!(
        escalation_receipts
            .iter()
            .any(|row| row.receipt_id == cited[0])
    );
    let standing_receipts: Vec<_> = projected
        .iter()
        .filter(|row| {
            crate::edit_distance::escalation::is_standing_policy_receipt(row)
                && row
                    .receipt_id
                    .starts_with(&format!("escalation_policy:{}.", standing.row_ref.to_hex()))
        })
        .collect();
    assert_eq!(standing_receipts.len(), 2); // proposal and acceptance
    assert!(
        standing_receipts
            .iter()
            .all(|row| row.fields[crate::receipt::FIELD_ESCALATION_CITED_RECEIPTS] == cited[0])
    );
    let floor = {
        let txn = vault.store.env.read_txn().expect("floor snapshot");
        let bytes = vault
            .store
            .vault_meta
            .get(&txn, crate::ports::ID_FLOOR)
            .expect("floor read")
            .expect("persisted ID floor");
        u128::from_be_bytes(bytes.as_ref().try_into().expect("floor bytes"))
    };
    assert!(floor >= u128::from_be_bytes(*standing.row_ref.as_bytes()));
    let repeated = facade
        .resume_fan_out_consults(
            paused.correlation_ref,
            paused.meter.plan_digest,
            ConsultFanOutChoice::ApproveAndRemember,
            &human,
        )
        .expect("idempotent replay");
    assert_eq!(repeated.choice_receipt_ref, approved.choice_receipt_ref);
    assert_eq!(
        vault
            .store
            .gate_decisions(100)
            .expect("persisted decisions")
            .into_iter()
            .filter(|row| row.content_kind == "consult_fanout")
            .count(),
        2
    );
    let after = vault
        .receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))
        .expect("replayed receipt projection");
    assert_eq!(
        after
            .iter()
            .filter(|row| escalation_receipts
                .iter()
                .any(|prior| prior.receipt_id == row.receipt_id))
            .count(),
        2
    );
    assert_eq!(
        after
            .iter()
            .filter(|row| standing_receipts
                .iter()
                .any(|prior| prior.receipt_id == row.receipt_id))
            .count(),
        2
    );
    assert_eq!(
        standing_policy_for(&vault, &scope(actor, &input), EscalationTrigger::Budget)
            .expect("replayed policy"),
        Some(standing)
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
                create_rate: ConsultFanOutPolicy::default().create_rate,
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
                create_rate: ConsultFanOutPolicy::default().create_rate,
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

#[test]
fn counted_fanout_estimates_and_mints_each_consult_for_one_peer() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let peer = consult_peer(&vault, 0xE2);
    let input = ConsultFanOutSpec {
        question_ref: consult_turn(&vault, 0x7A),
        context_refs: Vec::new(),
        assignees: vec![peer; 3],
        deadline_at: unix_seconds_now() + 3600,
        label: None,
        now: None,
    };
    let facade = vault.memory(actor, EdgeActorClass::Agent);
    let estimate = facade
        .estimate_counted_consults(&input, "research")
        .unwrap();
    assert_eq!(estimate.total_count, 3);
    assert_eq!(estimate.per_peer[&peer.to_hex()], 3);
    assert_eq!(task_entity_census(&vault), 0);
    let admitted = facade.fan_out_counted_consults(&input, "research").unwrap();
    assert_eq!(admitted.task_refs.len(), 3);
    assert_eq!(admitted.meter.total_count, 3);
    assert_eq!(admitted.meter.per_peer[&peer.to_hex()], 3);
    assert_eq!(task_entity_census(&vault), 3);
}

#[test]
fn counted_fanout_remembered_cap_is_preset_scoped() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let human = owner(&vault);
    let peer = consult_peer(&vault, 0xE2);
    let base = ConsultFanOutSpec {
        question_ref: consult_turn(&vault, 0x7A),
        context_refs: Vec::new(),
        assignees: vec![peer; 2],
        deadline_at: unix_seconds_now() + 3600,
        label: None,
        now: None,
    };
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
    let paused = facade.fan_out_counted_consults(&base, "research").unwrap();
    assert!(paused.paused.is_some());
    assert!(paused.task_refs.is_empty());
    let ruled = facade
        .resume_fan_out_consults_with_cap(
            paused.correlation_ref,
            paused.meter.plan_digest,
            ConsultFanOutChoice::ApproveAndRemember,
            &human,
            Some(5),
        )
        .unwrap();
    assert_eq!(ruled.task_refs.len(), 2);
    let larger = ConsultFanOutSpec {
        assignees: vec![peer; 4],
        ..base.clone()
    };
    assert_eq!(
        facade
            .fan_out_counted_consults(&larger, "research")
            .unwrap()
            .task_refs
            .len(),
        4
    );
    assert!(
        facade
            .fan_out_counted_consults(&larger, "outreach")
            .unwrap()
            .paused
            .is_some()
    );
    let over = ConsultFanOutSpec {
        assignees: vec![peer; 6],
        ..base
    };
    assert!(
        facade
            .fan_out_counted_consults(&over, "research")
            .unwrap()
            .paused
            .is_some()
    );
}

#[test]
fn fanout_threshold_is_owner_authored_manifest_data_and_survives_reopen() {
    let (dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let human = owner(&vault);
    let facade = vault.memory(actor, EdgeActorClass::Agent);
    assert_eq!(
        facade
            .get_consult_fanout_policy()
            .unwrap()
            .approval_threshold,
        25
    );
    let next = ConsultFanOutPolicy {
        approval_threshold: 100,
        ..ConsultFanOutPolicy::default()
    };
    facade.set_consult_fanout_policy(&human, &next).unwrap();
    let manifest_id = crate::gate::default_policy_manifest_id().unwrap();
    let raw = vault
        .latest_entity_bodies_by_type(crate::registry::ENTITY_TYPE_POLICY_MANIFEST, 10, 100)
        .unwrap()
        .into_iter()
        .find(|(id, _, _)| *id == manifest_id)
        .unwrap()
        .2;
    let Value::Map(rows) = rmpv::decode::read_value(&mut raw.as_slice()).unwrap() else {
        panic!("default manifest must remain a map")
    };
    let row = rows
        .iter()
        .find(|(name, _)| {
            name.as_str() == Some(crate::gate::POLICY_CONSULT_FANOUT_APPROVAL_THRESHOLD_KEY)
        })
        .unwrap();
    assert_eq!(row.1.as_u64(), Some(100));
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    assert_eq!(
        reopened
            .memory(actor, EdgeActorClass::Agent)
            .get_consult_fanout_policy()
            .unwrap()
            .approval_threshold,
        100
    );
}

/// Rewrites the seeded default manifest, e.g. as a vault seeded before the
/// fan-out rows existed.
fn reseed_default_manifest(vault: &Vault, edit: impl FnOnce(&mut Vec<(Value, Value)>)) {
    let Value::Map(mut rows) =
        rmpv::decode::read_value(&mut crate::gate::default_policy_manifest().unwrap().as_slice())
            .unwrap()
    else {
        panic!("default manifest must be a map")
    };
    edit(&mut rows);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(rows)).unwrap();
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id().unwrap(),
        &bytes,
    )
    .unwrap();
}

#[test]
fn fanout_missing_manifest_threshold_uses_shipped_row_and_malformed_refuses() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let peer = consult_peer(&vault, 0xE2);
    let input = ConsultFanOutSpec {
        question_ref: consult_turn(&vault, 0x7A),
        context_refs: Vec::new(),
        assignees: vec![peer],
        deadline_at: unix_seconds_now() + 3600,
        label: None,
        now: None,
    };
    reseed_default_manifest(&vault, |rows| {
        rows.retain(|(name, _)| {
            name.as_str() != Some(crate::gate::POLICY_CONSULT_FANOUT_APPROVAL_THRESHOLD_KEY)
        });
    });
    let facade = vault.memory(actor, EdgeActorClass::Agent);
    // Owner ruling 2026-09-27: a missing row falls back to the shipped row.
    assert_eq!(
        facade.get_consult_fanout_policy().unwrap(),
        ConsultFanOutPolicy::default()
    );
    let admitted = facade
        .fan_out_counted_consults(&input, "research")
        .expect("the shipped threshold row governs the missing one");
    assert_eq!(admitted.task_refs.len(), 1);
    assert_eq!(
        admitted.shipped_policy_rows,
        vec!["shipped:consult_fanout_approval_threshold".to_owned()]
    );
    assert_eq!(task_entity_census(&vault), 1);

    // An unreadable value is not a missing row: it counts as strictest.
    reseed_default_manifest(&vault, |rows| {
        rows.iter_mut()
            .find(|(name, _)| {
                name.as_str() == Some(crate::gate::POLICY_CONSULT_FANOUT_APPROVAL_THRESHOLD_KEY)
            })
            .expect("shipped threshold row")
            .1 = Value::from("twenty-five");
    });
    assert!(facade.get_consult_fanout_policy().is_err());
    assert!(facade.fan_out_counted_consults(&input, "research").is_err());
    assert_eq!(task_entity_census(&vault), 1);
}

#[test]
fn fanout_vault_seeded_before_fanout_rows_runs_under_shipped_defaults() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let human = owner(&vault);
    let silent = plan(&vault, 25);
    let over = plan(&vault, 26);
    reseed_default_manifest(&vault, |rows| {
        rows.retain(|(name, _)| {
            !name
                .as_str()
                .is_some_and(|name| name.starts_with("consult_fanout_"))
        });
    });
    let facade = vault.memory(actor, EdgeActorClass::Agent);
    assert_eq!(
        facade.get_consult_fanout_policy().unwrap(),
        ConsultFanOutPolicy::default()
    );
    let ran = facade
        .fan_out_consults(&silent)
        .expect("the shipped threshold admits 25");
    assert!(ran.paused.is_none());
    assert_eq!(ran.task_refs.len(), 25);
    assert_eq!(
        ran.shipped_policy_rows,
        vec![
            "shipped:consult_fanout_approval_threshold".to_owned(),
            "shipped:consult_fanout_controls".to_owned(),
            "shipped:consult_fanout_precedence".to_owned(),
        ]
    );
    let paused = facade
        .fan_out_consults(&over)
        .expect("over the shipped threshold pauses");
    assert!(paused.paused.is_some());
    assert!(paused.task_refs.is_empty());
    assert_eq!(task_entity_census(&vault), 25);

    // The owner maps the missing rows by hand; precedence stays shipped.
    let tuned = ConsultFanOutPolicy {
        approval_threshold: 30,
        ..ConsultFanOutPolicy::default()
    };
    facade.set_consult_fanout_policy(&human, &tuned).unwrap();
    assert_eq!(facade.get_consult_fanout_policy().unwrap(), tuned);
    let mapped = facade.fan_out_consults(&over).unwrap();
    assert!(mapped.paused.is_none());
    assert_eq!(mapped.task_refs.len(), 26);
    assert_eq!(
        mapped.shipped_policy_rows,
        vec!["shipped:consult_fanout_precedence".to_owned()]
    );
    assert_eq!(task_entity_census(&vault), 51);
}

struct CountedAllowClassifier {
    actor: EntityId,
    peer: EntityId,
}

impl FanoutAskClassifier for CountedAllowClassifier {
    fn classify(
        &self,
        context: &FanoutAskContext,
        view: &FanoutClassifierView<'_>,
        history: &FanoutDecisionHistory,
    ) -> Result<FanoutAskVerdict> {
        assert_eq!(view.peer_count(), 1);
        assert_eq!(view.total_count(), 26);
        assert_eq!(view.per_peer_counts(), vec![(self.peer.to_hex(), 26)]);
        assert_eq!(
            context.scope,
            format!("consult:{}:preset:research", self.actor.to_hex())
        );
        assert_eq!((history.approve, history.deny, history.amend), (0, 0, 0));
        assert!(history.last_rulings.is_empty());
        Ok(FanoutAskVerdict::Allow)
    }
}

#[test]
fn counted_fanout_passes_repeated_peer_to_available_auto_classifier() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let peer = consult_peer(&vault, 0xE2);
    let input = ConsultFanOutSpec {
        question_ref: consult_turn(&vault, 0x7A),
        context_refs: Vec::new(),
        assignees: vec![peer; 26],
        deadline_at: unix_seconds_now() + 3600,
        label: None,
        now: None,
    };
    let facade = vault.memory(actor, EdgeActorClass::Agent);
    let admitted = facade
        .fan_out_counted_consults_with_classifier(
            &input,
            "research",
            Some(&CountedAllowClassifier { actor, peer }),
        )
        .expect("host AUTO verdict admits the metered counted plan");
    assert!(admitted.paused.is_none());
    assert_eq!(admitted.meter.total_count, 26);
    assert_eq!(admitted.meter.per_peer[&peer.to_hex()], 26);
    assert_eq!(admitted.task_refs.len(), 26);
    assert_eq!(task_entity_census(&vault), 26);
}

#[test]
fn fanout_create_quota_is_owner_manifest_row_and_eleventh_request_follows_it() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let human = owner(&vault);
    let input = plan(&vault, 1);
    let facade = vault.memory(actor, EdgeActorClass::Agent);
    let policy = ConsultFanOutPolicy {
        create_rate: TaskCreateRateLimit {
            limit: 10,
            window_seconds: 3600,
        },
        ..ConsultFanOutPolicy::default()
    };
    facade.set_consult_fanout_policy(&human, &policy).unwrap();
    assert_eq!(
        facade.get_consult_fanout_policy().unwrap().create_rate,
        policy.create_rate
    );
    for _ in 0..10 {
        assert_eq!(
            facade
                .fan_out_counted_consults(&input, "research")
                .unwrap()
                .task_refs
                .len(),
            1
        );
    }
    let blocked = facade
        .fan_out_counted_consults(&input, "research")
        .unwrap_err();
    assert_eq!(blocked.code, MEMORY_CODE_INVALID_STATE);
    let denial = blocked
        .policy_denial
        .as_ref()
        .expect("typed policy refusal");
    assert_eq!(denial.level, "vault");
    assert_eq!(denial.row_ref, "oneiron.default.fanout.v1");
    assert_eq!(denial.role, "owner");
    assert_eq!(
        denial.exception_proposal.action,
        "ask_for_exception:fanout.create_rate"
    );
    assert_eq!(denial.exception_proposal.required_role, "holder");
    assert!(
        blocked
            .message
            .contains("level=vault row=oneiron.default.fanout.v1 role=owner")
    );
    assert!(
        blocked
            .suggestions
            .iter()
            .any(|proposal| proposal.contains("ask_for_exception:fanout.create_rate"))
    );
    assert_eq!(task_entity_census(&vault), 10);

    let expanded = ConsultFanOutPolicy {
        create_rate: TaskCreateRateLimit {
            limit: 12,
            window_seconds: 3600,
        },
        ..policy
    };
    facade.set_consult_fanout_policy(&human, &expanded).unwrap();
    assert_eq!(
        facade
            .fan_out_counted_consults(&input, "research")
            .unwrap()
            .task_refs
            .len(),
        1
    );
    assert_eq!(task_entity_census(&vault), 11);
}

#[test]
fn fanout_scoped_rows_narrow_parent_and_holder_override_stays_within_vault() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let human = owner(&vault);
    let facade = vault.memory(actor, EdgeActorClass::Agent);
    let vault_policy = ConsultFanOutPolicy {
        approval_threshold: 100,
        create_rate: TaskCreateRateLimit {
            limit: 20,
            window_seconds: 3600,
        },
        ..ConsultFanOutPolicy::default()
    };
    facade
        .set_consult_fanout_policy(&human, &vault_policy)
        .unwrap();
    let project = ConsultFanOutScope {
        project_ref: Some(EntityId::from_bytes([0xA1; 16]).unwrap().to_hex()),
        ..Default::default()
    };
    let subproject = ConsultFanOutScope {
        subproject_ref: Some(EntityId::from_bytes([0xA2; 16]).unwrap().to_hex()),
        ..project.clone()
    };
    let thread = ConsultFanOutScope {
        thread_ref: Some(EntityId::from_bytes([0xA3; 16]).unwrap().to_hex()),
        ..subproject.clone()
    };
    for (scope, threshold, quota) in [(&project, 60, 9), (&subproject, 40, 7), (&thread, 20, 5)] {
        let next = ConsultFanOutPolicy {
            approval_threshold: threshold,
            create_rate: TaskCreateRateLimit {
                limit: quota,
                window_seconds: 3600,
            },
            ..vault_policy.clone()
        };
        facade
            .set_consult_fanout_scope_policy(&human, scope, &next, false)
            .unwrap();
    }
    assert_eq!(
        facade
            .get_consult_fanout_policy_for(&project)
            .unwrap()
            .approval_threshold,
        60
    );
    assert_eq!(
        facade
            .get_consult_fanout_policy_for(&subproject)
            .unwrap()
            .approval_threshold,
        40
    );
    assert_eq!(
        facade
            .get_consult_fanout_policy_for(&thread)
            .unwrap()
            .approval_threshold,
        20
    );
    let scoped_input = plan(&vault, 50);
    let narrowed = facade
        .fan_out_counted_consults_in_scope(&scoped_input, "research", &thread, &human, None)
        .unwrap();
    assert!(narrowed.paused.is_some());
    assert!(narrowed.task_refs.is_empty());
    assert_eq!(task_entity_census(&vault), 0);
    let holder = ConsultFanOutPolicy {
        approval_threshold: 90,
        mode: ConsultFanOutMode::FullAccess,
        create_rate: TaskCreateRateLimit {
            limit: 12,
            window_seconds: 3600,
        },
        ..vault_policy
    };
    facade
        .set_consult_fanout_scope_policy(&human, &thread, &holder, true)
        .unwrap();
    let resolved = facade.get_consult_fanout_policy_for(&thread).unwrap();
    assert_eq!(resolved.approval_threshold, 90);
    assert_eq!(resolved.create_rate.limit, 12);
    assert_eq!(resolved.mode, ConsultFanOutMode::Auto); // vault mode cannot widen
    let admitted = facade
        .fan_out_counted_consults_in_scope(&scoped_input, "research", &thread, &human, None)
        .unwrap();
    assert_eq!(admitted.task_refs.len(), 50);
    assert_eq!(task_entity_census(&vault), 50);
    let past_vault = ConsultFanOutPolicy {
        approval_threshold: 150,
        create_rate: TaskCreateRateLimit {
            limit: 30,
            window_seconds: 3600,
        },
        ..holder
    };
    facade
        .set_consult_fanout_scope_policy(&human, &thread, &past_vault, true)
        .unwrap();
    let bounded = facade.get_consult_fanout_policy_for(&thread).unwrap();
    assert_eq!(bounded.approval_threshold, 100);
    assert_eq!(bounded.create_rate.limit, 20);
    assert_eq!(bounded.mode, ConsultFanOutMode::Auto);

    // The precedence row is data, not scan order: the strict option disables
    // the holder lift and the thread remains narrowed by its parent.
    let manifest_id = crate::gate::default_policy_manifest_id().unwrap();
    let raw = vault
        .latest_entity_bodies_by_type(crate::registry::ENTITY_TYPE_POLICY_MANIFEST, 10, 100)
        .unwrap()
        .into_iter()
        .find(|(id, _, _)| *id == manifest_id)
        .unwrap()
        .2;
    let Value::Map(mut rows) = rmpv::decode::read_value(&mut raw.as_slice()).unwrap() else {
        panic!("manifest map")
    };
    rows.iter_mut()
        .find(|(key, _)| key.as_str() == Some("consult_fanout_precedence"))
        .unwrap()
        .1 = Value::from("most_restrictive");
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(rows)).unwrap();
    vault
        .install_owner_policy_manifest(&human, manifest_id, bytes, unix_seconds_now())
        .unwrap();
    let strict = facade.get_consult_fanout_policy_for(&thread).unwrap();
    assert_eq!(strict.approval_threshold, 40);
    assert_eq!(strict.create_rate.limit, 7);
    let narrowed_again = facade
        .fan_out_counted_consults_in_scope(&scoped_input, "research", &thread, &human, None)
        .unwrap();
    assert!(narrowed_again.paused.is_some());
    assert!(narrowed_again.task_refs.is_empty());
    assert_eq!(task_entity_census(&vault), 50);
}

#[test]
fn fanout_ignores_legacy_node_local_policy_and_uses_manifest_rows() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let peer = consult_peer(&vault, 0xE2);
    // The old vault_meta carrier can no longer grant FullAccess, disable the
    // detector or move the approval threshold; only the manifest resolves.
    vault
        .with_write_txn(|txn| {
            vault
                .store
                .vault_meta
                .put(txn, b"tasks/fanout_policy/v1", b"corrupt stale policy")?;
            Ok(())
        })
        .unwrap();
    let facade = vault.memory(actor, EdgeActorClass::Agent);
    let policy = facade.get_consult_fanout_policy().unwrap();
    assert_eq!(policy.approval_threshold, 25);
    assert_eq!(policy.mode, ConsultFanOutMode::Auto);
    let input = ConsultFanOutSpec {
        question_ref: consult_turn(&vault, 0x7A),
        context_refs: Vec::new(),
        assignees: vec![peer; 26],
        deadline_at: unix_seconds_now() + 3600,
        label: None,
        now: None,
    };
    let parked = facade.fan_out_counted_consults(&input, "research").unwrap();
    assert!(parked.paused.is_some());
    assert!(parked.task_refs.is_empty());
}
