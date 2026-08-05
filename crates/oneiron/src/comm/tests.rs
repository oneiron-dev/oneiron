use super::*;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, encode_claim_body,
    validate_claim_body_and_decode,
};
use crate::config::VaultConfig;
use crate::error::ErrorKind;
use crate::identity_topology::{
    EntityLifecycleState, IdentityOpEvidence, IdentityOpWrite, IdentityTopologyOp, MergeOp,
    SurvivorshipPlan,
};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_COMM_RECORD, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
    ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON, EntityClassification, TypeByteBand,
    entity_type_registry_entry,
};
use crate::temporal::TimeRange;

use crate::test_util::entity;

fn open_vault() -> (tempfile::TempDir, Vault) {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    crate::test_util::open_test_vault_with(config)
}

fn validate_through_chokepoint(body: &ClaimBody) -> Result<ClaimBody> {
    let encoded = encode_claim_body(body)?;
    validate_claim_body_and_decode(&encoded, false)
}

fn standing_channel_claim_id(
    vault: &Vault,
    party_ref: EntityId,
    predicate: &str,
    channel_class: &str,
) -> CommResult<EntityId> {
    let rtxn = vault.store.env.read_txn()?;
    let claims = matching_claims_in_txn(
        vault,
        &rtxn,
        party_ref,
        predicate,
        Some(channel_class),
        None,
        true,
    )?;
    assert_eq!(claims.len(), 1);
    Ok(claims[0].0)
}

fn active_last_touch_occurred_at(
    vault: &Vault,
    party: &str,
    channel_class: &str,
) -> CommResult<u64> {
    let party_ref = resolve_party(vault, party)?.ok_or(CommError::InvalidRecord)?;
    let rtxn = vault.store.env.read_txn()?;
    let active = matching_claims_in_txn(
        vault,
        &rtxn,
        party_ref,
        PREDICATE_COMM_LAST_TOUCH,
        Some(channel_class),
        None,
        true,
    )?;
    require_at_most_one(&active)?;
    let Some((_, head)) = active.into_iter().next() else {
        return Err(CommError::InvalidRecord);
    };
    match head.value {
        CommClaimValue::LastTouch { occurred_at, .. } => Ok(occurred_at),
        _ => Err(CommError::InvalidRecord),
    }
}

fn put_malformed_comm_record(vault: &Vault) -> CommResult<()> {
    let id = EntityId::now();
    let payload = crate::test_util::entity_record(
        ENTITY_TYPE_COMM_RECORD,
        TimeRange { start: 0, end: 0 },
        0,
        &[0xC1],
    );

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .entities
        .put(&mut wtxn, id.as_bytes(), &payload)?;
    let type_key = crate::store::Store::encode_type_key(ENTITY_TYPE_COMM_RECORD, &id);
    vault.store.type_index.put(&mut wtxn, &type_key, &[])?;
    wtxn.commit()?;
    Ok(())
}

fn put_semantically_invalid_comm_record(vault: &Vault, party_ref: EntityId) -> CommResult<()> {
    let record = CommRecord::Event {
        sequence: u64::MAX,
        kind: CommEventKind::SendSucceeded,
        party_ref,
        channel_class: Some("Email".to_owned()),
        thread_ref: None,
        occurred_at: 20,
        projected: false,
    };
    let id = EntityId::now();
    let payload = crate::test_util::entity_record(
        ENTITY_TYPE_COMM_RECORD,
        TimeRange { start: 20, end: 20 },
        20,
        &encode_comm_record(&record)?,
    );

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .entities
        .put(&mut wtxn, id.as_bytes(), &payload)?;
    let type_key = crate::store::Store::encode_type_key(ENTITY_TYPE_COMM_RECORD, &id);
    vault.store.type_index.put(&mut wtxn, &type_key, &[])?;
    wtxn.commit()?;
    Ok(())
}

#[test]
fn comm_family_validator_accepts_all_shapes_and_rejects_malformed_values() -> Result<()> {
    let party = entity(0x51);
    let well_formed = [
        CommClaimValue::OptOut {
            party_ref: party,
            channel_class: "email".to_owned(),
            reason: OPT_OUT_REASON_STOP.to_owned(),
            occurred_at: 10,
        },
        CommClaimValue::LastTouch {
            party_ref: party,
            channel_class: "email".to_owned(),
            occurred_at: 11,
        },
        CommClaimValue::ThreadMember {
            party_ref: party,
            thread_ref: "thread-1".to_owned(),
            occurred_at: 12,
        },
        CommClaimValue::ReachableVia {
            party_ref: party,
            channel_class: "email".to_owned(),
            reachable: true,
        },
    ];
    let accepted = well_formed
        .iter()
        .map(CommClaimValue::claim_body)
        .map(|body| validate_through_chokepoint(&body))
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(accepted.len(), 4);

    let mut missing_channel = well_formed[0].claim_body();
    let Value::Map(entries) = &mut missing_channel.value else {
        unreachable!("fixture value is a map")
    };
    entries.retain(|(key, _)| key.as_str() != Some(KEY_CHANNEL_CLASS));
    let missing_error =
        validate_through_chokepoint(&missing_channel).expect_err("missing channel_class rejected");
    assert_eq!(missing_error.kind(), ErrorKind::InvalidClaimBody);

    let mut wrong_shape = well_formed[1].claim_body();
    wrong_shape.value = Value::from("email");
    let shape_error =
        validate_through_chokepoint(&wrong_shape).expect_err("non-map value rejected");
    assert_eq!(shape_error.kind(), ErrorKind::InvalidClaimBody);

    let one_segment = ClaimBody::new(
        "comm",
        ClaimSubject::Entity(party),
        Value::Map(Vec::new()),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    let predicate_error =
        validate_through_chokepoint(&one_segment).expect_err("one-segment predicate rejected");
    assert_eq!(predicate_error.kind(), ErrorKind::InvalidPredicate);

    let entry = entity_type_registry_entry(ENTITY_TYPE_COMM_RECORD).expect("comm registry row");
    assert_eq!(ENTITY_TYPE_COMM_RECORD, 136);
    assert_eq!(entry.kind, "COMM_RECORD");
    assert_eq!(entry.classification, EntityClassification::Maintenance);
    assert_eq!(entry.band, TypeByteBand::InducedDynamicMaintenance);
    Ok(())
}

#[test]
fn projector_replay_preserves_active_and_total_counts() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_send_receipt(&vault, "party-a", "email", 10)?;
    record_comm_inbound_stop(&vault, "party-a", "sms", 11)?;
    record_comm_thread_event(&vault, "thread-a", "party-a", true, 12)?;

    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_LAST_TOUCH, "party-a", "email")?,
        0
    );
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_OPT_OUT, "party-a", "sms")?,
        0
    );
    assert_eq!(
        count_active_thread_member_claims(&vault, "thread-a", "party-a")?,
        0
    );

    for pass in 1..=3 {
        run_comm_projector(&vault)?;
        assert_eq!(
            count_active_comm_claims(&vault, PREDICATE_COMM_LAST_TOUCH, "party-a", "email")?,
            1,
            "active last_touch after pass {pass}"
        );
        assert_eq!(
            count_total_comm_claim_rows(&vault, PREDICATE_COMM_LAST_TOUCH, "party-a", "email")?,
            1,
            "total last_touch after pass {pass}"
        );
        assert_eq!(
            count_active_comm_claims(&vault, PREDICATE_COMM_OPT_OUT, "party-a", "sms")?,
            1,
            "active opt_out after pass {pass}"
        );
        assert_eq!(
            count_total_comm_claim_rows(&vault, PREDICATE_COMM_OPT_OUT, "party-a", "sms")?,
            1,
            "total opt_out after pass {pass}"
        );
        assert_eq!(
            count_active_thread_member_claims(&vault, "thread-a", "party-a")?,
            1,
            "active membership after pass {pass}"
        );
    }
    Ok(())
}

#[test]
fn consent_refusal_and_one_shot_human_approval_preserve_exact_counts() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_inbound_stop(&vault, "party-a", "email", 10)?;
    run_comm_projector(&vault)?;
    assert_eq!(
        request_opt_out_clear(&vault, "party-a", "email", 11)?,
        CommClearOptOutOutcome::PendingHumanRuling
    );

    let party_ref = resolve_or_create_comm_party(&vault, "party-a")?;
    let agent = WriteActor::new(party_ref, EdgeActorClass::Agent);
    let before_agent = (
        count_pending_comm_consent_gates(&vault)?,
        count_active_comm_claims(&vault, PREDICATE_COMM_OPT_OUT, "party-a", "email")?,
        count_opt_out_clear_receipts(&vault, "party-a")?,
    );
    let agent_error = approve_pending_opt_out_clear(&vault, "party-a", "email", agent, 12)
        .expect_err("agent approval rejected");
    assert!(matches!(agent_error, CommError::HumanApprovalRequired));
    let after_agent = (
        count_pending_comm_consent_gates(&vault)?,
        count_active_comm_claims(&vault, PREDICATE_COMM_OPT_OUT, "party-a", "email")?,
        count_opt_out_clear_receipts(&vault, "party-a")?,
    );
    assert_eq!(before_agent, (1, 1, 0));
    assert_eq!(after_agent, before_agent);

    let human = WriteActor::new(party_ref, EdgeActorClass::Human);
    approve_pending_opt_out_clear(&vault, "party-a", "email", human, 13)?;
    let after_human = (
        count_pending_comm_consent_gates(&vault)?,
        count_active_comm_claims(&vault, PREDICATE_COMM_OPT_OUT, "party-a", "email")?,
        count_opt_out_clear_receipts(&vault, "party-a")?,
    );
    assert_eq!(after_human, (0, 0, 1));

    let second_error = approve_pending_opt_out_clear(&vault, "party-a", "email", human, 14)
        .expect_err("consumed gate rejects second ruling");
    assert!(matches!(second_error, CommError::PendingGateNotFound));
    let after_second = (
        count_pending_comm_consent_gates(&vault)?,
        count_active_comm_claims(&vault, PREDICATE_COMM_OPT_OUT, "party-a", "email")?,
        count_opt_out_clear_receipts(&vault, "party-a")?,
    );
    assert_eq!(after_second, after_human);
    Ok(())
}

#[test]
fn restrictive_stop_cancels_pending_clear_and_preserves_opt_out() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_inbound_stop(&vault, "party-stop-cancels-clear", "email", 10)?;
    run_comm_projector(&vault)?;
    assert_eq!(
        request_opt_out_clear(&vault, "party-stop-cancels-clear", "email", 20)?,
        CommClearOptOutOutcome::PendingHumanRuling
    );
    assert_eq!(count_pending_comm_consent_gates(&vault)?, 1);

    record_comm_inbound_stop(&vault, "party-stop-cancels-clear", "email", 30)?;
    run_comm_projector(&vault)?;
    assert_eq!(count_pending_comm_consent_gates(&vault)?, 0);
    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_OPT_OUT,
            "party-stop-cancels-clear",
            "email",
        )?,
        1
    );
    assert_eq!(
        count_opt_out_clear_receipts(&vault, "party-stop-cancels-clear")?,
        0
    );

    let party_ref =
        resolve_party(&vault, "party-stop-cancels-clear")?.ok_or(CommError::InvalidRecord)?;
    let human = WriteActor::new(party_ref, EdgeActorClass::Human);
    let error =
        approve_pending_opt_out_clear(&vault, "party-stop-cancels-clear", "email", human, 40)
            .expect_err("restrictive STOP consumes the pending widening gate");
    assert!(matches!(error, CommError::PendingGateNotFound));
    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_OPT_OUT,
            "party-stop-cancels-clear",
            "email",
        )?,
        1
    );
    assert_eq!(
        count_opt_out_clear_receipts(&vault, "party-stop-cancels-clear")?,
        0
    );
    Ok(())
}

#[test]
fn pending_clear_without_intervening_stop_is_approved_and_receipted() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_inbound_stop(&vault, "party-clear-approved", "email", 10)?;
    run_comm_projector(&vault)?;
    assert_eq!(
        request_opt_out_clear(&vault, "party-clear-approved", "email", 20)?,
        CommClearOptOutOutcome::PendingHumanRuling
    );
    assert_eq!(count_pending_comm_consent_gates(&vault)?, 1);

    let party_ref =
        resolve_party(&vault, "party-clear-approved")?.ok_or(CommError::InvalidRecord)?;
    let human = WriteActor::new(party_ref, EdgeActorClass::Human);
    approve_pending_opt_out_clear(&vault, "party-clear-approved", "email", human, 40)?;

    assert_eq!(count_pending_comm_consent_gates(&vault)?, 0);
    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_OPT_OUT,
            "party-clear-approved",
            "email",
        )?,
        0
    );
    assert_eq!(
        count_opt_out_clear_receipts(&vault, "party-clear-approved")?,
        1
    );
    Ok(())
}

#[test]
fn backdated_stop_does_not_cancel_later_pending_clear() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_inbound_stop(&vault, "party-backdated-stop", "email", 10)?;
    run_comm_projector(&vault)?;
    assert_eq!(
        request_opt_out_clear(&vault, "party-backdated-stop", "email", 20)?,
        CommClearOptOutOutcome::PendingHumanRuling
    );

    record_comm_inbound_stop(&vault, "party-backdated-stop", "email", 15)?;
    run_comm_projector(&vault)?;

    assert_eq!(count_pending_comm_consent_gates(&vault)?, 1);
    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_OPT_OUT,
            "party-backdated-stop",
            "email",
        )?,
        1
    );
    assert_eq!(
        count_opt_out_clear_receipts(&vault, "party-backdated-stop")?,
        0
    );
    Ok(())
}

#[test]
fn contact_materialization_is_deterministic_without_intervening_writes() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_send_receipt(&vault, "party-a", "email", 10)?;
    record_comm_inbound_stop(&vault, "party-a", "email", 11)?;
    run_comm_projector(&vault)?;

    let first = materialize_contact_record(&vault, "party-a")?;
    let second = materialize_contact_record(&vault, "party-a")?;
    assert_eq!(first, second);
    assert_eq!(count_contact_record_claim_entries(&vault, "party-a")?, 2);
    assert!(!first.is_empty());
    Ok(())
}

#[test]
fn materializing_unknown_party_is_read_only() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    assert_eq!(resolve_party(&vault, "party-never-recorded")?, None);

    let materialized = materialize_contact_record(&vault, "party-never-recorded")?;

    assert!(materialized.is_empty());
    assert_eq!(resolve_party(&vault, "party-never-recorded")?, None);
    Ok(())
}

#[test]
fn finding_1_future_dated_claims_are_standing_and_materialize_deterministically() -> CommResult<()>
{
    let (_dir, vault) = open_vault();
    let future = 4_000_000_000;
    record_comm_send_receipt(&vault, "party-f1", "email", future)?;
    run_comm_projector(&vault)?;

    let first = materialize_contact_record(&vault, "party-f1")?;
    let second = materialize_contact_record(&vault, "party-f1")?;
    assert_eq!(first, second);
    assert_eq!(count_contact_record_claim_entries(&vault, "party-f1")?, 1);
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_LAST_TOUCH, "party-f1", "email")?,
        1
    );

    record_comm_send_receipt(&vault, "party-f1", "email", future + 1)?;
    run_comm_projector(&vault)?;
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_LAST_TOUCH, "party-f1", "email")?,
        1
    );
    assert_eq!(
        count_total_comm_claim_rows(&vault, PREDICATE_COMM_LAST_TOUCH, "party-f1", "email")?,
        2
    );
    Ok(())
}

#[test]
fn finding_2_contact_view_is_purely_claim_derived() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_send_receipt(&vault, "party-f2", "email", 10)?;
    record_comm_inbound_stop(&vault, "party-f2", "email", 11)?;
    run_comm_projector(&vault)?;

    let first = materialize_contact_record(&vault, "party-f2")?;
    drop_contact_record(&vault, "party-f2")?;
    let rebuilt = materialize_contact_record(&vault, "party-f2")?;
    assert_eq!(first, rebuilt);
    assert!(!rebuilt.is_empty());
    assert_eq!(count_contact_record_claim_entries(&vault, "party-f2")?, 2);

    let party_ref = resolve_or_create_comm_party(&vault, "party-f2")?;
    let old_id = standing_channel_claim_id(&vault, party_ref, PREDICATE_COMM_OPT_OUT, "email")?;
    vault.try_with_write_txn(|wtxn| -> CommResult<()> {
        let replacement = CommClaimValue::OptOut {
            party_ref,
            channel_class: "email".to_owned(),
            reason: OPT_OUT_REASON_STOP.to_owned(),
            occurred_at: 12,
        };
        let new_id =
            put_comm_claim_with_id_in_txn(&vault, wtxn, EntityId::now(), &replacement, 12)?;
        vault.supersede_claim_in_txn(wtxn, &new_id, &old_id, 12)?;
        Ok(())
    })?;

    let refreshed = materialize_contact_record(&vault, "party-f2")?;
    assert_ne!(refreshed, first);
    assert_eq!(count_contact_record_claim_entries(&vault, "party-f2")?, 2);
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_OPT_OUT, "party-f2", "email")?,
        1
    );
    assert_eq!(
        count_total_comm_claim_rows(&vault, PREDICATE_COMM_OPT_OUT, "party-f2", "email")?,
        2
    );
    Ok(())
}

#[test]
fn finding_3_approval_refuses_when_replacement_head_postdates_the_request() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_inbound_stop(&vault, "party-f3", "email", 10)?;
    run_comm_projector(&vault)?;
    request_opt_out_clear(&vault, "party-f3", "email", 11)?;

    let party_ref = resolve_or_create_comm_party(&vault, "party-f3")?;
    let stale_gate_head =
        standing_channel_claim_id(&vault, party_ref, PREDICATE_COMM_OPT_OUT, "email")?;
    vault.retract_claim(&stale_gate_head, 12)?;
    record_comm_inbound_stop(&vault, "party-f3", "email", 13)?;
    run_comm_projector(&vault)?;
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_OPT_OUT, "party-f3", "email")?,
        1
    );
    assert_eq!(
        count_total_comm_claim_rows(&vault, PREDICATE_COMM_OPT_OUT, "party-f3", "email")?,
        2
    );
    assert_eq!(count_pending_comm_consent_gates(&vault)?, 1);
    assert_eq!(count_opt_out_clear_receipts(&vault, "party-f3")?, 0);

    let human = WriteActor::new(party_ref, EdgeActorClass::Human);
    // Canon: a clear requested before the opt-out's establishing STOP is stale — refused and consumed (L0 sweep-8 ruling).
    let error = approve_pending_opt_out_clear(&vault, "party-f3", "email", human, 14)
        .expect_err("replacement head postdates the request");
    assert!(matches!(error, CommError::PendingClearSupersededByStop));
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_OPT_OUT, "party-f3", "email")?,
        1
    );
    assert_eq!(
        count_total_comm_claim_rows(&vault, PREDICATE_COMM_OPT_OUT, "party-f3", "email")?,
        2
    );
    assert_eq!(count_pending_comm_consent_gates(&vault)?, 0);
    assert_eq!(count_opt_out_clear_receipts(&vault, "party-f3")?, 0);
    Ok(())
}

#[test]
fn finding_3_backdated_ruling_is_typed_and_has_no_state_change() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_inbound_stop(&vault, "party-f3-time", "email", 10)?;
    run_comm_projector(&vault)?;
    request_opt_out_clear(&vault, "party-f3-time", "email", 20)?;

    let party_ref = resolve_or_create_comm_party(&vault, "party-f3-time")?;
    let human = WriteActor::new(party_ref, EdgeActorClass::Human);
    let before = (
        count_pending_comm_consent_gates(&vault)?,
        count_active_comm_claims(&vault, PREDICATE_COMM_OPT_OUT, "party-f3-time", "email")?,
        count_opt_out_clear_receipts(&vault, "party-f3-time")?,
    );
    let error = approve_pending_opt_out_clear(&vault, "party-f3-time", "email", human, 19)
        .expect_err("backdated ruling rejected");
    assert!(matches!(error, CommError::RulingPredatesGate));
    let after = (
        count_pending_comm_consent_gates(&vault)?,
        count_active_comm_claims(&vault, PREDICATE_COMM_OPT_OUT, "party-f3-time", "email")?,
        count_opt_out_clear_receipts(&vault, "party-f3-time")?,
    );
    assert_eq!(before, (1, 1, 0));
    assert_eq!(after, before);
    Ok(())
}

#[test]
fn finding_3_missing_live_head_consumes_gate_without_receipt() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_inbound_stop(&vault, "party-f3-empty", "email", 10)?;
    run_comm_projector(&vault)?;
    request_opt_out_clear(&vault, "party-f3-empty", "email", 11)?;

    let party_ref = resolve_or_create_comm_party(&vault, "party-f3-empty")?;
    let claim_id = standing_channel_claim_id(&vault, party_ref, PREDICATE_COMM_OPT_OUT, "email")?;
    vault.retract_claim(&claim_id, 12)?;
    let human = WriteActor::new(party_ref, EdgeActorClass::Human);
    let error = approve_pending_opt_out_clear(&vault, "party-f3-empty", "email", human, 13)
        .expect_err("missing live head reports a typed outcome");
    assert!(matches!(error, CommError::ActiveOptOutNotFound));
    assert_eq!(count_pending_comm_consent_gates(&vault)?, 0);
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_OPT_OUT, "party-f3-empty", "email")?,
        0
    );
    assert_eq!(count_opt_out_clear_receipts(&vault, "party-f3-empty")?, 0);

    let second_error = approve_pending_opt_out_clear(&vault, "party-f3-empty", "email", human, 14)
        .expect_err("consumed gate is one-shot");
    assert!(matches!(second_error, CommError::PendingGateNotFound));
    assert_eq!(count_pending_comm_consent_gates(&vault)?, 0);
    assert_eq!(count_opt_out_clear_receipts(&vault, "party-f3-empty")?, 0);
    Ok(())
}

#[test]
fn finding_4_out_of_order_last_touch_events_do_not_wedge_projection() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_send_receipt(&vault, "party-f4", "email", 100)?;
    run_comm_projector(&vault)?;
    record_comm_send_receipt(&vault, "party-f4", "email", 50)?;
    run_comm_projector(&vault)?;
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_LAST_TOUCH, "party-f4", "email")?,
        1
    );
    assert_eq!(
        count_total_comm_claim_rows(&vault, PREDICATE_COMM_LAST_TOUCH, "party-f4", "email")?,
        2
    );
    assert_eq!(
        active_last_touch_occurred_at(&vault, "party-f4", "email")?,
        100
    );

    record_comm_send_receipt(&vault, "party-f4", "email", 25)?;
    run_comm_projector(&vault)?;
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_LAST_TOUCH, "party-f4", "email")?,
        1
    );
    assert_eq!(
        count_total_comm_claim_rows(&vault, PREDICATE_COMM_LAST_TOUCH, "party-f4", "email")?,
        3
    );
    assert_eq!(
        active_last_touch_occurred_at(&vault, "party-f4", "email")?,
        100
    );
    Ok(())
}

#[test]
fn forward_last_touch_event_replaces_the_active_head() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_send_receipt(&vault, "party-last-touch-forward", "email", 100)?;
    run_comm_projector(&vault)?;
    record_comm_send_receipt(&vault, "party-last-touch-forward", "email", 150)?;
    run_comm_projector(&vault)?;

    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_LAST_TOUCH,
            "party-last-touch-forward",
            "email",
        )?,
        1
    );
    assert_eq!(
        count_total_comm_claim_rows(
            &vault,
            PREDICATE_COMM_LAST_TOUCH,
            "party-last-touch-forward",
            "email",
        )?,
        2
    );
    assert_eq!(
        active_last_touch_occurred_at(&vault, "party-last-touch-forward", "email")?,
        150
    );
    Ok(())
}

#[test]
fn stale_leave_before_an_active_join_is_ignored() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_thread_event(&vault, "thread-backdated-leave", "party-thread", true, 100)?;
    run_comm_projector(&vault)?;
    assert_eq!(
        count_active_thread_member_claims(&vault, "thread-backdated-leave", "party-thread")?,
        1
    );

    record_comm_thread_event(&vault, "thread-backdated-leave", "party-thread", false, 50)?;
    run_comm_projector(&vault)?;

    assert_eq!(
        count_active_thread_member_claims(&vault, "thread-backdated-leave", "party-thread")?,
        1
    );
    assert_eq!(
        count_comm_claims(
            &vault,
            PREDICATE_COMM_THREAD_MEMBER,
            "party-thread",
            None,
            Some("thread-backdated-leave"),
            false,
        )?,
        1
    );
    Ok(())
}

#[test]
fn backdated_clear_before_the_head_stop_is_refused_and_consumed() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_inbound_stop(&vault, "party-opt-out-clamp", "email", 100)?;
    run_comm_projector(&vault)?;
    assert_eq!(
        request_opt_out_clear(&vault, "party-opt-out-clamp", "email", 40)?,
        CommClearOptOutOutcome::PendingHumanRuling
    );

    let party_ref =
        resolve_party(&vault, "party-opt-out-clamp")?.ok_or(CommError::InvalidRecord)?;
    let human = WriteActor::new(party_ref, EdgeActorClass::Human);
    // Canon: a clear requested before the opt-out's establishing STOP is stale — refused and consumed (L0 sweep-8 ruling).
    let error = approve_pending_opt_out_clear(&vault, "party-opt-out-clamp", "email", human, 50)
        .expect_err("backdated clear is superseded");
    assert!(matches!(error, CommError::PendingClearSupersededByStop));

    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_OPT_OUT,
            "party-opt-out-clamp",
            "email",
        )?,
        1
    );
    assert_eq!(
        count_total_comm_claim_rows(
            &vault,
            PREDICATE_COMM_OPT_OUT,
            "party-opt-out-clamp",
            "email",
        )?,
        1
    );
    assert_eq!(count_pending_comm_consent_gates(&vault)?, 0);
    assert_eq!(
        count_opt_out_clear_receipts(&vault, "party-opt-out-clamp")?,
        0
    );
    Ok(())
}

#[test]
fn delayed_stop_does_not_resurrect_a_human_cleared_opt_out() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_inbound_stop(&vault, "party-delayed-stop", "email", 100)?;
    run_comm_projector(&vault)?;

    assert_eq!(
        request_opt_out_clear(&vault, "party-delayed-stop", "email", 120)?,
        CommClearOptOutOutcome::PendingHumanRuling
    );
    let party_ref = resolve_party(&vault, "party-delayed-stop")?.ok_or(CommError::InvalidRecord)?;
    let human = WriteActor::new(party_ref, EdgeActorClass::Human);
    approve_pending_opt_out_clear(&vault, "party-delayed-stop", "email", human, 120)?;
    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_OPT_OUT,
            "party-delayed-stop",
            "email",
        )?,
        0
    );
    assert_eq!(
        count_opt_out_clear_receipts(&vault, "party-delayed-stop")?,
        1
    );

    record_comm_inbound_stop(&vault, "party-delayed-stop", "email", 90)?;
    run_comm_projector(&vault)?;
    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_OPT_OUT,
            "party-delayed-stop",
            "email",
        )?,
        0
    );
    assert_eq!(
        count_total_comm_claim_rows(
            &vault,
            PREDICATE_COMM_OPT_OUT,
            "party-delayed-stop",
            "email",
        )?,
        2
    );
    assert_eq!(
        count_opt_out_clear_receipts(&vault, "party-delayed-stop")?,
        1
    );

    record_comm_inbound_stop(&vault, "party-delayed-stop", "email", 130)?;
    run_comm_projector(&vault)?;
    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_OPT_OUT,
            "party-delayed-stop",
            "email",
        )?,
        1
    );
    assert_eq!(
        count_total_comm_claim_rows(
            &vault,
            PREDICATE_COMM_OPT_OUT,
            "party-delayed-stop",
            "email",
        )?,
        3
    );
    assert_eq!(
        count_opt_out_clear_receipts(&vault, "party-delayed-stop")?,
        1
    );
    Ok(())
}

#[test]
fn delayed_join_does_not_resurrect_membership_after_a_projected_leave() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_thread_event(
        &vault,
        "thread-delayed-join",
        "party-delayed-join",
        false,
        100,
    )?;
    run_comm_projector(&vault)?;
    record_comm_thread_event(
        &vault,
        "thread-delayed-join",
        "party-delayed-join",
        true,
        50,
    )?;
    run_comm_projector(&vault)?;
    assert_eq!(
        count_active_thread_member_claims(&vault, "thread-delayed-join", "party-delayed-join",)?,
        0
    );
    assert_eq!(
        count_comm_claims(
            &vault,
            PREDICATE_COMM_THREAD_MEMBER,
            "party-delayed-join",
            None,
            Some("thread-delayed-join"),
            false,
        )?,
        1
    );

    record_comm_thread_event(
        &vault,
        "thread-control-order",
        "party-delayed-join",
        true,
        60,
    )?;
    run_comm_projector(&vault)?;
    record_comm_thread_event(
        &vault,
        "thread-control-order",
        "party-delayed-join",
        false,
        100,
    )?;
    run_comm_projector(&vault)?;
    assert_eq!(
        count_active_thread_member_claims(&vault, "thread-control-order", "party-delayed-join",)?,
        0
    );

    record_comm_thread_event(
        &vault,
        "thread-delayed-join",
        "party-delayed-join",
        true,
        150,
    )?;
    run_comm_projector(&vault)?;
    assert_eq!(
        count_active_thread_member_claims(&vault, "thread-delayed-join", "party-delayed-join",)?,
        1
    );
    assert_eq!(
        count_comm_claims(
            &vault,
            PREDICATE_COMM_THREAD_MEMBER,
            "party-delayed-join",
            None,
            Some("thread-delayed-join"),
            false,
        )?,
        2
    );
    Ok(())
}

#[test]
fn delayed_projection_uses_current_learn_time_for_party_claim_and_record() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_send_receipt(&vault, "party-delayed-learning", "email", 100)?;
    run_comm_projector(&vault)?;

    let party_ref =
        resolve_party(&vault, "party-delayed-learning")?.ok_or(CommError::InvalidRecord)?;
    let (claim_id, record_id) = {
        let rtxn = vault.store.env.read_txn()?;
        let claims = matching_claims_in_txn(
            &vault,
            &rtxn,
            party_ref,
            PREDICATE_COMM_LAST_TOUCH,
            Some("email"),
            None,
            true,
        )?;
        assert_eq!(claims.len(), 1);
        let records = comm_records_in_txn(&vault, &rtxn)?;
        assert_eq!(records.len(), 1);
        (claims[0].0, records[0].0)
    };

    assert_eq!(vault.get_entity_type(&party_ref)?, Some(ENTITY_TYPE_PERSON));
    assert_eq!(vault.get_entity_type(&claim_id)?, Some(ENTITY_TYPE_CLAIM));
    assert_eq!(
        vault.get_entity_type(&record_id)?,
        Some(ENTITY_TYPE_COMM_RECORD)
    );
    let learned_after_event = vault.entities_in_learned_range(101, u64::MAX)?;
    assert!(learned_after_event.contains(&party_ref));
    assert!(learned_after_event.contains(&claim_id));
    assert!(learned_after_event.contains(&record_id));
    Ok(())
}

#[test]
fn party_absent_event_does_not_wedge_later_projection() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_send_receipt(&vault, "party-after-missing", "email", 20)?;

    let missing_party_ref = entity(0xB1);
    let missing_event_id = EntityId::now();
    let missing_event = CommRecord::Event {
        sequence: 0,
        kind: CommEventKind::SendSucceeded,
        party_ref: missing_party_ref,
        channel_class: Some("email".to_owned()),
        thread_ref: None,
        occurred_at: 10,
        projected: false,
    };
    vault.try_with_write_txn(|wtxn| {
        put_comm_record_in_txn(&vault, wtxn, missing_event_id, &missing_event)
    })?;
    assert_eq!(vault.get_entity_type(&missing_party_ref)?, None);

    run_comm_projector(&vault)?;

    let rtxn = vault.store.env.read_txn()?;
    let records = comm_records_in_txn(&vault, &rtxn)?;
    let (_, retained) = records
        .iter()
        .find(|(id, _)| *id == missing_event_id)
        .ok_or(CommError::InvalidRecord)?;
    assert!(matches!(
        retained,
        CommRecord::Event {
            projected: false,
            ..
        }
    ));
    drop(rtxn);
    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_LAST_TOUCH,
            "party-after-missing",
            "email",
        )?,
        1
    );
    assert_eq!(
        count_total_comm_claim_rows(
            &vault,
            PREDICATE_COMM_LAST_TOUCH,
            "party-after-missing",
            "email",
        )?,
        1
    );

    run_comm_projector(&vault)?;
    assert_eq!(
        count_total_comm_claim_rows(
            &vault,
            PREDICATE_COMM_LAST_TOUCH,
            "party-after-missing",
            "email",
        )?,
        1
    );
    Ok(())
}

#[test]
fn equal_time_join_and_leave_converge_to_non_membership_either_order() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    // Order A: join then leave at the same occurred_at.
    record_comm_thread_event(&vault, "thread-tie-a", "party-tie-a", true, 100)?;
    record_comm_thread_event(&vault, "thread-tie-a", "party-tie-a", false, 100)?;
    // Order B: leave then join at the same occurred_at.
    record_comm_thread_event(&vault, "thread-tie-b", "party-tie-b", false, 100)?;
    record_comm_thread_event(&vault, "thread-tie-b", "party-tie-b", true, 100)?;
    run_comm_projector(&vault)?;
    // Restrictive-wins-tie: equal-time opposing thread events converge to
    // non-membership regardless of which was projected first.
    assert_eq!(
        count_active_thread_member_claims(&vault, "thread-tie-a", "party-tie-a")?,
        0
    );
    assert_eq!(
        count_active_thread_member_claims(&vault, "thread-tie-b", "party-tie-b")?,
        0
    );
    Ok(())
}

#[test]
fn non_person_party_ref_is_skipped_without_wedging_projection() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    // A valid PERSON party whose send must still project (no wedge).
    record_comm_send_receipt(&vault, "valid-person", "email", 20)?;

    // An existing NON-PERSON entity (a MACHINE) named as party_ref by a
    // replicated event: comm.* claims must not attach to it.
    let non_person = entity(0xC3);
    vault.put_entity(
        &non_person,
        ENTITY_TYPE_MACHINE,
        TimeRange { start: 1, end: 1 },
        1,
        b"machine",
    )?;
    assert_eq!(
        vault.get_entity_type(&non_person)?,
        Some(ENTITY_TYPE_MACHINE)
    );

    let bad_event_id = EntityId::now();
    let bad_event = CommRecord::Event {
        sequence: 0,
        kind: CommEventKind::SendSucceeded,
        party_ref: non_person,
        channel_class: Some("email".to_owned()),
        thread_ref: None,
        occurred_at: 10,
        projected: false,
    };
    vault.try_with_write_txn(|wtxn| {
        put_comm_record_in_txn(&vault, wtxn, bad_event_id, &bad_event)
    })?;

    run_comm_projector(&vault)?;

    let rtxn = vault.store.env.read_txn()?;
    // The non-PERSON event is skipped (left unprojected), not marked done.
    let records = comm_records_in_txn(&vault, &rtxn)?;
    let (_, retained) = records
        .iter()
        .find(|(id, _)| *id == bad_event_id)
        .ok_or(CommError::InvalidRecord)?;
    assert!(matches!(
        retained,
        CommRecord::Event {
            projected: false,
            ..
        }
    ));
    // No comm.* claim was attached to the non-PERSON subject.
    let attached = matching_claims_in_txn(
        &vault,
        &rtxn,
        non_person,
        PREDICATE_COMM_LAST_TOUCH,
        Some("email"),
        None,
        false,
    )?;
    assert!(attached.is_empty());
    drop(rtxn);

    // The valid PERSON party's send still projected — no wedge.
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_LAST_TOUCH, "valid-person", "email")?,
        1
    );
    Ok(())
}

#[test]
fn opt_out_clear_rejects_actor_absent_at_ruling_time_without_consuming_gate() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_inbound_stop(&vault, "party-actor-absent", "email", 10)?;
    run_comm_projector(&vault)?;
    assert_eq!(
        request_opt_out_clear(&vault, "party-actor-absent", "email", 20)?,
        CommClearOptOutOutcome::PendingHumanRuling
    );
    // An actor entity that does not exist is rejected by the in-transaction
    // authorization read (TOCTOU-safe); the rejected ruling rolls back, so the
    // pending gate and active opt-out are left intact.
    let ghost = WriteActor::new(entity(0xD4), EdgeActorClass::Human);
    let error = approve_pending_opt_out_clear(&vault, "party-actor-absent", "email", ghost, 40)
        .expect_err("absent actor is not authorized");
    assert!(matches!(
        error,
        CommError::Engine(crate::error::Error::EntityNotFound)
    ));
    assert_eq!(count_pending_comm_consent_gates(&vault)?, 1);
    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_OPT_OUT,
            "party-actor-absent",
            "email"
        )?,
        1
    );
    Ok(())
}

#[test]
fn cross_populated_event_fields_are_rejected_at_decode() -> CommResult<()> {
    let party = entity(0xE7);
    // A send/STOP event carrying BOTH channel_class and thread_ref must not decode.
    let cross_send = CommRecord::Event {
        sequence: 1,
        kind: CommEventKind::SendSucceeded,
        party_ref: party,
        channel_class: Some("email".to_owned()),
        thread_ref: Some("thread-x".to_owned()),
        occurred_at: 10,
        projected: false,
    };
    assert!(matches!(
        decode_comm_record(&encode_comm_record(&cross_send)?),
        Err(CommError::InvalidRecord)
    ));

    // A thread event carrying BOTH thread_ref and channel_class must not decode.
    let cross_thread = CommRecord::Event {
        sequence: 2,
        kind: CommEventKind::ThreadJoined,
        party_ref: party,
        channel_class: Some("email".to_owned()),
        thread_ref: Some("thread-x".to_owned()),
        occurred_at: 11,
        projected: false,
    };
    assert!(matches!(
        decode_comm_record(&encode_comm_record(&cross_thread)?),
        Err(CommError::InvalidRecord)
    ));

    // The correctly-shaped variants still decode.
    let ok_send = CommRecord::Event {
        sequence: 3,
        kind: CommEventKind::SendSucceeded,
        party_ref: party,
        channel_class: Some("email".to_owned()),
        thread_ref: None,
        occurred_at: 12,
        projected: false,
    };
    assert!(decode_comm_record(&encode_comm_record(&ok_send)?).is_ok());
    Ok(())
}

#[test]
fn stale_non_person_cached_party_is_reminted_before_reuse() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    // Simulate a party whose original PERSON was deleted and whose indexed id
    // was reused by another entity type: create a fresh MACHINE and point the
    // comm party index directly at it (the precondition the resolver must
    // detect), without mutating any existing entity's type in place.
    let stale_id = entity(0xD4);
    vault.put_entity(
        &stale_id,
        ENTITY_TYPE_MACHINE,
        TimeRange { start: 1, end: 1 },
        1,
        b"machine",
    )?;
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(
            &mut wtxn,
            &party_index_key("party-reuse"),
            stale_id.as_bytes(),
        )?;
        wtxn.commit()?;
    }
    assert_eq!(vault.get_entity_type(&stale_id)?, Some(ENTITY_TYPE_MACHINE));
    // The cache is a shortcut, not truth: a hit naming a non-PERSON row is
    // rejected and the synced scan finds nothing, so the party reads as absent
    // rather than as the stale id.
    assert_eq!(resolve_party(&vault, "party-reuse")?, None);

    // A new local record must remint a fresh PERSON and rebind the index rather
    // than mint the event against the stale non-PERSON id.
    record_comm_send_receipt(&vault, "party-reuse", "email", 20)?;
    let new_id = resolve_party(&vault, "party-reuse")?.ok_or(CommError::InvalidRecord)?;
    assert_ne!(new_id, stale_id);
    assert_eq!(vault.get_entity_type(&new_id)?, Some(ENTITY_TYPE_PERSON));

    run_comm_projector(&vault)?;
    // The event minted against the fresh PERSON projects (no wedge).
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_LAST_TOUCH, "party-reuse", "email")?,
        1
    );
    Ok(())
}

#[test]
fn backdated_gate_after_later_stop_is_refused_and_consumed() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_inbound_stop(&vault, "party-superseded", "email", 10)?;
    run_comm_projector(&vault)?;
    // A later restrictive STOP is projected while no clear gate exists yet, so
    // the projection-side consume (:1013) does not fire.
    record_comm_inbound_stop(&vault, "party-superseded", "email", 30)?;
    run_comm_projector(&vault)?;
    // A clear gate whose created_at predates the projected STOP@30 (backdated / late).
    assert_eq!(
        request_opt_out_clear(&vault, "party-superseded", "email", 20)?,
        CommClearOptOutOutcome::PendingHumanRuling
    );
    assert_eq!(count_pending_comm_consent_gates(&vault)?, 1);

    let party_ref = resolve_party(&vault, "party-superseded")?.ok_or(CommError::InvalidRecord)?;
    let human = WriteActor::new(party_ref, EdgeActorClass::Human);
    let error = approve_pending_opt_out_clear(&vault, "party-superseded", "email", human, 40)
        .expect_err("clear superseded by a later restrictive STOP");
    assert!(matches!(error, CommError::PendingClearSupersededByStop));
    // Stale gate consumed, opt-out intact, no receipt written.
    assert_eq!(count_pending_comm_consent_gates(&vault)?, 0);
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_OPT_OUT, "party-superseded", "email")?,
        1
    );
    assert_eq!(count_opt_out_clear_receipts(&vault, "party-superseded")?, 0);
    Ok(())
}

#[test]
fn deleted_indexed_party_is_reminted_before_projector_reuse() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_send_receipt(&vault, "party-reminted", "email", 10)?;
    run_comm_projector(&vault)?;
    let deleted_party = resolve_party(&vault, "party-reminted")?.ok_or(CommError::InvalidRecord)?;

    assert!(vault.delete_entity(&deleted_party)?);
    assert_eq!(vault.get_entity_type(&deleted_party)?, None);
    // A cache hit naming a deleted row is stale, and synced truth holds no
    // replacement — absent, not the dangling id.
    assert_eq!(resolve_party(&vault, "party-reminted")?, None);

    record_comm_send_receipt(&vault, "party-reminted", "email", 20)?;
    let reminted_party =
        resolve_party(&vault, "party-reminted")?.ok_or(CommError::InvalidRecord)?;
    assert_ne!(reminted_party, deleted_party);
    assert_eq!(
        vault.get_entity_type(&reminted_party)?,
        Some(ENTITY_TYPE_PERSON)
    );

    run_comm_projector(&vault)?;
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_LAST_TOUCH, "party-reminted", "email",)?,
        1
    );
    assert_eq!(
        count_total_comm_claim_rows(&vault, PREDICATE_COMM_LAST_TOUCH, "party-reminted", "email",)?,
        1
    );
    Ok(())
}

#[test]
fn semantically_invalid_comm_record_is_skipped_without_wedging_family() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_send_receipt(&vault, "party-invalid-record", "email", 10)?;
    let party_ref =
        resolve_party(&vault, "party-invalid-record")?.ok_or(CommError::InvalidRecord)?;
    put_semantically_invalid_comm_record(&vault, party_ref)?;

    run_comm_projector(&vault)?;
    let rtxn = vault.store.env.read_txn()?;
    let records = comm_records_in_txn(&vault, &rtxn)?;
    assert_eq!(records.len(), 1);
    assert!(matches!(
        &records[0].1,
        CommRecord::Event {
            party_ref: candidate_party,
            channel_class: Some(channel_class),
            occurred_at: 10,
            ..
        } if *candidate_party == party_ref && channel_class == "email"
    ));
    drop(rtxn);
    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_LAST_TOUCH,
            "party-invalid-record",
            "email",
        )?,
        1
    );
    assert_eq!(
        count_total_comm_claim_rows(
            &vault,
            PREDICATE_COMM_LAST_TOUCH,
            "party-invalid-record",
            "email",
        )?,
        1
    );
    let materialized = materialize_contact_record(&vault, "party-invalid-record")?;
    assert!(!materialized.is_empty());
    assert_eq!(
        count_contact_record_claim_entries(&vault, "party-invalid-record")?,
        1
    );
    Ok(())
}

#[test]
fn finding_5_malformed_comm_record_does_not_wedge_family_operations() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_send_receipt(&vault, "party-f5", "email", 10)?;
    put_malformed_comm_record(&vault)?;
    run_comm_projector(&vault)?;

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(comm_records_in_txn(&vault, &rtxn)?.len(), 1);
    drop(rtxn);
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_LAST_TOUCH, "party-f5", "email")?,
        1
    );
    assert_eq!(
        count_total_comm_claim_rows(&vault, PREDICATE_COMM_LAST_TOUCH, "party-f5", "email")?,
        1
    );
    let materialized = materialize_contact_record(&vault, "party-f5")?;
    assert!(!materialized.is_empty());
    assert_eq!(count_contact_record_claim_entries(&vault, "party-f5")?, 1);
    Ok(())
}

#[test]
fn projected_claim_ids_are_derived_from_the_source_event_not_minted() -> CommResult<()> {
    let party = entity(0x71);
    let event = entity(0x72);
    let last_touch = CommClaimValue::LastTouch {
        party_ref: party,
        channel_class: "email".to_owned(),
        occurred_at: 10,
    };

    // Same inputs → same id, on any device, for any number of replays.
    assert_eq!(
        projected_comm_claim_id(event, &last_touch)?,
        projected_comm_claim_id(event, &last_touch)?
    );

    // occurred_at is NOT part of the conflict key: the same source event
    // projecting the same slot converges even if the payload time moves.
    let same_slot_later = CommClaimValue::LastTouch {
        party_ref: party,
        channel_class: "email".to_owned(),
        occurred_at: 999,
    };
    assert_eq!(
        projected_comm_claim_id(event, &last_touch)?,
        projected_comm_claim_id(event, &same_slot_later)?
    );

    // Every other input axis moves the id.
    let base = projected_comm_claim_id(event, &last_touch)?;
    let other_event = projected_comm_claim_id(entity(0x73), &last_touch)?;
    let other_predicate = projected_comm_claim_id(
        event,
        &CommClaimValue::OptOut {
            party_ref: party,
            channel_class: "email".to_owned(),
            reason: OPT_OUT_REASON_STOP.to_owned(),
            occurred_at: 10,
        },
    )?;
    let other_party = projected_comm_claim_id(
        event,
        &CommClaimValue::LastTouch {
            party_ref: entity(0x74),
            channel_class: "email".to_owned(),
            occurred_at: 10,
        },
    )?;
    let other_channel = projected_comm_claim_id(
        event,
        &CommClaimValue::LastTouch {
            party_ref: party,
            channel_class: "sms".to_owned(),
            occurred_at: 10,
        },
    )?;
    let thread_a = projected_comm_claim_id(
        event,
        &CommClaimValue::ThreadMember {
            party_ref: party,
            thread_ref: "thread-a".to_owned(),
            occurred_at: 10,
        },
    )?;
    let thread_b = projected_comm_claim_id(
        event,
        &CommClaimValue::ThreadMember {
            party_ref: party,
            thread_ref: "thread-b".to_owned(),
            occurred_at: 10,
        },
    )?;
    let distinct = std::collections::BTreeSet::from([
        base,
        other_event,
        other_predicate,
        other_party,
        other_channel,
        thread_a,
        thread_b,
    ]);
    assert_eq!(
        distinct.len(),
        7,
        "every input axis must move the derived id"
    );

    // Length prefixes: ("ab","c") and ("a","bc") must not collide.
    let split_left = projected_comm_conflict_key(&CommClaimValue::ThreadMember {
        party_ref: party,
        thread_ref: "ab-c".to_owned(),
        occurred_at: 1,
    });
    let split_right = projected_comm_conflict_key(&CommClaimValue::ThreadMember {
        party_ref: party,
        thread_ref: "a-bc".to_owned(),
        occurred_at: 1,
    });
    assert_ne!(split_left, split_right);

    // The derived id carries the same v7 version/variant nibbles as the
    // connector actor id, so it is a well-formed entity id.
    let bytes = base.as_bytes();
    assert_eq!(bytes[6] & 0xf0, 0x70);
    assert_eq!(bytes[8] & 0xc0, 0x80);
    Ok(())
}

#[test]
fn two_vaults_project_one_source_event_to_byte_identical_claim_ids() -> CommResult<()> {
    // The convergence property: the SAME explicit source event id, projected
    // independently on two devices, yields one physical row id per slot — so
    // importing both projections cannot produce two heads for one conflict key.
    fn project_in_fresh_vault(event_id: EntityId) -> CommResult<Vec<EntityId>> {
        let (_dir, vault) = open_vault();
        let party_ref = resolve_or_create_comm_party(&vault, "party-converge")?;
        let event = CommRecord::Event {
            sequence: 1,
            kind: CommEventKind::SendSucceeded,
            party_ref,
            channel_class: Some("email".to_owned()),
            thread_ref: None,
            occurred_at: 10,
            projected: false,
        };
        vault.try_with_write_txn(|wtxn| put_comm_record_in_txn(&vault, wtxn, event_id, &event))?;
        run_comm_projector(&vault)?;
        let rtxn = vault.store.env.read_txn()?;
        let claims = matching_claims_in_txn(
            &vault,
            &rtxn,
            party_ref,
            PREDICATE_COMM_LAST_TOUCH,
            Some("email"),
            None,
            true,
        )?;
        Ok(claims.into_iter().map(|(id, _)| id).collect())
    }

    let source_event = entity(0x75);
    let left = project_in_fresh_vault(source_event)?;
    let right = project_in_fresh_vault(source_event)?;
    assert_eq!(left.len(), 1);
    // Party ids differ per vault, yet the claim rows agree — the derivation is
    // anchored on the SOURCE EVENT, and the party enters through the conflict
    // key only. Two vaults sharing a party (the replicated case) converge on
    // one id; here we assert the derivation is stable and total.
    assert_eq!(right.len(), 1);

    // The replicated case proper: same event id AND same party id.
    let (_dir, vault) = open_vault();
    let party_ref = resolve_or_create_comm_party(&vault, "party-shared")?;
    let value = CommClaimValue::LastTouch {
        party_ref,
        channel_class: "email".to_owned(),
        occurred_at: 10,
    };
    let derived = projected_comm_claim_id(source_event, &value)?;
    let event = CommRecord::Event {
        sequence: 1,
        kind: CommEventKind::SendSucceeded,
        party_ref,
        channel_class: Some("email".to_owned()),
        thread_ref: None,
        occurred_at: 10,
        projected: false,
    };
    vault.try_with_write_txn(|wtxn| put_comm_record_in_txn(&vault, wtxn, source_event, &event))?;
    run_comm_projector(&vault)?;
    assert_eq!(
        standing_channel_claim_id(&vault, party_ref, PREDICATE_COMM_LAST_TOUCH, "email")?,
        derived,
        "the projected row lands at exactly the derived id"
    );
    Ok(())
}

#[test]
fn replaying_an_identical_event_is_a_no_op_without_self_supersession() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    let party_ref = resolve_or_create_comm_party(&vault, "party-replay")?;
    let source_event = entity(0x76);
    let event = CommRecord::Event {
        sequence: 1,
        kind: CommEventKind::SendSucceeded,
        party_ref,
        channel_class: Some("email".to_owned()),
        thread_ref: None,
        occurred_at: 10,
        projected: false,
    };
    vault.try_with_write_txn(|wtxn| put_comm_record_in_txn(&vault, wtxn, source_event, &event))?;
    run_comm_projector(&vault)?;
    let first = standing_channel_claim_id(&vault, party_ref, PREDICATE_COMM_LAST_TOUCH, "email")?;

    // Re-arm the very same source event (the cross-device replay shape) and
    // project again: the row must be recognized, not rewritten, and no
    // self-supersession edge may be attempted.
    vault.try_with_write_txn(|wtxn| put_comm_record_in_txn(&vault, wtxn, source_event, &event))?;
    run_comm_projector(&vault)?;

    assert_eq!(
        standing_channel_claim_id(&vault, party_ref, PREDICATE_COMM_LAST_TOUCH, "email")?,
        first
    );
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_LAST_TOUCH, "party-replay", "email")?,
        1
    );
    assert_eq!(
        count_total_comm_claim_rows(&vault, PREDICATE_COMM_LAST_TOUCH, "party-replay", "email")?,
        1,
        "replay must not add a history row"
    );
    Ok(())
}

#[test]
fn derived_id_collision_with_a_foreign_row_fails_closed() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    let party_ref = resolve_or_create_comm_party(&vault, "party-collide")?;
    let source_event = entity(0x77);
    let value = CommClaimValue::LastTouch {
        party_ref,
        channel_class: "email".to_owned(),
        occurred_at: 10,
    };
    let derived = projected_comm_claim_id(source_event, &value)?;

    // Squat the derived id with a foreign (non-CLAIM) row.
    vault.put_entity(
        &derived,
        ENTITY_TYPE_MACHINE,
        TimeRange { start: 1, end: 1 },
        1,
        b"machine",
    )?;

    let event = CommRecord::Event {
        sequence: 1,
        kind: CommEventKind::SendSucceeded,
        party_ref,
        channel_class: Some("email".to_owned()),
        thread_ref: None,
        occurred_at: 10,
        projected: false,
    };
    vault.try_with_write_txn(|wtxn| put_comm_record_in_txn(&vault, wtxn, source_event, &event))?;

    let error = run_comm_projector(&vault).expect_err("resident foreign row fails closed");
    assert!(matches!(error, CommError::InvalidRecord));
    // The squatter is untouched — nothing was overwritten.
    assert_eq!(vault.get_entity_type(&derived)?, Some(ENTITY_TYPE_MACHINE));
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_LAST_TOUCH, "party-collide", "email")?,
        0
    );
    Ok(())
}

#[test]
fn derived_id_collision_with_a_different_claim_body_fails_closed() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    let party_ref = resolve_or_create_comm_party(&vault, "party-collide-claim")?;
    let source_event = entity(0x78);
    let value = CommClaimValue::LastTouch {
        party_ref,
        channel_class: "email".to_owned(),
        occurred_at: 10,
    };
    let derived = projected_comm_claim_id(source_event, &value)?;

    // Squat the derived id with a CLAIM whose decoded body differs (a
    // different channel — i.e. a different standing-state slot).
    let foreign = CommClaimValue::LastTouch {
        party_ref,
        channel_class: "sms".to_owned(),
        occurred_at: 10,
    };
    vault.try_with_write_txn(|wtxn| {
        put_comm_claim_with_id_in_txn(&vault, wtxn, derived, &foreign, 10).map(|_| ())
    })?;

    let event = CommRecord::Event {
        sequence: 1,
        kind: CommEventKind::SendSucceeded,
        party_ref,
        channel_class: Some("email".to_owned()),
        thread_ref: None,
        occurred_at: 10,
        projected: false,
    };
    vault.try_with_write_txn(|wtxn| put_comm_record_in_txn(&vault, wtxn, source_event, &event))?;

    let error = run_comm_projector(&vault).expect_err("mismatched resident claim fails closed");
    assert!(matches!(error, CommError::InvalidRecord));
    // The resident claim keeps its own body — no overwrite.
    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_LAST_TOUCH,
            "party-collide-claim",
            "sms",
        )?,
        1
    );
    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_LAST_TOUCH,
            "party-collide-claim",
            "email",
        )?,
        0
    );
    Ok(())
}

fn clear_party_index(vault: &Vault, party: &str) -> CommResult<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .vault_meta
        .delete(&mut wtxn, &party_index_key(party))?;
    wtxn.commit()?;
    Ok(())
}

fn point_party_index(vault: &Vault, party: &str, id: EntityId) -> CommResult<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .vault_meta
        .put(&mut wtxn, &party_index_key(party), id.as_bytes())?;
    wtxn.commit()?;
    Ok(())
}

/// Mints a comm-owned PERSON for `party` WITHOUT touching the node-local
/// shortcut — the offline-twin shape: two devices each minted a party row for
/// one key while synced truth was unreachable.
fn mint_comm_person(vault: &Vault, party: &str) -> CommResult<EntityId> {
    vault.try_with_write_txn(|wtxn| mint_comm_person_in_txn(vault, wtxn, party))
}

fn count_person_rows(vault: &Vault) -> CommResult<usize> {
    let rtxn = vault.store.env.read_txn()?;
    let mut count = 0;
    for entry in vault
        .store
        .type_index
        .prefix_iter(&rtxn, &[ENTITY_TYPE_PERSON])?
    {
        entry?;
        count += 1;
    }
    Ok(count)
}

#[test]
fn cleared_party_index_rebuilds_from_synced_truth_without_minting() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_send_receipt(&vault, "party-rebuild", "email", 10)?;
    run_comm_projector(&vault)?;
    let synced = resolve_party(&vault, "party-rebuild")?.ok_or(CommError::InvalidRecord)?;
    let persons_before = count_person_rows(&vault)?;

    // Drop the node-local shortcut, leaving the synced PERSON row intact — the
    // shape a fresh device sees after replicating a party it never minted.
    clear_party_index(&vault, "party-rebuild")?;

    assert_eq!(resolve_party(&vault, "party-rebuild")?, Some(synced));
    assert_eq!(
        resolve_or_create_comm_party(&vault, "party-rebuild")?,
        synced
    );
    assert_eq!(
        count_person_rows(&vault)?,
        persons_before,
        "rebuild must not mint a PERSON"
    );

    // The shortcut is repaired, so the next lookup is a plain hit.
    {
        let rtxn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .vault_meta
            .get(&rtxn, &party_index_key("party-rebuild"))?
            .ok_or(CommError::InvalidRecord)?;
        assert_eq!(decode_entity_id(&raw)?, synced);
    }

    // Standing state is unchanged and still reachable through the rebuilt path.
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_LAST_TOUCH, "party-rebuild", "email")?,
        1
    );
    Ok(())
}

#[test]
fn stale_index_entries_are_rejected_and_repaired_before_minting() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_send_receipt(&vault, "party-stale", "email", 10)?;
    run_comm_projector(&vault)?;
    let synced = resolve_party(&vault, "party-stale")?.ok_or(CommError::InvalidRecord)?;
    let persons_before = count_person_rows(&vault)?;

    // (a) A hit naming a row that does not exist.
    point_party_index(&vault, "party-stale", entity(0x81))?;
    assert_eq!(resolve_party(&vault, "party-stale")?, Some(synced));

    // (b) A hit naming a live NON-PERSON row.
    let machine = entity(0x82);
    vault.put_entity(
        &machine,
        ENTITY_TYPE_MACHINE,
        TimeRange { start: 1, end: 1 },
        1,
        b"machine",
    )?;
    point_party_index(&vault, "party-stale", machine)?;
    assert_eq!(resolve_party(&vault, "party-stale")?, Some(synced));

    // (c) A hit naming a PERSON whose party_key is a DIFFERENT party.
    let other = resolve_or_create_comm_party(&vault, "party-other")?;
    assert_ne!(other, synced);
    point_party_index(&vault, "party-stale", other)?;
    assert_eq!(resolve_party(&vault, "party-stale")?, Some(synced));
    // The other party's own shortcut is untouched by the repair.
    assert_eq!(resolve_party(&vault, "party-other")?, Some(other));

    assert_eq!(
        count_person_rows(&vault)?,
        persons_before + 1,
        "only the explicitly created party-other was minted"
    );
    Ok(())
}

#[test]
fn a_cached_merged_shell_is_stale_despite_staying_a_person() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    let survivor = resolve_or_create_comm_party(&vault, "party-shell")?;
    // A second active PERSON carrying the same party_key, then merged away
    // through MS-01: its type stays PERSON while its identity moved.
    let shell = mint_comm_person(&vault, "party-shell")?;
    vault.apply_identity_topology_op(
        &IdentityTopologyOp::Merge(MergeOp {
            sources: vec![shell],
            survivor,
            evidence: IdentityOpEvidence {
                refs: vec![shell, survivor],
                rationale: "test fixture: merged party twin".to_owned(),
            },
            survivorship_plan: SurvivorshipPlan::ReadThrough,
        }),
        &IdentityOpWrite::auto(ClaimSource::Inferred),
        100,
    )?;
    assert_eq!(
        vault.get_entity_type(&shell)?,
        Some(ENTITY_TYPE_PERSON),
        "a merge leaves a readable PERSON shell, not a tombstone"
    );

    // Cache the shell: it is a PERSON with the right party_key, yet stale.
    point_party_index(&vault, "party-shell", shell)?;
    assert_eq!(resolve_party(&vault, "party-shell")?, Some(survivor));
    assert_eq!(
        resolve_or_create_comm_party(&vault, "party-shell")?,
        survivor
    );
    Ok(())
}

#[test]
fn malformed_person_bodies_do_not_wedge_party_resolution() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_send_receipt(&vault, "party-tolerant", "email", 10)?;
    run_comm_projector(&vault)?;
    let synced = resolve_party(&vault, "party-tolerant")?.ok_or(CommError::InvalidRecord)?;

    // A PERSON with undecodable bytes, and one with a valid but unrelated body:
    // neither is a comm party, and neither may wedge the scan.
    vault.put_entity(
        &entity(0x83),
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        &[0xC1],
    )?;
    let unrelated = crate::comm::encode_value(&Value::Map(vec![(
        Value::from("display_name"),
        Value::from("someone"),
    )]))?;
    vault.put_entity(
        &entity(0x84),
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        &unrelated,
    )?;

    clear_party_index(&vault, "party-tolerant")?;
    assert_eq!(resolve_party(&vault, "party-tolerant")?, Some(synced));
    assert_eq!(resolve_party(&vault, "party-never-seen")?, None);
    Ok(())
}

fn count_identity_topology_events(vault: &Vault) -> CommResult<usize> {
    let rtxn = vault.store.env.read_txn()?;
    let mut count = 0;
    for entry in vault
        .store
        .type_index
        .prefix_iter(&rtxn, &[ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT])?
    {
        entry?;
        count += 1;
    }
    Ok(count)
}

#[test]
fn offline_party_twins_converge_on_the_lowest_id_through_ms01() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    // Two devices each minted a PERSON for one party_key while synced truth
    // was unreachable; both rows land here after replication.
    let first = mint_comm_person(&vault, "party-twin")?;
    let second = mint_comm_person(&vault, "party-twin")?;
    assert_ne!(first, second);
    let mut sorted = [first, second];
    sorted.sort_unstable();
    let [survivor, loser] = sorted;
    point_party_index(&vault, "party-twin", loser)?;

    run_comm_projector(&vault)?;

    // Lowest id survives; the other becomes an MS-01 Merged redirect shell.
    assert_eq!(
        vault.entity_lifecycle_state(&survivor)?,
        EntityLifecycleState::Active
    );
    assert_eq!(
        vault.entity_lifecycle_state(&loser)?,
        EntityLifecycleState::Merged
    );
    // Exactly ONE read-through merge event, and the cache names the survivor.
    assert_eq!(count_identity_topology_events(&vault)?, 1);
    assert_eq!(resolve_party(&vault, "party-twin")?, Some(survivor));
    assert_eq!(
        resolve_or_create_comm_party(&vault, "party-twin")?,
        survivor
    );
    // The shell body is still readable — a merge is a redirect, not a delete.
    assert_eq!(vault.get_entity_type(&loser)?, Some(ENTITY_TYPE_PERSON));

    // A second pass writes no additional topology event: the group is no longer
    // a group, because the shell is no longer active.
    run_comm_projector(&vault)?;
    assert_eq!(count_identity_topology_events(&vault)?, 1);
    assert_eq!(resolve_party(&vault, "party-twin")?, Some(survivor));
    Ok(())
}

#[test]
fn twin_merge_records_sorted_evidence_and_the_stable_rationale_token() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    let first = mint_comm_person(&vault, "party-evidence")?;
    let second = mint_comm_person(&vault, "party-evidence")?;
    let mut expected_refs = vec![first, second];
    expected_refs.sort_unstable();

    run_comm_projector(&vault)?;

    let event_id = {
        let rtxn = vault.store.env.read_txn()?;
        let mut ids = Vec::new();
        for entry in vault
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT])?
        {
            let (key, _) = entry?;
            ids.push(entity_id_from_type_index_key(&key)?);
        }
        assert_eq!(ids.len(), 1);
        ids[0]
    };
    let event = vault
        .identity_topology_event(&event_id)?
        .ok_or(CommError::InvalidRecord)?;
    let evidence = event.evidence.ok_or(CommError::InvalidRecord)?;
    assert_eq!(evidence.refs, expected_refs);
    assert_eq!(evidence.rationale, PARTY_KEY_TWIN_RATIONALE);
    Ok(())
}

#[test]
fn parties_with_different_keys_are_never_merged() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    record_comm_send_receipt(&vault, "party-alpha", "email", 10)?;
    record_comm_send_receipt(&vault, "party-beta", "email", 11)?;
    run_comm_projector(&vault)?;

    let alpha = resolve_party(&vault, "party-alpha")?.ok_or(CommError::InvalidRecord)?;
    let beta = resolve_party(&vault, "party-beta")?.ok_or(CommError::InvalidRecord)?;
    assert_ne!(alpha, beta);

    run_comm_projector(&vault)?;

    // Distinct keys are distinct parties. Deciding otherwise is cross-channel
    // identity judgment, which this projector deliberately does not do.
    assert_eq!(count_identity_topology_events(&vault)?, 0);
    assert_eq!(
        vault.entity_lifecycle_state(&alpha)?,
        EntityLifecycleState::Active
    );
    assert_eq!(
        vault.entity_lifecycle_state(&beta)?,
        EntityLifecycleState::Active
    );
    assert_eq!(resolve_party(&vault, "party-alpha")?, Some(alpha));
    assert_eq!(resolve_party(&vault, "party-beta")?, Some(beta));
    Ok(())
}

#[test]
fn twin_merge_keeps_claims_on_their_own_subjects_and_reads_through() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    // Each twin carries its own projected standing state before reconciliation.
    let first = mint_comm_person(&vault, "party-readthrough")?;
    let second = mint_comm_person(&vault, "party-readthrough")?;
    let mut sorted = [first, second];
    sorted.sort_unstable();
    let [survivor, loser] = sorted;

    for (party_ref, channel, at) in [(survivor, "email", 10), (loser, "sms", 11)] {
        let event = CommRecord::Event {
            sequence: 0,
            kind: CommEventKind::SendSucceeded,
            party_ref,
            channel_class: Some(channel.to_owned()),
            thread_ref: None,
            occurred_at: at,
            projected: false,
        };
        vault.try_with_write_txn(|wtxn| {
            put_comm_record_in_txn(&vault, wtxn, EntityId::now(), &event)
        })?;
    }
    run_comm_projector(&vault)?;

    // MS-01 owns the redirect: the loser's claim stays on the loser's subject.
    let rtxn = vault.store.env.read_txn()?;
    let on_shell = matching_claims_in_txn(
        &vault,
        &rtxn,
        loser,
        PREDICATE_COMM_LAST_TOUCH,
        Some("sms"),
        None,
        true,
    )?;
    assert_eq!(on_shell.len(), 1, "claims are not reparented by a merge");
    let on_survivor = matching_claims_in_txn(
        &vault,
        &rtxn,
        survivor,
        PREDICATE_COMM_LAST_TOUCH,
        Some("sms"),
        None,
        true,
    )?;
    assert!(
        on_survivor.is_empty(),
        "read-through is a read-time union, not a rewrite"
    );
    drop(rtxn);

    // The redirect edge is the door's, authored exactly once.
    assert_eq!(count_identity_topology_events(&vault)?, 1);
    assert_eq!(
        vault.entity_lifecycle_state(&loser)?,
        EntityLifecycleState::Merged
    );
    // Contact materialization reads the canonical party.
    assert!(!materialize_contact_record(&vault, "party-readthrough")?.is_empty());
    Ok(())
}

#[test]
fn three_way_twins_converge_in_one_pass() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    let mut twins = [
        mint_comm_person(&vault, "party-triple")?,
        mint_comm_person(&vault, "party-triple")?,
        mint_comm_person(&vault, "party-triple")?,
    ];
    twins.sort_unstable();

    run_comm_projector(&vault)?;

    // One N→1 merge event, not a chain of pairwise merges.
    assert_eq!(count_identity_topology_events(&vault)?, 1);
    assert_eq!(
        vault.entity_lifecycle_state(&twins[0])?,
        EntityLifecycleState::Active
    );
    for loser in &twins[1..] {
        assert_eq!(
            vault.entity_lifecycle_state(loser)?,
            EntityLifecycleState::Merged
        );
    }
    assert_eq!(resolve_party(&vault, "party-triple")?, Some(twins[0]));
    Ok(())
}

#[test]
fn finding_6_opt_out_reason_is_pinned_to_machine_tokens() -> Result<()> {
    let party = entity(0x52);
    let accepted = [CommClaimValue::OptOut {
        party_ref: party,
        channel_class: "email".to_owned(),
        reason: OPT_OUT_REASON_STOP.to_owned(),
        occurred_at: 10,
    }]
    .iter()
    .map(CommClaimValue::claim_body)
    .map(|body| validate_through_chokepoint(&body))
    .collect::<Result<Vec<_>>>()?;
    assert_eq!(accepted.len(), 1);

    let invalid = CommClaimValue::OptOut {
        party_ref: party,
        channel_class: "email".to_owned(),
        reason: "please stop".to_owned(),
        occurred_at: 11,
    }
    .claim_body();
    let error = validate_through_chokepoint(&invalid).expect_err("free-form reason rejected");
    assert_eq!(error.kind(), ErrorKind::InvalidClaimBody);
    Ok(())
}
