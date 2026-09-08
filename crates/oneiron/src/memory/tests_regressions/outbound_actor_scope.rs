//! ONE-1876 actor-scoped outbound dedupe index regressions.

use super::*;

// ── ONE-1876: the live-schedule dedupe index carries an actor axis ──────

/// The shared draft the actor-scope cases schedule. Every field but the
/// idempotency key is identical across actors on purpose: the key is the only
/// thing two actors are supposed to be able to share.
fn actor_scope_draft(idempotency_key: &str, occurred_at: u64) -> OutboundDraftInput {
    OutboundDraftInput {
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        target: "kenji@example.com".to_owned(),
        on_behalf_of: None,
        content_ref: None,
        idempotency_key: Some(idempotency_key.to_owned()),
        dedupe_key: None,
        trigger: "agent_immediate".to_owned(),
        trigger_ref: "session:actor-scope".to_owned(),
        job_ref: None,
        occurred_at: Some(occurred_at),
    }
}

fn bridge_outbound_rows(vault: &crate::Vault) -> Vec<crate::attempt_queue::AttemptRecord> {
    crate::attempt_queue::AttemptQueue::new(vault)
        .list()
        .expect("list attempts")
        .into_iter()
        .filter(|row| row.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
        .collect()
}

/// The ratified contradiction this ticket closes: the delivered-send index is
/// actor-scoped, so the pending-schedule index must be too. Actor A's live
/// schedule may not answer actor B's first call with `already_scheduled`
/// before B has its own Gate decision or TASK.
#[test]
fn schedule_outbound_idempotency_is_scoped_by_actor() {
    let (_dir, vault) = open_vault();
    let actor_a = put_person(&vault, 0x62);
    let actor_b = put_person(&vault, 0x63);
    let draft = actor_scope_draft("idem-actor-scope-1", 6000);

    let first = facade_for(&vault, actor_a)
        .schedule_outbound(&draft)
        .expect("actor A schedules");
    let second = facade_for(&vault, actor_b)
        .schedule_outbound(&draft)
        .expect("actor B schedules");

    assert!(!first.deduped);
    assert!(
        !second.deduped,
        "actor B must not ride actor A's pending row"
    );
    assert_ne!(second.outcome, "already_scheduled");
    assert_ne!(first.intent_ref, second.intent_ref);

    // One live ATTEMPT each, under each actor's own scope.
    let rows = bridge_outbound_rows(&vault);
    assert_eq!(rows.len(), 2, "each actor owns one live outbound attempt");
    let scopes: Vec<_> = rows
        .iter()
        .filter_map(|row| row.dedupe_actor_ref.clone())
        .collect();
    assert!(scopes.contains(&actor_a.to_hex()));
    assert!(scopes.contains(&actor_b.to_hex()));

    // The axis narrows nothing else: a same-actor replay still coalesces onto
    // that actor's own row.
    let replay = facade_for(&vault, actor_b)
        .schedule_outbound(&draft)
        .expect("actor B replays");
    assert!(replay.deduped);
    assert_eq!(replay.intent_ref, second.intent_ref);
}

/// Sequential same-actor replay is unchanged by the new axis: the original
/// receipt and Gate binding come back, and nothing second is committed.
#[test]
fn schedule_outbound_same_actor_replay_returns_the_original_receipt() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x64);
    let facade = facade_for(&vault, actor);
    let draft = actor_scope_draft("idem-actor-scope-2", 6100);

    let first = facade.schedule_outbound(&draft).expect("first schedule");
    assert!(!first.deduped);
    let decisions_before = facade.receipts(100).expect("receipts").len();

    let replay = facade.schedule_outbound(&draft).expect("replay");
    assert!(replay.deduped);
    assert_eq!(replay.outcome, "already_scheduled");
    assert_eq!(replay.intent_ref, first.intent_ref);
    assert_eq!(replay.gate_outcome, first.gate_outcome);
    assert_eq!(replay.gate_decision_ref, first.gate_decision_ref);
    assert_eq!(
        facade.receipts(100).expect("receipts").len(),
        decisions_before,
        "a replay commits no second gate decision"
    );

    let rows = bridge_outbound_rows(&vault);
    assert_eq!(rows.len(), 1, "no second ATTEMPT");
    let task_refs: std::collections::BTreeSet<_> =
        rows.iter().filter_map(|row| row.task_ref.clone()).collect();
    assert_eq!(task_refs.len(), 1, "no second connector TASK");
}

/// After a ONE-1795 retry the CHILD owns the dedupe index, but the receipt a
/// replay receives must still be the schedule-time one: the walk climbs
/// `retry_of` to the originating attempt and derives its intent ref and Gate
/// binding from there. Index ownership never moves back.
#[test]
fn schedule_outbound_same_actor_replay_after_retry_derives_origin_binding() {
    use crate::attempt_queue::{
        AttemptQueue, ClaimAttempt, ClaimOutcome, RetryAttempt, RetryOutcome,
    };

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x65);
    let facade = facade_for(&vault, actor);
    let draft = actor_scope_draft("idem-actor-scope-3", 6200);

    let first = facade.schedule_outbound(&draft).expect("first schedule");
    let queue = AttemptQueue::new(&vault);
    let claim = ClaimAttempt {
        lease_owner: "connector-worker".to_owned(),
        now: 6300,
    };
    let ClaimOutcome::Claimed(claimed) = queue
        .claim_kind(BRIDGE_OUTBOUND_ATTEMPT_KIND, claim)
        .expect("claim the scheduled row")
    else {
        panic!("the scheduled outbound row must be claimable");
    };

    let RetryOutcome::Retried(child) = queue
        .retry(RetryAttempt {
            id: claimed.id,
            lease_owner: "connector-worker".to_owned(),
            attempt_count: claimed.attempt_count,
            backoff_until: 6400,
            last_error: Some("connector unavailable".to_owned()),
            now: 6350,
        })
        .expect("retry mints the successor");
    assert_eq!(child.retry_of, Some(claimed.id));
    assert_eq!(child.dedupe_actor_ref, Some(actor.to_hex()));

    let replay = facade
        .schedule_outbound(&draft)
        .expect("replay after retry");
    assert!(replay.deduped);
    assert_eq!(replay.outcome, "already_scheduled");
    assert_eq!(
        replay.intent_ref, first.intent_ref,
        "the receipt names the originating attempt, not the retry child"
    );
    assert_eq!(replay.gate_outcome, first.gate_outcome);
    assert_eq!(replay.gate_decision_ref, first.gate_decision_ref);
}

/// A fabricated row claiming to retry ITSELF must not make a replay hang: the
/// visited set stops the walk and the receipt falls back to the dedupe-hit
/// attempt's own binding.
#[test]
fn schedule_outbound_replay_walk_terminates_on_a_fabricated_self_cycle() {
    use crate::attempt_queue::ATTEMPT_RECORD_VERSION;

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x66);
    let facade = facade_for(&vault, actor);
    let draft = actor_scope_draft("idem-actor-scope-4", 6500);

    let first = facade.schedule_outbound(&draft).expect("first schedule");
    let mut row = bridge_outbound_rows(&vault)
        .pop()
        .expect("the scheduled outbound row");
    row.retry_of = Some(row.id);
    let mut encoded = vec![ATTEMPT_RECORD_VERSION];
    encoded.extend(rmp_serde::to_vec_named(&row).expect("encode fabricated row"));
    {
        let mut wtxn = vault.store.env.write_txn().expect("write txn");
        vault
            .store
            .attempt_records
            .put(&mut wtxn, row.id.as_bytes(), &encoded)
            .expect("put fabricated row");
        wtxn.commit().expect("commit fabricated row");
    }

    let replay = facade.schedule_outbound(&draft).expect("replay");
    assert!(replay.deduped);
    assert_eq!(
        replay.intent_ref, first.intent_ref,
        "the hit attempt is the floor of the walk"
    );
    assert_eq!(replay.gate_decision_ref, first.gate_decision_ref);
}
