//! Tick push and hybrid tests: coalescing, lane fairness, drain order, hint order and overflow, exhaustion races.

use std::time::Duration;

use oneiron::WakeTrigger;

use super::super::*;
use super::*;
use crate::session::SessionHint;

#[test]
fn session_hints_preserve_arrival_order_and_coalesce_only_adjacent_same_kind() {
    let (mut receiver, _wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
    // Arrival sequence: open, a typing burst (adjacent → ONE bump),
    // end, REOPEN, plain advisory. The second AppOpen is same-kind but
    // NOT adjacent to the first — collapsing them would erase a whole
    // sitting (the C4/G1 causality bug).
    hint.push_session_hint(SessionHint::AppOpen, None)
        .expect("open channel");
    for _ in 0..3 {
        hint.push_session_hint(SessionHint::Activity, None)
            .expect("open channel");
    }
    hint.push_session_hint(SessionHint::ExplicitEnd, None)
        .expect("open channel");
    hint.push_session_hint(SessionHint::AppOpen, None)
        .expect("open channel");
    hint.push_hint().expect("open channel");

    let mut drained = Vec::new();
    while let Some(tick) = receiver.take_pending() {
        let Tick::Hint(signal) = tick else {
            panic!("only hints were pushed, got {tick:?}");
        };
        drained.push(signal.session);
    }
    assert_eq!(
        drained,
        vec![
            Some(SessionHint::AppOpen),
            Some(SessionHint::Activity),
            Some(SessionHint::ExplicitEnd),
            Some(SessionHint::AppOpen),
            None,
        ],
        "arrival order preserved; only the adjacent typing burst coalesced"
    );
}

#[test]
fn wake_lane_round_robin_does_not_starve_buffered_macro_under_micro_refill() {
    // P2 (codex r4): fixed micro→meso→macro scan always drained a
    // refilled micro slot first, so a buffered macro/meso wake never
    // returned under continuous micro push. Rotating scan start after
    // each returned wake drains every occupied lane within N=3 takes.
    let (mut receiver, wake, _hint) = PushTick::channel(COALESCE_FLOOR_MS);
    wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
        .expect("open channel");
    wake.push_wake(WakeTrigger::Timer, DreamerConsolidationScope::Macro)
        .expect("open channel");

    let mut scopes = Vec::new();
    for _ in 0..3 {
        let Some(Tick::Wake(signal)) = receiver.take_pending() else {
            panic!("expected a wake within the 3-take fairness window");
        };
        scopes.push(signal.scope);
        // Refill micro after every take — the starvation pattern under
        // a fixed scan that always preferred lane 0.
        wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
            .expect("open channel");
    }

    assert!(scopes.contains(&DreamerConsolidationScope::Macro));
}

#[tokio::test]
async fn push_recv_delivers_final_wake_when_producer_drops_immediately() {
    // P2 (codex r6 / 3585850157): between empty take_pending and the
    // pushers==0 check a producer can push then Drop. Without a final
    // take_pending re-check, recv returns None while a wake is buffered.
    // Producer order: store under mutex, notify_one, Drop decrements
    // pushers (store-before-decrement). The re-check closes the window
    // either way. Concurrent push+drop while recv is waiting (and the
    // sequential push-then-drop case) both deliver exactly one signal.
    let (mut receiver, wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
    // Drop the unused hint first so the last producer can race alone.
    drop(hint);

    let producer = tokio::spawn(async move {
        // Let recv park on notified() after an empty take_pending.
        tokio::task::yield_now().await;
        wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
            .expect("open channel");
        drop(wake);
    });

    let first = receiver.recv().await;
    producer.await.expect("producer task");
    assert!(
        matches!(
            first,
            Some(Tick::Wake(WakeSignal {
                trigger: WakeTrigger::Compaction,
                scope: DreamerConsolidationScope::Micro,
            }))
        ),
        "exactly one buffered wake must be delivered, got {first:?}"
    );
    assert_eq!(
        receiver.recv().await,
        None,
        "second recv must exhaust (count: exactly 1 signal)"
    );
}

fn seed_digest_proposal_in_txn(vault: &Vault, seed: u8, rollback: bool) {
    use oneiron::ClaimCandidate;
    use oneiron::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
    use oneiron::write_envelope::{WriteEnvelope, WriteProvenance};
    let actor = vault.dreamer_authority().expect("Dreamer actor");
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::Generated,
        WriteProvenance::new(rmpv::Value::Map(vec![(
            rmpv::Value::from("surface"),
            rmpv::Value::from("dreamer"),
        )]))
        .unwrap(),
        ClaimApprovalStatus::Proposed,
    );
    let id = EntityId::from_bytes([seed; 16]).unwrap();
    let candidate = ClaimCandidate::new(
        "dreamer.proactivity.follow_up",
        ClaimSubject::Entity(actor.entity_ref()),
        rmpv::Value::from("pending"),
        0.7,
    );
    // The Dreamer signs its proposal with the key the host retained.
    let envelope = vault
        .sign_retained_machine_claim_for_test(&id, &candidate, &envelope)
        .unwrap();
    let result = vault.with_write_txn(|txn| {
        vault
            .batch_in()
            .claim_candidate(&id, candidate, &envelope, TimeRange { start: 1, end: 1 }, 1)
            .apply(txn)?;
        if rollback {
            return Err(oneiron::Error::InvalidConfig("test rollback".into()));
        }
        Ok(())
    });
    assert_eq!(result.is_err(), rollback);
}

#[tokio::test(start_paused = true)]
async fn transaction_owned_proposal_rearms_only_after_outer_commit() {
    let (_dir, vault) = open_vault();
    let node = vault_client_node_id(&vault);
    elect_home(&vault, node, 1);
    let clock = frozen_clock(100_000);
    let timer = TimerTick::with_clock(
        AttemptQueueDeadlines::with_commitment_clock(&vault, node, Arc::clone(&clock)),
        Arc::clone(&clock),
    );
    let (push, _wake, _hint) = PushTick::channel_with_clock(clock, COALESCE_FLOOR_MS);
    let mut hybrid = HybridTick::new(timer, push);
    let mut waiting = std::pin::pin!(hybrid.next_tick());
    assert!(
        tokio::time::timeout(Duration::from_millis(1), &mut waiting)
            .await
            .is_err()
    );
    seed_digest_proposal_in_txn(&vault, 0x79, true);
    assert_eq!(vault.next_proactivity_digest_at().unwrap(), None);
    assert!(
        tokio::time::timeout(Duration::from_millis(1), &mut waiting)
            .await
            .is_err()
    );
    seed_digest_proposal_in_txn(&vault, 0x79, false);
    let tick = tokio::time::timeout(Duration::from_secs(1), &mut waiting)
        .await
        .unwrap();
    assert_eq!(
        tick,
        Some(Tick::Deadline(CommitmentDeadline {
            due_at_ms: 0,
            scope: DreamerConsolidationScope::Micro,
        }))
    );
}
