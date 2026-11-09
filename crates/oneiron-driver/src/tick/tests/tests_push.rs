//! Tick push and hybrid tests: coalescing, lane fairness, drain order, hint order and overflow, exhaustion races.

use std::time::Duration;

use super::super::*;
use super::*;
use crate::session::SessionHint;

#[test]
fn session_hints_preserve_arrival_order_and_coalesce_only_adjacent_same_kind() {
    let (mut receiver, _wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
    // One actor's sitting on one machine: the hints share one causal queue.
    let key = oneiron::session_lifecycle::SessionKey {
        actor: EntityId::from_bytes([0x5e; 16]).expect("actor id"),
        machine: EntityId::from_bytes([0x3a; 16]).expect("machine id"),
    };
    // Arrival sequence: open, a typing burst (adjacent → ONE bump),
    // end, REOPEN, plain advisory. The second AppOpen is same-kind but
    // NOT adjacent to the first — collapsing them would erase a whole
    // sitting (the C4/G1 causality bug).
    hint.push_session_hint(key, SessionHint::AppOpen, None)
        .expect("open channel");
    for _ in 0..3 {
        hint.push_session_hint(key, SessionHint::Activity, None)
            .expect("open channel");
    }
    hint.push_session_hint(key, SessionHint::ExplicitEnd, None)
        .expect("open channel");
    hint.push_session_hint(key, SessionHint::AppOpen, None)
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
