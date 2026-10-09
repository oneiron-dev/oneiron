//! Observe subscriptions track committed queue and facade transactions only.

use super::*;

#[test]
fn observes_queue_commit_and_not_rollback() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let mut receiver = queue.subscribe();
    let result: Result<()> = vault.with_write_txn(|txn| {
        crate::ports::JobQueue::port_job_enqueue(&vault, txn, enqueue("test", None, 1))?;
        Err(Error::InvalidConfig("fixture rollback".into()))
    });
    assert!(result.is_err());
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    vault.with_write_txn(|txn| {
        crate::ports::JobQueue::port_job_enqueue(&vault, txn, enqueue("test", None, 2))
    })?;
    assert_eq!(receiver.try_recv().unwrap(), ());
    let rows = queue.list_run("run-2")?;
    assert_eq!(rows.len(), 1);
    queue.intervene(InterveneAttempt {
        id: rows[0].id,
        kind: AttemptInterventionKind::Pause,
        actor: "operator".into(),
        note: None,
        now: 3,
    })?;
    receiver.try_recv().unwrap();
    assert_eq!(queue.get(rows[0].id)?.unwrap().state, AttemptState::Paused);
    Ok(())
}

#[test]
fn empty_kind_claim_does_not_wake_its_own_notification_worker() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let mut updates = queue.subscribe();
    let claim = || {
        queue.claim_kind(
            "wave.plan",
            ClaimAttempt {
                lease_owner: "wave-worker".into(),
                now: 100,
            },
        )
    };
    assert!(matches!(claim()?, ClaimOutcome::Empty));
    assert!(matches!(
        updates.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    queue.enqueue(enqueue("wave.plan", None, 100))?;
    updates.try_recv().expect("enqueue notified");
    assert!(matches!(claim()?, ClaimOutcome::Claimed(_)));
    updates.try_recv().expect("real claim notified");
    assert!(matches!(claim()?, ClaimOutcome::Empty));
    assert!(matches!(
        updates.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    Ok(())
}
