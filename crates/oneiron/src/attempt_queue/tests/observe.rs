//! Observe subscriptions track committed queue and facade transactions only.

use super::*;

#[test]
fn observes_queue_commit_and_not_rollback() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let mut receiver = queue.subscribe();
    let result: Result<()> = vault.with_write_txn(|txn| {
        queue.enqueue_in_txn(txn, enqueue("test", None, 1))?;
        Err(Error::InvalidConfig("fixture rollback".into()))
    });
    assert!(result.is_err());
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    vault.with_write_txn(|txn| queue.enqueue_in_txn(txn, enqueue("test", None, 2)))?;
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
fn redirected_retry_keeps_worker_and_predecessor_lineage() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let first = enqueued(&queue, 10)?;
    queue.redirect(
        InterveneAttempt {
            id: first.id,
            kind: AttemptInterventionKind::Redirect,
            actor: "operator".into(),
            note: None,
            now: 11,
        },
        AttemptPlacement {
            parent: None,
            worker: Some("worker-b".into()),
        },
    )?;
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "worker-b".into(),
        now: 12,
    })?
    else {
        panic!("claim")
    };
    queue.retry(RetryAttempt {
        id: leased.id,
        lease_owner: "worker-b".into(),
        attempt_count: leased.attempt_count,
        now: 13,
        backoff_until: 20,
        last_error: None,
    })?;
    let tree = crate::run_tree::render_run_tree(queue.list_run("run-10")?)?;
    assert_eq!(tree.roots.len(), 1);
    assert_eq!(
        tree.roots[0].attempt_id,
        crate::entity_id::bytes_to_hex_lower(first.id.as_bytes())
    );
    assert_eq!(tree.roots[0].children.len(), 1);
    let successor = &tree.roots[0].children[0];
    assert_eq!(successor.worker.as_deref(), Some("worker-b"));
    assert_eq!(
        successor.parent_id.as_deref(),
        Some(tree.roots[0].attempt_id.as_str())
    );
    Ok(())
}

#[test]
fn redirect_preserves_the_first_claim_event() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let first = enqueued(&queue, 10)?;
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".into(),
        now: 11,
    })?
    else {
        panic!("first claim")
    };
    let claimed_event = || -> Result<crate::run_tree::RunTreeEvent> {
        let tree = crate::run_tree::render_run_tree(queue.list_run("run-10")?)?;
        Ok(tree.roots[0]
            .events
            .iter()
            .find(|event| event.kind == crate::run_tree::RunTreeEventKind::Claimed)
            .expect("claimed event")
            .clone())
    };
    let original = claimed_event()?;
    assert_eq!(original.at, 11);
    queue.redirect(
        InterveneAttempt {
            id: first.id,
            kind: AttemptInterventionKind::Redirect,
            actor: "operator".into(),
            note: None,
            now: 12,
        },
        AttemptPlacement {
            parent: None,
            worker: Some("worker-b".into()),
        },
    )?;
    assert_eq!(claimed_event()?, original);
    let ClaimOutcome::Claimed(reclaimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-b".into(),
        now: 13,
    })?
    else {
        panic!("redirected claim")
    };
    assert_eq!(reclaimed.id, leased.id);
    assert!(reclaimed.attempt_count > leased.attempt_count);
    assert_eq!(claimed_event()?, original);
    Ok(())
}
