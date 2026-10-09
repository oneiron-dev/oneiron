//! Actor-scoped dedupe, task_ref compatibility, and the run-id bound.

use super::*;
use crate::error::ArtifactError;

/// ONE-1876: the advisory dedupe index gains an ACTOR axis.
///
/// The generic kind-scoped cases above are deliberately untouched — they are
/// the proof that an actorless caller keeps byte-identical keys and behavior —
/// so everything here is about the second axis and its bounded legacy window.
mod one_1876_tests {
    use super::*;
    use crate::error::ArtifactError;

    const KIND: &str = "claim_extraction";
    const ACTOR_A: &str = "actor-a";
    const ACTOR_B: &str = "actor-b";

    /// Enqueues through the actor-scoped seam the outbound schedule path uses.
    fn enqueue_for_actor(
        vault: &Vault,
        queue: &AttemptQueue<'_>,
        input: EnqueueAttempt,
        actor_ref: &str,
    ) -> Result<EnqueueOutcome> {
        let mut wtxn = vault.store.env.write_txn()?;
        let outcome = queue.enqueue_with_task_ref_and_dedupe_actor_in_txn(
            &mut wtxn,
            input,
            None,
            Some(actor_ref),
        )?;
        wtxn.commit()?;
        Ok(outcome)
    }

    fn enqueued(outcome: EnqueueOutcome) -> AttemptRecord {
        match outcome {
            EnqueueOutcome::Enqueued(record) => record,
            EnqueueOutcome::Existing(_) => panic!("expected a new row, got a dedupe hit"),
        }
    }

    fn existing(outcome: EnqueueOutcome) -> AttemptRecord {
        match outcome {
            EnqueueOutcome::Existing(record) => record,
            EnqueueOutcome::Enqueued(_) => panic!("expected a dedupe hit, got a new row"),
        }
    }

    fn owner_of(vault: &Vault, index_key: &[u8]) -> Result<Option<AttemptId>> {
        let rtxn = vault.store.env.read_txn()?;
        let Some(raw) = vault.store.attempt_dedupe.get(&rtxn, index_key)? else {
            return Ok(None);
        };
        Ok(Some(AttemptId::from_bytes(&raw)?))
    }

    fn v1_owner(vault: &Vault, dedupe_key: &str) -> Result<Option<AttemptId>> {
        owner_of(vault, &dedupe_index_key(KIND, dedupe_key))
    }

    fn v2_owner(vault: &Vault, actor_ref: &str, dedupe_key: &str) -> Result<Option<AttemptId>> {
        owner_of(vault, &dedupe_index_key_v2(KIND, actor_ref, dedupe_key))
    }

    #[test]
    fn attempt_queue_actor_scoped_dedupe_separates_actors() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = AttemptQueue::new(&vault);

        let input = |now| enqueue(KIND, Some("idem"), now);
        let first = enqueued(enqueue_for_actor(&vault, &queue, input(10), ACTOR_A)?);
        // The whole defect: this second actor used to receive actor A's row.
        let second = enqueued(enqueue_for_actor(&vault, &queue, input(20), ACTOR_B)?);
        assert_ne!(first.id, second.id);
        assert_eq!(first.dedupe_actor_ref.as_deref(), Some(ACTOR_A));
        assert_eq!(second.dedupe_actor_ref.as_deref(), Some(ACTOR_B));

        // The axis narrows nothing else: the same actor still coalesces.
        let replay = existing(enqueue_for_actor(&vault, &queue, input(30), ACTOR_A)?);
        assert_eq!(replay.id, first.id);

        // Two disjoint v2 entries, and an actor-scoped row never writes the
        // actor-blind v1 key.
        let key_a = dedupe_index_key_v2(KIND, ACTOR_A, "idem");
        let key_b = dedupe_index_key_v2(KIND, ACTOR_B, "idem");
        assert_ne!(key_a, key_b);
        assert_eq!(v2_owner(&vault, ACTOR_A, "idem")?, Some(first.id));
        assert_eq!(v2_owner(&vault, ACTOR_B, "idem")?, Some(second.id));
        assert_eq!(v1_owner(&vault, "idem")?, None);

        Ok(())
    }

    #[test]
    fn attempt_queue_actor_scoped_dedupe_reads_v1_without_rewrite() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = AttemptQueue::new(&vault);

        // A pre-1876 actorless pending row owns the v1 entry.
        let legacy = enqueued(queue.enqueue(enqueue(KIND, Some("shared"), 10))?);
        assert_eq!(legacy.dedupe_actor_ref, None);

        let input = enqueue(KIND, Some("shared"), 20);
        let hit = existing(enqueue_for_actor(&vault, &queue, input, ACTOR_A)?);
        assert_eq!(hit.id, legacy.id);

        // Compatibility preserves the legacy row without inventing actor ownership.
        let preserved = queue.get(legacy.id)?.expect("legacy row");
        assert_eq!(preserved.id, legacy.id);
        assert_eq!(preserved.kind, legacy.kind);
        assert_eq!(preserved.payload, legacy.payload);
        assert_eq!(preserved.dedupe_key.as_deref(), Some("shared"));
        assert_eq!(preserved.dedupe_actor_ref, None);
        assert_eq!(preserved.task_ref, legacy.task_ref);
        assert_eq!(preserved.run_id, legacy.run_id);
        assert_eq!(preserved.lease_owner, legacy.lease_owner);
        assert_eq!(preserved.attempt_count, legacy.attempt_count);
        assert!(matches!(preserved.state, AttemptState::Queued));
        assert_eq!(v1_owner(&vault, "shared")?, Some(legacy.id));
        assert_eq!(v2_owner(&vault, ACTOR_A, "shared")?, None);

        // Once the legacy chain terminalizes, actor-scoped work owns its v2 entry.
        queue.intervene(InterveneAttempt {
            id: legacy.id,
            kind: AttemptInterventionKind::Cancel,
            actor: "operator".to_owned(),
            note: None,
            now: 30,
        })?;
        let input = enqueue(KIND, Some("shared"), 40);
        let fresh = enqueued(enqueue_for_actor(&vault, &queue, input, ACTOR_A)?);
        assert_ne!(fresh.id, legacy.id);
        assert_eq!(fresh.dedupe_actor_ref.as_deref(), Some(ACTOR_A));
        assert_eq!(v2_owner(&vault, ACTOR_A, "shared")?, Some(fresh.id));

        Ok(())
    }

    #[test]
    fn attempt_queue_retry_moves_actor_scoped_index_to_newest_pending() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = AttemptQueue::new(&vault);

        let input = enqueue(KIND, Some("retried"), 10);
        let source = enqueued(enqueue_for_actor(&vault, &queue, input, ACTOR_A)?);
        let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now: 20,
        })?
        else {
            panic!("expected the actor-scoped row to claim");
        };
        assert_eq!(claimed.id, source.id);

        let RetryOutcome::Retried(child) = queue.retry(RetryAttempt {
            id: source.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: claimed.attempt_count,
            backoff_until: 100,
            last_error: Some("transient".to_owned()),
            now: 30,
        })?;

        // The scope travels with the key it scopes, so the entry moves to the
        // newest pending member of the chain — still in the v2 family.
        assert_eq!(child.retry_of, Some(source.id));
        assert_eq!(child.dedupe_actor_ref.as_deref(), Some(ACTOR_A));
        assert_eq!(v2_owner(&vault, ACTOR_A, "retried")?, Some(child.id));
        assert_eq!(v1_owner(&vault, "retried")?, None);

        let input = enqueue(KIND, Some("retried"), 40);
        let hit = existing(enqueue_for_actor(&vault, &queue, input, ACTOR_A)?);
        assert_eq!(hit.id, child.id);

        // Terminalizing one actor's source never spent another actor's key
        // space: actor B still enqueues its own row.
        let input = enqueue(KIND, Some("retried"), 50);
        let other = enqueued(enqueue_for_actor(&vault, &queue, input, ACTOR_B)?);
        assert_ne!(other.id, child.id);
        assert_eq!(v2_owner(&vault, ACTOR_B, "retried")?, Some(other.id));

        Ok(())
    }

    #[test]
    fn attempt_queue_actor_scope_without_dedupe_key_is_corruption() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = AttemptQueue::new(&vault);

        // The write side never mints such a row: with no key to scope, an
        // offered scope is normalized away instead of persisted.
        let input = enqueue(KIND, None, 10);
        let mut record = enqueued(enqueue_for_actor(&vault, &queue, input, ACTOR_A)?);
        assert_eq!(record.dedupe_actor_ref, None);

        // And the read side refuses one that reached storage anyway.
        record.dedupe_actor_ref = Some(ACTOR_A.to_owned());
        let encoded = encode_record(&record)?;
        let err = decode_record(&encoded, record.id)
            .expect_err("an actor scope with no key is corruption");
        assert!(matches!(
            err,
            Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(reason)) if reason == ERR_DEDUPE_ACTOR_WITHOUT_KEY
        ));

        Ok(())
    }
}

/// ONE-1449 K3 M-3: the queue's run-id bound and the skill-edit CYCLE bound are
/// one contract, not two.
///
/// A run id becomes the Dreamer cycle label `skill_optimize::proven_cycle`
/// counts the per-cycle accept cap against, under a pinned `run:` prefix. A run
/// id this door admitted but no cycle could name stranded every proposal that
/// run drafted — and only after the author had been paid for the draft.
#[test]
fn a_run_id_leaves_room_for_the_skill_edit_cycle_prefix() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    assert_eq!(
        MAX_RUN_ID_LEN,
        crate::skill_optimize::SKILL_EDIT_CYCLE_MAX_BYTES
            - crate::skill_optimize::SKILL_EDIT_CYCLE_RUN_PREFIX.len(),
        "the budget is DERIVED from the label it has to fit inside"
    );

    let longest = "r".repeat(MAX_RUN_ID_LEN);
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
        kind: "dreamer.skill_optimize".to_owned(),
        payload: Vec::new(),
        dedupe_key: None,
        run_id: Some(longest.clone()),
        now: 10,
    })?
    else {
        panic!("expected new attempt");
    };
    let persisted = queue.get(attempt.id)?.expect("persisted attempt");
    assert_eq!(persisted.run_id.as_deref(), Some(longest.as_str()));
    assert_eq!(
        crate::skill_optimize::SKILL_EDIT_CYCLE_RUN_PREFIX.len() + longest.len(),
        crate::skill_optimize::SKILL_EDIT_CYCLE_MAX_BYTES,
        "the longest admitted run id names a cycle label of exactly the bound"
    );

    let refused = queue
        .enqueue(EnqueueAttempt {
            kind: "dreamer.skill_optimize".to_owned(),
            payload: Vec::new(),
            dedupe_key: None,
            run_id: Some(format!("{longest}r")),
            now: 20,
        })
        .expect_err("a run no cycle could name is not enqueued");
    assert!(matches!(
        refused,
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(reason)) if reason == ERR_RUN_ID_TOO_LONG
    ));
    Ok(())
}
