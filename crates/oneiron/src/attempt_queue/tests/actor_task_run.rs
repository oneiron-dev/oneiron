//! Actor-scoped dedupe, task_ref compatibility, and the run-id bound.

use super::*;

/// ONE-1876: the advisory dedupe index gains an ACTOR axis.
///
/// The generic kind-scoped cases above are deliberately untouched — they are
/// the proof that an actorless caller keeps byte-identical keys and behavior —
/// so everything here is about the second axis and its bounded legacy window.
mod one_1876_tests {
    use super::*;

    const KIND: &str = "claim_extraction";
    const ACTOR_A: &str = "actor-a";
    const ACTOR_B: &str = "actor-b";

    /// A row written before the actor axis existed, at the unchanged record
    /// version: every ONE-1795 field present, `dedupe_actor_ref` absent.
    #[derive(serde::Serialize)]
    struct Pre1876AttemptRecord {
        id: AttemptId,
        kind: String,
        payload: Vec<u8>,
        state: AttemptState,
        lease_owner: Option<String>,
        attempt_count: u32,
        claimed_at: Option<u64>,
        scheduled_at: Option<u64>,
        retry_of: Option<AttemptId>,
        backoff_until: Option<u64>,
        last_error: Option<String>,
        task_ref: Option<String>,
        run_id: Option<String>,
        dedupe_key: Option<String>,
        created_at: u64,
        updated_at: u64,
        events: Vec<AttemptEvent>,
        manifest: Vec<ManifestEntry>,
        cancel_state: AttemptCancelState,
    }

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

        // Read-only compatibility: the row is untouched, no actor was invented
        // for it, and no v2 entry was manufactured on its behalf.
        assert_eq!(queue.get(legacy.id)?.expect("legacy row"), legacy);
        assert_eq!(v1_owner(&vault, "shared")?, Some(legacy.id));
        assert_eq!(v2_owner(&vault, ACTOR_A, "shared")?, None);

        // The window is bounded: once the legacy chain terminalizes, the next
        // actor-scoped enqueue takes its own v2 entry.
        queue.intervene(InterveneAttempt {
            id: legacy.id,
            kind: AttemptInterventionKind::Cancel,
            actor: "operator".to_owned(),
            note: None,
            now: 30,
        })?;
        let input = enqueue(KIND, Some("shared"), 40);
        let fresh = enqueued(enqueue_for_actor(&vault, &queue, input, ACTOR_A)?);
        assert_eq!(fresh.dedupe_actor_ref.as_deref(), Some(ACTOR_A));
        assert_eq!(v2_owner(&vault, ACTOR_A, "shared")?, Some(fresh.id));

        Ok(())
    }

    #[test]
    fn attempt_queue_actor_scoped_dedupe_reads_raw_legacy_without_rewrite() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = AttemptQueue::new(&vault);

        let legacy = enqueued(queue.enqueue(enqueue(KIND, Some("raw"), 10))?);
        // Demote the entry to the pre-v1 raw key, where a row written before
        // the hashed index existed would still sit.
        let v1_key = dedupe_index_key(KIND, "raw");
        let raw_key = legacy_dedupe_index_key(KIND, "raw");
        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.attempt_dedupe.delete(&mut wtxn, &v1_key)?;
            vault
                .store
                .attempt_dedupe
                .put(&mut wtxn, &raw_key, legacy.id.as_bytes())?;
            wtxn.commit()?;
        }

        let input = enqueue(KIND, Some("raw"), 20);
        let hit = existing(enqueue_for_actor(&vault, &queue, input, ACTOR_A)?);
        assert_eq!(hit.id, legacy.id);

        // No duplicate row, no rewrite, no index promotion, and none of the
        // actorless raw -> v1 self-heal.
        assert_eq!(queue.get(legacy.id)?.expect("legacy row"), legacy);
        assert_eq!(owner_of(&vault, &raw_key)?, Some(legacy.id));
        assert_eq!(owner_of(&vault, &v1_key)?, None);
        assert_eq!(v2_owner(&vault, ACTOR_A, "raw")?, None);

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
            Error::InvalidAttemptQueueRecord(reason) if reason == ERR_DEDUPE_ACTOR_WITHOUT_KEY
        ));

        Ok(())
    }

    #[test]
    fn pre_1876_row_decodes_with_no_actor_scope() -> Result<()> {
        // No version bump and no migration: the field is additive and
        // defaulted, exactly like ONE-1795's.
        assert_eq!(ATTEMPT_RECORD_VERSION, 2);

        let id = AttemptId::from_bytes(&[0x8C; 16])?;
        let legacy = Pre1876AttemptRecord {
            id,
            kind: KIND.to_owned(),
            payload: b"legacy-payload".to_vec(),
            state: AttemptState::Queued,
            lease_owner: None,
            attempt_count: 0,
            claimed_at: None,
            scheduled_at: None,
            retry_of: None,
            backoff_until: None,
            last_error: None,
            task_ref: Some("tk_legacy".to_owned()),
            run_id: Some("run-legacy".to_owned()),
            dedupe_key: Some("turn:legacy".to_owned()),
            created_at: 10,
            updated_at: 10,
            events: Vec::new(),
            manifest: Vec::new(),
            cancel_state: AttemptCancelState::default(),
        };
        let mut encoded = vec![ATTEMPT_RECORD_VERSION];
        encoded.extend(rmp_serde::to_vec_named(&legacy).expect("serialize pre-1876 row"));

        let decoded = decode_record(&encoded, id)?;
        assert_eq!(decoded.dedupe_actor_ref, None);
        assert_eq!(decoded.dedupe_key.as_deref(), Some("turn:legacy"));
        // A defaulted row re-encodes and decodes unchanged.
        assert_eq!(decode_record(&encode_record(&decoded)?, id)?, decoded);

        Ok(())
    }
}

mod one_1695_tests {
    use super::*;

    #[derive(serde::Serialize)]
    struct LegacyAttemptRecord {
        id: AttemptId,
        kind: String,
        payload: Vec<u8>,
        state: AttemptState,
        lease_owner: Option<String>,
        attempt_count: u32,
        claimed_at: Option<u64>,
        backoff_until: Option<u64>,
        last_error: Option<String>,
        run_id: Option<String>,
        dedupe_key: Option<String>,
        created_at: u64,
        updated_at: u64,
        events: Vec<AttemptEvent>,
    }

    fn record(task_ref: Option<&str>) -> AttemptRecord {
        AttemptRecord {
            id: AttemptId::from_bytes(&[0x42; 16]).expect("attempt id from 16 bytes"),
            kind: "sync".to_owned(),
            payload: b"payload".to_vec(),
            state: AttemptState::Queued,
            lease_owner: None,
            attempt_count: 0,
            claimed_at: None,
            scheduled_at: None,
            retry_of: None,
            backoff_until: None,
            last_error: None,
            task_ref: task_ref.map(str::to_owned),
            run_id: Some("run-owner".to_owned()),
            dedupe_key: Some("owner-job".to_owned()),
            dedupe_actor_ref: None,
            created_at: 10,
            updated_at: 10,
            events: Vec::new(),
            manifest: Vec::new(),
            cancel_state: AttemptCancelState::default(),
            result_ref: None,
        }
    }

    #[test]
    fn task_ref_serde_round_trips() {
        let expected = record(Some("tk_owner"));
        let encoded = rmp_serde::to_vec_named(&expected).expect("serialize attempt record");
        let decoded: AttemptRecord =
            rmp_serde::from_slice(&encoded).expect("deserialize attempt record");

        assert_eq!(decoded, expected);
    }

    #[test]
    fn task_ref_defaults_when_legacy_record_omits_key() -> Result<()> {
        let current = record(None);
        let legacy = LegacyAttemptRecord {
            id: current.id,
            kind: current.kind,
            payload: current.payload,
            state: current.state,
            lease_owner: current.lease_owner,
            attempt_count: current.attempt_count,
            claimed_at: current.claimed_at,
            backoff_until: current.backoff_until,
            last_error: current.last_error,
            run_id: current.run_id,
            dedupe_key: current.dedupe_key,
            created_at: current.created_at,
            updated_at: current.updated_at,
            events: current.events,
        };
        let mut encoded = vec![ATTEMPT_RECORD_VERSION];
        encoded.extend(
            rmp_serde::to_vec_named(&legacy).expect("serialize legacy attempt record without key"),
        );

        let decoded = decode_record(&encoded, legacy.id)?;

        assert_eq!(decoded.task_ref, None);
        Ok(())
    }

    #[test]
    fn attempt_queue_sets_and_reads_optional_task_ref() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
        let queue = AttemptQueue::new(&vault);
        let input = |now| EnqueueAttempt {
            kind: "sync".to_owned(),
            payload: format!("payload-{now}").into_bytes(),
            dedupe_key: None,
            run_id: None,
            now,
        };

        queue.enqueue_with_task_ref(input(10), Some("tk_owner".to_owned()))?;
        queue.enqueue(input(20))?;

        let records = queue.list()?;
        assert_eq!(records.len(), 2);
        assert_eq!(
            records
                .iter()
                .filter(|record| record.task_ref.is_some())
                .count(),
            1
        );
        assert_eq!(records[0].task_ref.as_deref(), Some("tk_owner"));
        assert_eq!(records[1].task_ref, None);
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
        Error::InvalidAttemptQueueRecord(reason) if reason == ERR_RUN_ID_TOO_LONG
    ));
    Ok(())
}
