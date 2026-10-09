//! Task verb tests: Presence paging, scan caps, board-scan resilience and dangling-job rendering.

use super::support::*;
use super::*;

/// Hidden means one call away, never gone: a TASK ordered after the board
/// scan prefix still expands by id.
#[test]
fn describe_card_direct_lookup_survives_board_scan_cap() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = created_task_refs(&facade, 3);
    let beyond_prefix = *created.last().expect("three tasks");
    let beyond_hex = beyond_prefix.to_hex();

    // The bounded board really does stop before it.
    let snapshot = task_presence_with_limits(&vault, 1, 1).expect("one-row board prefix");
    assert!(!snapshot.source_exhausted);
    assert!(
        !snapshot
            .intents
            .iter()
            .any(|intent| intent.id == beyond_hex)
    );

    // The direct-by-id door does not inherit that cap.
    let direct = task_presence_for_id(&vault, beyond_prefix)
        .expect("direct lookup")
        .expect("a valid TASK id is always reachable");
    assert_eq!(direct.id, beyond_hex);
    let lines = facade.describe_card(beyond_prefix).expect("expand by id");
    assert!(lines[0].starts_with(&beyond_hex));

    // An unknown id is still EntityNotFound, not a silent empty expansion.
    assert_eq!(
        facade
            .describe_card(EntityId::from_bytes([0xD9; 16]).expect("unknown id"))
            .expect_err("an unknown id is not found")
            .code,
        crate::memory::MEMORY_CODE_NOT_FOUND
    );
}

/// The same for `tasks.update`, including the failed-only invariant and the
/// acked-failure invisibility that follows it.
#[test]
fn tasks_update_direct_lookup_survives_board_scan_cap() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = created_task_refs(&facade, 3);
    let beyond_prefix = *created.last().expect("three tasks");
    let beyond_hex = beyond_prefix.to_hex();

    // Fail exactly the realization behind the last-ordered TASK.
    let queue = AttemptQueue::new(&vault);
    loop {
        let ClaimOutcome::Claimed(claimed) = queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "worker".to_owned(),
                    now: 130,
                },
            )
            .expect("claim")
        else {
            panic!("the target task must own a claimable realization");
        };
        if claimed.task_ref.as_deref() == Some(beyond_hex.as_str()) {
            queue
                .fail(FailAttempt {
                    id: claimed.id,
                    lease_owner: "worker".to_owned(),
                    attempt_count: claimed.attempt_count,
                    reason: "failed".to_owned(),
                    now: 131,
                })
                .expect("fail the target realization");
            break;
        }
    }

    let snapshot = task_presence_with_limits(&vault, 1, 1).expect("one-row board prefix");
    assert!(!snapshot.source_exhausted);
    assert!(
        !snapshot
            .intents
            .iter()
            .any(|intent| intent.id == beyond_hex)
    );

    // Failed-only ack, reached directly by id past the board prefix.
    let receipt = facade
        .tasks_update(beyond_prefix)
        .expect("ack past the cap");
    assert!(receipt.acked);
    assert!(task_is_acked(&vault, beyond_prefix).expect("ack bit"));
    // A non-failed task acked by id is still a no-op.
    let queued = created[0];
    assert!(!facade.tasks_update(queued).expect("ack queued task").acked);
    assert!(!task_is_acked(&vault, queued).expect("no ack bit"));
    // The acked failure has left BOTH the board and the typed read verbs.
    assert_eq!(
        facade
            .describe_card(beyond_prefix)
            .expect_err("acked failure is not expandable")
            .code,
        crate::memory::MEMORY_CODE_NOT_FOUND
    );
}

/// Under a truncated scan, a realizing job whose owner id is ≤ the final
/// scanned cursor is provably dangling (owner was in the scanned prefix
/// and did not survive as an intent) and must render once as bare. A job
/// whose valid owner lies beyond the cursor remains withheld.
#[test]
fn truncated_task_scan_still_renders_provably_dangling_prefix_job_once() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = created_task_refs(&facade, 3);

    // Missing owner whose id sorts BEFORE every created TASK. UUIDv7
    // task ids carry a non-zero timestamp prefix; a near-zero id is
    // strictly earlier. After a 4-row prefix scan the cursor sits at or past
    // created[1], so this owner is ≤ cursor and therefore proven
    // absent from the scanned prefix.
    let mut prefix_bytes = [0_u8; 16];
    prefix_bytes[15] = 0x10;
    let dangling_owner = EntityId::from_bytes(prefix_bytes).expect("prefix id");
    assert!(
        dangling_owner <= created[1],
        "dangling owner must sit at-or-before the truncated cursor"
    );
    let EnqueueOutcome::Enqueued(attempt) = AttemptQueue::new(&vault)
        .enqueue_with_task_ref(
            EnqueueAttempt {
                kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                payload: Vec::new(),
                dedupe_key: None,
                run_id: None,
                now: 120,
            },
            Some(dangling_owner.to_hex()),
        )
        .expect("enqueue dangling attempt")
    else {
        panic!("attempt must enqueue");
    };
    let dangling_job_id = attempt_hex(attempt.id);

    // page_size=2, scan_cap=4 → inspect created[0..2] and the Owner fact each
    // one minted; the cursor lands past created[1]; source_exhausted=false
    // because created[2] remains beyond the cap.
    let snapshot = task_presence_with_limits(&vault, 2, 4).expect("truncated presence");

    assert!(!snapshot.source_exhausted);
    assert_eq!(snapshot.scanned_task_entities, 4);
    assert_eq!(snapshot.intents.len(), 2);
    assert_eq!(
        snapshot
            .bare_jobs
            .iter()
            .filter(|job| job.id == dangling_job_id)
            .count(),
        1,
        "prefix-dangling realizing job must render once as bare under truncation"
    );

    // Jobs owned by the unscanned third TASK must still not leak as bare.
    let whole = task_presence_with_limits(&vault, 8, 64).expect("full presence");
    let beyond_job_ids: Vec<&str> = whole
        .intents
        .iter()
        .filter(|intent| intent.id == created[2].to_hex())
        .flat_map(|intent| intent.realizing_jobs.iter())
        .map(|job| job.id.as_str())
        .collect();
    assert!(
        !beyond_job_ids.is_empty(),
        "third TASK must own a realizing job in the full census"
    );
    let bare_ids: std::collections::BTreeSet<&str> = snapshot
        .bare_jobs
        .iter()
        .map(|job| job.id.as_str())
        .collect();
    for job_id in beyond_job_ids {
        assert!(
            !bare_ids.contains(job_id),
            "job owned beyond cursor must not surface as bare under truncation"
        );
    }
}

/// A role-correct connector TASK with an invalid connector body fails only its
/// deferred read, not the other rows in the page or the direct-id error door.
#[test]
fn deferred_task_read_failure_is_reported_without_poisoning_section() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let healthy = facade
        .tasks_create(&spec(120))
        .expect("healthy task")
        .task_ref
        .expect("task ref");
    let malformed = EntityId::from_bytes([0xC4; 16]).expect("malformed id");
    let body = Value::Map(vec![
        (Value::from("role"), Value::from(TaskRole::Task.role_byte())),
        (
            Value::from("subkind"),
            Value::from(crate::outbound::CONNECTOR_SEND_TASK_SUBKIND),
        ),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body).expect("encode body");
    vault
        .put_entity(
            &malformed,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: 120,
                end: 120,
            },
            120,
            &bytes,
        )
        .expect("put malformed connector task");

    let snapshot = task_presence_with_limits(&vault, 2, 32).expect("section survives");
    assert!(
        snapshot
            .intents
            .iter()
            .any(|intent| intent.id == healthy.to_hex())
    );
    assert!(
        !snapshot
            .intents
            .iter()
            .any(|intent| intent.id == malformed.to_hex())
    );
    assert_eq!(snapshot.read_failures.len(), 1);
    assert_eq!(snapshot.read_failures[0].task_ref, malformed);
    assert_eq!(
        snapshot.read_failures[0].stage,
        TaskPresenceReadStage::Resolve
    );
    assert_eq!(
        snapshot.read_failures[0].kind,
        crate::error::ErrorKind::InvalidTaskBody
    );
    assert_eq!(
        task_presence_for_id(&vault, malformed)
            .expect_err("direct lookup returns connector decode failure")
            .kind(),
        crate::error::ErrorKind::InvalidTaskBody
    );
    let section = facade
        .describe_section()
        .expect("section remains available");
    assert!(section.rows.iter().any(|row| row.id == healthy.to_hex()));
}
