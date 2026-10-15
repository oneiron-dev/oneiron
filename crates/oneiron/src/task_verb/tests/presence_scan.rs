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
    let snapshot = task_presence_with_limits(&vault, 1, 1, crate::claim::CallerLocality::OnDevice)
        .expect("one-row board prefix");
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

    let snapshot = task_presence_with_limits(&vault, 1, 1, crate::claim::CallerLocality::OnDevice)
        .expect("one-row board prefix");
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
    let snapshot = task_presence_with_limits(&vault, 2, 4, crate::claim::CallerLocality::OnDevice)
        .expect("truncated presence");

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
    let whole = task_presence_with_limits(&vault, 8, 64, crate::claim::CallerLocality::OnDevice)
        .expect("full presence");
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

    let snapshot = task_presence_with_limits(&vault, 2, 32, crate::claim::CallerLocality::OnDevice)
        .expect("section survives");
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

/// Sol R7-002 on #1413: a handle bound to a read credential described every
/// TASK raw, so a credential held to one world got the card and the board row
/// of a TASK born in another, which its own point read withholds. The bound
/// handle describes only the TASKs its credential reads; an unbound handle,
/// and the rows a host cuts for its own reader, still hold the whole board.
/// Sol R8-003: a bare job is an attempt, so an entity that only shares its
/// id proves nothing about it; the bound handle shows no bare job.
#[test]
fn a_credential_bound_handle_describes_only_the_tasks_it_reads() {
    let (_dir, vault) = open_vault();
    crate::test_support::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id().expect("policy id"),
        &crate::gate::default_policy_manifest().expect("default policy"),
    )
    .expect("install the default policy");
    let own = own_agent(&vault);
    let (near, far) = (
        EntityId::from_bytes([0x5D; 16]).expect("world id"),
        EntityId::from_bytes([0x5E; 16]).expect("world id"),
    );
    let born_in = |world, now| {
        vault
            .memory(own, EdgeActorClass::Agent)
            .with_birth_position(crate::federation::record_scope::BirthPosition {
                world: Some(world),
                facet: None,
            })
            .tasks_create(&spec(now))
            .expect("the agent creates a TASK")
            .task_ref
            .expect("the create mints a TASK")
    };
    let (kept, withheld) = (born_in(near, 120), born_in(far, 121));
    let EnqueueOutcome::Enqueued(attempt) = AttemptQueue::new(&vault)
        .enqueue_with_task_ref(
            EnqueueAttempt {
                kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                payload: Vec::new(),
                dedupe_key: None,
                run_id: None,
                now: 120,
            },
            Some(EntityId::from_bytes([0x10; 16]).expect("owner id").to_hex()),
        )
        .expect("enqueue a job whose TASK is gone")
    else {
        panic!("attempt must enqueue");
    };
    let job = attempt_hex(attempt.id);
    // A readable PERSON that only shares the job's id.
    put_person(&vault, EntityId::from_hex(&job).expect("job id bytes"));

    let issuer = crate::test_support::test_host_issuer();
    let mut claims = vault
        .ensure_host_root_slip(&issuer)
        .expect("host root")
        .claims;
    claims.slip_id = *blake3::hash(b"one world task reader").as_bytes();
    claims.parent_id = None;
    claims.holder_ref = own.to_hex();
    claims.actor_class = Some("agent".into());
    claims.scope = crate::federation::scope_codec::read_preset();
    claims.scope.worlds = [near, crate::claim::base_world_id()]
        .into_iter()
        .map(crate::federation::ScopeId)
        .collect();
    let slip = vault.mint_capability_slip(&issuer, claims).expect("mint");
    let tag = b"one-world-tasks";
    let proof = vault
        .verify_capability_slip(
            &issuer.public_key(),
            &slip,
            tag,
            &issuer.binding_proof(&slip, tag).expect("binding proof"),
        )
        .expect("verify");
    let unbound = vault.memory(own, EdgeActorClass::Agent);
    let bound = vault
        .memory(own, EdgeActorClass::Agent)
        .with_read_proof(&proof);
    let listed = |memory: &Memory<'_>| {
        let mut ids: Vec<String> = memory
            .describe_section()
            .expect("the TASKS section")
            .rows
            .into_iter()
            .map(|row| row.id)
            .collect();
        ids.sort();
        ids
    };
    let mut every = vec![kept.to_hex(), withheld.to_hex(), job];
    every.sort();
    assert_eq!(listed(&unbound), every);
    assert_eq!(listed(&bound), vec![kept.to_hex()]);
    assert_eq!(
        bound.describe_rows().expect("rows").intents.len(),
        2,
        "the rows a host cuts itself stay whole"
    );
    assert!(bound.describe_card(kept).is_ok());
    assert!(
        bound.describe_card(withheld).is_err(),
        "a TASK the credential does not read has no card"
    );
}

/// H222 (F13, rule 5): no run of TASK rows hides a live task from the board.
/// Main read a 4,096-row prefix, so as many unreadable rows ordered first hid
/// every task after them; the board reads every row and, past the threshold
/// row, raises the owner's check once.
#[test]
fn no_run_of_task_rows_hides_a_live_task_from_the_board() {
    const AHEAD: u64 = 4_096;
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let live = created_task_refs(&facade, 1)[0];
    // Index rows with no TASK behind them, each ordered before the live one.
    vault
        .with_write_txn(|wtxn| {
            for index in 0..AHEAD {
                let mut bytes = [0_u8; 16];
                bytes[1] = 0x10;
                bytes[8..].copy_from_slice(&index.to_be_bytes());
                let key = crate::store::Store::encode_type_key(
                    ENTITY_TYPE_TASK,
                    &EntityId::from_bytes(bytes)?,
                );
                vault.store.type_index.put(wtxn, &key, &[])?;
            }
            Ok(())
        })
        .expect("seed");
    let scan = crate::scan_check::EngineScan::TaskBoardRows;
    vault.set_scan_threshold(scan, 2).expect("lower the row");

    let rows = facade.describe_rows().expect("the board");
    assert!(rows.source_exhausted);
    assert!(rows.intents.iter().any(|intent| intent.id == live.to_hex()));
    facade.describe_rows().expect("the board again");
    let checks = vault.scan_checks().expect("checks");
    assert_eq!(
        checks
            .iter()
            .filter(|check| check.scan == scan.code())
            .count(),
        1
    );
}
