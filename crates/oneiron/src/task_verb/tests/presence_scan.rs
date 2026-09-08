//! Task verb tests: Presence paging, scan caps, board-scan resilience and dangling-job rendering.

use super::support::*;
use super::*;

/// The cliff itself: one more row than `MAX_TYPE_QUERY_RESULTS`, the point
/// at which unpaged `entities_by_type` returns `IndexOverflow` and takes
/// `tasks.check` down permanently. The bounded loop stops at its own cap,
/// never materializes the index, and reports the truncation honestly.
#[test]
fn task_presence_page_loop_handles_100_001_synthetic_ids_without_unpaged_query() {
    const SOURCE_ROWS: u128 = 100_001;
    let mut fetched = 0_usize;
    let scan = scan_task_entity_pages(
        TASK_PRESENCE_PAGE_SIZE,
        TASK_PRESENCE_SCAN_CAP,
        synthetic_pager(SOURCE_ROWS, &mut fetched),
    )
    .expect("a bounded scan past the cliff must not error");

    assert_eq!(scan.scanned_task_entities, TASK_PRESENCE_SCAN_CAP);
    assert_eq!(
        scan.pages.iter().map(Vec::len).sum::<usize>(),
        TASK_PRESENCE_SCAN_CAP
    );
    assert!(
        !scan.source_exhausted,
        "100_001 rows behind a {TASK_PRESENCE_SCAN_CAP} cap is a lower bound, not a census"
    );
    // Never near 100k in memory: at most the scan budget plus one page or
    // the terminating one-row probe.
    assert!(
        fetched <= TASK_PRESENCE_SCAN_CAP + TASK_PRESENCE_PAGE_SIZE,
        "fetched {fetched} rows"
    );
}

/// Page-boundary arithmetic. Exhaustion is claimed only when it is true —
/// via a short page, an empty page, or the one-row probe that resolves a
/// final page which exactly filled its request.
#[test]
fn bounded_scan_page_boundaries_report_exhaustion_honestly() {
    // (source rows, page size, scan cap) → (scanned, source_exhausted)
    for (rows, page_size, scan_cap, scanned, exhausted) in [
        // Empty source.
        (0, 4, 10, 0, true),
        // Short final page proves exhaustion.
        (7, 4, 10, 7, true),
        // Sentinel row on the final capped page proves more exist.
        (20, 4, 10, 10, false),
        // Final page exactly fills its request AND the source ends there:
        // the probe turns a would-be lower bound into an exact census.
        (8, 4, 8, 8, true),
        // Same shape, but the source really does continue.
        (9, 4, 8, 8, false),
        // One page larger than the whole source.
        (3, 64, 64, 3, true),
        // A zero scan cap inspects nothing and therefore knows nothing.
        (5, 4, 0, 0, false),
    ] {
        let mut fetched = 0_usize;
        let scan = scan_task_entity_pages(page_size, scan_cap, synthetic_pager(rows, &mut fetched))
            .expect("synthetic scan");
        let label = format!("rows {rows} / page {page_size} / cap {scan_cap}");
        assert_eq!(scan.scanned_task_entities, scanned, "{label}");
        assert_eq!(scan.source_exhausted, exhausted, "{label}");
        let flat: Vec<EntityId> = scan.pages.iter().flatten().copied().collect();
        assert_eq!(flat.len(), scanned, "{label}");
        assert!(flat.windows(2).all(|pair| pair[0] < pair[1]), "{label}");
    }
}

/// A page size of zero would fetch nothing forever; it must not be read as
/// "the TASK index is empty".
#[test]
fn a_degenerate_page_size_still_makes_forward_progress() {
    let mut fetched = 0_usize;
    let scan = scan_task_entity_pages(0, 4, synthetic_pager(9, &mut fetched))
        .expect("degenerate page size");

    assert_eq!(scan.scanned_task_entities, 4);
    assert!(!scan.source_exhausted);
}

/// A source that refuses to advance the exclusive cursor must terminate the
/// walk rather than replay the same row forever.
#[test]
fn a_non_advancing_cursor_stops_the_scan_instead_of_looping() {
    let stuck = synthetic_task_id(1);
    let mut calls = 0_usize;
    let scan = scan_task_entity_pages(2, 64, |_after, _limit| {
        calls += 1;
        Ok(vec![stuck, stuck])
    })
    .expect("a stuck pager terminates");

    assert!(calls <= 2, "the scan must not spin: {calls} fetches");
    assert!(scan.scanned_task_entities <= 64);
    assert!(!scan.source_exhausted);
}

/// Real vault, injected small limits: the walk crosses several
/// `entities_by_type_page` calls and every processed id appears once.
#[test]
fn tasks_check_pages_across_multiple_vault_pages() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = created_task_refs(&facade, 5);

    let mut calls = 0_usize;
    let scan = scan_task_entity_pages(2, 64, |after, limit| {
        calls += 1;
        vault.entities_by_type_page(ENTITY_TYPE_TASK, after, limit)
    })
    .expect("paged scan over the real type index");

    assert!(
        calls >= 3,
        "page size 2 over 5 tasks must page at least three times: {calls}"
    );
    // Each create mints its Owner authority fact as a companion TASK row, so
    // the type index holds two rows per task. The walk is over ROWS; only the
    // five tasks project as intents.
    assert_eq!(scan.scanned_task_entities, 10);
    assert!(scan.source_exhausted);
    let flat: Vec<EntityId> = scan.pages.iter().flatten().copied().collect();
    let scanned_tasks: Vec<EntityId> = flat
        .iter()
        .copied()
        .filter(|id| created.contains(id))
        .collect();
    assert_eq!(scanned_tasks, created);
    assert!(flat.windows(2).all(|pair| pair[0] < pair[1]));

    let snapshot = task_presence_with_limits(&vault, 2, 64).expect("paged presence");
    assert!(snapshot.source_exhausted);
    assert_eq!(snapshot.scanned_task_entities, 10);
    let ids: std::collections::BTreeSet<&str> = snapshot
        .intents
        .iter()
        .map(|intent| intent.id.as_str())
        .collect();
    assert_eq!(ids.len(), snapshot.intents.len());
    assert_eq!(ids.len(), 5);
}

/// Past both caps the board shows a capped prefix and says the count is a
/// LOWER bound — never an exact census it could not have taken.
#[test]
fn tasks_check_scan_cap_reports_honest_additive_overflow() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    created_task_refs(&facade, 5);

    // Six inspected ROWS are three tasks and the three Owner facts minted
    // beside them; two tasks stay beyond the cap.
    let snapshot = task_presence_with_limits(&vault, 2, 6).expect("scan-capped presence");
    assert_eq!(snapshot.scanned_task_entities, 6);
    assert_eq!(snapshot.intents.len(), 3);
    assert!(!snapshot.source_exhausted);

    let section = TasksSection::render_with_cap(
        &snapshot.intents,
        &snapshot.bare_jobs,
        snapshot.source_exhausted,
        2,
    );

    assert_eq!(section.rows.len(), 2);
    let overflow = section.overflow.expect("a truncated scan always says so");
    assert_eq!(overflow.known_omitted_rows, 1);
    assert!(!overflow.source_exhausted);
    assert_eq!(
        overflow.line().as_deref(),
        Some("tasks: +1 more (at least; scan capped)")
    );
}

/// Past the render cap but inside the scan cap the count IS exact, so the
/// footer carries no lower-bound hedge.
#[test]
fn tasks_check_exact_exhaustion_reports_exact_additive_overflow() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    created_task_refs(&facade, 5);

    let snapshot = task_presence_with_limits(&vault, 2, 64).expect("exhausted presence");
    assert!(snapshot.source_exhausted);
    assert_eq!(snapshot.intents.len(), 5);

    let section = TasksSection::render_with_cap(
        &snapshot.intents,
        &snapshot.bare_jobs,
        snapshot.source_exhausted,
        3,
    );

    assert_eq!(section.rows.len(), 3);
    let overflow = section.overflow.expect("capped rows carry a footer");
    assert_eq!(overflow.line().as_deref(), Some("tasks: +2 more"));
    assert!(!overflow.line().expect("footer").contains("at least"));

    // Under both caps the landed footer-free render is unchanged.
    let whole = TasksSection::render_bounded(
        &snapshot.intents,
        &snapshot.bare_jobs,
        snapshot.source_exhausted,
    );
    assert_eq!(whole.rows.len(), 5);
    assert_eq!(whole.overflow, None);
}

/// Hidden means one call away, never gone: a TASK ordered after the board
/// scan prefix still expands by id.
#[test]
fn tasks_expand_direct_lookup_survives_board_scan_cap() {
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
    let lines = facade.tasks_expand(beyond_prefix).expect("expand by id");
    assert!(lines[0].starts_with(&beyond_hex));

    // An unknown id is still EntityNotFound, not a silent empty expansion.
    assert_eq!(
        facade
            .tasks_expand(EntityId::from_bytes([0xD9; 16]).expect("unknown id"))
            .expect_err("an unknown id is not found")
            .code,
        crate::memory::MEMORY_CODE_NOT_FOUND
    );
}

/// The same for `tasks.ack`, including the failed-only invariant and the
/// acked-failure invisibility that follows it.
#[test]
fn tasks_ack_direct_lookup_survives_board_scan_cap() {
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
    let receipt = facade.tasks_ack(beyond_prefix).expect("ack past the cap");
    assert!(receipt.acked);
    assert!(task_is_acked(&vault, beyond_prefix).expect("ack bit"));
    // A non-failed task acked by id is still a no-op.
    let queued = created[0];
    assert!(!facade.tasks_ack(queued).expect("ack queued task").acked);
    assert!(!task_is_acked(&vault, queued).expect("no ack bit"));
    // The acked failure has left BOTH the board and the typed read verbs.
    assert_eq!(
        facade
            .tasks_expand(beyond_prefix)
            .expect_err("acked failure is not expandable")
            .code,
        crate::memory::MEMORY_CODE_NOT_FOUND
    );
}

/// "Not scanned" is not "dangling": a job whose owning TASK lies beyond the
/// scan cap is withheld and counted, never re-emitted as a bare duplicate.
#[test]
fn truncated_task_scan_does_not_emit_linked_jobs_as_bare() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = created_task_refs(&facade, 3);

    // Every created TASK owns exactly one realizing job, all folded.
    let whole = task_presence_with_limits(&vault, 8, 64).expect("exhausted presence");
    assert!(whole.source_exhausted);
    assert_eq!(whole.intents.len(), 3);
    assert_eq!(whole.bare_jobs.len(), 0);
    let folded: usize = whole
        .intents
        .iter()
        .map(|intent| intent.realizing_jobs.len())
        .sum();
    assert_eq!(folded, 3);

    let truncated = task_presence_with_limits(&vault, 1, 1).expect("one-row board prefix");

    assert!(!truncated.source_exhausted);
    assert_eq!(truncated.intents.len(), 1);
    assert_eq!(truncated.intents[0].id, created[0].to_hex());
    assert_eq!(
        truncated.bare_jobs.len(),
        0,
        "jobs owned by unscanned TASKs must not surface as bare rows"
    );
    // No job renders twice: the withheld ones render nowhere at all, and
    // the only visible job is the scanned owner's own realization.
    let visible: std::collections::BTreeSet<&str> = truncated
        .intents
        .iter()
        .flat_map(|intent| intent.realizing_jobs.iter())
        .chain(truncated.bare_jobs.iter())
        .map(|job| job.id.as_str())
        .collect();
    assert_eq!(
        visible,
        whole.intents[0]
            .realizing_jobs
            .iter()
            .map(|job| job.id.as_str())
            .collect()
    );
}

/// The exhausted-scan half of the same invariant is untouched: a backlink
/// naming no surviving TASK still renders exactly once as a bare job.
#[test]
fn exhausted_task_scan_still_renders_genuinely_dangling_job_once() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let missing_task_hex = EntityId::from_bytes([0xC1; 16])
        .expect("missing id")
        .to_hex();
    let EnqueueOutcome::Enqueued(attempt) = AttemptQueue::new(&vault)
        .enqueue_with_task_ref(
            EnqueueAttempt {
                kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                payload: Vec::new(),
                dedupe_key: None,
                run_id: None,
                now: 120,
            },
            Some(missing_task_hex),
        )
        .expect("enqueue dangling attempt")
    else {
        panic!("attempt must enqueue");
    };
    let job_id = attempt_hex(attempt.id);

    let snapshot = task_presence_with_limits(&vault, 4, 64).expect("exhausted presence");

    assert!(snapshot.source_exhausted);
    assert_eq!(
        snapshot
            .bare_jobs
            .iter()
            .filter(|job| job.id == job_id)
            .count(),
        1
    );
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let section = facade.tasks_check().expect("check tasks");
    assert_eq!(
        section.rows.iter().filter(|row| row.id == job_id).count(),
        1
    );
    assert_eq!(section.overflow, None);
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

/// A cancelled TASK still consumes scan budget: the cap bounds inspected
/// ENTITY IDS, not successfully rendered rows, so a filtered prefix cannot
/// silently widen the walk.
#[test]
fn filtered_rows_still_consume_the_scan_budget() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xB7);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = created_task_refs(&facade, 3);
    facade
        .tasks_cancel(TaskCancelTarget::Task(created[0]))
        .expect("cancel the first task");

    let snapshot = task_presence_with_limits(&vault, 1, 4).expect("scan-capped presence");

    assert_eq!(snapshot.scanned_task_entities, 4);
    // Four ids inspected — two tasks and the two Owner facts beside them —
    // and one of the tasks is cancelled, so one row survives.
    assert_eq!(snapshot.intents.len(), 1);
    assert_eq!(snapshot.intents[0].id, created[1].to_hex());
    assert!(!snapshot.source_exhausted);
}

mod paged_scan_property {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// For arbitrary sorted unique ids, page sizes, and scan caps: no id
        /// repeats, the cursor strictly increases, the inspected count never
        /// exceeds the cap, and exhaustion is never claimed falsely.
        #[test]
        fn paged_task_scan_cursor_strictly_advances_and_never_exceeds_cap(
            indices in prop::collection::btree_set(1_u128..512, 0..180),
            page_size in 1_usize..17,
            scan_cap in 0_usize..300,
        ) {
            let source: Vec<EntityId> =
                indices.iter().copied().map(synthetic_task_id).collect();
            let mut cursors: Vec<Option<EntityId>> = Vec::new();
            let scan = scan_task_entity_pages(page_size, scan_cap, |after, limit| {
                cursors.push(after.copied());
                let start = source.partition_point(|id| after.is_some_and(|bound| id <= bound));
                Ok(source[start..].iter().take(limit).copied().collect())
            })
            .expect("the synthetic pager never errors");

            let flat: Vec<EntityId> = scan.pages.iter().flatten().copied().collect();
            prop_assert!(scan.scanned_task_entities <= scan_cap);
            prop_assert_eq!(flat.len(), scan.scanned_task_entities);
            prop_assert!(flat.windows(2).all(|pair| pair[0] < pair[1]));
            // The walk is a strict prefix of the source in type-index order.
            prop_assert_eq!(&flat[..], &source[..flat.len()]);
            // The walk opens with no cursor, then never repeats or moves back.
            prop_assert_eq!(cursors.first().copied().flatten(), None);
            let advanced: Vec<EntityId> = cursors.iter().flatten().copied().collect();
            prop_assert!(advanced.windows(2).all(|pair| pair[0] < pair[1]));
            // Exhaustion is only ever claimed when it is true.
            if scan.source_exhausted {
                prop_assert_eq!(flat.len(), source.len());
            }
            if source.len() > scan_cap {
                prop_assert!(!scan.source_exhausted);
            }
            if scan_cap > 0 && source.len() <= scan_cap {
                prop_assert!(scan.source_exhausted);
            }
        }
    }
}
