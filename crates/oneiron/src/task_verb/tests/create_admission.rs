//! Task verb tests: Create validation and deadlines, rate limits, over-quota proposals and claim-scan caps.

use super::support::*;
use super::*;

#[test]
fn own_create_effects_and_foreign_create_proposes() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let foreign = EntityId::from_bytes([0xE2; 16]).expect("foreign id");
    put_person(&vault, foreign);
    let rate = TaskCreateRateLimit {
        limit: 10,
        window_seconds: 60,
    };

    let own_result = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_create_with_rate_limit(&spec(120), rate)
        .expect("own create");
    let foreign_result = vault
        .memory(foreign, EdgeActorClass::Agent)
        .tasks_create_with_rate_limit(&spec(120), rate)
        .expect("foreign create");

    assert_eq!(usize::from(own_result.effected), 1);
    assert_eq!(own_result.approval, ClaimApprovalStatus::Auto);
    assert_eq!(usize::from(own_result.proposal_ref.is_some()), 0);
    assert_eq!(usize::from(foreign_result.effected), 0);
    assert_eq!(foreign_result.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(usize::from(foreign_result.proposal_ref.is_some()), 1);
    assert_eq!(task_entity_census(&vault), 1);
}

#[test]
fn rate_limit_effects_n_and_proposes_every_overflow() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let limit = 3;
    let attempted = 5;
    // The rate window is keyed on the ENGINE clock (`unix_seconds_now()`,
    // not caller time — the codex-r1 anti-bypass fix). A single window here
    // keeps the overflow behavior deterministic: with a finite window these
    // creates could straddle a wall-clock boundary under load and reset the
    // count mid-loop. (Window advancement is covered separately by
    // `create_rate_slot_overwrites_one_key_across_windows`.)
    let rate = TaskCreateRateLimit {
        limit,
        window_seconds: u64::MAX,
    };
    let mut results = Vec::new();
    for _ in 0..attempted {
        results.push(
            facade
                .tasks_create_with_rate_limit(&spec(120), rate)
                .expect("create"),
        );
    }

    assert_eq!(usize::from(results[limit - 1].effected), 1);
    assert_eq!(results[limit - 1].approval, ClaimApprovalStatus::Auto);
    assert_eq!(usize::from(results[limit - 1].proposal_ref.is_some()), 0);
    assert_eq!(usize::from(results[limit].effected), 0);
    assert_eq!(results[limit].approval, ClaimApprovalStatus::Proposed);
    assert_eq!(usize::from(results[limit].proposal_ref.is_some()), 1);
    assert_eq!(
        results.iter().filter(|result| result.effected).count(),
        limit
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.proposal_ref.is_some())
            .count(),
        attempted - limit
    );
}

/// A STANDARD task with a deadline already past is born expired, so the same
/// refusal the consult branch gives applies here. A future deadline passes,
/// and no deadline at all still means no TTL.
#[test]
fn a_standard_task_deadline_must_be_in_the_future() {
    let (_dir, vault) = open_vault();
    let facade = vault.memory(own_agent(&vault), EdgeActorClass::Agent);
    let now = 1_772_400_000;

    for past in [now, now - 1, 0] {
        let refused = facade
            .tasks_create(&spec(now).with_ttl(TaskTtl::at(past)))
            .expect_err("a past deadline rejects");
        assert_eq!(refused.code, crate::memory::MEMORY_CODE_BAD_REQUEST);
    }
    let accepted = facade
        .tasks_create(&spec(now).with_ttl(TaskTtl::at(now + 1)))
        .expect("a future deadline is a task with a TTL");
    let task_ref = accepted.task_ref.expect("task minted");
    assert_eq!(
        task_verb_body(&vault, task_ref)
            .expect("decode task")
            .expect("task is typed")
            .ttl,
        Some(TaskTtl::at(now + 1))
    );
    facade
        .tasks_create(&spec(now))
        .expect("no deadline is still a legal task");
}

/// The decoder already refuses a terminal that claims `countered` and names no
/// counter. Refusing it only on the way OUT is the wrong end: the row persists,
/// and every later read of that task fails instead of the write that made it
/// wrong. Both raw doors ask the question at admission now.
#[test]
fn a_raw_put_refuses_an_incoherent_countered_terminal() {
    let (_dir, vault) = open_vault();
    let now = 1_772_400_000;
    let body = incoherent_countered_task_body(&vault, now);

    for (door, refused) in [
        (
            "batch()",
            vault
                .put_entity(
                    &ladder_id(0xD5),
                    ENTITY_TYPE_TASK,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &body,
                )
                .expect_err("the public raw door refuses an incoherent terminal"),
        ),
        (
            "batch_in()",
            vault
                .with_write_txn(|wtxn| {
                    vault
                        .batch_in()
                        .put(
                            &ladder_id(0xD6),
                            ENTITY_TYPE_TASK,
                            TimeRange {
                                start: now,
                                end: now,
                            },
                            now,
                            &body,
                        )
                        .apply(wtxn)
                })
                .expect_err("the transactional door refuses it too"),
        ),
    ] {
        assert!(
            matches!(
                refused,
                crate::error::Error::InvalidTaskBody("tasks.terminal.ladder")
            ),
            "unexpected error from {door}: {refused}"
        );
    }
}

/// The facade refuses a task born expired; the PUBLIC raw door now asks the
/// same question of a body that never passed through the facade. Against the
/// row's own `learned_at` — the clock the facade compares to is the one it
/// stamps the write with, so the two doors cannot disagree about which
/// deadlines are in the future.
#[test]
fn a_public_raw_put_refuses_a_task_born_expired() {
    let (_dir, vault) = open_vault();
    let now = 1_772_400_000;
    let body = born_expired_task_body(&vault, now);

    let refused = vault
        .put_entity(
            &ladder_id(0xD1),
            ENTITY_TYPE_TASK,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &body,
        )
        .expect_err("the public raw door refuses a task born expired");
    assert!(
        matches!(
            refused,
            crate::error::Error::InvalidTaskBody("a task deadline must be in the future")
        ),
        "unexpected error: {refused}"
    );
}

/// The OTHER public raw door refuses it too.
///
/// `Vault::batch()` and `Vault::batch_in()` are both `pub` on `Vault` at the
/// same API tier, and the same body must not persist through one while the
/// other rejects it. `batch_in()` used to pass the INTERNAL door, so the
/// born-expired check — the one check that door gates — was skipped and this
/// body went in.
#[test]
fn the_transactional_public_raw_put_refuses_a_task_born_expired() {
    let (_dir, vault) = open_vault();
    let now = 1_772_400_000;
    let body = born_expired_task_body(&vault, now);

    let refused = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put(
                    &ladder_id(0xD3),
                    ENTITY_TYPE_TASK,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &body,
                )
                .apply(wtxn)
        })
        .expect_err("the transactional public door refuses a task born expired");
    assert!(
        matches!(
            refused,
            crate::error::Error::InvalidTaskBody("a task deadline must be in the future")
        ),
        "unexpected error: {refused}"
    );
}

/// ...and the INTERNAL door still admits it, which is not a gap but the whole
/// reason the seam is split: settling a task whose deadline has passed writes
/// a body carrying that past deadline, and the expiry lane exists to do
/// exactly that.
#[test]
fn the_internal_raw_put_still_admits_a_task_born_expired() {
    let (_dir, vault) = open_vault();
    let now = 1_772_400_000;
    let body = born_expired_task_body(&vault, now);

    vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_internal(
                    &ladder_id(0xD4),
                    ENTITY_TYPE_TASK,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &body,
                )
                .apply(wtxn)
        })
        .expect("the expiry lane must still be able to write an expired task");
}

/// The SYNC door does not. A peer's row is already written on the peer, so
/// refusing it here would leave the two vaults holding different histories —
/// storage convergence outranks an invariant on a row that already exists
/// (the STO-03 reading the TASK arm of `put_apply` records for the streak
/// counters). Nothing is lost by admitting it: the board derives `Expired`
/// from the deadline alone, which is the truth about that row.
#[cfg(feature = "sync")]
#[test]
fn sync_admission_takes_a_task_born_expired_and_the_board_derives_it() {
    let (_dir, vault) = open_vault();
    let now = 1_772_400_000;
    let body = born_expired_task_body(&vault, now);
    let replicated = ladder_id(0xD2);

    vault
        .batch()
        .put_replicated(
            &replicated,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &body,
        )
        .commit()
        .expect("the sync door admits a peer's row");

    let row = task_intent_presence(
        &vault,
        replicated,
        &replicated.to_hex(),
        Vec::new(),
        false,
        now,
    )
    .expect("project the replicated row")
    .expect("a Task-role row projects");
    assert_eq!(row.status, TaskBoardStatus::Failed);
    assert_eq!(
        row.terminal_disposition,
        Some(TaskTerminalDisposition::Expired)
    );
}

/// Overflow past quota parks a proposal — it does not refuse — so a retry
/// loop must land on the row already waiting rather than mint one per
/// attempt. The receipts still read as proposals every time; only the stored
/// rows are bounded.
#[test]
fn repeated_overflow_creates_park_on_one_proposal_row() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let limit = 1;
    let retries = 6;
    let rate = TaskCreateRateLimit {
        limit,
        window_seconds: u64::MAX,
    };
    let results: Vec<_> = (0..retries)
        .map(|_| {
            facade
                .tasks_create_with_rate_limit(&spec(120), rate)
                .expect("create")
        })
        .collect();

    assert_eq!(
        results.iter().filter(|result| result.effected).count(),
        limit
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.proposal_ref.is_some())
            .count(),
        retries - limit,
        "every overflow still answers with a proposal"
    );
    let proposal_refs: std::collections::BTreeSet<EntityId> = results
        .iter()
        .filter_map(|result| result.proposal_ref)
        .collect();
    assert_eq!(
        proposal_refs.len(),
        1,
        "the retries share ONE parked proposal"
    );
    assert_eq!(open_create_proposal_census(&vault, own), 1);
}

/// A DIFFERENT ask past quota still parks its own proposal: the dedupe is on
/// the ask, not on the actor.
#[test]
fn a_distinct_overflow_create_parks_its_own_proposal() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let rate = TaskCreateRateLimit {
        limit: 1,
        window_seconds: u64::MAX,
    };
    facade
        .tasks_create_with_rate_limit(&spec(120), rate)
        .expect("first create takes effect");
    facade
        .tasks_create_with_rate_limit(&spec(120), rate)
        .expect("overflow parks");
    facade
        .tasks_create_with_rate_limit(
            &TaskCreateSpec::new(Value::from("other-task"), None, None, Some(120)),
            rate,
        )
        .expect("a different overflow parks");

    assert_eq!(open_create_proposal_census(&vault, own), 2);
}

/// The dedupe index is claims-ABOUT-subject, so a row naming this actor may
/// have been written by anyone. A foreign-produced proposal with an identical
/// payload is not this caller's parked ask: the over-quota create parks its
/// own rather than answering with someone else's provenance and skipping the
/// gate receipt it owes.
#[test]
fn an_over_quota_create_never_reuses_a_foreign_actors_proposal() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let stranger = consult_peer(&vault, 0xC7);
    let rate = TaskCreateRateLimit {
        limit: 1,
        window_seconds: u64::MAX,
    };
    let facade = vault.memory(own, EdgeActorClass::Agent);
    facade
        .tasks_create_with_rate_limit(&spec(120), rate)
        .expect("the first create takes effect");
    let foreign = put_foreign_create_proposal(&vault, own, stranger, &spec(120), 120);

    let parked = facade
        .tasks_create_with_rate_limit(&spec(120), rate)
        .expect("the over-quota create parks");
    let proposal_ref = parked.proposal_ref.expect("the overflow parks a proposal");
    let body = vault
        .get_claim(&proposal_ref)
        .expect("claim body")
        .expect("the parked proposal is stored");

    assert_ne!(
        proposal_ref, foreign,
        "a row this actor did not write is never its parked ask"
    );
    assert_eq!(crate::claim::session_claim_producer(&body), Some(own));
    assert_eq!(open_create_proposal_census(&vault, own), 2);
}

/// An actor carrying more inbound claims than the MATERIALIZING edge scan
/// would admit still gets an answer past quota. The dedupe lookup streams, so
/// there is no ceiling on this path to hit: it walks the fan-in, finds this
/// actor has nothing of its own parked, and parks one — which is the correct
/// answer, not a degrade.
#[test]
fn a_capped_claim_scan_parks_a_proposal_instead_of_hard_failing() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let rate = TaskCreateRateLimit {
        limit: 1,
        window_seconds: u64::MAX,
    };
    let facade = vault.memory(own, EdgeActorClass::Agent);
    facade
        .tasks_create_with_rate_limit(&spec(120), rate)
        .expect("the first create takes effect");
    seed_capped_inbound_claim_edges(&vault, own);

    let parked = facade
        .tasks_create_with_rate_limit(&spec(120), rate)
        .expect("a capped claim scan never fails the create");

    assert_eq!(usize::from(parked.effected), 0);
    assert_eq!(usize::from(parked.proposal_ref.is_some()), 1);
    assert_eq!(parked.approval, ClaimApprovalStatus::Proposed);
}

/// The point of streaming rather than degrading. Inbound claims are attached
/// BY OTHERS, so a peer able to write rows about this actor could push it past
/// the edge-materialization cap and hold it there — and a lookup that answers
/// "nothing parked" above the cap has had its dedupe switched off by that
/// peer, permanently, minting a fresh proposal for every retry. The walk has
/// no ceiling, so the actor's own parked row is still found underneath a
/// hundred thousand foreign ones.
#[test]
fn dedupe_survives_a_claim_fan_in_past_the_materialization_cap() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let rate = TaskCreateRateLimit {
        limit: 1,
        window_seconds: u64::MAX,
    };
    let facade = vault.memory(own, EdgeActorClass::Agent);
    facade
        .tasks_create_with_rate_limit(&spec(120), rate)
        .expect("the first create takes effect");
    let parked = facade
        .tasks_create_with_rate_limit(&spec(120), rate)
        .expect("the second create parks a proposal")
        .proposal_ref
        .expect("a proposal ref");

    seed_capped_inbound_claim_edges(&vault, own);

    let retried = facade
        .tasks_create_with_rate_limit(&spec(120), rate)
        .expect("a high-degree claim subject never fails the create")
        .proposal_ref
        .expect("a proposal ref");
    assert_eq!(
        retried, parked,
        "the same ask must land on the row already waiting, however many \
         foreign claims are attached to this actor",
    );
    // Deliberately no census here: `open_create_proposal_census` reads through
    // the MATERIALIZING `claims_for_subject`, which is exactly the ceiling this
    // fixture sits above. The proposal ref is the assertion — a second parked
    // row would carry a different one.
}

/// A corrupt edge record is a different failure and
/// still reaches the caller, rather than being read as "this actor has parked
/// nothing" and answered with a fresh proposal over an unreadable index.
#[test]
fn a_corrupt_claim_edge_still_fails_the_over_quota_create() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let rate = TaskCreateRateLimit {
        limit: 1,
        window_seconds: u64::MAX,
    };
    let facade = vault.memory(own, EdgeActorClass::Agent);
    facade
        .tasks_create_with_rate_limit(&spec(120), rate)
        .expect("the first create takes effect");
    // One unreadable inbound claim edge: the scan fails decoding its value,
    // well inside the cap.
    vault
        .with_write_txn(|wtxn| {
            let key = crate::store::Store::encode_edge_key(
                &own,
                crate::edge::EdgeKind::ClaimOf,
                &ladder_id(0xCA),
            );
            vault.store.edges_in.put(wtxn, &key, &[])?;
            Ok(())
        })
        .expect("seed a corrupt claim edge");

    let error = facade
        .tasks_create_with_rate_limit(&spec(120), rate)
        .expect_err("a corrupt index is not an empty one");

    assert_eq!(usize::from(error.code.is_empty()), 0);
    assert_eq!(
        usize::from(error.message.contains("edge record")),
        1,
        "the corrupt index reaches the caller verbatim: {}",
        error.message
    );
}

#[test]
fn create_rate_slot_overwrites_one_key_across_windows() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let rate = TaskCreateRateLimit {
        limit: 2,
        window_seconds: 10,
    };
    {
        let mut wtxn = vault.store.env.write_txn().expect("write txn");
        // Window 0 (now 0..9): two slots, then the third is refused.
        assert!(consume_create_rate_slot(&vault, &mut wtxn, own, 0, rate).expect("w0 s1"));
        assert!(consume_create_rate_slot(&vault, &mut wtxn, own, 3, rate).expect("w0 s2"));
        assert!(!consume_create_rate_slot(&vault, &mut wtxn, own, 9, rate).expect("w0 over"));
        // Window 1 (now 10..): the count resets, a slot is available again.
        assert!(consume_create_rate_slot(&vault, &mut wtxn, own, 10, rate).expect("w1 s1"));
        // Window 2 (now 20..): still resets, still the same single key.
        assert!(consume_create_rate_slot(&vault, &mut wtxn, own, 20, rate).expect("w2 s1"));
        wtxn.commit().expect("commit");
    }
    // Elapsed windows overwrite the SAME key: exactly one rate key persists
    // for this (actor, window_seconds), not one row per elapsed window.
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let keys = vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, TASK_CREATE_RATE_KEY_PREFIX)
        .expect("rate prefix iter")
        .count();
    assert_eq!(keys, 1);
}

#[test]
fn caller_time_variation_does_not_bypass_one_engine_rate_window() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let limit = 3;
    let rate = TaskCreateRateLimit {
        limit,
        window_seconds: u64::MAX,
    };
    let caller_times = [0, 60, 120, 180];
    let results = caller_times.map(|now| {
        facade
            .tasks_create_with_rate_limit(&spec(now), rate)
            .expect("create")
    });

    assert_eq!(
        results.iter().filter(|result| result.effected).count(),
        limit
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.approval == ClaimApprovalStatus::Proposed)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.proposal_ref.is_some())
            .count(),
        1
    );
}
