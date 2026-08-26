use super::*;
use crate::attempt_queue::AttemptQueue;
use crate::config::VaultConfig;
use crate::dreamer_consolidation::{
    advance_watermark, decode_partition_payload, plan_partitions, read_watermark, scan_dirty_turns,
};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::edge::EdgeKind;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use crate::test_util::open_test_vault_with;

fn open_vault() -> (tempfile::TempDir, Vault) {
    open_test_vault_with(VaultConfig::device())
}

fn minted(outcome: SessionMintOutcome) -> EntityId {
    match outcome {
        SessionMintOutcome::Minted(id) => id,
        SessionMintOutcome::AlreadyOpen(id) => panic!("expected a fresh mint, got open {id:?}"),
    }
}

#[test]
fn decode_session_record_rejects_an_unsupported_version() {
    let encoded = encode_session_record(&SessionLifecycleRecord {
        version: SESSION_LIFECYCLE_RECORD_VERSION + 1,
        started_at: 1_000,
        last_activity: 1_000,
        ended_at: None,
        end_reason: None,
        started_effective_ms: 1_000_000,
        last_effective_ms: 1_000_000,
        app_open_hints: vec![SessionHintTimestamp {
            claimed_ms: None,
            arrival_ms: 1_000_000,
            effective_ms: 1_000_000,
        }],
        activity_periods: Vec::new(),
        explicit_end_hint: None,
    })
    .expect("encode unsupported-version record");

    let error = decode_session_record(&encoded).expect_err("unsupported version must fail closed");
    assert!(matches!(
        error,
        Error::CorruptedIndex("unsupported session lifecycle record version")
    ));
}

fn seed_conversation(vault: &Vault, seed: u8) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("conversation id");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_CONVERSATION,
            TimeRange { start: 1, end: 1 },
            1,
            b"conversation",
        )
        .expect("seed conversation");
    id
}

/// One admissible dirty turn (mirrors `dreamer_consolidation::tests`):
/// a TURN entity with an extraction-admissible speaker and the structural
/// ChildOf conversation edge the partition planner requires.
fn seed_dirty_turn(vault: &Vault, conversation: &EntityId, learned_at: u64) -> EntityId {
    let turn = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("spkr"), rmpv::Value::from("user")),
            (rmpv::Value::from("txt"), rmpv::Value::from("sitting turn")),
        ]),
    )
    .expect("turn body encode");
    vault
        .batch()
        .put(
            &turn,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        )
        .edge(&turn, EdgeKind::ChildOf, conversation, 1.0)
        .commit()
        .expect("seed turn");
    turn
}

/// The production planning trio, exactly as the driver's close runs it.
fn meso_wake(vault: &Vault) -> SessionEndWake {
    let scope = DreamerConsolidationScope::Meso;
    let watermark = read_watermark(vault, scope).expect("watermark");
    let dirty = scan_dirty_turns(vault, scope, &watermark, usize::MAX).expect("scan");
    let advance_watermark_to = dirty.iter().map(|turn| turn.learned_at).max();
    let planned_turn_ids = dirty.iter().map(|turn| turn.turn_id).collect();
    let plans = plan_partitions(vault, scope, &dirty, &watermark).expect("plan");
    SessionEndWake {
        plans,
        planned_watermark: watermark.last_learned_at,
        planned_turn_ids,
        advance_watermark_to,
    }
}

/// Every meso-queue attempt the close created, decoded on the PRODUCTION path
/// (attempt row → attempt payload), never a bespoke string.
fn meso_attempt_payloads(vault: &Vault) -> Vec<crate::dreamer_runner::DreamerAttemptPayload> {
    AttemptQueue::new(vault)
        .list()
        .expect("attempt list")
        .into_iter()
        .filter(|attempt| attempt.kind == crate::DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND)
        .map(|attempt| {
            decode_dreamer_attempt_payload(&attempt.payload).expect("attempt payload decodes")
        })
        .collect()
}

/// The meso-queue attempts that are PARTITION rounds.
///
/// The close also registers ED-04's substitution-mine pass on this queue — a
/// payload discriminator beside the partition rounds, not one of them — so the
/// kind alone no longer names a round.
fn meso_partition_payloads(vault: &Vault) -> Vec<crate::dreamer_runner::DreamerAttemptPayload> {
    meso_attempt_payloads(vault)
        .into_iter()
        .filter(|payload| payload.attempt_type == DreamerConsolidationScope::Meso.as_str())
        .collect()
}

/// COUNT of meso consolidation partition attempts ever created (any state) —
/// never `any()`.
fn meso_attempt_count(vault: &Vault) -> usize {
    meso_partition_payloads(vault).len()
}

#[test]
fn mint_opens_a_canonical_session_entity_with_zero_turns() {
    let (_dir, vault) = open_vault();
    // Presence is signal: no turn is ever witnessed in this test.
    let id = minted(vault.mint_session(1_000).expect("mint"));

    let header = vault
        .read_entity_header(&id)
        .expect("read header")
        .expect("session entity exists");
    assert_eq!(header.entity_type, ENTITY_TYPE_SESSION);

    let open = vault.open_session().expect("open").expect("session open");
    assert_eq!(open.session, id);
    assert_eq!(open.started_at, 1_000);
    assert_eq!(open.last_activity, 1_000);

    let record = vault
        .session_lifecycle_record(&id)
        .expect("record read")
        .expect("record exists");
    assert_eq!(record.started_at, 1_000);
    assert_eq!(record.last_activity, 1_000);
    assert_eq!(record.ended_at, None);
    assert_eq!(record.end_reason, None);
}

#[test]
fn second_mint_while_open_reports_already_open_and_mints_nothing() {
    let (_dir, vault) = open_vault();
    let first = minted(vault.mint_session(1_000).expect("mint"));

    let second = vault.mint_session(2_000).expect("second mint");
    assert_eq!(second, SessionMintOutcome::AlreadyOpen(first));

    // The open sitting is unchanged: same id, same clocks (AlreadyOpen
    // itself never bumps — that is caller policy).
    let open = vault.open_session().expect("open").expect("still open");
    assert_eq!(open.session, first);
    assert_eq!(open.started_at, 1_000);
    assert_eq!(open.last_activity, 1_000);
}

#[test]
fn bump_is_monotonic_and_noop_without_an_open_session() {
    let (_dir, vault) = open_vault();
    assert_eq!(
        vault.bump_session_activity(500).expect("bump on empty"),
        None,
        "an activity signal alone must not mint a session (fail-closed)"
    );
    assert_eq!(vault.open_session().expect("open"), None);

    let id = minted(vault.mint_session(1_000).expect("mint"));
    assert_eq!(vault.bump_session_activity(1_500).expect("bump"), Some(id));
    // A stale (older) bump never rewinds the activity clock.
    assert_eq!(vault.bump_session_activity(1_200).expect("bump"), Some(id));
    let open = vault.open_session().expect("open").expect("open");
    assert_eq!(open.last_activity, 1_500);
}

#[test]
fn end_stamps_reason_clears_pointer_and_is_idempotent() {
    let (_dir, vault) = open_vault();
    let id = minted(vault.mint_session(1_000).expect("mint"));
    vault.bump_session_activity(1_400).expect("bump");

    let ended = vault
        .end_session_with_wake(
            &id,
            SessionClosePredicate::Explicit,
            2_000,
            &SessionEndWake::none(0),
        )
        .expect("end")
        .expect("session ended");
    assert_eq!(ended.session, id);
    assert_eq!(ended.started_at, 1_000);
    assert_eq!(ended.last_activity, 1_400);
    assert_eq!(ended.ended_at, 2_000);
    assert_eq!(ended.reason, SessionEndReason::Explicit);

    assert_eq!(vault.open_session().expect("open"), None);
    // Ending again is a no-op, never an error (crash-retried closes).
    assert_eq!(
        vault
            .end_session_with_wake(
                &id,
                SessionClosePredicate::Explicit,
                2_100,
                &SessionEndWake::none(0),
            )
            .expect("re-end"),
        None
    );

    // The record is retained for audit after close.
    let record = vault
        .session_lifecycle_record(&id)
        .expect("record read")
        .expect("record retained");
    assert_eq!(record.ended_at, Some(2_000));
    assert_eq!(record.end_reason, Some(SessionEndReason::Explicit));
}

#[test]
fn ended_at_never_precedes_activity_under_clock_skew() {
    let (_dir, vault) = open_vault();
    let id = minted(vault.mint_session(1_000).expect("mint"));
    vault.bump_session_activity(1_800).expect("bump");

    // A skewed (earlier) close clock clamps to the last activity stamp — the
    // production close's clamp, reached via the unconditional Explicit
    // predicate (an Expiry close whose `now` trails activity is never due).
    let ended = vault
        .end_session_with_wake(
            &id,
            SessionClosePredicate::Explicit,
            1_500,
            &SessionEndWake::none(0),
        )
        .expect("end")
        .expect("ended");
    assert_eq!(ended.ended_at, 1_800);
}

#[test]
fn sequential_sittings_mint_distinct_sessions_and_keep_both_records() {
    let (_dir, vault) = open_vault();
    let first = minted(vault.mint_session(1_000).expect("mint"));
    vault
        .end_session_with_wake(
            &first,
            SessionClosePredicate::Explicit,
            2_000,
            &SessionEndWake::none(0),
        )
        .expect("end")
        .expect("ended");

    // "Same thread, two sittings": the next app-open is a NEW session.
    let second = minted(vault.mint_session(3_000).expect("second mint"));
    assert_ne!(first, second);

    let records = [first, second]
        .iter()
        .filter(|id| {
            vault
                .session_lifecycle_record(id)
                .expect("record read")
                .is_some()
        })
        .count();
    assert_eq!(records, 2, "both sittings keep their lifecycle records");
}

// ── ONE-1685 atomic, identity-bound close protocol ───────────────────────

#[test]
fn end_session_with_wake_closes_and_enqueues_the_production_round_atomically() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x51);
    let turn = seed_dirty_turn(&vault, &conversation, 900);
    let id = minted(vault.mint_session(1_000).expect("mint"));

    let wake = meso_wake(&vault);
    assert_eq!(wake.plans.len(), 1, "one dirty conversation, one partition");
    assert_eq!(
        wake.planned_turn_ids,
        vec![turn],
        "one dirty turn was planned"
    );
    let ended = vault
        .end_session_with_wake(&id, SessionClosePredicate::Explicit, 1_100, &wake)
        .expect("end")
        .expect("session ended");
    assert_eq!(ended.session, id);
    assert_eq!(ended.reason, SessionEndReason::Explicit);
    assert_eq!(vault.open_session().expect("open"), None);

    // Exactly one meso partition attempt, and it decodes on the PRODUCTION
    // executor path (attempt payload → partition payload), not a bespoke string.
    let partitions = meso_partition_payloads(&vault);
    assert_eq!(partitions.len(), 1, "exactly one SessionEnd meso round");
    let (partition, turn_ids, watermark) =
        decode_partition_payload(&partitions[0].input).expect("production partition decode");
    assert_eq!(partition.conversation_ref, conversation);
    assert_eq!(turn_ids, vec![turn]);
    assert_eq!(watermark, 0, "planned against the bootstrap watermark");

    // The watermark settled in the SAME commit as the enqueue.
    assert_eq!(
        read_watermark(&vault, DreamerConsolidationScope::Meso)
            .expect("watermark")
            .last_learned_at,
        900
    );

    // Re-ending the already-ended session is a structural no-op: no stamp,
    // no second attempt — the wake can never double.
    assert_eq!(
        vault
            .end_session_with_wake(
                &id,
                SessionClosePredicate::Explicit,
                1_200,
                &meso_wake(&vault)
            )
            .expect("re-end"),
        None
    );
    assert_eq!(meso_attempt_count(&vault), 1);
}

#[test]
fn an_in_range_dirty_turn_that_races_the_close_defers_the_whole_round() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x55);
    let planned = seed_dirty_turn(&vault, &conversation, 900);
    let id = minted(vault.mint_session(1_000).expect("mint"));

    let wake = meso_wake(&vault);
    assert_eq!(
        wake.planned_turn_ids,
        vec![planned],
        "one dirty turn was planned"
    );
    assert_eq!(wake.advance_watermark_to, Some(900));

    // Same-second arrival is inside the planned watermark window while the
    // watermark itself is unchanged.
    let injected = seed_dirty_turn(&vault, &conversation, 900);
    vault
        .end_session_with_wake(&id, SessionClosePredicate::Explicit, 1_100, &wake)
        .expect("end")
        .expect("the close itself still commits");

    assert_eq!(
        meso_attempt_count(&vault),
        0,
        "a moved dirty snapshot enqueues none of the stale round"
    );
    let watermark = read_watermark(&vault, DreamerConsolidationScope::Meso)
        .expect("watermark after deferred round");
    assert_eq!(
        watermark.last_learned_at, wake.planned_watermark,
        "the stale round must not advance the watermark"
    );
    let dirty = scan_dirty_turns(
        &vault,
        DreamerConsolidationScope::Meso,
        &watermark,
        usize::MAX,
    )
    .expect("fresh dirty scan");
    assert_eq!(dirty.len(), 2, "both turns remain consolidatable");
    assert_eq!(
        dirty.iter().filter(|turn| turn.turn_id == injected).count(),
        1,
        "the injected turn remains in the dirty set"
    );
}

#[test]
fn a_same_count_delete_and_insert_race_defers_the_whole_round_by_identity() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x56);
    seed_dirty_turn(&vault, &conversation, 900);
    seed_dirty_turn(&vault, &conversation, 900);
    let id = minted(vault.mint_session(1_000).expect("mint"));

    let wake = meso_wake(&vault);
    assert_eq!(
        wake.planned_turn_ids.len(),
        2,
        "two dirty turns were planned"
    );
    let deleted = wake.planned_turn_ids[0];
    let surviving = wake.planned_turn_ids[1];

    assert!(
        vault
            .delete_entity(&deleted)
            .expect("hard-delete planned turn")
    );
    let inserted = seed_dirty_turn(&vault, &conversation, 900);
    vault
        .end_session_with_wake(&id, SessionClosePredicate::Explicit, 1_100, &wake)
        .expect("end")
        .expect("the close itself still commits");

    assert_eq!(
        meso_attempt_count(&vault),
        0,
        "identity mismatch enqueues none of the stale round"
    );
    let watermark = read_watermark(&vault, DreamerConsolidationScope::Meso)
        .expect("watermark after deferred round");
    assert_eq!(
        watermark.last_learned_at, wake.planned_watermark,
        "the stale round must not advance the watermark"
    );
    let dirty = scan_dirty_turns(
        &vault,
        DreamerConsolidationScope::Meso,
        &watermark,
        usize::MAX,
    )
    .expect("fresh dirty scan");
    assert_eq!(dirty.len(), 2, "net dirty count remains unchanged");
    assert_eq!(
        dirty
            .iter()
            .filter(|turn| turn.turn_id == surviving)
            .count(),
        1,
        "the surviving planned turn remains dirty"
    );
    assert_eq!(
        dirty.iter().filter(|turn| turn.turn_id == inserted).count(),
        1,
        "the inserted turn remains dirty"
    );
    assert_eq!(
        dirty.iter().filter(|turn| turn.turn_id == deleted).count(),
        0,
        "the hard-deleted turn is absent"
    );
}

#[test]
fn a_stale_closer_holding_a_replaced_sessions_id_no_ops() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x52);
    seed_dirty_turn(&vault, &conversation, 900);
    let a = minted(vault.mint_session(1_000).expect("mint a"));
    vault
        .end_session_with_wake(
            &a,
            SessionClosePredicate::Explicit,
            1_100,
            &meso_wake(&vault),
        )
        .expect("end a")
        .expect("a ended");
    assert_eq!(
        meso_attempt_count(&vault),
        1,
        "A's close planned exactly one attempt"
    );
    let b = minted(vault.mint_session(1_200).expect("mint b"));

    // Fresh dirty work exists, so the stale closer arrives with a REAL
    // non-empty plan: the identity check must refuse before anything
    // enqueues — atomicity, not luck.
    seed_dirty_turn(&vault, &conversation, 1_150);
    let stale_wake = meso_wake(&vault);
    assert_eq!(stale_wake.plans.len(), 1);
    assert_eq!(
        vault
            .end_session_with_wake(&a, SessionClosePredicate::Explicit, 1_300, &stale_wake)
            .expect("stale close"),
        None,
        "a stale closer holding A's id must no-op"
    );

    let open = vault.open_session().expect("open").expect("B unaffected");
    assert_eq!(open.session, b);
    assert_eq!(open.started_at, 1_200);
    assert_eq!(
        vault
            .session_lifecycle_record(&b)
            .expect("record read")
            .expect("record")
            .ended_at,
        None
    );
    assert_eq!(
        meso_attempt_count(&vault),
        1,
        "exactly one meso attempt — A's"
    );
}

#[test]
fn an_activity_bump_that_raced_the_close_wins_inside_the_end_txn() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x53);
    seed_dirty_turn(&vault, &conversation, 900);
    let id = minted(vault.mint_session(1_000).expect("mint"));

    // The closer computed "idle due at 1_600" from a pre-bump snapshot;
    // the bump lands durably before the close transaction begins.
    vault.bump_session_activity(1_599).expect("bump");
    let wake = meso_wake(&vault);
    assert_eq!(wake.plans.len(), 1, "the racing closer carries a real plan");
    assert_eq!(
        vault
            .end_session_with_wake(
                &id,
                SessionClosePredicate::Expiry {
                    idle_floor_secs: 600,
                    lifetime_ceiling_secs: 10_000,
                },
                1_600,
                &wake,
            )
            .expect("racing close"),
        None,
        "the predicate re-read inside the txn sees the bump: the close no-ops"
    );

    let open = vault.open_session().expect("open").expect("still open");
    assert_eq!(open.session, id);
    assert_eq!(open.last_activity, 1_599);
    assert_eq!(
        meso_attempt_count(&vault),
        0,
        "no close ⇒ no wake attempt (atomic)"
    );
}

#[test]
fn expiry_names_the_close_first_to_fire_and_the_ceiling_wins_ties() {
    let (_dir, vault) = open_vault();
    let id = minted(vault.mint_session(1_000).expect("mint"));
    vault.bump_session_activity(1_400).expect("bump");

    // idle due 2_000, ceiling due 1_900: one second early is not a close.
    let expiry = SessionClosePredicate::Expiry {
        idle_floor_secs: 600,
        lifetime_ceiling_secs: 900,
    };
    assert_eq!(
        vault
            .end_session_with_wake(&id, expiry, 1_899, &SessionEndWake::none(0))
            .expect("not due"),
        None
    );
    let ended = vault
        .end_session_with_wake(&id, expiry, 1_900, &SessionEndWake::none(0))
        .expect("due")
        .expect("ended");
    assert_eq!(ended.session, id);
    assert_eq!(ended.reason, SessionEndReason::LifetimeCeiling);

    // Second sitting: the idle floor fires first when it is the earlier due.
    let second = minted(vault.mint_session(2_000).expect("mint second"));
    let ended = vault
        .end_session_with_wake(
            &second,
            SessionClosePredicate::Expiry {
                idle_floor_secs: 600,
                lifetime_ceiling_secs: 9_000,
            },
            2_600,
            &SessionEndWake::none(0),
        )
        .expect("due")
        .expect("ended");
    assert_eq!(ended.reason, SessionEndReason::IdleFloor);
}

#[test]
fn a_moved_watermark_skips_the_stale_planned_round_but_still_closes() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x54);
    seed_dirty_turn(&vault, &conversation, 900);
    let id = minted(vault.mint_session(1_000).expect("mint"));
    let wake = meso_wake(&vault); // planned against watermark 0

    // Another planner runs its round and advances the watermark first.
    advance_watermark(&vault, DreamerConsolidationScope::Meso, 950).expect("concurrent planner");

    let ended = vault
        .end_session_with_wake(&id, SessionClosePredicate::Explicit, 1_100, &wake)
        .expect("end")
        .expect("the close itself still commits");
    assert_eq!(ended.reason, SessionEndReason::Explicit);
    assert_eq!(
        meso_attempt_count(&vault),
        0,
        "the stale round is NOT enqueued — those turns belong to the other planner"
    );
    assert_eq!(
        read_watermark(&vault, DreamerConsolidationScope::Meso)
            .expect("watermark")
            .last_learned_at,
        950,
        "the moved watermark is left alone"
    );
}

// ── ONE-1790 G3: the in-transaction planner IS the production trio ──────────

/// An admissible dirty TURN with NO structural ChildOf edge — the round's
/// truncation boundary.
fn seed_edgeless_dirty_turn(vault: &Vault, learned_at: u64) -> EntityId {
    let turn = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("spkr"), rmpv::Value::from("user")),
            (
                rmpv::Value::from("txt"),
                rmpv::Value::from("edge-less turn"),
            ),
        ]),
    )
    .expect("turn body encode");
    vault
        .batch()
        .put(
            &turn,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        )
        .commit()
        .expect("seed edge-less turn");
    turn
}

/// A CONVERSATION carrying the documented opt-in `world_ref` body key.
fn seed_conversation_with_world_ref(vault: &Vault, seed: u8, world: &EntityId) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("conversation id");
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from(crate::dreamer_consolidation::TURN_BODY_WORLD_REF_KEY),
            rmpv::Value::Binary(world.as_bytes().to_vec()),
        )]),
    )
    .expect("conversation body encode");
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CONVERSATION,
            TimeRange { start: 1, end: 1 },
            1,
            &body,
        )
        .commit()
        .expect("seed conversation with world_ref");
    id
}

/// An admissible dirty TURN carrying its OWN `world_ref` body key.
fn seed_dirty_turn_with_world_ref(
    vault: &Vault,
    conversation: &EntityId,
    learned_at: u64,
    world: &EntityId,
) -> EntityId {
    let turn = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("spkr"), rmpv::Value::from("user")),
            (rmpv::Value::from("txt"), rmpv::Value::from("world turn")),
            (
                rmpv::Value::from(crate::dreamer_consolidation::TURN_BODY_WORLD_REF_KEY),
                rmpv::Value::Binary(world.as_bytes().to_vec()),
            ),
        ]),
    )
    .expect("turn body encode");
    vault
        .batch()
        .put(
            &turn,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        )
        .edge(&turn, EdgeKind::ChildOf, conversation, 1.0)
        .commit()
        .expect("seed turn with world_ref");
    turn
}

#[test]
fn in_txn_planner_truncates_at_the_first_edgeless_turn_including_same_second_ties() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x60);
    let a = seed_dirty_turn(&vault, &conversation, 900);
    let tie = seed_dirty_turn(&vault, &conversation, 910);
    let edgeless = seed_edgeless_dirty_turn(&vault, 910);
    let after = seed_dirty_turn(&vault, &conversation, 920);

    let wake = vault.plan_session_end_wake().expect("plan");
    assert_eq!(
        wake.planned_turn_ids,
        vec![a],
        "the round stops BEFORE the cut second: the edge-less turn, its \
         same-second tie, and everything after are all deferred"
    );
    assert!(!wake.planned_turn_ids.contains(&edgeless));
    assert!(
        !wake.planned_turn_ids.contains(&tie),
        "same-second ties at the cut are dropped exactly as the driver drops them"
    );
    assert!(!wake.planned_turn_ids.contains(&after));
    assert_eq!(
        wake.advance_watermark_to,
        Some(900),
        "the watermark can only settle on the planned prefix"
    );
    assert_eq!(wake.plans.len(), 1, "one partition over the planned prefix");
    assert_eq!(
        wake.plans[0]
            .turns
            .iter()
            .map(|turn| turn.turn_id)
            .collect::<Vec<_>>(),
        vec![a]
    );
}

#[test]
fn in_txn_planner_drops_an_admissible_turn_sharing_the_cut_second() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x61);
    let a = seed_dirty_turn(&vault, &conversation, 900);
    seed_edgeless_dirty_turn(&vault, 900);

    let wake = vault.plan_session_end_wake().expect("plan");
    assert!(
        wake.planned_turn_ids.is_empty(),
        "an edge-ful turn sharing the cut second is dropped with the tie, not kept"
    );
    assert!(!wake.planned_turn_ids.contains(&a));
    assert_eq!(wake.advance_watermark_to, None);
    assert!(wake.plans.is_empty());
}

#[test]
fn in_txn_planner_partition_keys_match_production_world_ref_fallback() {
    let (_dir, vault) = open_vault();
    let world_from_conversation = EntityId::from_bytes([0x71; 16]).expect("world id");
    let world_from_turn = EntityId::from_bytes([0x72; 16]).expect("world id");
    let inherited = seed_conversation_with_world_ref(&vault, 0x62, &world_from_conversation);
    seed_dirty_turn(&vault, &inherited, 900);
    let plain = seed_conversation(&vault, 0x63);
    seed_dirty_turn_with_world_ref(&vault, &plain, 901, &world_from_turn);

    let wake = vault.plan_session_end_wake().expect("plan");
    assert_eq!(wake.plans.len(), 2, "two conversations, two partitions");
    let keyed: std::collections::BTreeMap<_, _> = wake
        .plans
        .iter()
        .map(|plan| (plan.key.conversation_ref, plan.key.world_ref))
        .collect();
    assert_eq!(
        keyed.get(&inherited),
        Some(&Some(world_from_conversation)),
        "the conversation body key is the second leg of the production fallback chain"
    );
    assert_eq!(
        keyed.get(&plain),
        Some(&Some(world_from_turn)),
        "the turn body key is the first leg of the production fallback chain"
    );

    // Byte-for-byte parity with the committed-state production planner.
    let scope = DreamerConsolidationScope::Meso;
    let watermark = read_watermark(&vault, scope).expect("watermark");
    let dirty = scan_dirty_turns(&vault, scope, &watermark, usize::MAX).expect("scan");
    let production = plan_partitions(&vault, scope, &dirty, &watermark).expect("plan");
    assert_eq!(
        wake.plans, production,
        "the in-txn planner and the production planner plan the same round"
    );
}

#[test]
fn in_txn_planner_inherits_the_meso_round_cap() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x64);
    let cap = crate::dreamer_consolidation::DEFAULT_MESO_ROUND_TURN_CAP;
    for offset in 0..=cap as u64 {
        seed_dirty_turn(&vault, &conversation, 900 + offset);
    }

    let wake = vault.plan_session_end_wake().expect("plan");
    assert_eq!(
        wake.planned_turn_ids.len(),
        cap,
        "the planner inherits the Meso round cap instead of enumerating unbounded"
    );
}

// ── ONE-1790 G1: the snapshot fence has ONE matching leg ────────────────────

/// A round whose planned turns ALL vanished between plan and close is stale,
/// not "trivially matched". Admitting it would enqueue a round over rows that
/// no longer exist AND settle the Meso watermark COMPLETE past that second —
/// silently swallowing every turn at that second no planner ever saw.
#[test]
fn a_vanished_dirty_snapshot_enqueues_none_of_the_stale_round() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x65);
    let turn = seed_dirty_turn(&vault, &conversation, 900);
    let id = minted(vault.mint_session(1_000).expect("mint"));

    let wake = vault.plan_session_end_wake().expect("plan");
    assert_eq!(wake.planned_turn_ids, vec![turn]);
    assert_eq!(wake.advance_watermark_to, Some(900));
    let before = meso_attempt_count(&vault);

    // The whole planned snapshot vanishes before the close runs.
    assert!(
        vault
            .delete_entity(&turn)
            .expect("hard-delete planned turn")
    );

    let ended = vault
        .end_session_with_wake(&id, SessionClosePredicate::Explicit, 1_100, &wake)
        .expect("end")
        .expect("the close itself still commits");
    assert_eq!(ended.session, id);
    assert_eq!(
        meso_attempt_count(&vault),
        before,
        "an all-vanished snapshot enqueues none of the stale round"
    );
    assert_eq!(
        read_watermark(&vault, DreamerConsolidationScope::Meso)
            .expect("watermark")
            .last_learned_at,
        wake.planned_watermark,
        "the stale round must not advance the watermark past unplanned work"
    );
}
