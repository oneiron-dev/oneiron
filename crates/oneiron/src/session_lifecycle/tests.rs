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
    let record = SessionLifecycleRecord {
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
    };
    // The `Named` codec has no opinion on `version`: an unsupported version
    // still round-trips through encode/decode cleanly. The rejection is
    // `validated_record`'s domain check, exercised here after a real decode.
    let encoded = RECORDS
        .encode_value(&record)
        .expect("encode unsupported-version record");
    let decoded = RECORDS
        .decode_value(&encoded)
        .expect("well-formed msgpack decodes");

    let error = validated_record(decoded).expect_err("unsupported version must fail closed");
    assert!(matches!(error, Error::CorruptedIndex(_)));
}

fn seed_conversation(vault: &Vault, seed: u8) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("conversation id");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_CONVERSATION,
            TimeRange { start: 1, end: 1 },
            1,
            b"\x80",
        )
        .expect("seed conversation");
    id
}

/// Seeded turns carry no PERSON author, so only a room owner's
/// `policy_delete` may remove one; this legacy fixture holds no policy
/// manifest, where that door fails closed. Deletion is not under test here.
fn hard_delete_turn(vault: &Vault, turn: EntityId) -> bool {
    vault
        .delete_room_record_unchecked_for_test(&turn, crate::DeleteReason::UserHardDelete)
        .expect("hard-delete planned turn")
        .existed
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
    let mine = AttemptQueue::new(&vault)
        .list()
        .expect("attempt list")
        .into_iter()
        .find(|record| {
            decode_dreamer_attempt_payload(&record.payload).is_ok_and(|payload| {
                payload.attempt_type
                    == crate::dreamer_consolidation::DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE
            })
        })
        .expect("close registered substitution miner");
    let stamp = vault
        .dreamer_attempt_authority(mine.id)
        .expect("authority lookup")
        .expect("miner shares Dreamer authority");
    assert_eq!(stamp.facet, "dreamer.consolidation");
    assert_eq!(
        vault
            .dreamer_actor_for_attempt(mine.id)
            .expect("executor authority"),
        vault.dreamer_authority().expect("principal")
    );
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

    assert!(hard_delete_turn(&vault, deleted));
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

#[test]
fn in_txn_planner_truncates_at_the_first_edgeless_turn_including_same_second_ties() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x60);
    let a = seed_dirty_turn(&vault, &conversation, 900);
    let tie = seed_dirty_turn(&vault, &conversation, 910);
    let edgeless = seed_edgeless_dirty_turn(&vault, 910);
    let after = seed_dirty_turn(&vault, &conversation, 920);
    let session = minted(vault.mint_session(1_000).expect("mint session"));

    let wake = vault.plan_session_end_wake().expect("plan");
    let ended = vault
        .end_session_with_wake(&session, SessionClosePredicate::Explicit, 1_001, &wake)
        .expect("close session")
        .expect("session ended");
    assert_eq!(ended.session, session);
    assert!(vault.open_session().expect("open session").is_none());

    let payloads = meso_partition_payloads(&vault);
    assert_eq!(payloads.len(), 1);
    let (_, turns, _) = decode_partition_payload(&payloads[0].input).expect("decode partition");
    assert_eq!(turns, vec![a]);

    let scope = DreamerConsolidationScope::Meso;
    let watermark = read_watermark(&vault, scope).expect("persisted watermark");
    let remaining = scan_dirty_turns(&vault, scope, &watermark, usize::MAX)
        .expect("scan remaining turns")
        .iter()
        .map(|turn| turn.turn_id)
        .collect::<Vec<_>>();
    let mut expected = vec![tie, edgeless];
    expected.sort();
    expected.push(after);
    assert_eq!(remaining, expected);
}

#[test]
fn in_txn_planner_drops_an_admissible_turn_sharing_the_cut_second() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x61);
    let a = seed_dirty_turn(&vault, &conversation, 900);
    let edgeless = seed_edgeless_dirty_turn(&vault, 900);
    let session = minted(vault.mint_session(1_000).expect("mint session"));

    let wake = vault.plan_session_end_wake().expect("plan");
    let ended = vault
        .end_session_with_wake(&session, SessionClosePredicate::Explicit, 1_001, &wake)
        .expect("close session")
        .expect("session ended");
    assert_eq!(ended.session, session);
    assert!(vault.open_session().expect("open session").is_none());
    assert_eq!(meso_attempt_count(&vault), 0);

    let scope = DreamerConsolidationScope::Meso;
    let watermark = read_watermark(&vault, scope).expect("persisted watermark");
    let remaining = scan_dirty_turns(&vault, scope, &watermark, usize::MAX)
        .expect("scan retained turns")
        .iter()
        .map(|turn| turn.turn_id)
        .collect::<Vec<_>>();
    let mut expected = vec![a, edgeless];
    expected.sort();
    assert_eq!(remaining, expected);

    // A newly indexed earlier turn must also remain eligible: the empty
    // round must not move the persisted bootstrap watermark forward.
    let earlier = seed_dirty_turn(&vault, &conversation, 899);
    let watermark = read_watermark(&vault, scope).expect("persisted watermark");
    let remaining = scan_dirty_turns(&vault, scope, &watermark, usize::MAX)
        .expect("scan from unchanged watermark")
        .iter()
        .map(|turn| turn.turn_id)
        .collect::<Vec<_>>();
    expected.insert(0, earlier);
    assert_eq!(remaining, expected);
}
