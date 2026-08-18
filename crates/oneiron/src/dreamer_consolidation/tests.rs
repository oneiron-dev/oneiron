use std::collections::VecDeque;
use std::future::Future;
use std::pin::pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use crate::attempt_queue::AttemptQueue;
use crate::config::VaultConfig;
use crate::dreamer_runner::{
    AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, DreamerAdmissionOutcome,
    DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier,
    DreamerConsolidationAdmissionOutcome, decode_dreamer_attempt_payload,
};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION};
use crate::write_envelope::WriteProvenance;
use crate::{
    BudgetExhaustionPolicy, BudgetLease, ContentPart, EdgeActorClass, FinishReason,
    LlmGenerateFuture, LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage, LlmResult,
    LlmStreamResult, LlmUsage, SessionClosePredicate, SessionEndWake, SessionMintOutcome,
    WakePassDeadline,
};

use super::*;

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("consolidation future unexpectedly pending"),
    }
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

fn occurred(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn seed_session(vault: &Vault, seed: u8, at: u64) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("session id");
    vault
        .put_entity(&id, ENTITY_TYPE_SESSION, occurred(at), at, b"session")
        .expect("seed session");
    id
}

fn turn_body(speaker: &str, text: &str, facet: Option<&EntityId>) -> Vec<u8> {
    let mut entries = vec![
        (Value::from("txt"), Value::from(text)),
        (Value::from("spkr"), Value::from(speaker)),
    ];
    if let Some(facet) = facet {
        entries.push((
            Value::from(TURN_BODY_FACET_REF_KEY),
            Value::Binary(facet.as_bytes().to_vec()),
        ));
    }
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &Value::Map(entries)).expect("turn body encode");
    encoded
}

fn seed_turn(
    vault: &Vault,
    conversation: &EntityId,
    speaker: &str,
    text: &str,
    learned_at: u64,
) -> EntityId {
    seed_turn_with_facet(vault, conversation, speaker, text, learned_at, None)
}

fn seed_turn_with_facet(
    vault: &Vault,
    conversation: &EntityId,
    speaker: &str,
    text: &str,
    learned_at: u64,
    facet: Option<&EntityId>,
) -> EntityId {
    let id = EntityId::now();
    let body = turn_body(speaker, text, facet);
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_TURN,
            occurred(learned_at),
            learned_at,
            &body,
        )
        .edge(&id, EdgeKind::ChildOf, conversation, 1.0)
        .commit()
        .expect("seed turn");
    id
}

/// Deterministic turn ids whose BYTE order is their seeding order, so a test
/// can name the exact temporal key a capped round cuts at.
fn ordered_turn_id(prefix: u8, ordinal: u32) -> EntityId {
    let mut bytes = [0_u8; 16];
    bytes[0] = prefix;
    bytes[1..5].copy_from_slice(&ordinal.to_be_bytes());
    EntityId::from_bytes(bytes).expect("ordered turn id")
}

/// `count` admissible TURNs sharing ONE `learned_at`, with monotonically
/// ordered ids, in one commit.
fn seed_ordered_turns_at(
    vault: &Vault,
    conversation: &EntityId,
    prefix: u8,
    learned_at: u64,
    count: u32,
) -> Vec<EntityId> {
    let body = turn_body("user", "same-second turn", None);
    let mut batch = vault.batch();
    let mut ids = Vec::with_capacity(count as usize);
    for ordinal in 0..count {
        let id = ordered_turn_id(prefix, ordinal);
        batch = batch
            .put(
                &id,
                ENTITY_TYPE_TURN,
                occurred(learned_at),
                learned_at,
                &body,
            )
            .edge(&id, EdgeKind::ChildOf, conversation, 1.0);
        ids.push(id);
    }
    batch.commit().expect("seed same-second turns");
    ids
}

fn minted(outcome: SessionMintOutcome) -> EntityId {
    match outcome {
        SessionMintOutcome::Minted(id) => id,
        SessionMintOutcome::AlreadyOpen(id) => panic!("expected a fresh mint, got open {id:?}"),
    }
}

/// The production planning trio, exactly as the driver's close runs it —
/// including the `usize::MAX` limit that the Meso round cap bounds.
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

/// Meso PARTITION rounds only: the close also registers the substitution-mine
/// pass on this queue, which is a payload discriminator, not a round.
fn meso_partition_attempt_count(vault: &Vault) -> usize {
    AttemptQueue::new(vault)
        .list()
        .expect("attempt list")
        .into_iter()
        .filter(|attempt| attempt.kind == crate::DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND)
        .filter_map(|attempt| decode_dreamer_attempt_payload(&attempt.payload).ok())
        .filter(|payload| payload.attempt_type == DreamerConsolidationScope::Meso.as_str())
        .count()
}

fn user_claim(vault: &Vault, predicate: &str, at: u64) -> EntityId {
    let actor = EntityId::now();
    let subject = EntityId::now();
    vault
        .put_entity(&actor, ENTITY_TYPE_PERSON, occurred(at), at, b"actor")
        .expect("actor");
    vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, occurred(at), at, b"subject")
        .expect("subject");
    let claim_id = EntityId::now();
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("consolidation-test")).expect("provenance"),
        ClaimApprovalStatus::Approved,
    );
    let candidate = ClaimCandidate::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::from("v"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, occurred(at), at)
        .commit()
        .expect("user claim");
    claim_id
}

fn candidate(
    subject: EntityId,
    predicate: &str,
    value: &str,
    facet: Option<EntityId>,
) -> PromotionCandidate {
    let mut claim_candidate = ClaimCandidate::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::from(value),
        0.7,
    );
    if let Some(facet) = facet {
        claim_candidate = claim_candidate.with_scope(Value::Map(vec![(
            Value::from(TURN_BODY_FACET_REF_KEY),
            Value::Binary(facet.as_bytes().to_vec()),
        )]));
    }
    PromotionCandidate {
        claim_id: EntityId::now(),
        candidate: claim_candidate,
        evidence_turn_refs: Vec::new(),
        provenance_chain: Vec::new(),
        supersedes: None,
        evidence_meet: ClaimSource::Generated,
        occurred: occurred(1_000),
        learned_at: 1_000,
    }
}

fn map_candidate(subject: EntityId, predicate: &str, value: Value) -> PromotionCandidate {
    PromotionCandidate {
        claim_id: EntityId::now(),
        candidate: ClaimCandidate::new(predicate, ClaimSubject::Entity(subject), value, 0.7),
        evidence_turn_refs: Vec::new(),
        provenance_chain: Vec::new(),
        supersedes: None,
        evidence_meet: ClaimSource::Generated,
        occurred: occurred(1_000),
        learned_at: 1_000,
    }
}

fn prior_head(
    subject: EntityId,
    predicate: &str,
    value: &str,
    approval: ClaimApprovalStatus,
    source: ClaimSource,
) -> PriorHead {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::from(value),
        0.8,
        approval,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    body.source = Some(source);
    PriorHead {
        claim_id: EntityId::now(),
        body,
    }
}

#[test]
fn working_set_selects_only_new_admissible_turns() -> Result<()> {
    let (_dir, vault) = open_vault();
    let conversation = seed_session(&vault, 0x21, 5);
    let scope = DreamerConsolidationScope::Micro;

    seed_turn(&vault, &conversation, "user", "before watermark", 50);
    let user_turn = seed_turn(&vault, &conversation, "user", "after watermark", 110);
    let assistant_turn = seed_turn(&vault, &conversation, "assistant", "reply", 120);
    seed_turn(&vault, &conversation, "tool", "tool output", 130);
    seed_turn(&vault, &conversation, "system", "system note", 140);
    user_claim(&vault, "profile.name", 150); // claims never enter

    let watermark = ConsolidationWatermark {
        schema_version: WATERMARK_SCHEMA_VERSION,
        last_learned_at: 100,
        last_turn_id: None,
    };
    let turns = scan_dirty_turns(&vault, scope, &watermark, 100)?;
    assert_eq!(turns.len(), 2, "only admissible post-watermark turns");
    assert_eq!(turns[0].turn_id, user_turn);
    assert_eq!(turns[0].role, DreamerTurnRole::User);
    assert_eq!(turns[0].conversation, Some(conversation));
    assert_eq!(turns[1].turn_id, assistant_turn);
    assert_eq!(turns[1].role, DreamerTurnRole::Assistant);
    Ok(())
}

#[test]
fn bootstrap_round_on_empty_vault() -> Result<()> {
    let (_dir, vault) = open_vault();
    let scope = DreamerConsolidationScope::Micro;

    // Absent row IS watermark 0.
    let watermark = read_watermark(&vault, scope)?;
    assert_eq!(watermark.last_learned_at, 0);
    assert!(scan_dirty_turns(&vault, scope, &watermark, 10)?.is_empty());

    let conversation = seed_session(&vault, 0x22, 1);
    seed_turn(&vault, &conversation, "user", "oldest", 5);
    seed_turn(&vault, &conversation, "user", "middle", 10);
    seed_turn(&vault, &conversation, "user", "newest", 15);

    // Oldest-first, bounded by limit.
    let first_round = scan_dirty_turns(&vault, scope, &watermark, 2)?;
    assert_eq!(first_round.len(), 2);
    assert_eq!(first_round[0].learned_at, 5);
    assert_eq!(first_round[1].learned_at, 10);

    // Repeated rounds converge: each advances past what it scanned.
    advance_watermark(&vault, scope, 10)?;
    let watermark = read_watermark(&vault, scope)?;
    let second_round = scan_dirty_turns(&vault, scope, &watermark, 2)?;
    assert_eq!(second_round.len(), 1);
    assert_eq!(second_round[0].learned_at, 15);

    advance_watermark(&vault, scope, 15)?;
    let watermark = read_watermark(&vault, scope)?;
    assert!(scan_dirty_turns(&vault, scope, &watermark, 2)?.is_empty());
    Ok(())
}

#[test]
fn watermark_crash_replay_idempotent() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let scope = DreamerConsolidationScope::Micro;
    let conversation = seed_session(&vault, 0x23, 1);
    seed_turn(&vault, &conversation, "user", "hello", 10);
    seed_turn(&vault, &conversation, "assistant", "hi", 11);

    let watermark = read_watermark(&vault, scope)?;
    let turns = scan_dirty_turns(&vault, scope, &watermark, 10)?;
    let plans = plan_partitions(&vault, scope, &turns, &watermark)?;
    assert_eq!(plans.len(), 1);
    let outcomes = enqueue_partition_attempts(&store, scope, &plans, "run-1", 20)?;
    assert!(matches!(
        outcomes[0],
        EnqueueDreamerAttemptOutcome::Enqueued(_)
    ));

    // Simulated crash BEFORE the watermark advanced: the re-run re-scans the
    // same turns and re-plans — the advisory dedupe key absorbs it.
    let watermark = read_watermark(&vault, scope)?;
    assert_eq!(watermark.last_learned_at, 0, "crash: watermark untouched");
    let turns = scan_dirty_turns(&vault, scope, &watermark, 10)?;
    let plans = plan_partitions(&vault, scope, &turns, &watermark)?;
    let outcomes = enqueue_partition_attempts(&store, scope, &plans, "run-1", 30)?;
    assert!(matches!(
        outcomes[0],
        EnqueueDreamerAttemptOutcome::Existing(_)
    ));
    Ok(())
}

#[test]
fn partition_attempts_dedupe_advisory() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let scope = DreamerConsolidationScope::Micro;
    let conversation = seed_session(&vault, 0x24, 1);
    seed_turn(&vault, &conversation, "user", "text", 10);

    let watermark = read_watermark(&vault, scope)?;
    let turns = scan_dirty_turns(&vault, scope, &watermark, 10)?;
    let plans = plan_partitions(&vault, scope, &turns, &watermark)?;

    let first = enqueue_partition_attempts(&store, scope, &plans, "run-1", 20)?;
    let second = enqueue_partition_attempts(&store, scope, &plans, "run-1", 21)?;
    assert!(matches!(
        first[0],
        EnqueueDreamerAttemptOutcome::Enqueued(_)
    ));
    assert!(matches!(
        second[0],
        EnqueueDreamerAttemptOutcome::Existing(_)
    ));
    Ok(())
}

#[test]
fn offset_pager_never_authority() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let scope = DreamerConsolidationScope::Micro;
    let conversation = seed_session(&vault, 0x25, 1);
    seed_turn(&vault, &conversation, "user", "text", 10);

    let watermark = read_watermark(&vault, scope)?;
    let turns = scan_dirty_turns(&vault, scope, &watermark, 10)?;
    let plans = plan_partitions(&vault, scope, &turns, &watermark)?;
    let partition_hash = plans[0].key.partition_hash();

    // A STALE offset-era cursor is present; the watermark scan neither
    // consults it nor lets it duplicate work.
    write_cursor(
        &vault,
        scope,
        &partition_hash,
        &ConsolidationCursor {
            schema_version: 1,
            last_learned_at: 999_999, // stale/absurd offset residue
            last_ledger_revision_hint: 42,
        },
    )?;

    let rescanned = scan_dirty_turns(&vault, scope, &watermark, 10)?;
    assert_eq!(rescanned, turns, "stale cursor does not change selection");
    let replanned = plan_partitions(&vault, scope, &rescanned, &watermark)?;
    let first = enqueue_partition_attempts(&store, scope, &replanned, "run-1", 20)?;
    let second = enqueue_partition_attempts(&store, scope, &replanned, "run-1", 21)?;
    assert!(matches!(
        first[0],
        EnqueueDreamerAttemptOutcome::Enqueued(_)
    ));
    assert!(
        matches!(second[0], EnqueueDreamerAttemptOutcome::Existing(_)),
        "a partition scanned twice produces no duplicate attempts"
    );
    Ok(())
}

#[test]
fn revision_hint_never_authority() -> Result<()> {
    let (_dir, vault) = open_vault();
    let scope = DreamerConsolidationScope::Micro;
    let conversation = seed_session(&vault, 0x26, 1);
    seed_turn(&vault, &conversation, "user", "a", 10);
    seed_turn(&vault, &conversation, "assistant", "b", 11);

    let watermark = read_watermark(&vault, scope)?;
    let baseline = scan_dirty_turns(&vault, scope, &watermark, 10)?;
    let plans = plan_partitions(&vault, scope, &baseline, &watermark)?;
    let partition_hash = plans[0].key.partition_hash();

    // Corrupt the hint; selection must be bit-identical.
    write_cursor(
        &vault,
        scope,
        &partition_hash,
        &ConsolidationCursor {
            schema_version: 1,
            last_learned_at: 0,
            last_ledger_revision_hint: u64::MAX,
        },
    )?;
    let with_corrupt_hint = scan_dirty_turns(&vault, scope, &watermark, 10)?;
    assert_eq!(baseline, with_corrupt_hint);
    let replanned = plan_partitions(&vault, scope, &with_corrupt_hint, &watermark)?;
    assert_eq!(plans, replanned);
    Ok(())
}

// ── ONE-1793 bounded Meso rounds: the compound-cursor watermark ──────────

fn watermark_row(entries: Vec<(Value, Value)>) -> Vec<u8> {
    encode_value(&Value::Map(entries)).expect("watermark row encode")
}

fn put_watermark_row(vault: &Vault, scope: DreamerConsolidationScope, raw: &[u8]) {
    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    vault
        .store
        .vault_meta
        .put(&mut wtxn, &watermark_key(scope), raw)
        .expect("put watermark row");
    wtxn.commit().expect("commit watermark row");
}

fn assert_rejected(raw: &[u8], case: &str) {
    let error = decode_watermark(raw).expect_err(case);
    assert!(
        matches!(error, Error::InvalidClaimBody(_)),
        "{case} must fail with the typed consolidation error, got {error:?}"
    );
}

#[test]
fn watermark_v1_decodes_as_complete_second_boundary() -> Result<()> {
    let (_dir, vault) = open_vault();
    let scope = DreamerConsolidationScope::Meso;

    // The exact landed two-key row.
    let raw = watermark_row(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(WATERMARK_SCHEMA_VERSION_V1),
        ),
        (Value::from(KEY_LAST_LEARNED_AT), Value::from(900_u64)),
    ]);
    let decoded = decode_watermark(&raw)?;
    assert_eq!(decoded.schema_version, 1, "the row stays schema 1 on read");
    assert_eq!(decoded.last_learned_at, 900);
    assert_eq!(
        decoded.last_turn_id, None,
        "a v1 row means the whole second is consumed"
    );

    // "Through second 900" must not replay second 900.
    let conversation = seed_session(&vault, 0x2c, 1);
    seed_ordered_turns_at(&vault, &conversation, 0x41, 900, 3);
    let later = seed_turn(&vault, &conversation, "user", "next second", 901);
    put_watermark_row(&vault, scope, &raw);

    let watermark = read_watermark(&vault, scope)?;
    assert_eq!(watermark, decoded, "the stored row decodes identically");
    let dirty = scan_dirty_turns(&vault, scope, &watermark, usize::MAX)?;
    assert_eq!(
        dirty.iter().map(|turn| turn.turn_id).collect::<Vec<_>>(),
        vec![later],
        "no TURN at the v1 second replays"
    );
    Ok(())
}

#[test]
fn watermark_v2_roundtrips_compound_position() -> Result<()> {
    let turn_id = ordered_turn_id(0x42, 7);
    let exact = ConsolidationWatermark {
        schema_version: WATERMARK_SCHEMA_VERSION,
        last_learned_at: 900,
        last_turn_id: Some(turn_id),
    };
    assert_eq!(decode_watermark(&encode_watermark(&exact)?)?, exact);
    let boundary = ConsolidationWatermark::bootstrap();
    assert_eq!(decode_watermark(&encode_watermark(&boundary)?)?, boundary);
    assert_eq!(
        boundary.last_turn_id, None,
        "bootstrap/admin rows carry the end-of-second sentinel"
    );

    // Nine closed rejection classes.
    assert_rejected(
        &watermark_row(vec![
            (Value::from(KEY_SCHEMA_VERSION), Value::from(3_u64)),
            (Value::from(KEY_LAST_LEARNED_AT), Value::from(900_u64)),
            (Value::from(KEY_LAST_TURN_ID), Value::Nil),
        ]),
        "unsupported schema version",
    );
    assert_rejected(
        &watermark_row(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(WATERMARK_SCHEMA_VERSION),
            ),
            (Value::from(KEY_LAST_LEARNED_AT), Value::from(900_u64)),
        ]),
        "missing v2 last_turn_id",
    );
    assert_rejected(
        &watermark_row(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(WATERMARK_SCHEMA_VERSION),
            ),
            (Value::from(KEY_LAST_LEARNED_AT), Value::from(900_u64)),
            (Value::from(KEY_LAST_TURN_ID), Value::Binary(vec![0x42; 15])),
        ]),
        "wrong-length turn id bytes",
    );
    assert_rejected(
        &watermark_row(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(WATERMARK_SCHEMA_VERSION),
            ),
            (Value::from(KEY_LAST_LEARNED_AT), Value::from(900_u64)),
            (Value::from(KEY_LAST_TURN_ID), Value::Binary(vec![0; 16])),
        ]),
        "reserved turn id bytes",
    );
    assert_rejected(
        &watermark_row(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(WATERMARK_SCHEMA_VERSION),
            ),
            (Value::from(KEY_LAST_LEARNED_AT), Value::from(900_u64)),
            (Value::from(KEY_LAST_TURN_ID), Value::from("not-binary")),
        ]),
        "wrong turn id value type",
    );
    assert_rejected(
        &watermark_row(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(WATERMARK_SCHEMA_VERSION),
            ),
            (Value::from(KEY_LAST_LEARNED_AT), Value::from(900_u64)),
            (Value::from(KEY_LAST_LEARNED_AT), Value::from(901_u64)),
            (Value::from(KEY_LAST_TURN_ID), Value::Nil),
        ]),
        "duplicate pinned key (never last-write-wins)",
    );
    assert_rejected(
        &watermark_row(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(WATERMARK_SCHEMA_VERSION),
            ),
            (Value::from(KEY_LAST_LEARNED_AT), Value::from("900")),
            (Value::from(KEY_LAST_TURN_ID), Value::Nil),
        ]),
        "wrong value type",
    );
    assert_rejected(
        &watermark_row(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(WATERMARK_SCHEMA_VERSION),
            ),
            (Value::from(KEY_LAST_LEARNED_AT), Value::from(900_u64)),
            (Value::from(KEY_LAST_TURN_ID), Value::Nil),
            (Value::from("last_round_size"), Value::from(1_u64)),
        ]),
        "unknown key in schema 2",
    );
    assert_rejected(
        &watermark_row(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(WATERMARK_SCHEMA_VERSION_V1),
            ),
            (Value::from(KEY_LAST_LEARNED_AT), Value::from(900_u64)),
            (Value::from("last_round_size"), Value::from(1_u64)),
        ]),
        "unknown key in schema 1",
    );
    assert_rejected(
        &watermark_row(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(WATERMARK_SCHEMA_VERSION_V1),
            ),
            (Value::from(KEY_LAST_LEARNED_AT), Value::from(900_u64)),
            (
                Value::from(KEY_LAST_TURN_ID),
                Value::Binary(turn_id.as_bytes().to_vec()),
            ),
        ]),
        "a schema-1 row carrying last_turn_id",
    );
    Ok(())
}

#[test]
fn cap_cuts_mid_second_without_stall() -> Result<()> {
    const SECOND: u64 = 900;
    const ROUND: usize = 100;
    let (_dir, vault) = open_vault();
    let scope = DreamerConsolidationScope::Meso;
    let conversation = seed_session(&vault, 0x2d, 1);
    let seeded = seed_ordered_turns_at(
        &vault,
        &conversation,
        0x43,
        SECOND,
        u32::try_from(DEFAULT_MESO_ROUND_TURN_CAP).expect("cap fits"),
    );

    let mut consumed: Vec<EntityId> = Vec::new();
    for round in 0..DEFAULT_MESO_ROUND_TURN_CAP / ROUND {
        let watermark = read_watermark(&vault, scope)?;
        let turns = scan_dirty_turns(&vault, scope, &watermark, ROUND)?;
        assert_eq!(
            turns.iter().map(|turn| turn.turn_id).collect::<Vec<_>>(),
            seeded[round * ROUND..(round + 1) * ROUND],
            "round {round} returns the NEXT {ROUND} ids"
        );
        let last = *turns.last().expect("a capped round is non-empty");
        advance_watermark_to_turn(&vault, scope, &last)?;
        let settled = read_watermark(&vault, scope)?;
        assert_eq!(
            settled.last_learned_at, SECOND,
            "the cursor stays INSIDE the cut second"
        );
        assert_eq!(settled.last_turn_id, Some(last.turn_id));
        consumed.extend(turns.iter().map(|turn| turn.turn_id));
    }

    assert_eq!(consumed, seeded, "every seeded turn appears exactly once");
    assert_eq!(
        consumed.iter().copied().collect::<BTreeSet<_>>().len(),
        DEFAULT_MESO_ROUND_TURN_CAP,
        "no id appears twice"
    );
    let watermark = read_watermark(&vault, scope)?;
    assert!(
        scan_dirty_turns(&vault, scope, &watermark, ROUND)?.is_empty(),
        "the round after the last one is empty — no stall, no replay"
    );
    Ok(())
}

#[test]
fn default_meso_cap_is_500_but_other_scopes_keep_their_limit() -> Result<()> {
    let (_dir, vault) = open_vault();
    let conversation = seed_session(&vault, 0x2e, 1);
    let backlog = DEFAULT_MESO_ROUND_TURN_CAP + 1;
    seed_ordered_turns_at(
        &vault,
        &conversation,
        0x44,
        900,
        u32::try_from(backlog).expect("backlog fits"),
    );
    let watermark = read_watermark(&vault, DreamerConsolidationScope::Meso)?;

    assert_eq!(DEFAULT_MESO_ROUND_TURN_CAP, 500);
    assert_eq!(
        scan_dirty_turns(
            &vault,
            DreamerConsolidationScope::Meso,
            &watermark,
            usize::MAX,
        )?
        .len(),
        DEFAULT_MESO_ROUND_TURN_CAP,
        "the production usize::MAX call is a capped Meso round"
    );
    for scope in [
        DreamerConsolidationScope::Micro,
        DreamerConsolidationScope::Macro,
    ] {
        assert_eq!(
            scan_dirty_turns(&vault, scope, &watermark, usize::MAX)?.len(),
            backlog,
            "{scope:?} keeps the caller's bound"
        );
    }

    // Zero and sub-default requested limits are honored by every scope.
    for scope in [
        DreamerConsolidationScope::Micro,
        DreamerConsolidationScope::Meso,
        DreamerConsolidationScope::Macro,
    ] {
        assert!(scan_dirty_turns(&vault, scope, &watermark, 0)?.is_empty());
        assert_eq!(scan_dirty_turns(&vault, scope, &watermark, 3)?.len(), 3);
    }
    Ok(())
}

#[test]
fn resume_is_strictly_after_compound_key() -> Result<()> {
    let (_dir, vault) = open_vault();
    let scope = DreamerConsolidationScope::Meso;
    let conversation = seed_session(&vault, 0x2f, 1);
    let same_second = seed_ordered_turns_at(&vault, &conversation, 0x45, 900, 3);
    let later_second = seed_turn(&vault, &conversation, "user", "later second", 901);

    let inside = ConsolidationWatermark {
        schema_version: WATERMARK_SCHEMA_VERSION,
        last_learned_at: 900,
        last_turn_id: Some(same_second[1]),
    };
    assert_eq!(
        scan_dirty_turns(&vault, scope, &inside, usize::MAX)?
            .iter()
            .map(|turn| turn.turn_id)
            .collect::<Vec<_>>(),
        vec![same_second[2], later_second],
        "resumption is strictly after X || id — later ids at X come before later seconds"
    );

    let boundary = ConsolidationWatermark {
        schema_version: WATERMARK_SCHEMA_VERSION,
        last_learned_at: 900,
        last_turn_id: None,
    };
    assert_eq!(
        scan_dirty_turns(&vault, scope, &boundary, usize::MAX)?
            .iter()
            .map(|turn| turn.turn_id)
            .collect::<Vec<_>>(),
        vec![later_second],
        "the None sentinel puts EVERY key at that second behind the cursor"
    );
    Ok(())
}

#[test]
fn a_fence_window_below_the_live_watermark_collects_nothing() -> Result<()> {
    let (_dir, vault) = open_vault();
    let scope = DreamerConsolidationScope::Meso;
    let conversation = seed_session(&vault, 0x30, 1);
    let dirty = seed_turn(&vault, &conversation, "user", "dirty", 900);
    advance_watermark(&vault, scope, 800)?;

    let wtxn = vault.store.env.write_txn()?;
    assert!(
        collect_dirty_turn_ids_in_txn(&vault, &wtxn, scope, 700, 900)?.is_empty(),
        "a window whose lower second is not the live watermark enumerates nothing"
    );
    assert_eq!(
        collect_dirty_turn_ids_in_txn(&vault, &wtxn, scope, 800, 900)?,
        vec![dirty],
        "the matching window still enumerates the planned round"
    );
    wtxn.abort();
    Ok(())
}

#[test]
fn late_smaller_same_second_id_defers_the_existing_count_fence() -> Result<()> {
    let (_dir, vault) = open_vault();
    let scope = DreamerConsolidationScope::Meso;
    let conversation = seed_session(&vault, 0x32, 1);
    let planned = seed_ordered_turns_at(&vault, &conversation, 0x46, 900, 4);
    let session = minted(vault.mint_session(1_000)?);

    let wake = meso_wake(&vault);
    assert_eq!(wake.planned_turn_ids, planned, "the default-capped prefix");
    assert_eq!(wake.advance_watermark_to, Some(900));

    // A same-second admissible TURN whose id sorts INTO the planned prefix.
    let late = seed_ordered_turns_at(&vault, &conversation, 0x45, 900, 1)[0];
    assert!(late.as_bytes() < planned[0].as_bytes());
    vault
        .end_session_with_wake(&session, SessionClosePredicate::Explicit, 1_100, &wake)?
        .expect("the close itself still commits");

    assert_eq!(
        meso_partition_attempt_count(&vault),
        0,
        "a moved dirty snapshot enqueues none of the stale round"
    );
    let watermark = read_watermark(&vault, scope)?;
    assert_eq!(watermark, ConsolidationWatermark::bootstrap());
    let dirty = scan_dirty_turns(&vault, scope, &watermark, usize::MAX)?;
    assert_eq!(
        dirty.first().map(|turn| turn.turn_id),
        Some(late),
        "the late turn leads the next round"
    );
    assert_eq!(dirty.len(), 5, "nothing was consumed by the deferred round");
    Ok(())
}

#[test]
fn same_second_round_two_settles_through_end_session_with_wake() -> Result<()> {
    const SECOND: u64 = 900;
    let (_dir, vault) = open_vault();
    let scope = DreamerConsolidationScope::Meso;
    let conversation = seed_session(&vault, 0x33, 1);
    // cap < N <= 2 * cap, all inside ONE second, one partition.
    let total = DEFAULT_MESO_ROUND_TURN_CAP + DEFAULT_MESO_ROUND_TURN_CAP / 2;
    let seeded = seed_ordered_turns_at(
        &vault,
        &conversation,
        0x47,
        SECOND,
        u32::try_from(total).expect("backlog fits"),
    );

    // Round 1 consumes exactly the cap and settles INSIDE the second.
    let first = minted(vault.mint_session(1_000)?);
    let wake = meso_wake(&vault);
    assert_eq!(wake.plans.len(), 1, "one conversation, one partition");
    assert_eq!(
        wake.planned_turn_ids,
        seeded[..DEFAULT_MESO_ROUND_TURN_CAP],
        "round 1 is the capped prefix"
    );
    vault
        .end_session_with_wake(&first, SessionClosePredicate::Explicit, 1_100, &wake)?
        .expect("first close");
    assert_eq!(meso_partition_attempt_count(&vault), 1);
    let settled = read_watermark(&vault, scope)?;
    assert_eq!(
        settled,
        ConsolidationWatermark {
            schema_version: WATERMARK_SCHEMA_VERSION,
            last_learned_at: SECOND,
            last_turn_id: Some(seeded[DEFAULT_MESO_ROUND_TURN_CAP - 1]),
        },
        "the stored row is the exact within-second position"
    );

    // Round 2 drains the remainder of the SAME second (lower == upper).
    let second = minted(vault.mint_session(2_000)?);
    let wake = meso_wake(&vault);
    assert_eq!(
        wake.planned_turn_ids,
        seeded[DEFAULT_MESO_ROUND_TURN_CAP..],
        "round 2 is the rest of the second"
    );
    assert_eq!(wake.planned_watermark, SECOND);
    assert_eq!(wake.advance_watermark_to, Some(SECOND));
    vault
        .end_session_with_wake(&second, SessionClosePredicate::Explicit, 2_100, &wake)?
        .expect("second close");
    assert_eq!(meso_partition_attempt_count(&vault), 2);
    assert_eq!(
        read_watermark(&vault, scope)?,
        ConsolidationWatermark {
            schema_version: WATERMARK_SCHEMA_VERSION,
            last_learned_at: SECOND,
            last_turn_id: Some(seeded[total - 1]),
        }
    );

    // A third close has nothing left to plan.
    let third = minted(vault.mint_session(3_000)?);
    let wake = meso_wake(&vault);
    assert!(wake.plans.is_empty());
    vault
        .end_session_with_wake(&third, SessionClosePredicate::Explicit, 3_100, &wake)?
        .expect("third close");
    assert_eq!(meso_partition_attempt_count(&vault), 2);
    Ok(())
}

#[test]
fn empty_matched_round_still_commits_close() -> Result<()> {
    let (_dir, vault) = open_vault();
    let scope = DreamerConsolidationScope::Meso;
    let session = minted(vault.mint_session(1_000)?);

    // Planned an empty round through second 900: the fence matches empty
    // against empty and the settlement takes the complete-second position.
    let wake = SessionEndWake {
        plans: Vec::new(),
        planned_watermark: 0,
        planned_turn_ids: Vec::new(),
        advance_watermark_to: Some(900),
    };
    vault
        .end_session_with_wake(&session, SessionClosePredicate::Explicit, 1_100, &wake)?
        .expect("the close commits");
    assert_eq!(vault.open_session()?, None);
    assert_eq!(meso_partition_attempt_count(&vault), 0);
    assert_eq!(
        read_watermark(&vault, scope)?,
        ConsolidationWatermark {
            schema_version: WATERMARK_SCHEMA_VERSION,
            last_learned_at: 900,
            last_turn_id: None,
        }
    );
    Ok(())
}

#[test]
fn same_second_partition_batches_have_distinct_advisory_dedupe() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let scope = DreamerConsolidationScope::Meso;
    let conversation = seed_session(&vault, 0x34, 1);
    seed_ordered_turns_at(&vault, &conversation, 0x48, 900, 6);

    // Two adjacent capped batches inside ONE second, same partition.
    let watermark = read_watermark(&vault, scope)?;
    let first_turns = scan_dirty_turns(&vault, scope, &watermark, 3)?;
    let first = plan_partitions(&vault, scope, &first_turns, &watermark)?;
    assert!(matches!(
        enqueue_partition_attempts(&store, scope, &first, "run-1", 20)?[0],
        EnqueueDreamerAttemptOutcome::Enqueued(_)
    ));
    advance_watermark_to_turn(&vault, scope, first_turns.last().expect("batch 1"))?;

    let watermark = read_watermark(&vault, scope)?;
    let second_turns = scan_dirty_turns(&vault, scope, &watermark, 3)?;
    let second = plan_partitions(&vault, scope, &second_turns, &watermark)?;
    assert_eq!(
        first[0].key, second[0].key,
        "same partition, same second — only the batch differs"
    );
    assert_ne!(
        partition_round_hash(&first[0].turns),
        partition_round_hash(&second[0].turns),
        "two disjoint same-second batches never share an advisory key"
    );
    assert!(matches!(
        enqueue_partition_attempts(&store, scope, &second, "run-1", 21)?[0],
        EnqueueDreamerAttemptOutcome::Enqueued(_)
    ));

    // Replaying either EXACT batch coalesces.
    for (batch, now) in [(&first, 22), (&second, 23)] {
        assert!(matches!(
            enqueue_partition_attempts(&store, scope, batch, "run-1", now)?[0],
            EnqueueDreamerAttemptOutcome::Existing(_)
        ));
    }

    // The persisted partition payload schema is untouched.
    let Value::Map(entries) = encode_partition_payload(&second[0]) else {
        panic!("partition payload must be a map");
    };
    assert_eq!(
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(KEY_SCHEMA_VERSION))
            .and_then(|(_, value)| value.as_u64()),
        Some(PARTITION_PAYLOAD_SCHEMA_VERSION),
        "the payload schema stays v1"
    );

    // ACCEPTED behavior: planners whose local turn sets differ (superset,
    // partial overlap) enqueue distinct advisory attempts. Re-consolidating
    // the overlap is best-effort cost — an attempt is identity, not a lock.
    let all = scan_dirty_turns(&vault, scope, &ConsolidationWatermark::bootstrap(), 6)?;
    let superset = vec![ConsolidationPartitionPlan {
        key: first[0].key,
        turns: all[..4].to_vec(),
        watermark_last_learned_at: 0,
    }];
    let overlap = vec![ConsolidationPartitionPlan {
        key: first[0].key,
        turns: all[2..5].to_vec(),
        watermark_last_learned_at: 0,
    }];
    let superset_hash = partition_round_hash(&superset[0].turns);
    let overlap_hash = partition_round_hash(&overlap[0].turns);
    assert_ne!(superset_hash, partition_round_hash(&first[0].turns));
    assert_ne!(superset_hash, overlap_hash);
    assert!(matches!(
        enqueue_partition_attempts(&store, scope, &superset, "run-2", 24)?[0],
        EnqueueDreamerAttemptOutcome::Enqueued(_)
    ));
    assert!(matches!(
        enqueue_partition_attempts(&store, scope, &overlap, "run-2", 25)?[0],
        EnqueueDreamerAttemptOutcome::Enqueued(_)
    ));
    Ok(())
}

#[test]
fn partition_round_hash_conformance() {
    assert_eq!(
        DREAMER_PARTITION_ROUND_HASH_DOMAIN, b"oneiron:dreamer-partition-round:v1",
        "the advisory round-hash domain is pinned"
    );

    let batch = vec![
        WorkingSetTurn {
            turn_id: ordered_turn_id(0x49, 1),
            role: DreamerTurnRole::User,
            learned_at: 900,
            conversation: None,
        },
        WorkingSetTurn {
            turn_id: ordered_turn_id(0x49, 2),
            role: DreamerTurnRole::Assistant,
            learned_at: 900,
            conversation: None,
        },
    ];
    // Pinned known-answer vector: any domain or preimage edit fails here.
    assert_eq!(
        bytes_to_hex_lower(&partition_round_hash(&batch)),
        "9e15aee7540f9590095547cce43459fadadff5579012c975e6885039d9d3921e",
        "partition round hash known-answer vector"
    );

    // Count, order, timestamp, and id all move the hash.
    let base = partition_round_hash(&batch);
    assert_ne!(base, partition_round_hash(&batch[..1]));
    let mut reordered = batch.clone();
    reordered.swap(0, 1);
    assert_ne!(base, partition_round_hash(&reordered));
    let mut retimed = batch.clone();
    retimed[1].learned_at = 901;
    assert_ne!(base, partition_round_hash(&retimed));
    let mut reidentified = batch.clone();
    reidentified[1].turn_id = ordered_turn_id(0x49, 3);
    assert_ne!(base, partition_round_hash(&reidentified));
    // The GATE-10 role is provenance, not batch identity.
    let mut rerolled = batch;
    rerolled[1].role = DreamerTurnRole::User;
    assert_eq!(base, partition_round_hash(&rerolled));
}

#[test]
fn redirtied_turn_reenters_scan() -> Result<()> {
    let (_dir, vault) = open_vault();
    let scope = DreamerConsolidationScope::Meso;
    let conversation = seed_session(&vault, 0x35, 1);
    let turn = seed_turn(&vault, &conversation, "user", "first pass", 900);

    let watermark = read_watermark(&vault, scope)?;
    let consumed = scan_dirty_turns(&vault, scope, &watermark, usize::MAX)?;
    assert_eq!(consumed.len(), 1);
    advance_watermark_to_turn(&vault, scope, &consumed[0])?;
    let watermark = read_watermark(&vault, scope)?;
    assert!(scan_dirty_turns(&vault, scope, &watermark, usize::MAX)?.is_empty());

    // ONE-1767's re-dirty, simulated directly: the SAME id and body take a
    // NEW `learned_at` AHEAD of the cursor.
    vault
        .batch()
        .put(
            &turn,
            ENTITY_TYPE_TURN,
            occurred(950),
            950,
            &turn_body("user", "first pass, amended", None),
        )
        .commit()?;

    let redirtied = scan_dirty_turns(&vault, scope, &watermark, usize::MAX)?;
    assert_eq!(
        redirtied
            .iter()
            .map(|entry| (entry.turn_id, entry.learned_at))
            .collect::<Vec<_>>(),
        vec![(turn, 950)],
        "the later temporal key is selected again"
    );
    Ok(())
}

#[test]
fn bucket_hash_conformance() {
    let subject = EntityId::from_bytes([0x22; 16]).expect("subject");
    let key = ConsolidationBucketKey {
        subject,
        predicate_root: "profile".to_owned(),
        world: None,
        facet: None,
    };
    // Pinned known-answer vector for the domain-separated hash.
    assert_eq!(
        bytes_to_hex_lower(&key.bucket_hash()),
        "c096c3dfc3c02e94daa1347a58a7686939930e2e113f4507992f2452ab29d0a7",
        "bucket hash known-answer vector"
    );

    // Identical content hashes identically regardless of construction path.
    let rebuilt = ConsolidationBucketKey {
        facet: None,
        world: None,
        predicate_root: String::from("profile"),
        subject,
    };
    assert_eq!(key.bucket_hash(), rebuilt.bucket_hash());

    // Any field change moves the hash; partition hashes never collide with
    // bucket hashes even over the same leading bytes.
    let mut other = key.clone();
    other.predicate_root = "preference".to_owned();
    assert_ne!(key.bucket_hash(), other.bucket_hash());
    let partition = ConsolidationPartitionKey {
        conversation_ref: subject,
        world_ref: None,
        facet_ref: None,
    };
    assert_ne!(key.bucket_hash(), partition.partition_hash());
}

#[test]
fn facet_locality_zero_conflicts() -> Result<()> {
    let subject = EntityId::from_bytes([0x31; 16]).expect("subject");
    let facet_a = EntityId::from_bytes([0x41; 16]).expect("facet a");
    let facet_b = EntityId::from_bytes([0x62; 16]).expect("facet b");

    // Same subject + FULL predicate, non-equal values, DIFFERENT facets:
    // work-me and RP-me are both true — zero conflicts.
    let candidates = vec![
        candidate(subject, "profile.tone", "formal", Some(facet_a)),
        candidate(subject, "profile.tone", "playful", Some(facet_b)),
    ];
    assert!(detect_conflicts(&candidates, &[])?.is_empty());

    // Positive control: same facet + non-equal values IS a conflict.
    let clashing = vec![
        candidate(subject, "profile.tone", "formal", Some(facet_a)),
        candidate(subject, "profile.tone", "playful", Some(facet_a)),
    ];
    let conflicts = detect_conflicts(&clashing, &[])?;
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].candidate_indexes, vec![0, 1]);

    // Root-granularity false-conflict guard: different LEAVES never clash.
    let disjoint = vec![
        candidate(subject, "profile.name", "Oleksii", None),
        candidate(subject, "profile.lives_in", "Tokyo", None),
    ];
    assert!(detect_conflicts(&disjoint, &[])?.is_empty());
    Ok(())
}

#[test]
fn null_shadow_non_conflict() -> Result<()> {
    let subject = EntityId::from_bytes([0x32; 16]).expect("subject");
    let facet = EntityId::from_bytes([0x43; 16]).expect("facet");

    // Null-facet is the invariant layer; a facet claim shadows it within
    // that facet — non-equal values are NOT a conflict.
    let candidates = vec![
        candidate(subject, "profile.tone", "neutral", None),
        candidate(subject, "profile.tone", "playful", Some(facet)),
    ];
    assert!(detect_conflicts(&candidates, &[])?.is_empty());
    Ok(())
}

#[test]
fn reducer_consumes_only_consolidatable() -> Result<()> {
    let subject = EntityId::from_bytes([0x33; 16]).expect("subject");
    let candidates = vec![candidate(subject, "profile.tone", "formal", None)];

    // Auto+generated-origin prior: NOT consolidatable — never a conflict
    // source and never corroboration.
    let auto_generated = prior_head(
        subject,
        "profile.tone",
        "playful",
        ClaimApprovalStatus::Auto,
        ClaimSource::Generated,
    );
    assert!(detect_conflicts(&candidates, std::slice::from_ref(&auto_generated))?.is_empty());
    assert_eq!(
        corroboration_count(&CollapsedEvidence::default(), &[auto_generated]),
        0
    );

    // Approved+Generated prior: merge-eligible (a conflict source) but
    // contributes ZERO corroboration (GATE-11 divergence).
    let approved_generated = prior_head(
        subject,
        "profile.tone",
        "playful",
        ClaimApprovalStatus::Approved,
        ClaimSource::Generated,
    );
    let conflicts = detect_conflicts(&candidates, std::slice::from_ref(&approved_generated))?;
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].prior_head, Some(approved_generated.claim_id));
    assert_eq!(
        corroboration_count(&CollapsedEvidence::default(), &[approved_generated]),
        0
    );

    // A UserStated prior corroborates.
    let user_prior = prior_head(
        subject,
        "profile.tone",
        "formal",
        ClaimApprovalStatus::Approved,
        ClaimSource::UserStated,
    );
    assert_eq!(
        corroboration_count(&CollapsedEvidence::default(), &[user_prior]),
        1
    );
    Ok(())
}

#[test]
fn sibling_evidence_collapses() -> Result<()> {
    let source = EntityId::from_bytes([0x34; 16]).expect("source");
    let other = EntityId::from_bytes([0x35; 16]).expect("other");
    let shared = SwarmEvidenceRef {
        source_id: source,
        content_hash: [0x51; 32],
        trust_class: ClaimSource::UserStated,
    };
    let distinct = SwarmEvidenceRef {
        source_id: other,
        content_hash: [0x52; 32],
        trust_class: ClaimSource::UserStated,
    };

    let child = |refs: Vec<SwarmEvidenceRef>| SwarmChildReturn {
        evidence: refs.into_iter().collect(),
        candidates: Vec::new(),
        read_pin: 7,
    };

    // Two children citing the SAME source hash: one independent signal.
    let collapsed = collapse_sibling_evidence(&[child(vec![shared]), child(vec![shared])])?;
    assert_eq!(collapsed.independent.len(), 1);
    assert_eq!(collapsed.duplicates_collapsed, 1);

    // A genuinely distinct source adds a second signal.
    let collapsed =
        collapse_sibling_evidence(&[child(vec![shared]), child(vec![shared, distinct])])?;
    assert_eq!(collapsed.independent.len(), 2);
    Ok(())
}

#[test]
fn predicate_root_never_bucket_key_conflict_key_confusion() {
    // The BUCKET key uses the root; the CONFLICT key uses the full
    // predicate. Same root, different leaves must co-bucket.
    let subject = EntityId::from_bytes([0x36; 16]).expect("subject");
    let candidates = vec![
        candidate(subject, "profile.name", "Oleksii", None),
        candidate(subject, "profile.lives_in", "Tokyo", None),
    ];
    let buckets = plan_candidate_buckets(&candidates).expect("buckets");
    assert_eq!(buckets.len(), 1, "shared root co-buckets");
    assert_eq!(buckets[0].key.predicate_root, "profile");
    assert_eq!(buckets[0].candidate_indexes, vec![0, 1]);
}

struct ScriptedBackend {
    calls: AtomicUsize,
    script: Mutex<VecDeque<LlmResult<crate::LlmResponse>>>,
}

impl ScriptedBackend {
    fn new(script: Vec<LlmResult<crate::LlmResponse>>) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            script: Mutex::new(script.into_iter().collect()),
        }
    }
}

impl LlmBackend for ScriptedBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let next = self
            .script
            .lock()
            .expect("script mutex")
            .pop_front()
            .expect("scripted backend exhausted");
        Box::pin(async move { next })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(crate::LlmError::Fatal(crate::FatalLlmError::InvalidRequest))
    }
}

fn extraction_response(subject: &EntityId, turn: &EntityId) -> crate::LlmResponse {
    let json = format!(
        "{{\"candidates\": [{{\"subject\": \"{}\", \"predicate\": \"profile.name\", \
         \"value\": \"Oleksii\", \"confidence\": 0.8, \"evidence_turn_refs\": [\"{}\"]}}]}}",
        bytes_to_hex_lower(subject.as_bytes()),
        bytes_to_hex_lower(turn.as_bytes()),
    );
    crate::LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text { text: json }],
        },
        usage: LlmUsage {
            input: LlmInputUsage {
                total: 90,
                cache_read: 0,
                cache_write: 0,
            },
            output: LlmOutputUsage {
                total: 30,
                text: 30,
                reasoning: 0,
            },
            raw_provider: serde_json::Value::Null,
        },
        finish_reason: FinishReason::Stop,
    }
}

#[derive(Default)]
struct CapturingSink {
    accepted: Vec<PromotionCandidate>,
}

impl ConsolidationSink for CapturingSink {
    fn accept(&mut self, candidates: Vec<PromotionCandidate>) -> Result<()> {
        self.accepted.extend(candidates);
        Ok(())
    }
}

#[test]
fn no_fabricated_belief_writes() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let scope = DreamerConsolidationScope::Micro;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;
    let conversation = seed_session(&vault, 0x27, 1);
    let turn = seed_turn(&vault, &conversation, "user", "my name is Oleksii", 10);
    let actor = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(1), 1, b"agent")?;

    let watermark = read_watermark(&vault, scope)?;
    let turns = scan_dirty_turns(&vault, scope, &watermark, 10)?;
    let plans = plan_partitions(&vault, scope, &turns, &watermark)?;
    enqueue_partition_attempts(&store, scope, &plans, "run-1", 20)?;

    let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
        admitted,
    )) = store.admit_next_consolidation(AdmitDreamerConsolidationAttempt {
        scope,
        local_node_id: node_id,
        claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
        claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
        admission: AdmitDreamerAttempt {
            lease_owner: "consolidation-test".to_owned(),
            now: 21,
            budget_id: "wake".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 100,
            started_milestone: None,
        },
    })?
    else {
        panic!("expected admitted consolidation attempt");
    };

    let subject = EntityId::from_bytes([0x37; 16]).expect("subject");
    let backend = ScriptedBackend::new(vec![Ok(extraction_response(&subject, &turn))]);
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut sink = CapturingSink::default();
    let mut executor = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: WriteActor::new(actor, EdgeActorClass::Agent),
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink: &mut sink,
    };
    let mut ctx = WakeAttemptContext {
        vault: &vault,
        deadline: &deadline,
        budget_id: "wake",
        now_ms: 21_000,
    };
    let execution = block_on_ready(executor.execute(&admitted, &mut ctx))?;
    assert!(matches!(
        execution,
        DreamerAttemptExecution::Completed {
            completed_units: 120
        }
    ));

    // The sink received the decoded candidates…
    assert_eq!(sink.accepted.len(), 1);
    assert_eq!(sink.accepted[0].evidence_turn_refs, vec![turn]);

    // …and the module wrote ZERO belief claims itself: the only claims in
    // the store are the step layer's dreamer.step runtime records.
    let predicates = claim_predicates_in_store(&vault)?;
    assert!(
        predicates
            .iter()
            .all(|predicate| predicate == "dreamer.step"),
        "unexpected claim predicates: {predicates:?}"
    );
    Ok(())
}

#[test]
fn gap_dedupe_and_decay() -> Result<()> {
    let (_dir, vault) = open_vault();
    let conversation = seed_session(&vault, 0x28, 1);
    let turn = seed_turn(&vault, &conversation, "user", "i will call mom?", 10);
    let gap = ReflectionGap {
        kind: ReflectionGapKind::UnresolvedThread,
        subject: conversation,
        evidence_turn_refs: vec![turn],
        first_seen: 0,
        last_seen: 0,
        escalations: 0,
        decayed: false,
    };

    // First observation: created + the ONE per-lifetime escalation.
    let delta = upsert_gap_queue(&vault, vec![gap.clone()], 1_000)?;
    assert_eq!(delta.created, 1);
    assert_eq!(delta.escalations.len(), 1);
    assert_eq!(delta.escalations[0].escalations, 1);

    // Re-observation refreshes last_seen and NEVER re-escalates.
    let delta = upsert_gap_queue(&vault, vec![gap.clone()], 2_000)?;
    assert_eq!(delta.created, 0);
    assert_eq!(delta.refreshed, 1);
    assert!(delta.escalations.is_empty(), "escalate once per lifetime");

    // Not re-observed past the decay window: decays.
    let decay_at = 2_000 + DREAMER_GAP_DECAY_MS;
    let delta = upsert_gap_queue(&vault, Vec::new(), decay_at)?;
    assert_eq!(delta.decayed, 1);

    // A decayed gap is let go: re-observing neither refreshes nor
    // escalates nor re-creates.
    let delta = upsert_gap_queue(&vault, vec![gap], decay_at + 1_000)?;
    assert_eq!(delta.created, 0);
    assert_eq!(delta.refreshed, 0);
    assert!(
        delta.escalations.is_empty(),
        "decayed gaps never re-surface"
    );
    Ok(())
}

#[test]
fn gap_detectors_v1_taxonomy() -> Result<()> {
    let (_dir, vault) = open_vault();
    let conversation = seed_session(&vault, 0x29, 1);
    let question = seed_turn(&vault, &conversation, "user", "should i email him?", 10);
    let intent = seed_turn(
        &vault,
        &conversation,
        "user",
        "i will email him tomorrow",
        11,
    );

    let scope = DreamerConsolidationScope::Meso;
    let watermark = ConsolidationWatermark::bootstrap();
    let working_set = scan_dirty_turns(&vault, scope, &watermark, 10)?;
    let gaps = scan_reflection_gaps(&vault, &working_set, 1_000)?;

    let kinds: Vec<ReflectionGapKind> = gaps.iter().map(|gap| gap.kind).collect();
    assert!(kinds.contains(&ReflectionGapKind::UnresolvedThread));
    assert!(kinds.contains(&ReflectionGapKind::MissingFollowUp));
    assert!(kinds.contains(&ReflectionGapKind::StatedIntentWithoutAction));
    let question_gap = gaps
        .iter()
        .find(|gap| gap.kind == ReflectionGapKind::MissingFollowUp)
        .expect("question gap");
    assert_eq!(question_gap.evidence_turn_refs, vec![question]);
    let intent_gap = gaps
        .iter()
        .find(|gap| gap.kind == ReflectionGapKind::StatedIntentWithoutAction)
        .expect("intent gap");
    assert_eq!(intent_gap.evidence_turn_refs, vec![intent]);
    Ok(())
}

#[test]
fn key_reordered_objects_are_not_a_conflict() -> Result<()> {
    let subject = EntityId::from_bytes([0x40; 16]).expect("subject");
    // Same object, keys reordered at BOTH the top level and inside the nested
    // map (serde_json preserve_order carries the LLM key order verbatim into
    // Value::Map). Canonical bytes must ignore key order (#485-4).
    let value_ab = Value::Map(vec![
        (
            Value::from("geo"),
            Value::Map(vec![
                (Value::from("lat"), Value::from(1_u64)),
                (Value::from("lon"), Value::from(2_u64)),
            ]),
        ),
        (Value::from("city"), Value::from("Tokyo")),
    ]);
    let value_ba = Value::Map(vec![
        (Value::from("city"), Value::from("Tokyo")),
        (
            Value::from("geo"),
            Value::Map(vec![
                (Value::from("lon"), Value::from(2_u64)),
                (Value::from("lat"), Value::from(1_u64)),
            ]),
        ),
    ]);
    let candidates = vec![
        map_candidate(subject, "profile.location", value_ab),
        map_candidate(subject, "profile.location", value_ba),
    ];
    assert!(
        detect_conflicts(&candidates, &[])?.is_empty(),
        "key-reordered identical objects must not be a conflict"
    );

    // Sanity: a genuinely different value still conflicts.
    let clashing = vec![
        map_candidate(
            subject,
            "profile.location",
            Value::Map(vec![(Value::from("city"), Value::from("Tokyo"))]),
        ),
        map_candidate(
            subject,
            "profile.location",
            Value::Map(vec![(Value::from("city"), Value::from("Osaka"))]),
        ),
    ];
    assert_eq!(
        detect_conflicts(&clashing, &[])?.len(),
        1,
        "distinct object values must still conflict"
    );
    Ok(())
}

fn two_candidate_extraction(
    subject: &EntityId,
    turn_a: &EntityId,
    turn_b: &EntityId,
) -> crate::LlmResponse {
    let json = format!(
        "{{\"candidates\": [\
         {{\"subject\": \"{s}\", \"predicate\": \"profile.name\", \"value\": \"Oleksii\", \
          \"confidence\": 0.8, \"evidence_turn_refs\": [\"{a}\"]}},\
         {{\"subject\": \"{s}\", \"predicate\": \"profile.name\", \"value\": \"Alex\", \
          \"confidence\": 0.6, \"evidence_turn_refs\": [\"{b}\"]}}]}}",
        s = bytes_to_hex_lower(subject.as_bytes()),
        a = bytes_to_hex_lower(turn_a.as_bytes()),
        b = bytes_to_hex_lower(turn_b.as_bytes()),
    );
    text_response(json)
}

fn text_response(json: String) -> crate::LlmResponse {
    crate::LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text { text: json }],
        },
        usage: LlmUsage {
            input: LlmInputUsage {
                total: 40,
                cache_read: 0,
                cache_write: 0,
            },
            output: LlmOutputUsage {
                total: 10,
                text: 10,
                reasoning: 0,
            },
            raw_provider: serde_json::Value::Null,
        },
        finish_reason: FinishReason::Stop,
    }
}

fn admitted_attempt_fixture<'a>(
    vault: &'a Vault,
    store: &DreamerRunnerStore<'a>,
    session_seed: u8,
    texts: &[(&str, &str)],
) -> Result<(
    crate::dreamer_runner::DreamerAdmittedAttempt,
    Vec<EntityId>,
    EntityId,
)> {
    let scope = DreamerConsolidationScope::Micro;
    let node_id = crate::identity::load_or_mint_client_id(vault)?;
    let conversation = seed_session(vault, session_seed, 1);
    let mut turns = Vec::new();
    for (index, (speaker, text)) in texts.iter().enumerate() {
        turns.push(seed_turn(
            vault,
            &conversation,
            speaker,
            text,
            10 + index as u64,
        ));
    }
    let watermark = read_watermark(vault, scope)?;
    let dirty = scan_dirty_turns(vault, scope, &watermark, 10)?;
    let plans = plan_partitions(vault, scope, &dirty, &watermark)?;
    enqueue_partition_attempts(store, scope, &plans, "run-1", 20)?;
    let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
        admitted,
    )) = store.admit_next_consolidation(AdmitDreamerConsolidationAttempt {
        scope,
        local_node_id: node_id,
        claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
        claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
        admission: AdmitDreamerAttempt {
            lease_owner: "consolidation-test".to_owned(),
            now: 21,
            budget_id: "wake".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 100,
            started_milestone: None,
        },
    })?
    else {
        panic!("expected admitted consolidation attempt");
    };
    Ok((*admitted, turns, conversation))
}

#[test]
fn conflicting_sets_enter_scoped_merge() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (admitted, turns, _) = admitted_attempt_fixture(
        &vault,
        &store,
        0x2A,
        &[("user", "call me Oleksii"), ("user", "or Alex")],
    )?;
    let actor = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(1), 1, b"agent")?;
    let subject = EntityId::from_bytes([0x38; 16]).expect("subject");
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;

    let backend = ScriptedBackend::new(vec![
        Ok(two_candidate_extraction(&subject, &turns[0], &turns[1])),
        Ok(text_response(
            "{\"resolution\": \"merge\", \"value\": \"Oleksii (Alex)\"}".to_owned(),
        )),
    ]);
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut sink = CapturingSink::default();
    let mut executor = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: WriteActor::new(actor, EdgeActorClass::Agent),
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink: &mut sink,
    };
    let mut ctx = WakeAttemptContext {
        vault: &vault,
        deadline: &deadline,
        budget_id: "wake",
        now_ms: 21_000,
    };
    block_on_ready(executor.execute(&admitted, &mut ctx))?;

    // The conflicting pair collapsed into ONE merged candidate carrying the
    // union of the evidence refs.
    assert_eq!(sink.accepted.len(), 1);
    assert_eq!(sink.accepted[0].evidence_turn_refs, turns);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 2, "one merge step");
    Ok(())
}

#[test]
fn escalated_conflicts_route_to_gap_queue() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (admitted, turns, _) = admitted_attempt_fixture(
        &vault,
        &store,
        0x2B,
        &[("user", "i live in Tokyo"), ("user", "i live in Osaka")],
    )?;
    let actor = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(1), 1, b"agent")?;
    let subject = EntityId::from_bytes([0x39; 16]).expect("subject");
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;

    let backend = ScriptedBackend::new(vec![
        Ok(two_candidate_extraction(&subject, &turns[0], &turns[1])),
        Ok(text_response("{\"resolution\": \"escalate\"}".to_owned())),
    ]);
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut sink = CapturingSink::default();
    let mut executor = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: WriteActor::new(actor, EdgeActorClass::Agent),
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink: &mut sink,
    };
    let mut ctx = WakeAttemptContext {
        vault: &vault,
        deadline: &deadline,
        budget_id: "wake",
        now_ms: 21_000,
    };
    block_on_ready(executor.execute(&admitted, &mut ctx))?;

    // Contradictions never land silently: nothing sinks, the gap row exists
    // (a re-upsert of the same identity refreshes rather than creates).
    assert!(sink.accepted.is_empty());
    let probe = ReflectionGap {
        kind: ReflectionGapKind::ContradictionLeftStanding,
        subject,
        evidence_turn_refs: turns,
        first_seen: 0,
        last_seen: 0,
        escalations: 0,
        decayed: false,
    };
    let delta = upsert_gap_queue(&vault, vec![probe], 22_000)?;
    assert_eq!(delta.refreshed, 1, "escalation created the gap row");
    assert_eq!(delta.created, 0);
    Ok(())
}

#[test]
fn child_returns_hash_only() -> Result<()> {
    let (_dir, vault) = open_vault();
    let conversation = seed_session(&vault, 0x2C, 1);
    let secret_text = "SECRET-SOURCE-CONTENT-the-user-is-afraid-of-clowns".repeat(50);
    let turn = seed_turn(&vault, &conversation, "user", &secret_text, 10);

    // The child that "read" this large source returns hashes only.
    let raw = vault.get_raw(&turn)?.expect("turn raw");
    let content_hash =
        swarm_evidence_content_hash(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]);
    let child = SwarmChildReturn {
        evidence: [SwarmEvidenceRef {
            source_id: turn,
            content_hash,
            trust_class: ClaimSource::UserStated,
        }]
        .into_iter()
        .collect(),
        candidates: Vec::new(),
        read_pin: 10,
    };

    // Type-level: no field can carry source bytes; and the serialized
    // return of a child that read a large source contains none of it.
    let serialized = format!("{child:?}");
    assert!(
        !serialized.contains("SECRET-SOURCE-CONTENT"),
        "no source body bytes may appear in a child return"
    );
    assert!(
        !serialized.contains("clowns"),
        "no source body bytes may appear in a child return"
    );
    Ok(())
}

#[test]
fn sibling_collapse_on_shared_hash() -> Result<()> {
    let source = EntityId::from_bytes([0x3A; 16]).expect("source");
    let make = |trust_class| SwarmEvidenceRef {
        source_id: source,
        content_hash: [0x61; 32],
        trust_class,
    };
    let child = |entry: SwarmEvidenceRef| SwarmChildReturn {
        evidence: [entry].into_iter().collect(),
        candidates: Vec::new(),
        read_pin: 1,
    };

    let collapsed = collapse_sibling_evidence(&[
        child(make(ClaimSource::UserStated)),
        child(make(ClaimSource::Imported)),
    ])?;
    assert_eq!(collapsed.independent.len(), 1);
    assert_eq!(collapsed.duplicates_collapsed, 1);
    // Trust ties on one identity resolve to the MOST restrictive class.
    assert_eq!(collapsed.independent[0].trust_class, ClaimSource::Imported);
    Ok(())
}

#[test]
fn intra_child_trust_tie_resolves_to_most_restrictive() {
    // A SINGLE child listing the same (source_id, content_hash) at two
    // different trust classes must not silently drop the stricter one: the
    // evidence container is a Vec precisely so BOTH refs reach the collapse
    // meet. A BTreeSet keyed on identity would keep only the first-inserted
    // entry, letting a child inflate trust by listing the higher class first.
    let source = EntityId::from_bytes([0x3C; 16]).expect("source");
    let make = |trust_class| SwarmEvidenceRef {
        source_id: source,
        content_hash: [0x63; 32],
        trust_class,
    };
    // Higher trust listed FIRST — the drop-the-stricter bug would keep it.
    let child = SwarmChildReturn {
        evidence: vec![make(ClaimSource::UserStated), make(ClaimSource::Imported)],
        candidates: Vec::new(),
        read_pin: 1,
    };
    let collapsed = collapse_sibling_evidence(&[child]).expect("collapse");
    assert_eq!(collapsed.independent.len(), 1);
    assert_eq!(collapsed.duplicates_collapsed, 1);
    assert_eq!(
        collapsed.independent[0].trust_class,
        ClaimSource::Imported,
        "intra-child trust tie must resolve to the most restrictive class"
    );
}

#[test]
fn most_restrictive_trust() {
    let entry = |trust_class| SwarmEvidenceRef {
        source_id: EntityId::from_bytes([0x3B; 16]).expect("id"),
        content_hash: [0x62; 32],
        trust_class,
    };

    let set = [entry(ClaimSource::UserStated), entry(ClaimSource::Imported)];
    assert_eq!(evidence_trust_meet(set.iter()), ClaimSource::Imported);

    let set = [entry(ClaimSource::Observed), entry(ClaimSource::Generated)];
    assert_eq!(evidence_trust_meet(set.iter()), ClaimSource::Generated);

    // Empty iterator: the Dreamer's own floor.
    assert_eq!(evidence_trust_meet([].iter()), ClaimSource::Generated);

    // Inferred and Generated share one rank: their meet stays at that
    // rank (the fold seeds at the Generated floor, so equal-rank inputs
    // resolve to Generated).
    let set = [entry(ClaimSource::Inferred), entry(ClaimSource::Generated)];
    assert_eq!(evidence_trust_meet(set.iter()), ClaimSource::Generated);

    // A strictly higher class alone still cannot rise above the floor.
    let set = [entry(ClaimSource::UserStated)];
    assert_eq!(evidence_trust_meet(set.iter()), ClaimSource::Generated);
}

#[test]
fn ledger_revision_pin() {
    let child = SwarmChildReturn {
        evidence: Vec::new(),
        candidates: Vec::new(),
        read_pin: 41,
    };
    assert!(validate_child_read_pin(42, &child).is_err());
    let child = SwarmChildReturn {
        read_pin: 42,
        ..child
    };
    assert!(validate_child_read_pin(42, &child).is_ok());
}

#[test]
fn evidence_hash_conformance() -> Result<()> {
    // Pinned known-answer vector for the domain-separated hash.
    assert_eq!(DREAMER_EVIDENCE_HASH_DOMAIN, b"oneiron:dreamer-evidence:v1");
    assert_eq!(
        bytes_to_hex_lower(&swarm_evidence_content_hash(b"known-answer-input")),
        "88faa590a017dbc83e70a38f05245f0234342b191c904b4cabbdfc7882279e27",
        "evidence hash known-answer vector"
    );

    // The hash input is the header-stripped stored body: hashing the bytes
    // we wrote equals hashing raw[ENTITY_METADATA_HEADER_LEN..].
    let (_dir, vault) = open_vault();
    let conversation = seed_session(&vault, 0x2D, 1);
    let turn = seed_turn(&vault, &conversation, "user", "hash me", 10);
    let raw = vault.get_raw(&turn)?.expect("turn raw");
    let body = turn_body("user", "hash me", None);
    assert_eq!(
        swarm_evidence_content_hash(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]),
        swarm_evidence_content_hash(&body),
        "stored body bytes after the header are byte-identical to the put"
    );
    Ok(())
}

#[test]
fn tainted_claim_not_consolidatable_until_approved() {
    use crate::claim::{claim_consolidatable, claim_surfaceable};
    use ClaimApprovalStatus as A;

    let subject = ClaimSubject::Entity(EntityId::from_bytes([0x3C; 16]).expect("id"));
    let body = |appr: ClaimApprovalStatus, taint: Option<&str>| {
        let mut body = ClaimBody::new(
            "profile.tone",
            subject,
            Value::from("v"),
            0.5,
            appr,
            crate::claim::ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::Inferred);
        if let Some(taint) = taint {
            body.scope = Some(Value::Map(vec![(
                Value::from("evidence_taint"),
                Value::from(taint),
            )]));
        }
        body
    };

    // Auto + tool_output taint: surfaceable, NOT consolidatable.
    let tainted_auto = body(A::Auto, Some("tool_output"));
    assert!(claim_surfaceable(&tainted_auto));
    assert!(!claim_consolidatable(&tainted_auto));

    // Human re-stamp (Approved) clears admission; surfaceability unchanged.
    let tainted_approved = body(A::Approved, Some("tool_output"));
    assert!(claim_surfaceable(&tainted_approved));
    assert!(claim_consolidatable(&tainted_approved));

    // imported taint blocks the same way.
    assert!(!claim_consolidatable(&body(A::Auto, Some("imported"))));

    // A taint ABOVE tool_output does not block.
    assert!(claim_consolidatable(&body(A::Auto, Some("user_stated"))));

    // Unparseable taint marker fails closed (treated as lattice bottom).
    assert!(!claim_consolidatable(&body(A::Auto, Some("garbage-class"))));

    // Untainted control.
    assert!(claim_consolidatable(&body(A::Auto, None)));
}

#[test]
fn turn_trust_class_meet_space() {
    // Pinned table (DESIGN-PIN B1).
    assert_eq!(
        turn_trust_class(DreamerTurnRole::User, false),
        Some(ClaimSource::UserStated)
    );
    assert_eq!(
        turn_trust_class(DreamerTurnRole::Assistant, false),
        Some(ClaimSource::Generated),
        "assistant turns classify Generated, never Observed"
    );
    assert_eq!(
        turn_trust_class(DreamerTurnRole::User, true),
        Some(ClaimSource::Imported)
    );
    assert_eq!(
        turn_trust_class(DreamerTurnRole::Assistant, true),
        Some(ClaimSource::Imported)
    );
    for role in [
        DreamerTurnRole::System,
        DreamerTurnRole::Tool,
        DreamerTurnRole::Injected,
        DreamerTurnRole::Unknown,
    ] {
        assert_eq!(turn_trust_class(role, false), None);
        assert_eq!(turn_trust_class(role, true), None);
    }

    // The reachable working-set meet space is {UserStated, Generated,
    // Imported} — every classified turn maps into it, so every fold of
    // source_meet over it stays inside it.
    let reachable = [
        ClaimSource::UserStated,
        ClaimSource::Generated,
        ClaimSource::Imported,
    ];
    for left in reachable {
        for right in reachable {
            let entry = |trust_class| SwarmEvidenceRef {
                source_id: EntityId::from_bytes([0x3D; 16]).expect("id"),
                content_hash: [0x63; 32],
                trust_class,
            };
            let meet = evidence_trust_meet([entry(left), entry(right)].iter());
            assert!(
                reachable.contains(&meet),
                "{left:?} meet {right:?} = {meet:?}"
            );
        }
    }
}

#[test]
fn budget_trapped_extraction_parks_for_resume() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (admitted, _turns, _) = admitted_attempt_fixture(
        &vault,
        &store,
        0x2C,
        &[("user", "call me Oleksii"), ("user", "or Alex")],
    )?;
    let actor = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(1), 1, b"agent")?;

    // No script: admission is denied up-front, so generate is never called.
    let backend = ScriptedBackend::new(Vec::new());
    // reserve 100 > cap 50 → the extraction step is budget-exhausted, so the
    // step layer opens a budget trap, parks the attempt, and returns Trapped.
    let guard =
        crate::BudgetGuard::with_reserve_units("wake", 50, 100, BudgetExhaustionPolicy::Suspend);
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut sink = CapturingSink::default();
    let mut executor = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: WriteActor::new(actor, EdgeActorClass::Agent),
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink: &mut sink,
    };
    let mut ctx = WakeAttemptContext {
        vault: &vault,
        deadline: &deadline,
        budget_id: "wake",
        now_ms: 21_000,
    };

    let execution = block_on_ready(executor.execute(&admitted, &mut ctx))?;
    // A trapped attempt PARKS for resume; it must NOT complete-as-done (#485-1).
    assert!(
        matches!(execution, DreamerAttemptExecution::Park { .. }),
        "trapped extraction must park, got {execution:?}"
    );
    assert!(
        sink.accepted.is_empty(),
        "no candidates sink on a trapped attempt"
    );
    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        0,
        "admission denied before any generate"
    );
    // The step layer parked the attempt (resumable).
    assert!(
        store.parked_attempt(admitted.status.attempt.id)?.is_some(),
        "trapped attempt is parked for resume"
    );
    Ok(())
}

#[test]
fn budget_trapped_merge_parks_without_false_contradiction_gap() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (admitted, turns, _) = admitted_attempt_fixture(
        &vault,
        &store,
        0x2D,
        &[("user", "i live in Tokyo"), ("user", "i live in Osaka")],
    )?;
    let actor = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(1), 1, b"agent")?;
    let subject = EntityId::from_bytes([0x3B; 16]).expect("subject");
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;

    // Extraction succeeds with two conflicting values; the merge step is then
    // denied. reserve 100, limit 100: extraction admits (projected 100 ≤ 100)
    // and settles 50 used, so the merge admit projects 50 + 100 > 100 →
    // Exhausted → the step layer traps and parks mid-merge.
    let backend = ScriptedBackend::new(vec![Ok(two_candidate_extraction(
        &subject, &turns[0], &turns[1],
    ))]);
    let guard =
        crate::BudgetGuard::with_reserve_units("wake", 100, 100, BudgetExhaustionPolicy::Suspend);
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut sink = CapturingSink::default();
    let mut executor = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: WriteActor::new(actor, EdgeActorClass::Agent),
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink: &mut sink,
    };
    let mut ctx = WakeAttemptContext {
        vault: &vault,
        deadline: &deadline,
        budget_id: "wake",
        now_ms: 21_000,
    };

    let execution = block_on_ready(executor.execute(&admitted, &mut ctx))?;
    // Park, not Complete: the merge never decided (#485-1, #485-2).
    assert!(
        matches!(execution, DreamerAttemptExecution::Park { .. }),
        "merge-trapped attempt must park, got {execution:?}"
    );
    assert!(
        sink.accepted.is_empty(),
        "no partial survivors sink on a trapped merge"
    );
    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        1,
        "only the extraction step ran; the merge was denied at admission"
    );
    assert!(
        store.parked_attempt(admitted.status.attempt.id)?.is_some(),
        "trapped attempt is parked for resume"
    );

    // No FALSE ContradictionLeftStanding gap was written: a fresh upsert of the
    // contradiction identity CREATES the row. A pre-existing false gap would
    // make this a refresh instead (#485-2).
    let probe = ReflectionGap {
        kind: ReflectionGapKind::ContradictionLeftStanding,
        subject,
        evidence_turn_refs: turns,
        first_seen: 0,
        last_seen: 0,
        escalations: 0,
        decayed: false,
    };
    let delta = upsert_gap_queue(&vault, vec![probe], 22_000)?;
    assert_eq!(delta.created, 1, "no false contradiction gap pre-existed");
    assert_eq!(delta.refreshed, 0);
    Ok(())
}

#[test]
fn re_executed_step_mints_same_claim_id() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (admitted, turns, _) =
        admitted_attempt_fixture(&vault, &store, 0x2E, &[("user", "my name is Oleksii")])?;
    let actor = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(1), 1, b"agent")?;
    let subject = EntityId::from_bytes([0x37; 16]).expect("subject");
    let backend = ScriptedBackend::new(vec![Ok(extraction_response(&subject, &turns[0]))]);
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));

    let run = |now_ms: u64| -> Result<Vec<EntityId>> {
        let mut sink = CapturingSink::default();
        let mut executor = ConsolidationExecutor {
            backend: &backend,
            guard: &guard,
            strategy: DreamerClaimAuthoringStrategy::SinglePass,
            actor: WriteActor::new(actor, EdgeActorClass::Agent),
            model: crate::ModelId::new("test/model@r1").expect("model"),
            sink: &mut sink,
        };
        let mut ctx = WakeAttemptContext {
            vault: &vault,
            deadline: &deadline,
            budget_id: "wake",
            now_ms,
        };
        block_on_ready(executor.execute(&admitted, &mut ctx))?;
        Ok(sink
            .accepted
            .iter()
            .map(|candidate| candidate.claim_id)
            .collect())
    };

    let ids_first = run(21_000)?;
    // At-least-once re-execution at a DIFFERENT wall clock: the extraction step
    // memo-hits (backend never called again) and the candidate id must be
    // identical — proving it is content-addressed, not EntityId::now() (#485-3).
    let ids_second = run(987_000)?;

    assert_eq!(ids_first.len(), 1, "one extracted candidate");
    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        1,
        "the re-run memo-hit; no second generate"
    );
    assert_eq!(
        ids_first, ids_second,
        "re-running the same durable step mints the SAME write-once claim id"
    );
    Ok(())
}

#[test]
fn re_executed_merge_mints_same_claim_id() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (admitted, turns, _) = admitted_attempt_fixture(
        &vault,
        &store,
        0x2F,
        &[("user", "call me Oleksii"), ("user", "or Alex")],
    )?;
    let actor = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(1), 1, b"agent")?;
    let subject = EntityId::from_bytes([0x38; 16]).expect("subject");
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    let backend = ScriptedBackend::new(vec![
        Ok(two_candidate_extraction(&subject, &turns[0], &turns[1])),
        Ok(text_response(
            "{\"resolution\": \"merge\", \"value\": \"Oleksii (Alex)\"}".to_owned(),
        )),
    ]);
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));

    let run = |now_ms: u64| -> Result<Vec<EntityId>> {
        let mut sink = CapturingSink::default();
        let mut executor = ConsolidationExecutor {
            backend: &backend,
            guard: &guard,
            strategy: DreamerClaimAuthoringStrategy::SinglePass,
            actor: WriteActor::new(actor, EdgeActorClass::Agent),
            model: crate::ModelId::new("test/model@r1").expect("model"),
            sink: &mut sink,
        };
        let mut ctx = WakeAttemptContext {
            vault: &vault,
            deadline: &deadline,
            budget_id: "wake",
            now_ms,
        };
        block_on_ready(executor.execute(&admitted, &mut ctx))?;
        Ok(sink
            .accepted
            .iter()
            .map(|candidate| candidate.claim_id)
            .collect())
    };

    let ids_first = run(21_000)?;
    // Both the extraction and the merge memo-hit on the re-run; the MERGED
    // candidate id is content-addressed, so it is stable across re-execution
    // and independent of `now` (#485-3).
    let ids_second = run(987_000)?;

    assert_eq!(ids_first.len(), 1, "one merged candidate");
    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        2,
        "the re-run memo-hit both steps; no new generate"
    );
    assert_eq!(
        ids_first, ids_second,
        "re-running the same merge mints the SAME write-once claim id"
    );
    Ok(())
}
