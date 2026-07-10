use std::collections::VecDeque;
use std::future::Future;
use std::pin::pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use crate::config::VaultConfig;
use crate::dreamer_runner::{
    AdmitDreamerConsolidationJob, AdmitDreamerJob, DreamerAdmissionOutcome,
    DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier,
    DreamerConsolidationAdmissionOutcome,
};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION};
use crate::write_envelope::WriteProvenance;
use crate::{
    BudgetExhaustionPolicy, BudgetLease, ContentPart, EdgeActorClass, FinishReason,
    LlmGenerateFuture, LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage, LlmResult,
    LlmStreamResult, LlmUsage, WakePassDeadline,
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
        schema_version: 1,
        last_learned_at: 100,
    };
    let turns = scan_dirty_turns(&vault, scope, &watermark, 100)?;
    assert_eq!(turns.len(), 2, "only admissible post-watermark turns");
    assert_eq!(turns[0].turn_id, user_turn);
    assert_eq!(turns[0].role, DreamerTurnRole::User);
    assert_eq!(turns[0].session, Some(conversation));
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
    let outcomes = enqueue_partition_jobs(&store, scope, &plans, "run-1", 20)?;
    assert!(matches!(outcomes[0], EnqueueDreamerJobOutcome::Enqueued(_)));

    // Simulated crash BEFORE the watermark advanced: the re-run re-scans the
    // same turns and re-plans — the advisory dedupe key absorbs it.
    let watermark = read_watermark(&vault, scope)?;
    assert_eq!(watermark.last_learned_at, 0, "crash: watermark untouched");
    let turns = scan_dirty_turns(&vault, scope, &watermark, 10)?;
    let plans = plan_partitions(&vault, scope, &turns, &watermark)?;
    let outcomes = enqueue_partition_jobs(&store, scope, &plans, "run-1", 30)?;
    assert!(matches!(outcomes[0], EnqueueDreamerJobOutcome::Existing(_)));
    Ok(())
}

#[test]
fn partition_jobs_dedupe_advisory() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let scope = DreamerConsolidationScope::Micro;
    let conversation = seed_session(&vault, 0x24, 1);
    seed_turn(&vault, &conversation, "user", "text", 10);

    let watermark = read_watermark(&vault, scope)?;
    let turns = scan_dirty_turns(&vault, scope, &watermark, 10)?;
    let plans = plan_partitions(&vault, scope, &turns, &watermark)?;

    let first = enqueue_partition_jobs(&store, scope, &plans, "run-1", 20)?;
    let second = enqueue_partition_jobs(&store, scope, &plans, "run-1", 21)?;
    assert!(matches!(first[0], EnqueueDreamerJobOutcome::Enqueued(_)));
    assert!(matches!(second[0], EnqueueDreamerJobOutcome::Existing(_)));
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
    let first = enqueue_partition_jobs(&store, scope, &replanned, "run-1", 20)?;
    let second = enqueue_partition_jobs(&store, scope, &replanned, "run-1", 21)?;
    assert!(matches!(first[0], EnqueueDreamerJobOutcome::Enqueued(_)));
    assert!(
        matches!(second[0], EnqueueDreamerJobOutcome::Existing(_)),
        "a partition scanned twice produces no duplicate jobs"
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
    let facet_b = EntityId::from_bytes([0x42; 16]).expect("facet b");

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

    // Two children citing the SAME source hash: one independent signal.
    let collapsed = collapse_sibling_evidence(&[vec![shared], vec![shared]])?;
    assert_eq!(collapsed.independent_signals(), 1);

    // A genuinely distinct source adds a second signal.
    let collapsed = collapse_sibling_evidence(&[vec![shared], vec![shared, distinct]])?;
    assert_eq!(collapsed.independent_signals(), 2);
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
    enqueue_partition_jobs(&store, scope, &plans, "run-1", 20)?;

    let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
        admitted,
    )) = store.admit_next_consolidation(AdmitDreamerConsolidationJob {
        scope,
        local_node_id: node_id,
        claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
        claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
        admission: AdmitDreamerJob {
            lease_owner: "consolidation-test".to_owned(),
            now: 21,
            budget_id: "wake".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 100,
            started_milestone: None,
        },
    })?
    else {
        panic!("expected admitted consolidation job");
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
    let mut ctx = WakeJobContext {
        vault: &vault,
        deadline: &deadline,
        budget_id: "wake",
        now_ms: 21_000,
    };
    let execution = block_on_ready(executor.execute(&admitted, &mut ctx))?;
    assert!(matches!(
        execution,
        DreamerJobExecution::Completed {
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

fn admitted_job_fixture<'a>(
    vault: &'a Vault,
    store: &DreamerRunnerStore<'a>,
    session_seed: u8,
    texts: &[(&str, &str)],
) -> Result<(
    crate::dreamer_runner::DreamerAdmittedJob,
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
    enqueue_partition_jobs(store, scope, &plans, "run-1", 20)?;
    let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
        admitted,
    )) = store.admit_next_consolidation(AdmitDreamerConsolidationJob {
        scope,
        local_node_id: node_id,
        claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
        claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
        admission: AdmitDreamerJob {
            lease_owner: "consolidation-test".to_owned(),
            now: 21,
            budget_id: "wake".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 100,
            started_milestone: None,
        },
    })?
    else {
        panic!("expected admitted consolidation job");
    };
    Ok((*admitted, turns, conversation))
}

#[test]
fn conflicting_sets_enter_scoped_merge() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (admitted, turns, _) = admitted_job_fixture(
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
    let mut ctx = WakeJobContext {
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
    let (admitted, turns, _) = admitted_job_fixture(
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
    let mut ctx = WakeJobContext {
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
fn budget_trapped_extraction_parks_for_resume() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (admitted, _turns, _) = admitted_job_fixture(
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
    // step layer opens a budget trap, parks the job, and returns Trapped.
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        50,
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
    let mut ctx = WakeJobContext {
        vault: &vault,
        deadline: &deadline,
        budget_id: "wake",
        now_ms: 21_000,
    };

    let execution = block_on_ready(executor.execute(&admitted, &mut ctx))?;
    // A trapped job PARKS for resume; it must NOT complete-as-done (#485-1).
    assert!(
        matches!(execution, DreamerJobExecution::Park { .. }),
        "trapped extraction must park, got {execution:?}"
    );
    assert!(sink.accepted.is_empty(), "no candidates sink on a trapped job");
    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        0,
        "admission denied before any generate"
    );
    // The step layer parked the job (resumable).
    assert!(
        store.parked_job(admitted.status.job.id)?.is_some(),
        "trapped job is parked for resume"
    );
    Ok(())
}

#[test]
fn budget_trapped_merge_parks_without_false_contradiction_gap() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (admitted, turns, _) = admitted_job_fixture(
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
    let backend =
        ScriptedBackend::new(vec![Ok(two_candidate_extraction(&subject, &turns[0], &turns[1]))]);
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        100,
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
    let mut ctx = WakeJobContext {
        vault: &vault,
        deadline: &deadline,
        budget_id: "wake",
        now_ms: 21_000,
    };

    let execution = block_on_ready(executor.execute(&admitted, &mut ctx))?;
    // Park, not Complete: the merge never decided (#485-1, #485-2).
    assert!(
        matches!(execution, DreamerJobExecution::Park { .. }),
        "merge-trapped job must park, got {execution:?}"
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
        store.parked_job(admitted.status.job.id)?.is_some(),
        "trapped job is parked for resume"
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
