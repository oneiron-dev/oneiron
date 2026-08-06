// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! ONE-1773 (CA-02) public-surface oracle for SAVED_QUERY.
//!
//! Everything here goes through the crate's PUBLIC API. The in-crate unit tests
//! in `src/saved_query/tests.rs` pin private encodings; this file pins the
//! behaviors a consumer (ONE-1774's consequence writer, ONE-1778's surfaces)
//! depends on — staged-evaluation ordering, memo invalidation, owner binding,
//! the epoch watermark, and the pack-drift ladder.

mod common;

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use common::entity as test_id;
use oneiron::campaign::claims::{
    CampaignMemberChannel, CampaignMemberState, CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER,
    encode_campaign_member_value,
};
use oneiron::campaign::{CRM_PACK_ID, register_crm_pack};
use oneiron::registry::{ENTITY_TYPE_PERSON, TypeByteBand};
use oneiron::saved_query::{
    SAVED_QUERY_SCHEMA_VERSION, SAVED_QUERY_SHORT_ID_PREFIX, commit_membership_plan,
    membership_events, next_membership_epoch, parse_filter_ast, put_pack_migration_map,
    register_saved_query_kind, repair_pack_drift,
};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallClass, CallEnvelope, CallPurpose,
    ClaimApprovalStatus, ClaimBody, ClaimComparison, ClaimLifecycleStatus, ClaimSubject,
    ContentPart, CreateSavedQueryRequest, EntityId, Error, EvalMode, EvalPolicy, EvaluationRequest,
    FatalLlmError, FilterAst, FinishReason, LlmBackend, LlmCapability, LlmError, LlmGenerateFuture,
    LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult, LlmUsage, MatchVerdict,
    MatcherSpec, MembershipCause, MembershipCommitOutcome, MembershipEvent, MembershipTransition,
    MembershipWritePlan, ModelLocality, ModelTierRef, PackDrift, PackDriftResolution,
    PackMigrationMap, PackPredicateRewrite, QueryScope, ResponseFormat, Result,
    SavedQueryEvaluator, SavedQueryJudgeBinding, SavedQueryLifecycle, SavedQueryRecord,
    TierPrecedence, TimeRange, UnsupportedCapability, UpdateSavedQueryRequest, Vault, VaultConfig,
};
use serde_json::{Value, json};

const JUDGE_MODEL: &str = "openai/gpt-4.1-mini@2026-07-02";
const SENIORITY: &str = "profile.seniority";
const HEADCOUNT: &str = "profile.headcount";
const UNRELATED: &str = "profile.timezone";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Minimal executor. The crate's async surface is runtime-agnostic and `tokio`
/// is only compiled under the `sync` feature, so the oracle drives futures
/// itself rather than depending on a runtime the default build does not have.
fn block_on<F: Future>(future: F) -> F::Output {
    struct ThreadWaker(std::thread::Thread);
    impl std::task::Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::park(),
        }
    }
}

/// Counts every call and records the last request, so a test can prove both
/// that stage 2 did NOT run and that when it did it carried the owner's rubric.
#[derive(Default)]
struct CountingJudge {
    calls: AtomicUsize,
    verdict: std::sync::Mutex<String>,
    last_request: std::sync::Mutex<Option<LlmRequest>>,
}

impl CountingJudge {
    fn answering(verdict: &str) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            verdict: std::sync::Mutex::new(verdict.to_owned()),
            last_request: std::sync::Mutex::new(None),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn last_request(&self) -> LlmRequest {
        self.last_request
            .lock()
            .unwrap()
            .clone()
            .expect("judge was called")
    }
}

impl LlmBackend for CountingJudge {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_request.lock().unwrap() = Some(request);
        let text = self.verdict.lock().unwrap().clone();
        Box::pin(async move {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text { text }],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
            })
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(LlmError::Fatal(FatalLlmError::Unsupported(
            UnsupportedCapability {
                capability: LlmCapability::Streaming,
                model: None,
                reason: None,
            },
        )))
    }
}

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config
}

/// Unseeded keeps the claim write door open without a policy fixture, matching
/// the CA-01 oracle's setup.
fn oracle_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).unwrap();
    (dir, vault)
}

fn put_person(vault: &Vault, id: &EntityId) {
    vault
        .put_entity(
            id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"saved query oracle person",
        )
        .unwrap();
}

fn put_claim(vault: &Vault, claim_id: &EntityId, subject: EntityId, predicate: &str, value: &str) {
    let body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        rmpv::Value::from(value),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault
        .put_claim(claim_id, &body, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
}

fn claim_term(predicate: &str, cmp: ClaimComparison, value: Value) -> FilterAst {
    FilterAst::Claim {
        predicate: predicate.to_owned(),
        cmp,
        value,
    }
}

fn eval_policy(max_entities: u32, max_judges: u32) -> EvalPolicy {
    EvalPolicy {
        mode: EvalMode::Manual,
        max_entities_per_wake: max_entities,
        max_judges_per_wake: max_judges,
    }
}

fn create_request(filter: FilterAst, matcher: MatcherSpec) -> CreateSavedQueryRequest {
    CreateSavedQueryRequest {
        schema_version: SAVED_QUERY_SCHEMA_VERSION,
        scope: QueryScope::default(),
        filter,
        matcher,
        eval: eval_policy(8, 4),
    }
}

fn judge_envelope() -> CallEnvelope {
    CallEnvelope {
        purpose: CallPurpose::Eval,
        class: CallClass::BestEffort,
        tier: TierPrecedence {
            per_call: None,
            vault_policy: None,
            purpose_default: None,
            global_default: ModelTierRef("default".to_owned()),
        },
        response_format: ResponseFormat::Text,
        locality: ModelLocality::OwnServer,
    }
}

fn lease() -> BudgetLease {
    BudgetGuard::new(
        "saved-query-oracle",
        10_000,
        BudgetExhaustionPolicy::Suspend,
    )
    .admit()
    .expect("budget admits")
    .lease
}

fn evaluation(record: &SavedQueryRecord, entity_ref: EntityId) -> EvaluationRequest<'_> {
    EvaluationRequest {
        query_ref: record.query_ref,
        campaign_ref: test_id(0x41),
        entity_ref,
        definition: &record.definition,
        cause: MembershipCause::DataChange,
        valid_at: 1_000,
        detected_at: 1_000,
    }
}

// ---------------------------------------------------------------------------
// Pack registration
// ---------------------------------------------------------------------------

/// The kind takes a caller-assigned CRM-band byte at registration, keeps the
/// `sq` prefix and the ONE CRM pack id, and inherits the registrar's existing
/// collision and band errors rather than inventing its own.
#[test]
fn saved_query_registers_dynamically_in_crm_band_without_static_byte() {
    let (_dir, vault) = oracle_vault();
    let pack = register_crm_pack(&vault, 100, 101).unwrap();

    assert_eq!(pack.saved_query.type_byte, 101);
    assert_eq!(
        pack.saved_query.short_id_prefix,
        SAVED_QUERY_SHORT_ID_PREFIX
    );
    assert_eq!(pack.saved_query.band, TypeByteBand::Crm);
    assert_eq!(pack.saved_query.pack, CRM_PACK_ID);
    assert_eq!(
        pack.campaign.pack, CRM_PACK_ID,
        "one pack identity, not two"
    );
    assert_eq!(
        vault.structural_kind_registration(101),
        Some(pack.saved_query),
        "the registration must survive as vault-scoped state"
    );

    // The byte is not chosen here, so a caller CAN pick a bad one — and the
    // existing registrar, not this module, is what rejects it.
    assert!(matches!(
        register_saved_query_kind(&vault, 102),
        Err(Error::StructuralKindPrefixCollision(prefix)) if prefix == SAVED_QUERY_SHORT_ID_PREFIX
    ));
    assert!(matches!(
        register_saved_query_kind(&vault, 50),
        Err(Error::StructuralKindBandViolation { .. })
    ));
}

/// Byte-space v3: this batch allocates ZERO static bytes. No constant, no
/// registry row, no `registry.rs` edit.
#[test]
fn no_static_saved_query_type_byte_exists_in_source() {
    let registry = include_str!("../src/registry.rs");
    let module = include_str!("../src/saved_query.rs");
    let campaign = include_str!("../src/campaign.rs");

    assert!(
        !registry.contains("SAVED_QUERY"),
        "registry.rs must carry no SAVED_QUERY row"
    );
    for (label, source) in [("saved_query.rs", module), ("campaign.rs", campaign)] {
        assert!(
            !source.contains("ENTITY_TYPE_SAVED_QUERY"),
            "{label} must not mint an ENTITY_TYPE_SAVED_QUERY constant"
        );
        assert!(
            !source
                .lines()
                .any(|line| line.contains("const") && line.contains(": u8 =")),
            "{label} must declare no static type byte"
        );
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[test]
fn saved_query_crud_round_trips_and_archives_without_delete() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let owner = test_id(0x30);
    let request = create_request(
        claim_term(SENIORITY, ClaimComparison::Exists, Value::Null),
        MatcherSpec::Hard {
            expression: FilterAst::All { terms: Vec::new() },
        },
    );

    let created = oneiron::saved_query::create_saved_query(&vault, owner, &request, 10)?;
    assert_eq!(created.definition.definition_version, 1);
    assert_eq!(
        oneiron::saved_query::read_saved_query(&vault, owner, created.query_ref)?,
        Some(created.clone())
    );

    // A stale expected version loses the CAS; the stored record is untouched.
    let update = UpdateSavedQueryRequest {
        expected_definition_version: 99,
        scope: request.scope.clone(),
        filter: request.filter.clone(),
        matcher: request.matcher.clone(),
        eval: request.eval,
    };
    assert!(matches!(
        oneiron::saved_query::update_saved_query(&vault, owner, created.query_ref, &update, 20),
        Err(Error::ConcurrentWrite(_))
    ));

    let updated = oneiron::saved_query::update_saved_query(
        &vault,
        owner,
        created.query_ref,
        &UpdateSavedQueryRequest {
            expected_definition_version: 1,
            filter: claim_term(HEADCOUNT, ClaimComparison::Exists, Value::Null),
            ..update
        },
        20,
    )?;
    assert_eq!(updated.definition.definition_version, 2);
    assert_eq!(updated.updated_at, 20);
    assert_eq!(updated.created_at, created.created_at);

    let archived =
        oneiron::saved_query::archive_saved_query(&vault, owner, created.query_ref, 2, 30)?;
    assert_eq!(archived.definition.lifecycle, SavedQueryLifecycle::Archived);
    assert_eq!(
        oneiron::saved_query::read_saved_query(&vault, owner, created.query_ref)?
            .expect("archived records stay addressable for ONE-1778"),
        archived,
        "archive is a lifecycle transition, never a delete"
    );
    Ok(())
}

/// The owner comes from the authenticated principal and from nowhere else. A
/// different principal cannot read, update, or archive — and cannot even learn
/// the query exists.
#[test]
fn saved_query_write_boundary_binds_authenticated_owner() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let (owner, intruder) = (test_id(0x43), test_id(0x44));
    let request = create_request(
        claim_term(SENIORITY, ClaimComparison::Exists, Value::Null),
        MatcherSpec::Hard {
            expression: FilterAst::All { terms: Vec::new() },
        },
    );

    let created = oneiron::saved_query::create_saved_query(&vault, owner, &request, 10)?;
    assert_eq!(
        created.definition.owner_actor, owner,
        "create binds the owner from the authenticated principal"
    );

    assert_eq!(
        oneiron::saved_query::read_saved_query(&vault, intruder, created.query_ref)?,
        None,
        "a non-owner must not even learn the query exists"
    );
    let update = UpdateSavedQueryRequest {
        expected_definition_version: 1,
        scope: request.scope.clone(),
        filter: claim_term(HEADCOUNT, ClaimComparison::Exists, Value::Null),
        matcher: request.matcher.clone(),
        eval: request.eval,
    };
    assert!(matches!(
        oneiron::saved_query::update_saved_query(&vault, intruder, created.query_ref, &update, 20),
        Err(Error::EntityNotFound)
    ));
    assert!(matches!(
        oneiron::saved_query::archive_saved_query(&vault, intruder, created.query_ref, 1, 20),
        Err(Error::EntityNotFound)
    ));
    assert_eq!(
        oneiron::saved_query::read_saved_query(&vault, owner, created.query_ref)?,
        Some(created),
        "a rejected intruder write must leave the record untouched"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Filter AST
// ---------------------------------------------------------------------------

#[test]
fn filter_ast_accepts_only_per_entity_decidable_operators() -> Result<()> {
    let target = test_id(0x45);
    let parsed = parse_filter_ast(&json!({
        "op": "all",
        "terms": [
            {"op": "claim", "predicate": SENIORITY, "cmp": "eq", "value": "director"},
            {"op": "any", "terms": [
                {"op": "claim", "predicate": HEADCOUNT, "cmp": "gte", "value": 50},
                {"op": "not", "term": {"op": "claim", "predicate": UNRELATED, "cmp": "exists"}}
            ]},
            {"op": "edge_exists", "edge_kind": "employed_by", "target": target.to_hex()}
        ]
    }))?;

    let FilterAst::All { terms } = &parsed else {
        panic!("expected a conjunction, got {parsed:?}");
    };
    assert_eq!(terms.len(), 3);
    assert_eq!(
        terms[2],
        FilterAst::EdgeExists {
            edge_kind: "employed_by".to_owned(),
            target: Some(target),
        }
    );

    // An edge term with no target matches any target of that kind.
    assert_eq!(
        parse_filter_ast(&json!({"op": "edge_exists", "edge_kind": "mentions"}))?,
        FilterAst::EdgeExists {
            edge_kind: "mentions".to_owned(),
            target: None,
        }
    );
    Ok(())
}

/// Ranked and global-relative operators die AT PARSE, before an evaluable AST
/// exists — and by name, so the rejection cannot be mistaken for a generic
/// unknown-operator error that a later reader might widen.
#[test]
fn filter_ast_rejects_top_k_and_ppr_score_at_parse() {
    for op in [
        "top_k",
        "topk",
        "ppr_score",
        "ppr",
        "rank",
        "percentile",
        "global_count",
        "relative_score",
    ] {
        let error = parse_filter_ast(&json!({"op": op, "k": 10}))
            .expect_err("ranked operator must not parse");
        let Error::InvalidConfig(message) = error else {
            panic!("{op} must be rejected as invalid config");
        };
        assert!(
            message.contains(op) && message.contains("per-entity-decidable"),
            "{op} rejection must name the operator and the law: {message}"
        );
    }

    // Unknown operators are rejected too; there is no permissive catch-all.
    assert!(matches!(
        parse_filter_ast(&json!({"op": "vibes"})),
        Err(Error::InvalidConfig(_))
    ));
    assert!(matches!(
        parse_filter_ast(&json!({"op": "edge_exists", "edge_kind": "made_up"})),
        Err(Error::InvalidConfig(_))
    ));
    assert!(matches!(
        parse_filter_ast(&json!(["all"])),
        Err(Error::InvalidConfig(_))
    ));
}

// ---------------------------------------------------------------------------
// Staged evaluation
// ---------------------------------------------------------------------------

#[test]
fn stage_one_failure_never_invokes_stage_two() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let (owner, person) = (test_id(0x46), test_id(0x31));
    put_person(&vault, &person);
    // No `profile.seniority` claim exists, so stage 1 cannot pass.

    let record = oneiron::saved_query::create_saved_query(
        &vault,
        owner,
        &create_request(
            claim_term(SENIORITY, ClaimComparison::Exists, Value::Null),
            MatcherSpec::LlmJudge {
                model_id: JUDGE_MODEL.to_owned(),
                rubric: json!({"criterion": "is a decision maker"}),
                rubric_version: "v1".to_owned(),
            },
        ),
        10,
    )?;

    let judge = CountingJudge::answering(r#"{"verdict":"match","why":"unreachable"}"#);
    let lease = lease();
    let envelope = judge_envelope();
    let grants = QueryScope::default();
    let evaluator = SavedQueryEvaluator {
        vault: &vault,
        owner_grants: &grants,
        judge: Some(SavedQueryJudgeBinding {
            backend: &judge,
            lease: &lease,
            envelope: &envelope,
        }),
    };

    let outcome = block_on(evaluator.evaluate_entity(&evaluation(&record, person)))?;
    assert_eq!(outcome.decision.verdict, MatchVerdict::NoMatch);
    assert_eq!(
        judge.calls(),
        0,
        "a failing stage-1 filter must not spend a stage-2 judge call"
    );
    Ok(())
}

/// The judge runs only through the injected backend, carries the owner's model
/// id and rubric, and cannot run at all without a backend AND a budget lease —
/// the two travel as one binding, so neither can be supplied alone.
#[test]
fn llm_judge_uses_injected_backend_and_budget_lease() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let (owner, person) = (test_id(0x48), test_id(0x49));
    put_person(&vault, &person);
    put_claim(&vault, &test_id(0x4A), person, SENIORITY, "director");

    let rubric = json!({"criterion": "is a decision maker"});
    let record = oneiron::saved_query::create_saved_query(
        &vault,
        owner,
        &create_request(
            claim_term(SENIORITY, ClaimComparison::Exists, Value::Null),
            MatcherSpec::LlmJudge {
                model_id: JUDGE_MODEL.to_owned(),
                rubric: rubric.clone(),
                rubric_version: "v1".to_owned(),
            },
        ),
        10,
    )?;

    let grants = QueryScope::default();
    let unbound = SavedQueryEvaluator {
        vault: &vault,
        owner_grants: &grants,
        judge: None,
    };
    assert!(
        matches!(
            block_on(unbound.evaluate_entity(&evaluation(&record, person))),
            Err(Error::InvalidConfig(_))
        ),
        "an unbound judge must fail loudly, never quietly answer no-match"
    );

    let judge = CountingJudge::answering(r#"{"verdict":"match","why":"director-level"}"#);
    let lease = lease();
    let envelope = judge_envelope();
    let evaluator = SavedQueryEvaluator {
        vault: &vault,
        owner_grants: &grants,
        judge: Some(SavedQueryJudgeBinding {
            backend: &judge,
            lease: &lease,
            envelope: &envelope,
        }),
    };

    let outcome = block_on(evaluator.evaluate_entity(&evaluation(&record, person)))?;
    assert_eq!(outcome.decision.verdict, MatchVerdict::Match);
    assert_eq!(outcome.decision.why, "director-level");
    assert_eq!(judge.calls(), 1);

    let sent = judge.last_request();
    assert_eq!(sent.model.as_str(), JUDGE_MODEL);
    assert_eq!(sent.envelope, envelope, "the HOST owns the call envelope");
    let system = sent
        .messages
        .iter()
        .find(|message| message.role == LlmMessageRole::System)
        .expect("rubric rides the system message");
    let ContentPart::Text { text } = &system.content[0] else {
        panic!("rubric must be text");
    };
    assert_eq!(
        serde_json::from_str::<Value>(text).unwrap(),
        rubric,
        "the owner's rubric passes through verbatim"
    );
    Ok(())
}

/// The owner is the evaluation principal. Viewers are not an input at all, and
/// a scope the owner can no longer reach fails CLOSED.
#[test]
fn owner_actor_is_the_only_evaluation_principal() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let (owner, person, world) = (test_id(0x4B), test_id(0x4C), test_id(0x4D));
    put_person(&vault, &person);
    put_claim(&vault, &test_id(0x4E), person, SENIORITY, "director");

    let mut request = create_request(
        claim_term(SENIORITY, ClaimComparison::Eq, json!("director")),
        MatcherSpec::Hard {
            expression: FilterAst::All { terms: Vec::new() },
        },
    );
    request.scope = QueryScope {
        worlds: vec![world],
        facets: Vec::new(),
    };
    let record = oneiron::saved_query::create_saved_query(&vault, owner, &request, 10)?;

    // Two different viewers read the SAME stored query and get the same
    // membership: the evaluator takes no viewer principal.
    let in_reach = QueryScope {
        worlds: vec![world],
        facets: Vec::new(),
    };
    let matched = block_on(
        SavedQueryEvaluator {
            vault: &vault,
            owner_grants: &in_reach,
            judge: None,
        }
        .evaluate_entity(&evaluation(&record, person)),
    )?;
    assert_eq!(matched.decision.verdict, MatchVerdict::Match);

    // The owner loses the world grant. Same evidence, same definition — but the
    // effective scope is now closed, so membership fails closed.
    let out_of_reach = QueryScope {
        worlds: vec![test_id(0x4F)],
        facets: Vec::new(),
    };
    let closed = block_on(
        SavedQueryEvaluator {
            vault: &vault,
            owner_grants: &out_of_reach,
            judge: None,
        }
        .evaluate_entity(&evaluation(&record, person)),
    )?;
    assert_eq!(closed.decision.verdict, MatchVerdict::NoMatch);
    assert!(closed.decision.why.contains("scope"));
    assert!(
        !closed.memo_hit,
        "the granted verdict's memo must not answer for a revoked grant"
    );
    assert_ne!(
        matched.evidence_hash, closed.evidence_hash,
        "a closed scope reads no evidence, so it cannot collide with the granted hash"
    );

    // Restoring the grant restores membership: the denial cached nothing.
    assert_eq!(
        block_on(
            SavedQueryEvaluator {
                vault: &vault,
                owner_grants: &in_reach,
                judge: None,
            }
            .evaluate_entity(&evaluation(&record, person)),
        )?
        .decision
        .verdict,
        MatchVerdict::Match
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Verdict memos
// ---------------------------------------------------------------------------

#[test]
fn verdict_memo_hits_on_identical_evidence_hash() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let (owner, person) = (test_id(0x50), test_id(0x51));
    put_person(&vault, &person);
    put_claim(&vault, &test_id(0x52), person, SENIORITY, "director");

    let record = oneiron::saved_query::create_saved_query(
        &vault,
        owner,
        &create_request(
            claim_term(SENIORITY, ClaimComparison::Exists, Value::Null),
            MatcherSpec::LlmJudge {
                model_id: JUDGE_MODEL.to_owned(),
                rubric: json!({"criterion": "decision maker"}),
                rubric_version: "v1".to_owned(),
            },
        ),
        10,
    )?;

    let judge = CountingJudge::answering(r#"{"verdict":"match","why":"first pass"}"#);
    let lease = lease();
    let envelope = judge_envelope();
    let grants = QueryScope::default();
    let evaluator = SavedQueryEvaluator {
        vault: &vault,
        owner_grants: &grants,
        judge: Some(SavedQueryJudgeBinding {
            backend: &judge,
            lease: &lease,
            envelope: &envelope,
        }),
    };

    let first = block_on(evaluator.evaluate_entity(&evaluation(&record, person)))?;
    assert!(!first.memo_hit);
    assert_eq!(judge.calls(), 1);

    let second = block_on(evaluator.evaluate_entity(&evaluation(&record, person)))?;
    assert!(
        second.memo_hit,
        "unchanged evidence must answer from the memo"
    );
    assert_eq!(second.evidence_hash, first.evidence_hash);
    assert_eq!(second.decision, first.decision);
    assert_eq!(
        judge.calls(),
        1,
        "a memo hit must not reach the stage-2 matcher"
    );
    Ok(())
}

#[test]
fn verdict_memo_invalidates_on_relevant_evidence_or_definition_change() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let (owner, person) = (test_id(0x53), test_id(0x54));
    put_person(&vault, &person);
    put_claim(&vault, &test_id(0x55), person, SENIORITY, "director");

    let request = create_request(
        claim_term(SENIORITY, ClaimComparison::Exists, Value::Null),
        MatcherSpec::Hard {
            expression: FilterAst::All { terms: Vec::new() },
        },
    );
    let record = oneiron::saved_query::create_saved_query(&vault, owner, &request, 10)?;
    let grants = QueryScope::default();
    let evaluator = SavedQueryEvaluator {
        vault: &vault,
        owner_grants: &grants,
        judge: None,
    };
    let baseline = block_on(evaluator.evaluate_entity(&evaluation(&record, person)))?;

    // Evidence the AST never declared moves nothing.
    put_claim(&vault, &test_id(0x56), person, UNRELATED, "utc+2");
    let after_irrelevant = block_on(evaluator.evaluate_entity(&evaluation(&record, person)))?;
    assert_eq!(after_irrelevant.evidence_hash, baseline.evidence_hash);
    assert!(after_irrelevant.memo_hit);

    // Declared evidence moves the hash, so the memo cannot answer.
    put_claim(&vault, &test_id(0x57), person, SENIORITY, "vp");
    let after_relevant = block_on(evaluator.evaluate_entity(&evaluation(&record, person)))?;
    assert_ne!(after_relevant.evidence_hash, baseline.evidence_hash);
    assert!(!after_relevant.memo_hit);

    // So does a definition-version bump, even with identical evidence.
    let updated = oneiron::saved_query::update_saved_query(
        &vault,
        owner,
        record.query_ref,
        &UpdateSavedQueryRequest {
            expected_definition_version: 1,
            scope: request.scope.clone(),
            filter: request.filter.clone(),
            matcher: request.matcher.clone(),
            eval: request.eval,
        },
        20,
    )?;
    let after_version = block_on(evaluator.evaluate_entity(&evaluation(&updated, person)))?;
    assert_ne!(after_version.evidence_hash, after_relevant.evidence_hash);
    assert!(!after_version.memo_hit);
    Ok(())
}

// ---------------------------------------------------------------------------
// Membership: CA-01 contract, closed causes, epochs
// ---------------------------------------------------------------------------

fn member_channel() -> CampaignMemberChannel {
    CampaignMemberChannel {
        channel: "email".to_owned(),
        basis_evidence: test_id(0x58),
        sender_ref: test_id(0x59),
    }
}

/// The CA-01 validator is the single authority on the member value: it accepts
/// manual membership with NO derivation and CA-02 membership WITH the exact
/// `{source_query, evidence_hash, epoch}` triple. CA-02 defines no second
/// member or derivation type.
#[test]
fn campaign_member_uses_ca01_optional_derivation_contract() {
    let (_dir, vault) = oracle_vault();
    let (person, campaign) = (test_id(0x5A), test_id(0x5B));
    put_person(&vault, &person);

    let manual = CampaignMemberValue {
        campaign,
        state: CampaignMemberState::Enrolled,
        channels: vec![member_channel()],
        derivation: None,
    };
    let derived = CampaignMemberValue {
        derivation: Some(oneiron::campaign::claims::CampaignMemberDerivation {
            source_query: test_id(0x5C),
            evidence_hash: [4u8; 32],
            epoch: 1,
        }),
        ..manual.clone()
    };

    for (label, value, claim_id) in [
        ("manual", &manual, test_id(0x5D)),
        ("derived", &derived, test_id(0x5E)),
    ] {
        let body = ClaimBody::new(
            PREDICATE_CAMPAIGN_MEMBER,
            ClaimSubject::Entity(person),
            encode_campaign_member_value(value),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        vault
            .put_claim(&claim_id, &body, TimeRange { start: 1, end: 1 }, 1)
            .unwrap_or_else(|error| panic!("{label} membership must be accepted: {error}"));
    }

    // A derivation missing a component is not a CA-02 derivation.
    let truncated = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("campaign"),
            rmpv::Value::from(campaign.to_hex()),
        ),
        (
            rmpv::Value::from("state"),
            rmpv::Value::Map(vec![(
                rmpv::Value::from("kind"),
                rmpv::Value::from("enrolled"),
            )]),
        ),
        (
            rmpv::Value::from("channels"),
            rmpv::Value::Array(vec![rmpv::Value::Map(vec![
                (rmpv::Value::from("channel"), rmpv::Value::from("email")),
                (
                    rmpv::Value::from("basis_evidence"),
                    rmpv::Value::from(test_id(0x58).to_hex()),
                ),
                (
                    rmpv::Value::from("sender_ref"),
                    rmpv::Value::from(test_id(0x59).to_hex()),
                ),
            ])]),
        ),
        (
            rmpv::Value::from("derivation"),
            rmpv::Value::Map(vec![(
                rmpv::Value::from("source_query"),
                rmpv::Value::from(test_id(0x5C).to_hex()),
            )]),
        ),
    ]);
    let body = ClaimBody::new(
        PREDICATE_CAMPAIGN_MEMBER,
        ClaimSubject::Entity(person),
        truncated,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    assert!(matches!(
        vault.put_claim(&test_id(0x5F), &body, TimeRange { start: 1, end: 1 }, 1),
        Err(Error::InvalidClaimBody(_))
    ));
}

fn write_plan(
    query: EntityId,
    campaign: EntityId,
    person: EntityId,
    epoch: u64,
    transition: MembershipTransition,
    cause: MembershipCause,
    at: u64,
) -> MembershipWritePlan {
    let event = MembershipEvent {
        query_ref: query,
        campaign_ref: campaign,
        entity_ref: person,
        epoch,
        valid_at: at,
        detected_at: at,
        transition,
        cause,
        evidence_hash: [u8::try_from(epoch % 251).unwrap_or_default(); 32],
    };
    let state = match transition {
        MembershipTransition::Entered => CampaignMemberState::Enrolled,
        MembershipTransition::Exited => CampaignMemberState::Exited,
    };
    MembershipWritePlan {
        value: oneiron::saved_query::derived_member_value(&event, state, vec![member_channel()]),
        event,
    }
}

/// Causes are a closed set: every member round-trips, and the plan's own
/// coherence check refuses an event whose transition disagrees with the state.
#[test]
fn membership_events_use_closed_causes() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let (query, campaign, person) = (test_id(0x60), test_id(0x61), test_id(0x62));
    put_person(&vault, &person);

    for (index, cause) in MembershipCause::ALL.into_iter().enumerate() {
        let epoch = u64::try_from(index).unwrap_or_default() + 1;
        let plan = write_plan(
            query,
            campaign,
            person,
            epoch,
            MembershipTransition::Entered,
            cause,
            100 + epoch,
        );
        assert_eq!(
            commit_membership_plan(&vault, &plan, 100 + epoch)?,
            MembershipCommitOutcome::Applied
        );
    }
    let events = membership_events(&vault, query, person)?;
    assert_eq!(
        events.iter().map(|event| event.cause).collect::<Vec<_>>(),
        MembershipCause::ALL.to_vec(),
        "every closed-set cause must round-trip, in epoch order"
    );
    assert!(MembershipCause::parse("vibe_change").is_none());
    assert!(MembershipTransition::parse("lingering").is_none());

    // An Entered event carrying an Exited member state is incoherent.
    let mut incoherent = write_plan(
        query,
        campaign,
        person,
        9,
        MembershipTransition::Entered,
        MembershipCause::DataChange,
        200,
    );
    incoherent.value.state = CampaignMemberState::Exited;
    assert!(matches!(
        commit_membership_plan(&vault, &incoherent, 200),
        Err(Error::InvalidClaimBody(_))
    ));
    Ok(())
}

#[test]
fn membership_epoch_reentry_is_new_epoch() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let (query, campaign, person) = (test_id(0x63), test_id(0x64), test_id(0x65));
    put_person(&vault, &person);

    let entered = next_membership_epoch(&vault, query, person)?;
    assert_eq!(entered, 1);
    commit_membership_plan(
        &vault,
        &write_plan(
            query,
            campaign,
            person,
            entered,
            MembershipTransition::Entered,
            MembershipCause::DataChange,
            100,
        ),
        100,
    )?;

    let exited = next_membership_epoch(&vault, query, person)?;
    commit_membership_plan(
        &vault,
        &write_plan(
            query,
            campaign,
            person,
            exited,
            MembershipTransition::Exited,
            MembershipCause::ScopeChange,
            200,
        ),
        200,
    )?;

    let re_entered = next_membership_epoch(&vault, query, person)?;
    commit_membership_plan(
        &vault,
        &write_plan(
            query,
            campaign,
            person,
            re_entered,
            MembershipTransition::Entered,
            MembershipCause::DataChange,
            300,
        ),
        300,
    )?;

    assert!(
        entered < exited && exited < re_entered,
        "re-entry mints a new epoch, never reuses the prior Entered one"
    );
    let events = membership_events(&vault, query, person)?;
    assert_eq!(events.len(), 3, "history is preserved, never rewritten");
    assert_eq!(
        events
            .iter()
            .map(|event| (event.transition, event.epoch, event.valid_at))
            .collect::<Vec<_>>(),
        vec![
            (MembershipTransition::Entered, entered, 100),
            (MembershipTransition::Exited, exited, 200),
            (MembershipTransition::Entered, re_entered, 300),
        ]
    );
    Ok(())
}

/// The distinguishing test: a REPLAYED `Entered` from before an exit must be
/// rejected as stale, not reported as already-applied. Payload dedupe would get
/// this wrong and leave the cohort holding a resurrected member.
#[test]
fn membership_commit_is_watermark_guarded_not_dedupe_guarded() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let (query, campaign, person) = (test_id(0x66), test_id(0x67), test_id(0x68));
    put_person(&vault, &person);

    let entered = write_plan(
        query,
        campaign,
        person,
        1,
        MembershipTransition::Entered,
        MembershipCause::DataChange,
        100,
    );
    assert_eq!(
        commit_membership_plan(&vault, &entered, 100)?,
        MembershipCommitOutcome::Applied
    );
    assert_eq!(
        commit_membership_plan(&vault, &entered, 100)?,
        MembershipCommitOutcome::AlreadyApplied,
        "an exact retry at the same epoch is idempotent"
    );

    commit_membership_plan(
        &vault,
        &write_plan(
            query,
            campaign,
            person,
            2,
            MembershipTransition::Exited,
            MembershipCause::DataChange,
            200,
        ),
        200,
    )?;
    commit_membership_plan(
        &vault,
        &write_plan(
            query,
            campaign,
            person,
            3,
            MembershipTransition::Entered,
            MembershipCause::DataChange,
            300,
        ),
        300,
    )?;

    assert_eq!(
        commit_membership_plan(&vault, &entered, 400)?,
        MembershipCommitOutcome::RejectedStaleEpoch { current_epoch: 3 },
        "the stale Entered replay must be REJECTED, never AlreadyApplied"
    );
    assert_eq!(
        membership_events(&vault, query, person)?.len(),
        3,
        "the rejected replay wrote nothing"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// OF-241 independence and wake bounds
// ---------------------------------------------------------------------------

/// No live-subscription runtime exists and none is minted. On-demand,
/// enrollment-epoch, and bounded-wake evaluation all work without one.
#[test]
fn of241_absence_does_not_block_evaluation() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let (owner, campaign) = (test_id(0x69), test_id(0x6A));
    let people = [test_id(0x6B), test_id(0x6C)];
    for (index, person) in people.iter().enumerate() {
        put_person(&vault, person);
        put_claim(
            &vault,
            &test_id(0x6D + u8::try_from(index).unwrap_or_default()),
            *person,
            SENIORITY,
            "director",
        );
    }

    let mut request = create_request(
        claim_term(SENIORITY, ClaimComparison::Eq, json!("director")),
        MatcherSpec::Hard {
            expression: FilterAst::All { terms: Vec::new() },
        },
    );
    request.eval = eval_policy(8, 4);
    // Reactive mode is STORED but needs no runtime to be evaluated.
    request.eval.mode = EvalMode::Reactive;
    let record = oneiron::saved_query::create_saved_query(&vault, owner, &request, 10)?;

    let grants = QueryScope::default();
    let evaluator = SavedQueryEvaluator {
        vault: &vault,
        owner_grants: &grants,
        judge: None,
    };

    // On-demand.
    assert_eq!(
        block_on(evaluator.evaluate_entity(&evaluation(&record, people[0])))?
            .decision
            .verdict,
        MatchVerdict::Match
    );
    // Bounded wake.
    let report = block_on(evaluator.evaluate_wake_batch(record.query_ref, &people, 1_000))?;
    assert_eq!(report.evaluated, 2);
    assert_eq!(report.resume_after, None);

    // Enrollment epoch: the membership consequence lands with no subscription.
    let plan = write_plan(
        record.query_ref,
        campaign,
        people[0],
        next_membership_epoch(&vault, record.query_ref, people[0])?,
        MembershipTransition::Entered,
        MembershipCause::DataChange,
        1_000,
    );
    assert_eq!(
        commit_membership_plan(&vault, &plan, 1_000)?,
        MembershipCommitOutcome::Applied
    );
    Ok(())
}

/// A bulk candidate set stops at the configured bound and says WHERE it
/// stopped. Degradation is visible progress, never a silently disabled query.
#[test]
fn wake_budget_degrades_with_visible_progress() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let owner = test_id(0x70);
    let people = [test_id(0x71), test_id(0x72), test_id(0x73), test_id(0x74)];
    for (index, person) in people.iter().enumerate() {
        put_person(&vault, person);
        put_claim(
            &vault,
            &test_id(0x75 + u8::try_from(index).unwrap_or_default()),
            *person,
            SENIORITY,
            "director",
        );
    }

    let mut entity_bound = create_request(
        claim_term(SENIORITY, ClaimComparison::Exists, Value::Null),
        MatcherSpec::Hard {
            expression: FilterAst::All { terms: Vec::new() },
        },
    );
    entity_bound.eval = eval_policy(2, 4);
    let record = oneiron::saved_query::create_saved_query(&vault, owner, &entity_bound, 10)?;

    let grants = QueryScope::default();
    let report = block_on(
        SavedQueryEvaluator {
            vault: &vault,
            owner_grants: &grants,
            judge: None,
        }
        .evaluate_wake_batch(record.query_ref, &people, 1_000),
    )?;
    assert_eq!(report.evaluated, 2, "the entity bound stopped the batch");
    assert_eq!(
        report.resume_after,
        Some(people[1]),
        "the report must name where to resume"
    );

    // The judge bound stops the batch too, and counts only judgements that ran.
    let mut judge_bound = create_request(
        claim_term(SENIORITY, ClaimComparison::Exists, Value::Null),
        MatcherSpec::LlmJudge {
            model_id: JUDGE_MODEL.to_owned(),
            rubric: json!({"criterion": "decision maker"}),
            rubric_version: "v1".to_owned(),
        },
    );
    judge_bound.eval = eval_policy(10, 1);
    let judged = oneiron::saved_query::create_saved_query(&vault, owner, &judge_bound, 10)?;
    let judge = CountingJudge::answering(r#"{"verdict":"match","why":"ok"}"#);
    let lease = lease();
    let envelope = judge_envelope();
    let report = block_on(
        SavedQueryEvaluator {
            vault: &vault,
            owner_grants: &grants,
            judge: Some(SavedQueryJudgeBinding {
                backend: &judge,
                lease: &lease,
                envelope: &envelope,
            }),
        }
        .evaluate_wake_batch(judged.query_ref, &people, 1_000),
    )?;
    assert_eq!(report.judges_run, 1);
    assert_eq!(report.evaluated, 1);
    assert_eq!(report.resume_after, Some(people[0]));
    assert_eq!(judge.calls(), 1, "the bound is enforced, not just reported");
    Ok(())
}

// ---------------------------------------------------------------------------
// Pack drift ladder
// ---------------------------------------------------------------------------

fn drift(affected: &str) -> PackDrift {
    PackDrift {
        from_pack_id: CRM_PACK_ID.to_owned(),
        from_version: "1.0".to_owned(),
        to_pack_id: CRM_PACK_ID.to_owned(),
        to_version: "2.0".to_owned(),
        affected_predicates: vec![affected.to_owned()],
    }
}

fn drifting_query(vault: &Vault, owner: EntityId) -> Result<SavedQueryRecord> {
    oneiron::saved_query::create_saved_query(
        vault,
        owner,
        &create_request(
            claim_term(SENIORITY, ClaimComparison::Exists, Value::Null),
            MatcherSpec::Hard {
                expression: claim_term(SENIORITY, ClaimComparison::Exists, Value::Null),
            },
        ),
        10,
    )
}

/// The ladder runs in order and never silently disables or half-evaluates a
/// query: rename migrates, equivalent rewrites with a notice, meaning-changing
/// asks the owner and changes nothing, and an unmapped predicate PAUSES with a
/// visible error.
#[test]
fn pack_drift_repair_ladder_is_ordered_and_fails_loud() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let owner = test_id(0x7A);
    let moved = drift(SENIORITY);

    // Rung 1: migration-map rename, with a receipt.
    let renamed = drifting_query(&vault, owner)?;
    put_pack_migration_map(
        &vault,
        &moved,
        &PackMigrationMap {
            rewrites: [(
                SENIORITY.to_owned(),
                PackPredicateRewrite::Rename {
                    to: HEADCOUNT.to_owned(),
                },
            )]
            .into_iter()
            .collect(),
        },
    )?;
    let resolution =
        repair_pack_drift(&vault, renamed.query_ref, &renamed.definition, &moved, 100)?;
    assert!(matches!(
        resolution,
        PackDriftResolution::AutoMigrated { .. }
    ));
    let migrated = oneiron::saved_query::read_saved_query(&vault, owner, renamed.query_ref)?
        .expect("record survives migration");
    assert_eq!(
        migrated.definition.filter,
        claim_term(HEADCOUNT, ClaimComparison::Exists, Value::Null),
        "the rewrite reaches the stage-1 filter"
    );
    assert_eq!(
        migrated.definition.matcher,
        MatcherSpec::Hard {
            expression: claim_term(HEADCOUNT, ClaimComparison::Exists, Value::Null),
        },
        "and the stage-2 hard matcher, so the two cannot disagree"
    );
    assert_eq!(migrated.definition.definition_version, 2);

    // Rung 2: semantics-preserving rewrite, with a notice.
    let equivalent = drifting_query(&vault, owner)?;
    put_pack_migration_map(
        &vault,
        &moved,
        &PackMigrationMap {
            rewrites: [(
                SENIORITY.to_owned(),
                PackPredicateRewrite::Equivalent {
                    to: HEADCOUNT.to_owned(),
                    note: "same values, new spelling".to_owned(),
                },
            )]
            .into_iter()
            .collect(),
        },
    )?;
    assert!(matches!(
        repair_pack_drift(
            &vault,
            equivalent.query_ref,
            &equivalent.definition,
            &moved,
            110,
        )?,
        PackDriftResolution::AutoRewritten { .. }
    ));

    // Rung 3: meaning changed — the owner rules, and NOTHING is rewritten.
    let proposal = drifting_query(&vault, owner)?;
    put_pack_migration_map(
        &vault,
        &moved,
        &PackMigrationMap {
            rewrites: [(
                SENIORITY.to_owned(),
                PackPredicateRewrite::SemanticsChanging {
                    to: HEADCOUNT.to_owned(),
                    note: "counts staff, not rank".to_owned(),
                },
            )]
            .into_iter()
            .collect(),
        },
    )?;
    assert!(matches!(
        repair_pack_drift(
            &vault,
            proposal.query_ref,
            &proposal.definition,
            &moved,
            120
        )?,
        PackDriftResolution::ProposalRequired { .. }
    ));
    assert_eq!(
        oneiron::saved_query::read_saved_query(&vault, owner, proposal.query_ref)?
            .expect("record survives")
            .definition,
        proposal.definition,
        "a proposal changes nothing until the owner rules"
    );

    // Rung 4: no viable rewrite — paused, loudly.
    let paused = drifting_query(&vault, owner)?;
    let unmapped = drift(UNRELATED);
    let PackDriftResolution::Paused { error } =
        repair_pack_drift(&vault, paused.query_ref, &paused.definition, &unmapped, 130)?
    else {
        panic!("an unmapped predicate must pause the query");
    };
    assert!(
        error.contains(UNRELATED),
        "the error must name the predicate"
    );
    let stored = oneiron::saved_query::read_saved_query(&vault, owner, paused.query_ref)?
        .expect("record survives");
    assert_eq!(
        stored.definition.lifecycle,
        SavedQueryLifecycle::Paused { error },
        "the pause is stored, so nothing evaluates a broken query"
    );

    // And a paused query refuses to evaluate rather than partially matching.
    let grants = QueryScope::default();
    let person = test_id(0x7B);
    put_person(&vault, &person);
    assert!(matches!(
        block_on(
            SavedQueryEvaluator {
                vault: &vault,
                owner_grants: &grants,
                judge: None,
            }
            .evaluate_entity(&evaluation(&stored, person))
        ),
        Err(Error::InvalidConfig(_))
    ));
    Ok(())
}
