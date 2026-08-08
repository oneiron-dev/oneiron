// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! ONE-1774 (CA-03) cross-module oracle for the enrollment consequence writer.
//!
//! Everything here runs through the crate's PUBLIC API. The in-crate tests in
//! `src/campaign/enrollment.rs` pin the private encodings and the outward leg
//! (whose transport seam is crate-visible); this file pins the behaviors a
//! consumer depends on — home-node admission, refs-only payloads, cause
//! routing, the epoch watermark, and the fact that queue dedupe is hygiene
//! rather than correctness.

mod common;

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use common::entity as test_id;
use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimOutcome, EnqueueAttempt, EnqueueOutcome,
};
use oneiron::campaign::claims::{CampaignMemberState, PREDICATE_CAMPAIGN_MEMBER};
use oneiron::campaign::enrollment::{
    CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND, CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
    CampaignEnrollmentAttemptPayload, CampaignEnrollmentClaim, CampaignEnrollmentEvent,
    CampaignEnrollmentRunner, CampaignHomeNodeAdmission, CampaignHomeNodeCandidate,
    CampaignHomeNodeClass, CampaignProgram, CampaignProgramOutbound, CampaignProgramStep,
    DetectEnrollment, EnrollmentDetection, EnrollmentExecution, accept_enrollment_baseline,
    campaign_enrollment_event, campaign_home_node_designation, derive_enrollment_outbound_request,
    elect_campaign_home_node_designation, encode_enrollment_attempt_payload, enrollment_dedupe_key,
    put_campaign_program, put_campaign_program_step, require_campaign_home_node,
};
use oneiron::campaign::register_crm_pack;
use oneiron::dreamer_runner::DreamerRunnerStore;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use oneiron::saved_query::{
    SAVED_QUERY_SCHEMA_VERSION, commit_membership_plan, create_saved_query, derived_member_value,
    membership_events, next_membership_epoch, update_saved_query,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimComparison, ClaimLifecycleStatus, ClaimSubject,
    CreateSavedQueryRequest, EdgeKind, EntityId, Error, EvalMode, EvalPolicy, FilterAst,
    MatcherSpec, MembershipCause, MembershipEvent, MembershipTransition, MembershipWritePlan,
    QueryScope, Result, SavedQueryEvaluator, SavedQueryRecord, TimeRange, UpdateSavedQueryRequest,
    Vault, VaultConfig,
};
use serde_json::json;

const SENIORITY: &str = "profile.seniority";
const CHANNEL: &str = "email";
const HOME_NODE: u64 = 11;
const OTHER_NODE: u64 = 12;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Minimal executor: the crate's async surface is runtime-agnostic and `tokio`
/// only exists under the `sync` feature, so the oracle drives futures itself.
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

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config
}

/// Unseeded keeps the claim write door open without a policy fixture, matching
/// the CA-01/CA-02 oracles; the CRM pack is installed because saved queries are
/// entities of its dynamically registered kind.
fn oracle_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).unwrap();
    register_crm_pack(&vault, 107, 108).unwrap();
    (dir, vault)
}

struct Fixture {
    owner: EntityId,
    person: EntityId,
    campaign: EntityId,
    program: EntityId,
    step: EntityId,
    query: SavedQueryRecord,
}

impl Fixture {
    fn payload(&self, event_ref: EntityId) -> CampaignEnrollmentAttemptPayload {
        CampaignEnrollmentAttemptPayload {
            membership_event_ref: event_ref,
            campaign_program_ref: self.program,
            program_step_ref: self.step,
        }
    }

    fn detect(&self, now: u64) -> DetectEnrollment {
        DetectEnrollment {
            query_ref: self.query.query_ref,
            campaign_ref: self.campaign,
            entity_ref: self.person,
            now,
        }
    }
}

fn install_fixture(vault: &Vault) -> Fixture {
    let owner = test_id(0x30);
    let person = test_id(0x31);
    let campaign = test_id(0x32);
    let program = test_id(0x33);
    let step = test_id(0x34);
    put_person(vault, person);
    put_claim(vault, test_id(0x35), person, SENIORITY, "vp");
    let query = create_saved_query(
        vault,
        owner,
        &CreateSavedQueryRequest {
            schema_version: SAVED_QUERY_SCHEMA_VERSION,
            scope: QueryScope::default(),
            filter: seniority_is("vp"),
            matcher: MatcherSpec::Hard {
                expression: seniority_is("vp"),
            },
            eval: EvalPolicy {
                mode: EvalMode::Manual,
                max_entities_per_wake: 8,
                max_judges_per_wake: 4,
            },
        },
        1,
    )
    .unwrap();
    put_campaign_program(
        vault,
        &CampaignProgram {
            schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
            program_ref: program,
            campaign_ref: campaign,
        },
    )
    .unwrap();
    put_step(vault, program, step, 7);
    elect_campaign_home_node_designation(
        vault,
        &[CampaignHomeNodeCandidate::always_on_local(HOME_NODE)],
        1,
    )
    .unwrap();
    Fixture {
        owner,
        person,
        campaign,
        program,
        step,
        query,
    }
}

fn put_step(vault: &Vault, program: EntityId, step: EntityId, call_seq: u64) {
    put_campaign_program_step(
        vault,
        &CampaignProgramStep {
            schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
            program_ref: program,
            step_ref: step,
            channel: CHANNEL.to_owned(),
            sender_ref: test_id(0x36),
            basis_evidence: test_id(0x37),
            outbound: Some(CampaignProgramOutbound {
                call_seq,
                verb: "send".to_owned(),
                payload: b"enrollment-body".to_vec(),
                idempotency_supported: true,
            }),
        },
    )
    .unwrap();
}

fn seniority_is(value: &str) -> FilterAst {
    FilterAst::Claim {
        predicate: SENIORITY.to_owned(),
        cmp: ClaimComparison::Eq,
        value: json!(value),
    }
}

/// Places `person` in `world` the way the engine models world membership.
fn place_in_world(vault: &Vault, person: EntityId, world: EntityId) {
    vault
        .put_entity(
            &world,
            ENTITY_TYPE_WORLD,
            TimeRange { start: 1, end: 1 },
            1,
            b"enrollment oracle world",
        )
        .unwrap();
    vault
        .put_edge(&person, EdgeKind::InWorld, &world, 1.0)
        .unwrap();
}

fn put_person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"enrollment oracle person",
        )
        .unwrap();
}

fn put_claim(vault: &Vault, claim_id: EntityId, subject: EntityId, predicate: &str, value: &str) {
    vault
        .put_claim(
            &claim_id,
            &ClaimBody::new(
                predicate,
                ClaimSubject::Entity(subject),
                rmpv::Value::from(value),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            ),
            TimeRange { start: 1, end: 1 },
            1,
        )
        .unwrap();
}

fn evaluator<'a>(vault: &'a Vault, grants: &'a QueryScope) -> SavedQueryEvaluator<'a> {
    SavedQueryEvaluator {
        vault,
        owner_grants: grants,
        judge: None,
    }
}

/// Detection through the public door; panics unless a transition was recorded.
fn detect(
    vault: &Vault,
    fixture: &Fixture,
    grants: &QueryScope,
    now: u64,
) -> CampaignEnrollmentEvent {
    detect_entity(vault, fixture, fixture.person, grants, now)
}

fn detect_entity(
    vault: &Vault,
    fixture: &Fixture,
    entity_ref: EntityId,
    grants: &QueryScope,
    now: u64,
) -> CampaignEnrollmentEvent {
    let evaluator = evaluator(vault, grants);
    match block_on(oneiron::campaign::enrollment::detect_enrollment(
        &evaluator,
        fixture.owner,
        &DetectEnrollment {
            entity_ref,
            ..fixture.detect(now)
        },
    ))
    .unwrap()
    {
        EnrollmentDetection::Recorded(event) => *event,
        EnrollmentDetection::NoTransition => panic!("expected a recorded transition"),
    }
}

fn enqueue(vault: &Vault, payload: &CampaignEnrollmentAttemptPayload, now: u64) -> AttemptRecord {
    match CampaignEnrollmentRunner::new(vault)
        .enqueue(payload, None, now)
        .unwrap()
    {
        EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record) => record,
        other => panic!("unexpected enqueue outcome: {other:?}"),
    }
}

fn claim(vault: &Vault, node: u64, now: u64) -> CampaignEnrollmentClaim {
    CampaignEnrollmentRunner::new(vault)
        .claim_if_home(node, format!("worker:{node}"), now)
        .unwrap()
}

fn claimed_record(vault: &Vault, node: u64, now: u64) -> AttemptRecord {
    match claim(vault, node, now) {
        CampaignEnrollmentClaim::Queue(ClaimOutcome::Claimed(record)) => record,
        other => panic!("expected a claim, got {other:?}"),
    }
}

fn execute(
    vault: &Vault,
    node: u64,
    record: &AttemptRecord,
    grants: &QueryScope,
    now: u64,
) -> EnrollmentExecution {
    let evaluator = evaluator(vault, grants);
    block_on(CampaignEnrollmentRunner::new(vault).execute_claimed(node, record, &evaluator, now))
        .unwrap()
}

fn member_field<'a>(value: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    value
        .as_map()?
        .iter()
        .find_map(|(candidate, inner)| (candidate.as_str() == Some(key)).then_some(inner))
}

/// Live `campaign.member` claims on `subject` derived from `query`, projected to
/// `(state kind, epoch, channels)`.
fn live_member_heads(
    vault: &Vault,
    subject: EntityId,
    query: EntityId,
) -> Vec<(String, u64, Vec<String>)> {
    vault
        .claims_for_subject(&subject)
        .unwrap()
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).unwrap())
        .filter(|body| {
            body.predicate == PREDICATE_CAMPAIGN_MEMBER
                && body.lifecycle == ClaimLifecycleStatus::Active
        })
        .filter_map(|body| {
            let derivation = member_field(&body.value, "derivation")?;
            if member_field(derivation, "source_query")?.as_str()? != query.to_hex() {
                return None;
            }
            let state = member_field(member_field(&body.value, "state")?, "kind")?
                .as_str()?
                .to_owned();
            let channels = member_field(&body.value, "channels")?
                .as_array()?
                .iter()
                .filter_map(|row| Some(member_field(row, "channel")?.as_str()?.to_owned()))
                .collect();
            Some((
                state,
                member_field(derivation, "epoch")?.as_u64()?,
                channels,
            ))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Attempt kind and payload
// ---------------------------------------------------------------------------

/// One kind string, one payload shape. No queue enum, no recurrence primitive,
/// and nothing authority-bearing on the wire.
#[test]
fn campaign_attempt_kind_is_exact() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let fixture = install_fixture(&vault);
    let grants = QueryScope::default();
    let event = detect(&vault, &fixture, &grants, 100);
    let payload = fixture.payload(event.event_ref);

    let record = enqueue(&vault, &payload, 100);
    assert_eq!(record.kind, "campaign.enrollment.macro");
    assert_eq!(record.kind, CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND);

    let wire: serde_json::Value =
        serde_json::from_slice(&encode_enrollment_attempt_payload(&payload)?).unwrap();
    let keys: Vec<&str> = wire
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        vec![
            "schema_version",
            "membership_event_ref",
            "campaign_program_ref",
            "program_step_ref"
        ],
        "refs only: no cause, epoch, evidence hash, timestamp, enrolled flag, \
         or outbound request rides the queue"
    );

    // The queue is shared. A foreign kind sitting in front of ours must neither
    // be claimed by this runner nor block it.
    AttemptQueue::new(&vault).enqueue(EnqueueAttempt {
        kind: "dreamer.consolidation.macro".to_owned(),
        payload: b"foreign".to_vec(),
        dedupe_key: None,
        run_id: None,
        now: 101,
    })?;
    assert_eq!(claimed_record(&vault, HOME_NODE, 102).id, record.id);
    Ok(())
}

// ---------------------------------------------------------------------------
// Home-node designation
// ---------------------------------------------------------------------------

/// Attached cloud beats always-on local beats primary device; the lowest stable
/// node id resolves a same-tier tie; a detached cloud node is not eligible at
/// all rather than silently demoted into a local tier.
#[test]
fn campaign_home_node_election_matches_preference_order() -> Result<()> {
    let (_dir, vault) = oracle_vault();

    let cloud = elect_campaign_home_node_designation(
        &vault,
        &[
            CampaignHomeNodeCandidate::primary_device(2),
            CampaignHomeNodeCandidate::always_on_local(9),
            CampaignHomeNodeCandidate::cloud(7, true),
        ],
        10,
    )?
    .expect("an eligible candidate exists");
    assert_eq!(cloud.class, CampaignHomeNodeClass::CloudAttached);
    assert_eq!(cloud.node_id, 7);

    let local = elect_campaign_home_node_designation(
        &vault,
        &[
            CampaignHomeNodeCandidate::cloud(7, false),
            CampaignHomeNodeCandidate::always_on_local(9),
            CampaignHomeNodeCandidate::always_on_local(3),
            CampaignHomeNodeCandidate::primary_device(2),
        ],
        11,
    )?
    .expect("an eligible candidate exists");
    assert_eq!(local.class, CampaignHomeNodeClass::AlwaysOnLocal);
    assert_eq!(local.node_id, 3, "lowest stable id wins inside a tier");

    assert_eq!(
        elect_campaign_home_node_designation(
            &vault,
            &[CampaignHomeNodeCandidate::cloud(7, false)],
            12
        )?,
        None,
        "an all-ineligible set clears the designation"
    );
    Ok(())
}

/// The campaign designation is campaign-local state. Electing one must not
/// create, move, or read the Dreamer's private MACRO designation.
#[test]
fn campaign_designation_uses_only_campaign_vault_meta_key() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let dreamer = DreamerRunnerStore::new(&vault);
    assert_eq!(dreamer.home_node_designation()?, None);

    let elected = elect_campaign_home_node_designation(
        &vault,
        &[CampaignHomeNodeCandidate::always_on_local(HOME_NODE)],
        20,
    )?
    .expect("an eligible candidate exists");

    assert_eq!(campaign_home_node_designation(&vault)?, Some(elected));
    assert_eq!(
        dreamer.home_node_designation()?,
        None,
        "the Dreamer's designation must be untouched by a campaign election"
    );
    assert!(matches!(
        require_campaign_home_node(&vault, HOME_NODE)?,
        CampaignHomeNodeAdmission::Designated(_)
    ));
    assert!(matches!(
        require_campaign_home_node(&vault, OTHER_NODE)?,
        CampaignHomeNodeAdmission::NotHomeNode(_)
    ));
    assert!(matches!(
        require_campaign_home_node(&vault, 0),
        Err(Error::InvalidConfig(_))
    ));
    Ok(())
}

/// A non-designated node is refused BEFORE the queue is touched, so the row it
/// could not have finished stays available to the node that can.
#[test]
fn non_home_node_cannot_claim_enrollment() {
    let (_dir, vault) = oracle_vault();
    let fixture = install_fixture(&vault);
    let grants = QueryScope::default();
    let event = detect(&vault, &fixture, &grants, 100);
    let queued = enqueue(&vault, &fixture.payload(event.event_ref), 100);

    assert!(matches!(
        claim(&vault, OTHER_NODE, 101),
        CampaignEnrollmentClaim::NotHomeNode(_)
    ));
    assert_eq!(
        claimed_record(&vault, HOME_NODE, 102).id,
        queued.id,
        "the refused claim must leave the row queued for the home node"
    );
}

/// A lease proves this node CLAIMED the work, not that it may still finish it.
/// Designation is re-read immediately before the consequence write.
#[test]
fn leadership_is_rechecked_before_consequence_write() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let fixture = install_fixture(&vault);
    let grants = QueryScope::default();
    let event = detect(&vault, &fixture, &grants, 100);
    enqueue(&vault, &fixture.payload(event.event_ref), 100);
    let record = claimed_record(&vault, HOME_NODE, 101);

    elect_campaign_home_node_designation(
        &vault,
        &[CampaignHomeNodeCandidate::always_on_local(OTHER_NODE)],
        102,
    )?;
    assert!(matches!(
        execute(&vault, HOME_NODE, &record, &grants, 103),
        EnrollmentExecution::NotHomeNode(designation) if designation.node_id == OTHER_NODE
    ));
    assert!(
        live_member_heads(&vault, fixture.person, fixture.query.query_ref).is_empty(),
        "a demoted node must not write"
    );

    // The new home node drains the same work.
    assert!(matches!(
        execute(&vault, OTHER_NODE, &record, &grants, 104),
        EnrollmentExecution::Applied { .. }
    ));
    assert_eq!(
        live_member_heads(&vault, fixture.person, fixture.query.query_ref).len(),
        1
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Re-derivation and cause routing
// ---------------------------------------------------------------------------

/// The payload is not a membership assertion. Move the live evidence after the
/// enqueue and execution re-derives through ONE-1773 instead of writing what
/// the queue row implies.
#[test]
fn enrollment_payload_is_refs_only_and_not_trusted_membership() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let fixture = install_fixture(&vault);
    let grants = QueryScope::default();
    let event = detect(&vault, &fixture, &grants, 100);
    enqueue(&vault, &fixture.payload(event.event_ref), 100);
    let record = claimed_record(&vault, HOME_NODE, 101);

    // The person stops matching AFTER the attempt was queued.
    put_claim(&vault, test_id(0x38), fixture.person, SENIORITY, "ic");

    assert_eq!(
        execute(&vault, HOME_NODE, &record, &grants, 102),
        EnrollmentExecution::SkippedStale
    );
    assert!(
        live_member_heads(&vault, fixture.person, fixture.query.query_ref).is_empty(),
        "no cohort row may be derived from a stale queue payload"
    );
    // The persisted event still says what it said; it is the WRITE that is
    // refused, not the history that is rewritten.
    assert_eq!(
        campaign_enrollment_event(&vault, event.event_ref)?
            .expect("event row")
            .evidence_hash,
        event.evidence_hash
    );
    Ok(())
}

/// A matching `data_change` entry writes exactly one CA-01 cohort row carrying
/// the program step's channel and the full `{source_query, evidence_hash,
/// epoch}` derivation.
#[test]
fn data_change_entered_event_auto_enrolls() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let fixture = install_fixture(&vault);
    let grants = QueryScope::default();
    let event = detect(&vault, &fixture, &grants, 100);
    assert_eq!(event.cause, MembershipCause::DataChange);
    assert_eq!(event.transition, MembershipTransition::Entered);
    assert_eq!(event.epoch, 1);

    enqueue(&vault, &fixture.payload(event.event_ref), 100);
    let record = claimed_record(&vault, HOME_NODE, 101);
    assert!(matches!(
        execute(&vault, HOME_NODE, &record, &grants, 102),
        EnrollmentExecution::Applied {
            outbound_intent: Some(_)
        }
    ));

    assert_eq!(
        live_member_heads(&vault, fixture.person, fixture.query.query_ref),
        vec![("enrolled".to_owned(), 1, vec![CHANNEL.to_owned()])]
    );
    let history = membership_events(&vault, fixture.query.query_ref, fixture.person)?;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].evidence_hash, event.evidence_hash);
    assert_eq!(history[0].cause, MembershipCause::DataChange);
    Ok(())
}

/// Bulk causes are the owner's call. They route to `ReviewRequired` with no
/// write and no send, and ordinary `data_change` keeps its automatic path — no
/// new per-lead approval gate is introduced.
#[test]
fn scope_and_definition_changes_require_review_not_auto_write() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let fixture = install_fixture(&vault);
    // The owner's reach is what MOVES in the second half, so the person needs a
    // world for a widened grant to be observable rather than vacuous.
    let home_world = test_id(0x39);
    place_in_world(&vault, fixture.person, home_world);
    let narrow = QueryScope {
        worlds: vec![home_world],
        facets: Vec::new(),
    };

    // First consequence establishes the derivation context.
    let first = detect(&vault, &fixture, &narrow, 100);
    enqueue(&vault, &fixture.payload(first.event_ref), 100);
    let record = claimed_record(&vault, HOME_NODE, 101);
    assert!(matches!(
        execute(&vault, HOME_NODE, &record, &narrow, 102),
        EnrollmentExecution::Applied { .. }
    ));

    // The DEFINITION moves; the person still matches.
    update_saved_query(
        &vault,
        fixture.owner,
        fixture.query.query_ref,
        &UpdateSavedQueryRequest {
            expected_definition_version: fixture.query.definition.definition_version,
            scope: QueryScope::default(),
            filter: seniority_is("vp"),
            matcher: MatcherSpec::Hard {
                expression: FilterAst::All {
                    terms: vec![seniority_is("vp")],
                },
            },
            eval: fixture.query.definition.eval,
        },
        200,
    )?;

    let definition_move = detect(&vault, &fixture, &narrow, 201);
    assert_eq!(definition_move.cause, MembershipCause::DefinitionChange);
    enqueue(&vault, &fixture.payload(definition_move.event_ref), 201);
    let record = claimed_record(&vault, HOME_NODE, 202);
    assert_eq!(
        execute(&vault, HOME_NODE, &record, &narrow, 203),
        EnrollmentExecution::ReviewRequired {
            cause: MembershipCause::DefinitionChange
        }
    );

    // The owner rules on the definition move, so the next detection compares
    // against IT rather than reporting the same move again.
    accept_enrollment_baseline(&vault, &definition_move)?;

    // The OWNER'S REACH moves; the person still matches. Same answer.
    let widened = QueryScope {
        worlds: vec![home_world, test_id(0x3A)],
        facets: Vec::new(),
    };
    let scope_move = detect(&vault, &fixture, &widened, 300);
    assert_eq!(scope_move.cause, MembershipCause::ScopeChange);
    // Both review-required transitions sit at the same unspent epoch, so the
    // advisory key would coalesce them. Enqueue without one: the routing dial
    // this test pins does not depend on the coalescer either way.
    AttemptQueue::new(&vault).enqueue(EnqueueAttempt {
        kind: CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND.to_owned(),
        payload: encode_enrollment_attempt_payload(&fixture.payload(scope_move.event_ref))?,
        dedupe_key: None,
        run_id: None,
        now: 300,
    })?;
    let record = claimed_record(&vault, HOME_NODE, 301);
    assert_eq!(
        execute(&vault, HOME_NODE, &record, &widened, 302),
        EnrollmentExecution::ReviewRequired {
            cause: MembershipCause::ScopeChange
        }
    );

    // Exactly the ONE automatic write from the data_change pass survives.
    assert_eq!(
        live_member_heads(&vault, fixture.person, fixture.query.query_ref),
        vec![("enrolled".to_owned(), 1, vec![CHANNEL.to_owned()])]
    );
    Ok(())
}

/// The cause baseline is the derivation state the OWNER last accepted for the
/// query, not the state the last detection happened to run under, and it is
/// held per query rather than per entity. Both differences are load-bearing:
/// advancing it at detection would let a definition move launder itself into
/// ordinary data movement on its second sighting, and holding it per entity
/// would leave the entities the move SWEPT IN with no row at all — and an
/// absent row can only read as data movement.
#[test]
fn a_definition_move_cannot_launder_itself_into_data_change() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let fixture = install_fixture(&vault);
    let grants = QueryScope::default();

    let before = detect(&vault, &fixture, &grants, 100);
    assert_eq!(before.cause, MembershipCause::DataChange);

    update_saved_query(
        &vault,
        fixture.owner,
        fixture.query.query_ref,
        &UpdateSavedQueryRequest {
            expected_definition_version: fixture.query.definition.definition_version,
            scope: QueryScope::default(),
            filter: seniority_is("vp"),
            matcher: MatcherSpec::Hard {
                expression: FilterAst::All {
                    terms: vec![seniority_is("vp")],
                },
            },
            eval: fixture.query.definition.eval,
        },
        200,
    )?;

    let first_sighting = detect(&vault, &fixture, &grants, 201);
    assert_eq!(first_sighting.cause, MembershipCause::DefinitionChange);

    // Nothing has been reviewed, so the SECOND sighting is not suddenly
    // ordinary data movement.
    let second_sighting = detect(&vault, &fixture, &grants, 202);
    assert_eq!(
        second_sighting.cause,
        MembershipCause::DefinitionChange,
        "an unreviewed definition move stays a definition move"
    );

    // An entity the moved definition sweeps in for the FIRST time has no
    // per-entity history to compare against at all.
    let newcomer = test_id(0x40);
    put_person(&vault, newcomer);
    put_claim(&vault, test_id(0x41), newcomer, SENIORITY, "vp");
    assert_eq!(
        detect_entity(&vault, &fixture, newcomer, &grants, 203).cause,
        MembershipCause::DefinitionChange,
        "the entities a widened definition swept in are exactly the ones review is for"
    );

    // The owner rules on the move. Its derivation state becomes the query's
    // new normal and ordinary data movement is automatic again — the routing
    // rule is a dial, not a wall.
    accept_enrollment_baseline(&vault, &second_sighting)?;
    assert_eq!(
        detect_entity(&vault, &fixture, newcomer, &grants, 204).cause,
        MembershipCause::DataChange
    );
    Ok(())
}

/// An exited, stale, or no-longer-matching event is a no-op — and that answer
/// outranks its cause. Parking a dead transition for owner review would fill
/// the review queue with work reality has already settled.
#[test]
fn stale_bulk_event_is_skipped_rather_than_parked_for_review() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let fixture = install_fixture(&vault);
    let grants = QueryScope::default();

    // First detection establishes the derivation baseline; the definition then
    // moves, so the next detection carries a bulk cause.
    detect(&vault, &fixture, &grants, 100);
    update_saved_query(
        &vault,
        fixture.owner,
        fixture.query.query_ref,
        &UpdateSavedQueryRequest {
            expected_definition_version: fixture.query.definition.definition_version,
            scope: QueryScope::default(),
            filter: seniority_is("vp"),
            matcher: MatcherSpec::Hard {
                expression: FilterAst::All {
                    terms: vec![seniority_is("vp")],
                },
            },
            eval: fixture.query.definition.eval,
        },
        200,
    )?;
    let definition_move = detect(&vault, &fixture, &grants, 201);
    assert_eq!(definition_move.cause, MembershipCause::DefinitionChange);

    AttemptQueue::new(&vault).enqueue(EnqueueAttempt {
        kind: CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND.to_owned(),
        payload: encode_enrollment_attempt_payload(&fixture.payload(definition_move.event_ref))?,
        dedupe_key: None,
        run_id: None,
        now: 201,
    })?;
    let record = claimed_record(&vault, HOME_NODE, 202);

    // Reality moves on before the attempt executes: the person stops matching.
    put_claim(&vault, test_id(0x3D), fixture.person, SENIORITY, "ic");

    assert_eq!(
        execute(&vault, HOME_NODE, &record, &grants, 203),
        EnrollmentExecution::SkippedStale,
        "a bulk cause does not rescue a transition that no longer describes reality"
    );
    assert!(live_member_heads(&vault, fixture.person, fixture.query.query_ref).is_empty());
    Ok(())
}

/// The cause and the outward call come from persisted rows. A caller cannot
/// present either, and refs that do not cross-bind fail closed.
#[test]
fn runner_derives_cause_and_outbound_request_from_persisted_state() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let fixture = install_fixture(&vault);
    let grants = QueryScope::default();
    let event = detect(&vault, &fixture, &grants, 100);
    let payload = fixture.payload(event.event_ref);
    let record = enqueue(&vault, &payload, 100);

    let request = derive_enrollment_outbound_request(&vault, &payload, &event, 1_000)?
        .expect("the step declares an outward leg");
    assert_eq!(request.call_seq, 7);
    // The ledger identity is the CONSEQUENCE's, not the queue row's. Deriving
    // it from the attempt id would make the send identity a function of how
    // many times the work was enqueued.
    assert_ne!(request.attempt_id, record.id);

    // Move the PERSISTED program step; the derived request moves with it.
    put_step(&vault, fixture.program, fixture.step, 9);
    assert_eq!(
        derive_enrollment_outbound_request(&vault, &payload, &event, 1_000)?
            .expect("the step declares an outward leg")
            .call_seq,
        9
    );

    // A program belonging to another campaign is not usable just because the
    // payload points at it.
    let foreign = test_id(0x3B);
    put_campaign_program(
        &vault,
        &CampaignProgram {
            schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
            program_ref: foreign,
            campaign_ref: test_id(0x3C),
        },
    )?;
    assert!(matches!(
        derive_enrollment_outbound_request(
            &vault,
            &CampaignEnrollmentAttemptPayload {
                campaign_program_ref: foreign,
                ..payload
            },
            &event,
            1_000,
        ),
        Err(Error::InvalidConfig(_))
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// The epoch watermark is the correctness mechanism
// ---------------------------------------------------------------------------

/// Two attempts for the same transition, enqueued with NO dedupe key at all,
/// still produce exactly one applied consequence. Dedupe is hygiene; the
/// watermark is correctness.
#[test]
fn advisory_dedupe_is_not_correctness() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let fixture = install_fixture(&vault);
    let grants = QueryScope::default();

    // Two detections before either executes: same epoch, same evidence, two
    // distinct durable event rows.
    let first = detect(&vault, &fixture, &grants, 100);
    let second = detect(&vault, &fixture, &grants, 100);
    assert_ne!(first.event_ref, second.event_ref);
    assert_eq!(first.epoch, second.epoch);
    assert_eq!(
        enrollment_dedupe_key(&vault, &fixture.payload(first.event_ref))?,
        enrollment_dedupe_key(&vault, &fixture.payload(second.event_ref))?,
        "two rows describing the identical transition are the same work"
    );

    // Bypass the coalescer entirely.
    let queue = AttemptQueue::new(&vault);
    for event_ref in [first.event_ref, second.event_ref] {
        queue.enqueue(EnqueueAttempt {
            kind: CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND.to_owned(),
            payload: encode_enrollment_attempt_payload(&fixture.payload(event_ref))?,
            dedupe_key: None,
            run_id: None,
            now: 101,
        })?;
    }

    let one = claimed_record(&vault, HOME_NODE, 102);
    let two = claimed_record(&vault, HOME_NODE, 103);
    assert_ne!(one.id, two.id, "both rows really are on the queue");
    assert!(matches!(
        execute(&vault, HOME_NODE, &one, &grants, 104),
        EnrollmentExecution::Applied { .. }
    ));
    assert!(matches!(
        execute(&vault, HOME_NODE, &two, &grants, 105),
        EnrollmentExecution::AlreadyApplied { .. }
    ));
    assert_eq!(
        live_member_heads(&vault, fixture.person, fixture.query.query_ref),
        vec![("enrolled".to_owned(), 1, vec![CHANNEL.to_owned()])]
    );
    Ok(())
}

/// Two DIFFERENT pending transitions share an epoch, because the epoch only
/// moves when a commit spends it. The advisory key must still tell them apart:
/// coalescing them would drop the newer, truer transition and leave the older
/// one to execute as stale — which is dedupe deciding what gets enrolled, the
/// one job it must never have.
#[test]
fn distinct_pending_transitions_do_not_share_a_dedupe_key() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let fixture = install_fixture(&vault);
    let first_world = test_id(0x3E);
    let second_world = test_id(0x3F);
    let grants = QueryScope {
        worlds: vec![first_world, second_world],
        facets: Vec::new(),
    };
    place_in_world(&vault, fixture.person, first_world);
    let first = detect(&vault, &fixture, &grants, 100);

    // The entity's own reach moves. It still matches, on different evidence,
    // and nothing has committed yet — so both transitions are pending at once.
    place_in_world(&vault, fixture.person, second_world);
    let second = detect(&vault, &fixture, &grants, 101);

    assert_eq!(first.epoch, second.epoch, "no commit has spent the epoch");
    assert_eq!(first.cause, second.cause);
    assert_ne!(first.evidence_hash, second.evidence_hash);
    assert_ne!(
        enrollment_dedupe_key(&vault, &fixture.payload(first.event_ref))?,
        enrollment_dedupe_key(&vault, &fixture.payload(second.event_ref))?,
        "an unspent epoch is not enough to make two transitions the same work"
    );

    // Both reach the queue as their own rows through the ordinary door.
    let one = enqueue(&vault, &fixture.payload(first.event_ref), 102);
    let two = enqueue(&vault, &fixture.payload(second.event_ref), 103);
    assert_ne!(one.id, two.id);
    Ok(())
}

/// Re-executing the SAME attempt is `AlreadyApplied`, and the outward-leg
/// identity it reports does not drift between runs.
#[test]
fn same_epoch_reexecution_is_already_applied() {
    let (_dir, vault) = oracle_vault();
    let fixture = install_fixture(&vault);
    let grants = QueryScope::default();
    let event = detect(&vault, &fixture, &grants, 100);
    enqueue(&vault, &fixture.payload(event.event_ref), 100);
    let record = claimed_record(&vault, HOME_NODE, 101);

    let EnrollmentExecution::Applied { outbound_intent } =
        execute(&vault, HOME_NODE, &record, &grants, 102)
    else {
        panic!("first execution must apply");
    };
    // A crash between the cohort write and the intent record re-enters HERE.
    // Membership is already done; the outward leg keeps its identity so the
    // send can still be recovered exactly once.
    assert_eq!(
        execute(&vault, HOME_NODE, &record, &grants, 103),
        EnrollmentExecution::AlreadyApplied { outbound_intent }
    );
    assert!(outbound_intent.is_some());
    assert_eq!(
        live_member_heads(&vault, fixture.person, fixture.query.query_ref).len(),
        1
    );
}

/// A replayed `Entered` from before an exit is REJECTED, never reported as
/// already-applied: reporting success would leave the cohort holding a
/// resurrected member the watermark exists to prevent.
#[test]
fn older_epoch_cannot_overwrite_newer_epoch() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let fixture = install_fixture(&vault);
    let grants = QueryScope::default();
    let event = detect(&vault, &fixture, &grants, 100);
    enqueue(&vault, &fixture.payload(event.event_ref), 100);
    let record = claimed_record(&vault, HOME_NODE, 101);
    assert!(matches!(
        execute(&vault, HOME_NODE, &record, &grants, 102),
        EnrollmentExecution::Applied { .. }
    ));

    // The cohort moves on without this attempt: an exit lands at epoch 2.
    let exit = MembershipEvent {
        query_ref: fixture.query.query_ref,
        campaign_ref: fixture.campaign,
        entity_ref: fixture.person,
        epoch: next_membership_epoch(&vault, fixture.query.query_ref, fixture.person)?,
        valid_at: 200,
        detected_at: 200,
        transition: MembershipTransition::Exited,
        cause: MembershipCause::DataChange,
        evidence_hash: event.evidence_hash,
    };
    assert_eq!(exit.epoch, 2);
    commit_membership_plan(
        &vault,
        &MembershipWritePlan {
            value: derived_member_value(
                &exit,
                CampaignMemberState::Exited,
                vec![oneiron::campaign::claims::CampaignMemberChannel {
                    channel: CHANNEL.to_owned(),
                    basis_evidence: test_id(0x37),
                    sender_ref: test_id(0x36),
                }],
            ),
            event: exit,
        },
        200,
    )?;

    assert_eq!(
        execute(&vault, HOME_NODE, &record, &grants, 300),
        EnrollmentExecution::RejectedStaleEpoch { current_epoch: 2 }
    );
    assert_eq!(
        live_member_heads(&vault, fixture.person, fixture.query.query_ref),
        vec![("exited".to_owned(), 2, vec![CHANNEL.to_owned()])],
        "the live claim and the watermark stay at the newer epoch"
    );
    Ok(())
}
