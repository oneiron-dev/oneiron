// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! ONE-1773 (CA-02) public-surface oracle for SAVED_QUERY.
//!
//! Everything here goes through the crate's PUBLIC API. The in-crate unit tests
//! in `src/saved_query/tests.rs` pin private encodings; this file pins the
//! behaviors a consumer (ONE-1774's consequence writer, ONE-1778's surfaces)
//! depends on — staged-evaluation ordering, memo invalidation, owner binding,
//! the epoch watermark, and the pack-drift ladder.

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use crate::common::entity as test_id;
use oneiron::campaign::claims::{
    CampaignMemberChannel, CampaignMemberState, CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER,
    encode_campaign_member_value,
};
use oneiron::campaign::{CRM_PACK_ID, register_crm_pack};
use oneiron::error::RegistryError;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use oneiron::saved_query::{
    SAVED_QUERY_SCHEMA_VERSION, commit_membership_plan, membership_events, next_membership_epoch,
    put_pack_migration_map, repair_pack_drift,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeKind, EntityId, Error,
    Result, TimeRange, Vault, VaultConfig, saved_query::ClaimComparison,
    saved_query::CreateSavedQueryRequest, saved_query::EvalMode, saved_query::EvalPolicy,
    saved_query::EvaluationRequest, saved_query::FilterAst, saved_query::MatchVerdict,
    saved_query::MatcherSpec, saved_query::MembershipCause, saved_query::MembershipCommitOutcome,
    saved_query::MembershipEvent, saved_query::MembershipTransition,
    saved_query::MembershipWritePlan, saved_query::PackDrift, saved_query::PackDriftResolution,
    saved_query::PackMigrationMap, saved_query::PackPredicateRewrite, saved_query::QueryScope,
    saved_query::SavedQueryEvaluator, saved_query::SavedQueryLifecycle,
    saved_query::SavedQueryRecord, saved_query::UpdateSavedQueryRequest,
};
use serde_json::{Value, json};

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

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config
}

/// A vault with NO pack installed. Only the registration oracle wants this: the
/// SAVED_QUERY definition is a real entity of the dynamically registered kind,
/// so every other test needs the pack.
fn raw_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).unwrap();
    (dir, vault)
}

/// Unseeded keeps the claim write door open without a policy fixture, matching
/// the CA-01 oracle's setup; the CRM pack is installed because saved queries are
/// entities of its dynamically registered kind.
fn oracle_vault() -> (tempfile::TempDir, Vault) {
    let (dir, vault) = raw_vault();
    register_crm_pack(
        &vault,
        107,
        108,
        oneiron::registry::TypeByteFamily::Productivity,
    )
    .unwrap();
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

fn put_world(vault: &Vault, id: &EntityId) {
    vault
        .put_entity(
            id,
            ENTITY_TYPE_WORLD,
            TimeRange { start: 1, end: 1 },
            1,
            b"saved query oracle world",
        )
        .unwrap();
}

/// Places `person` in `world` the way the engine models world membership.
fn place_in_world(vault: &Vault, person: &EntityId, world: &EntityId) {
    put_world(vault, world);
    vault
        .put_edge(person, EdgeKind::InWorld, world, 1.0)
        .unwrap();
}

fn put_claim(vault: &Vault, claim_id: &EntityId, subject: EntityId, predicate: &str, value: &str) {
    put_claim_body(vault, claim_id, claim_body(subject, predicate, value));
}

fn claim_body(subject: EntityId, predicate: &str, value: &str) -> ClaimBody {
    ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        rmpv::Value::from(value),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("fixture")
}

fn put_claim_body(vault: &Vault, claim_id: &EntityId, body: ClaimBody) {
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

/// ONE entry point means a host cannot be LEFT with half a pack. A bad second
/// byte is rejected before the first slot becomes durable, and re-running the
/// same call after any partial state converges instead of colliding with the
/// registration it already made.
#[test]
fn crm_pack_registration_never_leaves_half_a_pack() {
    let (_dir, vault) = raw_vault();

    // A CRM-band byte for SAVED_QUERY that collides with CAMPAIGN's own slot.
    assert!(matches!(
        register_crm_pack(
            &vault,
            107,
            107,
            oneiron::registry::TypeByteFamily::Productivity
        ),
        Err(Error::Registry(
            RegistryError::StructuralKindTypeByteCollision(107)
        ))
    ));
    // An out-of-band SAVED_QUERY byte.
    assert!(matches!(
        register_crm_pack(
            &vault,
            107,
            50,
            oneiron::registry::TypeByteFamily::Productivity
        ),
        Err(Error::Registry(
            RegistryError::StructuralKindZoneViolation { .. }
        ))
    ));
    assert_eq!(
        vault.structural_kind_registrations(),
        Vec::new(),
        "a rejected pack must not leave CAMPAIGN durable on its own"
    );

    // A half-install that DID happen (a bare CAMPAIGN registration) is repaired
    // by the whole-pack entry point rather than colliding with itself.
    let campaign = oneiron::campaign::register_campaign_kind(
        &vault,
        107,
        oneiron::registry::TypeByteFamily::Productivity,
    )
    .unwrap();
    let pack = register_crm_pack(
        &vault,
        107,
        108,
        oneiron::registry::TypeByteFamily::Productivity,
    )
    .unwrap();
    assert_eq!(pack.campaign, campaign, "the existing slot is reused");
    assert_eq!(pack.saved_query.type_byte, 108);

    // And the whole call is idempotent once both slots are installed.
    assert_eq!(
        register_crm_pack(
            &vault,
            107,
            108,
            oneiron::registry::TypeByteFamily::Productivity
        )
        .unwrap(),
        pack
    );
}

/// The version CAS is a real CAS: two writers that both believe version 1 is
/// current cannot both succeed. Comparing before the write transaction opens
/// would let the loser's definition overwrite the winner's with no error at
/// all, because LMDB's single-writer rule serializes the WRITES, not a compare
/// performed outside them.
#[test]
fn concurrent_updates_cannot_both_win_the_version_cas() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let owner = test_id(0x40);
    let request = create_request(
        claim_term(SENIORITY, ClaimComparison::Exists, Value::Null),
        MatcherSpec::Hard {
            expression: FilterAst::All { terms: Vec::new() },
        },
    );
    let created = oneiron::saved_query::create_saved_query(&vault, owner, &request, 10)?;

    let vault = Arc::new(vault);
    let update = |predicate: &'static str| {
        let vault = Arc::clone(&vault);
        let request = request.clone();
        let query_ref = created.query_ref;
        std::thread::spawn(move || {
            oneiron::saved_query::update_saved_query(
                &vault,
                owner,
                query_ref,
                &UpdateSavedQueryRequest {
                    expected_definition_version: 1,
                    scope: request.scope.clone(),
                    filter: claim_term(predicate, ClaimComparison::Exists, Value::Null),
                    matcher: request.matcher.clone(),
                    eval: request.eval,
                },
                20,
            )
        })
    };
    let outcomes = [update(HEADCOUNT), update(UNRELATED)]
        .map(|handle| handle.join().expect("update thread did not panic"));

    let winners = outcomes.iter().filter(|it| it.is_ok()).count();
    assert_eq!(winners, 1, "exactly one writer may win a version-1 CAS");
    assert!(
        outcomes
            .iter()
            .any(|it| matches!(it, Err(Error::ConcurrentWrite(_)))),
        "the loser must be told it lost, not silently overwrite the winner"
    );

    let stored = oneiron::saved_query::read_saved_query(&vault, owner, created.query_ref)?
        .expect("record survives");
    assert_eq!(stored.definition.definition_version, 2);
    let winner = outcomes
        .into_iter()
        .find_map(std::result::Result::ok)
        .expect("one winner");
    assert_eq!(
        stored.definition, winner.definition,
        "the stored definition is the winner's, never the loser's"
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
// Staged evaluation
// ---------------------------------------------------------------------------

/// The owner is the evaluation principal. Viewers are not an input at all, and
/// a scope the owner can no longer reach fails CLOSED.
#[test]
fn owner_actor_is_the_only_evaluation_principal() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let (owner, person, world) = (test_id(0x4B), test_id(0x4C), test_id(0x4D));
    put_person(&vault, &person);
    place_in_world(&vault, &person, &world);
    put_claim(&vault, &test_id(0x4E), person, SENIORITY, "director");

    // Base-reality evidence needs an explicit base grant: a named world no
    // longer implies base. Both the declared scope and the owner's reach
    // name the world AND base, so the effective scope honestly covers the
    // base claim this positive reads.
    let base = oneiron::claim::base_world_id();
    let mut request = create_request(
        claim_term(SENIORITY, ClaimComparison::Eq, json!("director")),
        MatcherSpec::Hard {
            expression: FilterAst::All { terms: Vec::new() },
        },
    );
    request.scope = QueryScope {
        worlds: vec![world, base],
        facets: Vec::new(),
    };
    let record = oneiron::saved_query::create_saved_query(&vault, owner, &request, 10)?;

    // Two different viewers read the SAME stored query and get the same
    // membership: the evaluator takes no viewer principal.
    let in_reach = QueryScope {
        worlds: vec![world, base],
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
    // The GRANT-CLOSED reason, not the stage-0 per-candidate one: both say
    // "scope", and only the named constant separates them.
    assert_eq!(
        closed.decision.why,
        oneiron::saved_query::SAVED_QUERY_WHY_SCOPE_CLOSED
    );
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

/// Evidence is read at the effective scope too: a claim scoped to a world the
/// query cannot reach is not evidence this query may act on. Base-reality
/// claims read only when base is explicitly in scope, mirroring the engine's
/// scoped-read world rule.
#[test]
fn out_of_scope_claim_evidence_does_not_satisfy_the_filter() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let (owner, world, elsewhere, person) =
        (test_id(0x90), test_id(0x91), test_id(0x92), test_id(0x93));
    put_person(&vault, &person);
    place_in_world(&vault, &person, &world);
    put_world(&vault, &elsewhere);

    // The ONLY `profile.seniority` claim lives in another world.
    let mut foreign = claim_body(person, SENIORITY, "director");
    foreign.world = Some(elsewhere);
    put_claim_body(&vault, &test_id(0x94), foreign);

    // Base is explicitly in scope alongside the named world, so the
    // foreign-world negative below still fails on world mismatch while the
    // base positive reads honestly.
    let base = oneiron::claim::base_world_id();
    let mut request = create_request(
        claim_term(SENIORITY, ClaimComparison::Eq, json!("director")),
        MatcherSpec::Hard {
            expression: FilterAst::All { terms: Vec::new() },
        },
    );
    request.scope = QueryScope {
        worlds: vec![world, base],
        facets: Vec::new(),
    };
    let record = oneiron::saved_query::create_saved_query(&vault, owner, &request, 10)?;
    let grants = QueryScope {
        worlds: vec![world, base],
        facets: Vec::new(),
    };
    let evaluator = SavedQueryEvaluator {
        vault: &vault,
        owner_grants: &grants,
        judge: None,
    };
    assert_eq!(
        block_on(evaluator.evaluate_entity(&evaluation(&record, person)))?
            .decision
            .verdict,
        MatchVerdict::NoMatch,
        "a claim scoped to an unreachable world is not evidence for this query"
    );

    // The same claim in base reality DOES read when base is in scope.
    put_claim(&vault, &test_id(0x95), person, SENIORITY, "director");
    assert_eq!(
        block_on(evaluator.evaluate_entity(&evaluation(&record, person)))?
            .decision
            .verdict,
        MatchVerdict::Match
    );
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

/// Reads one key out of an encoded `campaign.member` map. The decoder itself is
/// CA-01-private, so the oracle reads the wire shape the CA-01 encoder produced.
fn member_field<'a>(value: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    value
        .as_map()?
        .iter()
        .find_map(|(candidate, inner)| (candidate.as_str() == Some(key)).then_some(inner))
}

/// Live `campaign.member` claims on `subject` derived from `query`, projected to
/// `(state kind, epoch)`.
fn live_member_heads(vault: &Vault, subject: EntityId, query: EntityId) -> Vec<(String, u64)> {
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
            let source = member_field(derivation, "source_query")?
                .as_str()?
                .to_owned();
            if source != query.to_hex() {
                return None;
            }
            let state = member_field(member_field(&body.value, "state")?, "kind")?
                .as_str()?
                .to_owned();
            Some((state, member_field(derivation, "epoch")?.as_u64()?))
        })
        .collect()
}

/// A transition REPLACES the cohort head. Without same-txn supersession,
/// Entered -> Exited -> Entered would leave three live `campaign.member` claims
/// on one person carrying mutually incompatible states, and every subject-claim
/// reader would see all three as current truth.
#[test]
fn membership_transitions_leave_exactly_one_live_head() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let (query, campaign, person) = (test_id(0xB0), test_id(0xB1), test_id(0xB2));
    put_person(&vault, &person);

    for (epoch, transition, at) in [
        (1, MembershipTransition::Entered, 100),
        (2, MembershipTransition::Exited, 200),
        (3, MembershipTransition::Entered, 300),
    ] {
        assert_eq!(
            commit_membership_plan(
                &vault,
                &write_plan(
                    query,
                    campaign,
                    person,
                    epoch,
                    transition,
                    MembershipCause::DataChange,
                    at,
                ),
                at,
            )?,
            MembershipCommitOutcome::Applied
        );
        let expected = match transition {
            MembershipTransition::Entered => "enrolled",
            MembershipTransition::Exited => "exited",
        };
        assert_eq!(
            live_member_heads(&vault, person, query),
            vec![(expected.to_owned(), epoch)],
            "epoch {epoch} must leave exactly one live head"
        );
    }
    assert_eq!(
        membership_events(&vault, query, person)?.len(),
        3,
        "closing the prior head never erases event history"
    );
    Ok(())
}

/// The epoch floor is replica-convergent. A node holding replicated
/// `campaign.member` claims but no local watermark row (the promoted-home-node
/// case) must continue the sequence, not restart at 1 and re-mint epochs its
/// peers already spent.
#[test]
fn membership_epoch_floor_survives_a_promoted_node_with_no_local_watermark() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let (query, campaign, person) = (test_id(0xB3), test_id(0xB4), test_id(0xB5));
    put_person(&vault, &person);

    // A replicated derived-membership claim arriving from a peer: the claim
    // lands, the peer's node-local watermark row does not.
    let replicated = CampaignMemberValue {
        campaign,
        state: CampaignMemberState::Enrolled,
        channels: vec![member_channel()],
        derivation: Some(oneiron::campaign::claims::CampaignMemberDerivation {
            source_query: query,
            evidence_hash: [7u8; 32],
            epoch: 5,
        }),
    };
    put_claim_body(
        &vault,
        &test_id(0xB6),
        ClaimBody::new(
            PREDICATE_CAMPAIGN_MEMBER,
            ClaimSubject::Entity(person),
            encode_campaign_member_value(&replicated),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )?,
    );

    assert_eq!(
        next_membership_epoch(&vault, query, person)?,
        6,
        "the replicated claim chain is the epoch floor"
    );
    assert_eq!(
        commit_membership_plan(
            &vault,
            &write_plan(
                query,
                campaign,
                person,
                3,
                MembershipTransition::Entered,
                MembershipCause::DataChange,
                400,
            ),
            400,
        )?,
        MembershipCommitOutcome::RejectedStaleEpoch { current_epoch: 5 },
        "an epoch a peer already spent must not be re-minted locally"
    );
    assert_eq!(
        commit_membership_plan(
            &vault,
            &write_plan(
                query,
                campaign,
                person,
                6,
                MembershipTransition::Entered,
                MembershipCause::DataChange,
                500,
            ),
            500,
        )?,
        MembershipCommitOutcome::Applied
    );
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

/// Pack repair goes through the same versioned, validated, lifecycle-respecting
/// door as an owner edit. It cannot overwrite a concurrent update, reopen an
/// archived query, or persist a rewrite target the write door would reject.
#[test]
fn pack_repair_respects_the_definition_write_door() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let owner = test_id(0xC1);
    let moved = drift(SENIORITY);
    let renames = |to: &str| PackMigrationMap {
        rewrites: [(
            SENIORITY.to_owned(),
            PackPredicateRewrite::Rename { to: to.to_owned() },
        )]
        .into_iter()
        .collect(),
    };

    // A repair planned from version 1 loses to an owner update that already
    // landed, instead of silently reverting it.
    put_pack_migration_map(&vault, &moved, &renames(HEADCOUNT))?;
    let stale_plan = drifting_query(&vault, owner)?;
    let updated = oneiron::saved_query::update_saved_query(
        &vault,
        owner,
        stale_plan.query_ref,
        &UpdateSavedQueryRequest {
            expected_definition_version: 1,
            scope: stale_plan.definition.scope.clone(),
            filter: claim_term(UNRELATED, ClaimComparison::Exists, Value::Null),
            matcher: stale_plan.definition.matcher.clone(),
            eval: stale_plan.definition.eval,
        },
        20,
    )?;
    assert!(matches!(
        repair_pack_drift(
            &vault,
            stale_plan.query_ref,
            &stale_plan.definition,
            &moved,
            100
        ),
        Err(Error::ConcurrentWrite(_))
    ));
    assert_eq!(
        oneiron::saved_query::read_saved_query(&vault, owner, stale_plan.query_ref)?
            .expect("record survives")
            .definition,
        updated.definition,
        "the owner's update survives the stale repair"
    );

    // An archived query is not reopened by a repair.
    let archived_query = drifting_query(&vault, owner)?;
    let archived =
        oneiron::saved_query::archive_saved_query(&vault, owner, archived_query.query_ref, 1, 30)?;
    assert!(matches!(
        repair_pack_drift(
            &vault,
            archived.query_ref,
            &archived.definition,
            &moved,
            110
        ),
        Err(Error::InvalidConfig(_))
    ));
    assert_eq!(
        oneiron::saved_query::read_saved_query(&vault, owner, archived.query_ref)?
            .expect("record survives")
            .definition
            .lifecycle,
        SavedQueryLifecycle::Archived
    );

    // A rewrite target the write door would never accept pauses the query
    // rather than being persisted as an active definition.
    put_pack_migration_map(&vault, &moved, &renames("top_k"))?;
    let poisoned = drifting_query(&vault, owner)?;
    assert!(matches!(
        repair_pack_drift(
            &vault,
            poisoned.query_ref,
            &poisoned.definition,
            &moved,
            120
        )?,
        PackDriftResolution::Paused { .. }
    ));
    let stored = oneiron::saved_query::read_saved_query(&vault, owner, poisoned.query_ref)?
        .expect("record survives");
    assert!(matches!(
        stored.definition.lifecycle,
        SavedQueryLifecycle::Paused { .. }
    ));
    assert_eq!(
        stored.definition.filter, poisoned.definition.filter,
        "an invalid rewrite is never persisted"
    );
    Ok(())
}
