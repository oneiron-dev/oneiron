use core::assert_matches;
use std::collections::{BTreeMap, HashMap};

use super::*;
use crate::claim::ClaimSource;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::codebase::CODEBASE_SCOPE_KEY_LEN;
use crate::corpus::{CorpusId, CorpusScope, scope_with_corpus_id};
use crate::federation::FederationStaleReason;
use crate::query_expansion::HydeExpansion;
use crate::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_TURN};
use crate::test_util::embedding_test_config;

#[path = "../world_authority_tests.rs"]
mod world_authority_tests;

#[path = "../corpus_tests.rs"]
mod corpus_tests;

mod community_quality;
mod facet_status_world;
mod relationship_scope_filter;
mod rerank_hyde_session_stale;
mod retrieval_blend;
mod scoring_basics;
mod telemetry_trace;
mod temporal;
mod world_access;

use self::rerank_hyde_session_stale::{ClaimProbeReranker, ReversingReranker, StubHyde};
use self::world_access::{
    WORLD_ACCESS_NOW, WorldAccessRowSpec, world_access_body, world_access_fixture,
    world_access_ids, world_access_query, world_default_evidence,
};

// Shared with the sibling `decay_tests` module: the ONE-1402 read-side
// decay suite owns its own file but keeps using this module's canonical
// fixture helpers instead of forking them.
pub(super) fn open_test_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(embedding_test_config())
}

pub(super) fn entity_id(byte: u8) -> EntityId {
    crate::test_util::entity(byte)
}

fn put_entity(
    vault: &Vault,
    id: EntityId,
    entity_type: u8,
    start: u64,
    end: u64,
    learned: u64,
) -> Result<()> {
    vault.put_entity(
        &id,
        entity_type,
        TimeRange { start, end },
        learned,
        b"payload",
    )
}

fn put_text(vault: &Vault, id: EntityId, text: &str) -> Result<()> {
    put_text_at(vault, id, text, 1)
}

fn put_text_at(vault: &Vault, id: EntityId, text: &str, learned_at: u64) -> Result<()> {
    vault
        .batch()
        .put(
            &id,
            1,
            TimeRange { start: 1, end: 1 },
            learned_at,
            b"payload",
        )
        .text(&id, &[("body", text)])
        .commit()
}

fn put_text_with_time(
    vault: &Vault,
    id: EntityId,
    text: &str,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    vault
        .batch()
        .put(&id, 1, occurred, learned_at, b"payload")
        .text(&id, &[("body", text)])
        .commit()
}

fn active_claim_body(world: Option<EntityId>) -> Vec<u8> {
    let mut body = ClaimBody::new(
        "test.prefix_scope",
        crate::claim::ClaimSubject::Entity(entity_id(0x7C)),
        rmpv::Value::from("v"),
        0.9,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    body.world = world;
    crate::claim::encode_claim_body(&body).expect("encode claim body")
}

fn active_claim_body_with_salience(salience: f32) -> Vec<u8> {
    let mut body = ClaimBody::new(
        "test.blend_salience",
        crate::claim::ClaimSubject::Entity(entity_id(0x7D)),
        rmpv::Value::from("v"),
        0.9,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    body.salience = Some(salience);
    crate::claim::encode_claim_body(&body).expect("encode claim body")
}

pub(super) fn put_claim_text(
    vault: &Vault,
    id: EntityId,
    text: &str,
    world: Option<EntityId>,
) -> Result<()> {
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &active_claim_body(world),
        )
        .text(&id, &[("body", text)])
        .commit()
}

fn put_claim_text_with_salience(
    vault: &Vault,
    id: EntityId,
    text: &str,
    salience: f32,
) -> Result<()> {
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &active_claim_body_with_salience(salience),
        )
        .text(&id, &[("body", text)])
        .commit()
}

fn put_vector(vault: &Vault, id: EntityId, vector: [f32; 4]) -> Result<()> {
    put_vector_at(vault, id, vector, 1)
}

fn put_vector_at(vault: &Vault, id: EntityId, vector: [f32; 4], learned_at: u64) -> Result<()> {
    vault
        .batch()
        .put(
            &id,
            1,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            b"payload",
        )
        .vector(&id, &vector)
        .commit()
}

fn put_text_and_vector(vault: &Vault, id: EntityId, text: &str, vector: [f32; 4]) -> Result<()> {
    vault
        .batch()
        .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
        .text(&id, &[("body", text)])
        .vector(&id, &vector)
        .commit()
}

fn put_codebase_vector(
    vault: &Vault,
    id: EntityId,
    project_id: &str,
    repo_ref: RepoRef,
    vector: [f32; 4],
) -> Result<()> {
    let canonical_repo_ref = repo_ref.canonical();
    let commit_hash = canonical_repo_ref
        .split_once('#')
        .map(|(_, commit_hash)| commit_hash.to_owned());
    let body = crate::code_artifact::CodeArtifactBody::new(
        "Summarize the codebase snapshot.",
        [0xA5; crate::code_artifact::CODE_ARTIFACT_SUMMARY_HASH_LEN],
        canonical_repo_ref,
    );
    vault.put_code_artifact(&id, &body, TimeRange { start: 1, end: 1 }, 1)?;
    let content = b"pub fn vector_fixture() {}".to_vec();
    let snapshot = crate::codebase::CodebaseSnapshot::new(
        project_id,
        repo_ref,
        commit_hash,
        vec![crate::codebase::CodebaseFileEntry::new(
            "src/lib.rs",
            *blake3::hash(&content).as_bytes(),
            content.len() as u64,
        )],
    )?;
    vault.put_codebase_snapshot(&id, &snapshot, &|_| Some(content.clone()))?;
    vault.batch().vector(&id, &vector).commit()
}

fn put_text_and_vector_with_time(
    vault: &Vault,
    id: EntityId,
    text: &str,
    vector: [f32; 4],
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    vault
        .batch()
        .put(&id, 1, occurred, learned_at, b"payload")
        .text(&id, &[("body", text)])
        .vector(&id, &vector)
        .commit()
}

fn scored(id: EntityId, score: f32) -> ScoredEntity {
    ScoredEntity { id, score }
}

fn count_entries(db: &crate::overlay_db::OverlayDb, vault: &Vault) -> Result<usize> {
    let rtxn = vault.store.env.read_txn()?;
    let mut count = 0;
    for entry in db.iter(&rtxn)? {
        entry?;
        count += 1;
    }
    Ok(count)
}

pub(super) fn to_score_map(scores: &[ScoredEntity]) -> HashMap<EntityId, f32> {
    scores.iter().map(|entry| (entry.id, entry.score)).collect()
}

pub(super) fn approx_eq(left: f32, right: f32, eps: f32) -> bool {
    (left - right).abs() <= eps
}

fn trace_candidates_contain(candidates: &[RetrievalScoreBreakdown], id: EntityId) -> bool {
    candidates
        .iter()
        .any(|candidate| candidate.result_id == *id.as_bytes())
}

pub(super) fn captured_retrieval_trace(
    vault: &Vault,
    builder: PipelineBuilder<'_>,
) -> Result<RetrievalTrace> {
    captured_retrieval_run_trace(vault, builder).map(|(_, trace)| trace)
}

fn captured_retrieval_run_trace(
    vault: &Vault,
    builder: PipelineBuilder<'_>,
) -> Result<(RetrievalRunId, RetrievalTrace)> {
    let results = builder.capture_retrieval_trace(true).run_with_telemetry()?;
    let run_id = results
        .run_id
        .ok_or(Error::InvariantViolation("trace test missing run id"))?;
    let run = vault
        .retrieval_run(run_id)?
        .ok_or(Error::InvariantViolation("trace test missing run"))?;
    let trace = run
        .trace
        .ok_or(Error::InvariantViolation("trace test missing trace"))?;
    Ok((run_id, trace))
}

// ── ARCH-0039 facet filter (ONE-1117) ──────────────────────────

/// The query vector every facet test searches with.
const FACET_QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];

/// The frozen run clock every facet test queries under, equal to the
/// `learned_at` of every fixture row below.
///
/// ONE-1402 made read-side decay a post-fusion multiplier on CLAIM
/// candidates, so an unpinned wall clock would age these epoch-second
/// fixture claims by decades and floor them at `ACCESS_FACTOR_FLOOR` while
/// the non-claim rows stayed neutral — the facet contracts would then be
/// asserting decay arithmetic instead of facet scope. Freezing the clock at
/// the fixture's own `learned_at` gives every candidate age `0`, hence
/// factor `2^0 = 1.0` exactly, which is the decay-NEUTRAL baseline these
/// pins have always meant. Decay's own behavior is owned by `decay_tests`.
const FACET_NOW: u64 = 1;

/// Neutral four-signal blend score when no optional signals are enabled:
/// all z-normalized signal columns are zero, so `exp(0) = 1`.
const FACET_R0: f32 = 1.0;
const FACET_R1: f32 = 1.0;
const FACET_R2: f32 = 1.0;
const FACET_R3: f32 = 1.0;

struct FacetFixture {
    facet_a: EntityId,
    /// CLAIM, `FacetOf → facet_b`, vector rank 0.
    claim_other: EntityId,
    /// CLAIM, `FacetOf → facet_a`, vector rank 1.
    claim_active: EntityId,
    /// CLAIM, no `FacetOf` edge (core / unfaceted), vector rank 2.
    claim_core: EntityId,
    /// Non-claim (EVENT) carrying a `FacetOf → facet_b` edge, rank 3.
    event_faceted: EntityId,
}

fn facet_claim_body() -> Vec<u8> {
    let body = ClaimBody::new(
        "facet.scope_test",
        ClaimSubject::Entity(entity_id(0x7C)),
        rmpv::Value::from("v"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    crate::claim::encode_claim_body(&body).expect("encode claim body")
}

fn put_claim_with_vector(vault: &Vault, id: EntityId, vector: [f32; 4]) -> Result<()> {
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &facet_claim_body(),
        )
        .vector(&id, &vector)
        .commit()
}

/// A vector-ranked CLAIM whose body carries an optional `world` scope
/// (`None` = base reality). Built through the pinned claim encoder so the
/// `world` key is the real 16-byte binary the read side groups by.
fn put_claim_with_vector_world(
    vault: &Vault,
    id: EntityId,
    vector: [f32; 4],
    world: Option<EntityId>,
) -> Result<()> {
    let mut body = ClaimBody::new(
        "facet.scope_test",
        ClaimSubject::Entity(entity_id(0x7C)),
        rmpv::Value::from("v"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.world = world;
    let encoded = crate::claim::encode_claim_body(&body).expect("encode claim body");
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &encoded,
        )
        .vector(&id, &vector)
        .commit()
}

/// Two FACET entities + four vector-ranked candidates. Vector channel
/// distances to [`FACET_QUERY`] are strictly increasing, so the fused
/// baseline is exactly `[claim_other R0, claim_active R1, claim_core R2,
/// event_faceted R3]`.
fn setup_facet_fixture(vault: &Vault) -> Result<FacetFixture> {
    let facet_a = entity_id(0x91);
    let facet_b = entity_id(0xB1);
    put_entity(vault, facet_a, ENTITY_TYPE_FACET, 1, 1, 1)?;
    put_entity(vault, facet_b, ENTITY_TYPE_FACET, 1, 1, 1)?;

    let fixture = FacetFixture {
        facet_a,
        claim_other: entity_id(0x21),
        claim_active: entity_id(0x22),
        claim_core: entity_id(0x23),
        event_faceted: entity_id(0x24),
    };

    put_claim_with_vector(vault, fixture.claim_other, [1.0, 0.0, 0.0, 0.0])?;
    put_claim_with_vector(vault, fixture.claim_active, [0.8, 0.6, 0.0, 0.0])?;
    put_claim_with_vector(vault, fixture.claim_core, [0.6, 0.8, 0.0, 0.0])?;
    vault
        .batch()
        .put(
            &fixture.event_faceted,
            ENTITY_TYPE_EVENT,
            TimeRange { start: 1, end: 1 },
            1,
            b"payload",
        )
        .vector(&fixture.event_faceted, &[0.0, 1.0, 0.0, 0.0])
        .commit()?;

    vault
        .batch()
        .edge(&fixture.claim_other, EdgeKind::FacetOf, &facet_b, 0.7)
        .edge(&fixture.claim_active, EdgeKind::FacetOf, &facet_a, 0.7)
        .edge(&fixture.event_faceted, EdgeKind::FacetOf, &facet_b, 0.7)
        .commit()?;

    Ok(fixture)
}

fn ordered_results(scores: &[ScoredEntity]) -> Vec<(EntityId, f32)> {
    scores.iter().map(|entry| (entry.id, entry.score)).collect()
}

// ── D19 read-path claim status gate (ONE-1111) ─────────────────

fn claim_body_bytes(appr: ClaimApprovalStatus, life: ClaimLifecycleStatus, stale: bool) -> Vec<u8> {
    let mut body = ClaimBody::new(
        "test.status",
        ClaimSubject::Entity(EntityId::from_bytes([0x7C; 16]).expect("valid id")),
        rmpv::Value::from("v"),
        0.9,
        appr,
        life,
    );
    body.stale = stale;
    crate::claim::encode_claim_body(&body).expect("encode claim body")
}

pub(super) fn put_status_claim(
    vault: &Vault,
    id: EntityId,
    text: &str,
    appr: ClaimApprovalStatus,
    life: ClaimLifecycleStatus,
    stale: bool,
) -> Result<()> {
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &claim_body_bytes(appr, life, stale),
        )
        .text(&id, &[("body", text)])
        .commit()
}

/// Raw-writes an entity record (25-byte envelope + `body`), bypassing
/// every write-path validation — the AC 7 corruption fixture.
fn overwrite_entity_record(
    vault: &Vault,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<()> {
    let raw = crate::test_util::entity_record(entity_type, TimeRange { start: 1, end: 1 }, 1, body);
    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &raw)?;
        Ok(())
    })
}

// ── ONE-1420: world-access authority tiers and the per-turn ActiveSet ─────
//
// Three nested tiers, two of them ordinary bitemporal CLAIM rows and the
// third in-memory turn state: the owner's ALLOWED-SET, the agent's
// DEFAULT-SUBSET, and the per-turn selection. These rows pin what each tier
// may and may not do to a read — it may only ever NARROW, and no failure mode
// falls back to `WorldScope::All`.
