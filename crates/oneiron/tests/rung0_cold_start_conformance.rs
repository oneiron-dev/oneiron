#![cfg(feature = "sync")]
//! ONE-1346 — rung-0 cold-start conformance contract.
//!
//! Rung 0 is the vault a host gets before it has injected anything: no
//! embedder, no LLM backend, no vectors. This file pins what that vault
//! still promises, through public APIs only:
//!
//! 1. first-party CLAIM writes land and stay `Auto`;
//! 2. the default policy manifest is seeded by `Vault::open`
//!    (`vault.rs::seed_default_policy_manifest`, called from the
//!    `finish_open` seed site) — a public read observable exists
//!    (`Vault::entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)`), so this
//!    fixture asserts presence rather than merely citing the call site;
//! 3. the lexical (BM25F), graph (PPR), and temporal channels each answer
//!    independently with no vector channel configured;
//! 4. every retrieved CLAIM reports itself pending-embedding with a
//!    non-empty token instead of pretending a semantic vector exists;
//! 5. attaching one `Embedder` later is ordinary cold backfill, not an
//!    embedding-model migration.
//!
//! Rung 0 says nothing about retroactive Dreamer work: attaching an
//! `LlmBackend` does NOT guarantee a walk of pre-backend verbatim history.
//! Extraction and consolidation are guaranteed only for work explicitly
//! planned after backend availability. The engine has an explicit dirty-TURN
//! scan and an explicit partition-attempt enqueue in
//! `dreamer_consolidation.rs`, but the only production caller of
//! `enqueue_partition_attempts_in_txn` is `session_lifecycle.rs`'s
//! `end_session_with_wake` — a SessionEnd trigger, not a backend-attach
//! trigger. Nothing here may be read as a retroactive-extraction promise.
//!
//! `rung0_attach_uses_priority_three_without_migration_or_double_fill` is
//! authored strict and parked under `#[ignore]`: current main enqueues
//! ordinary local claim writes at `EMBED_PRIORITY_DEVICE` (`2`) even with
//! `embedding_model = None`, so the write-time assert-empty half of the
//! pinned invariant is red. Removing the ignore belongs to the owner-slate
//! engine ticket, not to this file.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use common::entity;
use oneiron::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_MODEL, ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST,
};
use oneiron::sync::{QueuedEmbedJob, SyncQueue};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EMBED_PRIORITY_BACKFILL,
    EdgeKind, Embedder, EmbedderLocality, EntityId, PendingEmbeddingInput,
    PendingEmbeddingReconciler, Result, RetrievalWithPendingVectors, ScoredEntity,
    TemporalAnchorMode, TimeRange, Vault, VaultConfig,
};
use rmpv::Value;

/// The joined engine-side identity of the BEAM deterministic test embedder:
/// `oneiron-eval/offline-deterministic-stub` at revision
/// `test-only-sha256-v1`. Test-only evidence; never a live-model claim.
const MODEL_ID: &str = "oneiron-eval/offline-deterministic-stub@test-only-sha256-v1";
const DIMENSIONS: usize = 8;

// Cross-repository identity table (binding; mirrored byte-for-byte by
// `oneiron-eval/tests/fixtures/beam/rung0_cold_start.run.jsonl` and
// `rung0_embedder_attach.pending.jsonl`).
const PERSON_SEED: u8 = 0x21;
const GRAPH_SEED: u8 = 0x22;
const LEXICAL_CLAIM_SEED: u8 = 0x31;
const GRAPH_CLAIM_SEED: u8 = 0x32;
const TEMPORAL_CLAIM_SEED: u8 = 0x33;

const LEXICAL_TEXT: &str = "The rung0lexemetoken identifies the lexical target.";
const GRAPH_TEXT: &str = "The graph seed points to the graph target.";
const TEMPORAL_TEXT: &str = "The temporal target is the latest pinned claim.";

const LEXICAL_TS: u64 = 1_700_000_001;
const GRAPH_TS: u64 = 1_700_000_002;
const TEMPORAL_TS: u64 = 1_700_000_003;

/// The lexical probe appears in exactly one claim text.
const LEXICAL_TOKEN: &str = "rung0lexemetoken";
/// Frozen retrieval clock: bit-exact replay is defined only under an
/// injected clock.
const TEMPORAL_NOW: u64 = 1_700_000_100;
const TEMPORAL_SIGMA_SECS: u64 = 3_600;

const CLAIM_PREDICATE: &str = "profile.note";
const QUERY_LIMIT: usize = 16;

/// Host-injected embedder that records which claims it was asked to embed
/// so the fixture can prove no claim is filled twice.
#[derive(Debug, Default)]
struct RecordingEmbedder {
    calls: Mutex<Vec<EntityId>>,
}

impl RecordingEmbedder {
    fn counts(&self) -> BTreeMap<EntityId, usize> {
        let calls = self.calls.lock().expect("recorder mutex is not poisoned");
        let mut counts = BTreeMap::new();
        for id in calls.iter() {
            *counts.entry(*id).or_insert(0_usize) += 1;
        }
        counts
    }
}

impl Embedder for RecordingEmbedder {
    fn model_id(&self) -> &str {
        MODEL_ID
    }

    fn dimensions(&self) -> usize {
        DIMENSIONS
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> Result<Vec<Vec<f32>>> {
        let mut calls = self.calls.lock().expect("recorder mutex is not poisoned");
        let mut vectors = Vec::with_capacity(inputs.len());
        for input in inputs {
            calls.push(input.entity_id);
            // Deterministic, non-zero, and derived only from the entity id:
            // the fixture proves scheduling, not embedding quality.
            let mut vector = vec![0.0_f32; DIMENSIONS];
            for (slot, byte) in vector.iter_mut().zip(input.entity_id.as_bytes()) {
                *slot = f32::from(*byte) / 255.0;
            }
            vectors.push(vector);
        }
        Ok(vectors)
    }
}

struct Rung0Fixture {
    lexical_claim: EntityId,
    graph_claim: EntityId,
    temporal_claim: EntityId,
    graph_seed: EntityId,
}

impl Rung0Fixture {
    fn claims(&self) -> [EntityId; 3] {
        [self.lexical_claim, self.graph_claim, self.temporal_claim]
    }
}

/// One model-free channel's replay projection. Deterministic fields only:
/// no wall-clock telemetry, no generated run ids, no queue timestamps.
#[derive(Debug, PartialEq, Eq)]
struct ChannelProjection {
    label: &'static str,
    result_ids: Vec<EntityId>,
    score_bits: Vec<(EntityId, u32)>,
    pending_ids: Vec<EntityId>,
    pending_tokens: Vec<(EntityId, Vec<u8>)>,
}

fn rung0_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = DIMENSIONS;
    assert!(
        config.embedding_model.is_none(),
        "rung 0 is a genuinely vector-less vault: embedding_model must be None before open"
    );
    config
}

fn attached_config() -> VaultConfig {
    // Identical to `rung0_config()` in every field except the attached model.
    let mut config = rung0_config();
    config.embedding_model = Some(MODEL_ID.to_owned());
    config
}

fn at(timestamp: u64) -> TimeRange {
    TimeRange {
        start: timestamp,
        end: timestamp,
    }
}

fn write_rung0_fixture(vault: &Vault) -> Result<Rung0Fixture> {
    let person = entity(PERSON_SEED);
    let graph_seed = entity(GRAPH_SEED);
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        at(LEXICAL_TS),
        LEXICAL_TS,
        b"rung0 conformance subject",
    )?;
    vault.put_entity(
        &graph_seed,
        ENTITY_TYPE_PERSON,
        at(GRAPH_TS),
        GRAPH_TS,
        b"rung0 conformance graph seed",
    )?;

    let fixture = Rung0Fixture {
        lexical_claim: entity(LEXICAL_CLAIM_SEED),
        graph_claim: entity(GRAPH_CLAIM_SEED),
        temporal_claim: entity(TEMPORAL_CLAIM_SEED),
        graph_seed,
    };

    for (id, text, timestamp) in [
        (fixture.lexical_claim, LEXICAL_TEXT, LEXICAL_TS),
        (fixture.graph_claim, GRAPH_TEXT, GRAPH_TS),
        (fixture.temporal_claim, TEMPORAL_TEXT, TEMPORAL_TS),
    ] {
        let body = ClaimBody::new(
            CLAIM_PREDICATE,
            ClaimSubject::Entity(person),
            Value::from(text),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        // No vectors anywhere on this path: rung 0 writes claims, not embeddings.
        vault.put_claim(&id, &body, at(timestamp), timestamp)?;
    }

    let about_weight = EdgeKind::About
        .default_weight()
        .expect("About carries a default stored weight");
    vault
        .batch()
        .text(&fixture.lexical_claim, &[("body", LEXICAL_TEXT)])
        .text(&fixture.graph_claim, &[("body", GRAPH_TEXT)])
        .text(&fixture.temporal_claim, &[("body", TEMPORAL_TEXT)])
        // Forward from the seed reaches only the graph claim, and no reverse
        // edge enters the seed, so the PPR target is unambiguous.
        .edge(
            &fixture.graph_seed,
            EdgeKind::About,
            &fixture.graph_claim,
            about_weight,
        )
        .commit()?;

    for id in fixture.claims() {
        let stored = vault
            .get_claim(&id)?
            .expect("first-party rung-0 claim is readable back");
        assert_eq!(
            stored.approval,
            ClaimApprovalStatus::Auto,
            "first-party rung-0 write must stay Auto for {id:?}"
        );
        assert_eq!(stored.lifecycle, ClaimLifecycleStatus::Active);
    }

    Ok(fixture)
}

fn score_bits(rows: &[ScoredEntity]) -> Vec<(EntityId, u32)> {
    rows.iter()
        .map(|row| (row.id, row.score.to_bits()))
        .collect()
}

/// One executed model-free channel: its label, its golden claim, and the
/// retrieval surface carrying pending-vector evidence.
type ChannelRun = (
    &'static str,
    EntityId,
    RetrievalWithPendingVectors<Vec<ScoredEntity>>,
);

/// Runs the three model-free channels independently. No `search_vector` call
/// exists on any of them — the vector channel is never configured at rung 0.
fn run_model_free_channels(vault: &Vault, fixture: &Rung0Fixture) -> Result<Vec<ChannelRun>> {
    let lexical = vault
        .query()
        .search_text(LEXICAL_TOKEN, QUERY_LIMIT)
        .filter_types(&[ENTITY_TYPE_CLAIM])
        .limit(QUERY_LIMIT)
        .run_with_pending_vectors()?;
    let graph = vault
        .query()
        .search_ppr(&[fixture.graph_seed], 1)
        .filter_types(&[ENTITY_TYPE_CLAIM])
        .limit(QUERY_LIMIT)
        .run_with_pending_vectors()?;
    let temporal = vault
        .query()
        .search_temporal_with_sigma(
            TEMPORAL_TS,
            TEMPORAL_TS,
            TEMPORAL_SIGMA_SECS,
            TemporalAnchorMode::Occurred,
            QUERY_LIMIT,
        )
        .with_temporal_now(TEMPORAL_NOW)
        .temporal_adaptive(false)
        .filter_types(&[ENTITY_TYPE_CLAIM])
        .limit(QUERY_LIMIT)
        .run_with_pending_vectors()?;

    Ok(vec![
        ("lexical", fixture.lexical_claim, lexical),
        ("graph", fixture.graph_claim, graph),
        ("temporal", fixture.temporal_claim, temporal),
    ])
}

fn projection(
    label: &'static str,
    result: &RetrievalWithPendingVectors<Vec<ScoredEntity>>,
) -> ChannelProjection {
    ChannelProjection {
        label,
        result_ids: result.value.iter().map(|row| row.id).collect(),
        score_bits: score_bits(&result.value),
        pending_ids: result.pending_vector_ids.clone(),
        pending_tokens: result
            .pending_vectors
            .iter()
            .map(|pending| (pending.id, pending.token.clone()))
            .collect(),
    }
}

fn model_free_projections() -> Result<Vec<ChannelProjection>> {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), rung0_config())?;
    let fixture = write_rung0_fixture(&vault)?;
    let channels = run_model_free_channels(&vault, &fixture)?;
    Ok(channels
        .iter()
        .map(|(label, _, result)| projection(label, result))
        .collect())
}

fn model_rows(vault: &Vault) -> Result<BTreeSet<EntityId>> {
    Ok(vault
        .entities_by_type(ENTITY_TYPE_MODEL)?
        .into_iter()
        .collect())
}

fn dump_jobs(jobs: &[QueuedEmbedJob]) -> String {
    if jobs.is_empty() {
        return "<empty>".to_owned();
    }
    jobs.iter()
        .map(|job| {
            format!(
                "{{entity_id={}, priority={}, queued_at={}}}",
                job.entity_id.to_hex(),
                job.priority,
                job.queued_at
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[test]
fn rung0_fresh_vault_answers_all_model_free_channels() -> Result<()> {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), rung0_config())?;

    // A public policy-manifest read observable exists, so the default seed
    // written by `Vault::open` is asserted, not merely cited.
    assert!(
        !vault
            .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)?
            .is_empty(),
        "Vault::open must seed the default policy manifest on a fresh vault"
    );

    let fixture = write_rung0_fixture(&vault)?;
    let claims: BTreeSet<EntityId> = fixture.claims().into_iter().collect();

    let mut pending_union: BTreeSet<EntityId> = BTreeSet::new();
    for (label, expected, result) in run_model_free_channels(&vault, &fixture)? {
        let returned: Vec<EntityId> = result.value.iter().map(|row| row.id).collect();
        assert!(
            returned.contains(&expected),
            "{label} channel must return its golden claim {expected:?}; got {returned:?}"
        );

        // Every fixture CLAIM this query returned must be honestly pending in
        // THIS query's own evidence — one query may not borrow another's.
        for id in fixture.claims() {
            if !returned.contains(&id) {
                continue;
            }
            let occurrences = result
                .pending_vector_ids
                .iter()
                .filter(|pending| **pending == id)
                .count();
            assert_eq!(
                occurrences, 1,
                "{label} channel returned {id:?} but reported it pending {occurrences} times"
            );
            let token = result
                .pending_vectors
                .iter()
                .find(|pending| pending.id == id)
                .map_or_else(
                    || panic!("{label} channel must expose a pending embedding for {id:?}"),
                    |pending| pending.token.clone(),
                );
            assert!(
                !token.is_empty(),
                "{label} channel pending token for {id:?} must be non-empty"
            );
        }

        pending_union.extend(result.pending_vector_ids.iter().copied());
    }

    assert_eq!(
        pending_union, claims,
        "the union of pending ids across the model-free channels must be exactly the fixture claims"
    );
    assert_eq!(
        vault.doctor()?.embedding_model_id,
        None,
        "rung 0 must not report an embedding model"
    );

    Ok(())
}

/// Parked: the strict cold-attach contract. Current main enqueues ordinary
/// local claim writes at `EMBED_PRIORITY_DEVICE` (`2`) even when
/// `embedding_model = None`, so phase 1's assert-empty check is red and the
/// exact-priority-3 attach scan does not exist yet.
///
/// Pinned invariant (owner-slate engine ticket): a vault opened with
/// `embedding_model = None` must not enqueue device-priority embed jobs at
/// write time; the attach reopen performs a cold-attach pending scan
/// enqueueing every pending row at `EMBED_PRIORITY_BACKFILL`; a pending row
/// already enqueued at a numerically higher urgency (e.g. surfaced-hot `0`)
/// keeps that urgency — it is already scheduled and the exact-priority-3
/// guarantee applies only to rows not previously surfaced. No priority-rewrite
/// exception in `push_embed_job_in_txn`: that would weaken urgency
/// preservation for every caller to serve one fixture.
#[test]
#[ignore = "blocked on <engine-ticket-id>: cold-attach backfill"]
fn rung0_attach_uses_priority_three_without_migration_or_double_fill() -> Result<()> {
    let dir = tempfile::tempdir().expect("temporary vault directory");

    // ─── Phase 1: rung-0 writes, one physical vault, no embedder ───
    let fixture;
    let models_before;
    {
        let vault = Arc::new(Vault::open(dir.path(), rung0_config())?);
        fixture = write_rung0_fixture(&vault)?;
        assert_eq!(
            vault.doctor()?.embedding_model_id,
            None,
            "phase 1 must be model-free"
        );
        models_before = model_rows(&vault)?;

        // Read-only queue inspection. `run_with_pending_vectors` is NOT
        // called on this phase: it would enqueue at surfaced-hot `0` and
        // corrupt the attach-priority evidence below.
        let queue = SyncQueue::new(Arc::clone(&vault))?;
        let jobs = queue.drain_embed_jobs()?;
        assert!(
            jobs.is_empty(),
            "a vault opened with embedding_model = None must not enqueue embed jobs at write \
             time; queue dump: [{}]",
            dump_jobs(&jobs)
        );
        drop(queue);
        drop(vault);
    }

    // ─── Phase 2: attach one embedder over the same physical vault ───
    let vault = Arc::new(Vault::open(dir.path(), attached_config())?);

    let queue = SyncQueue::new(Arc::clone(&vault))?;
    let jobs = queue.drain_embed_jobs()?;
    let queued: BTreeSet<EntityId> = jobs.iter().map(|job| job.entity_id).collect();
    assert_eq!(
        jobs.len(),
        3,
        "cold attach must enqueue exactly one job per pre-attach claim; queue dump: [{}]",
        dump_jobs(&jobs)
    );
    assert_eq!(
        queued,
        fixture.claims().into_iter().collect::<BTreeSet<_>>(),
        "cold attach must enqueue exactly the pre-attach fixture claims and nothing else; \
         queue dump: [{}]",
        dump_jobs(&jobs)
    );
    for job in &jobs {
        assert_eq!(
            job.priority,
            EMBED_PRIORITY_BACKFILL,
            "cold-attach backfill priority must be exactly {EMBED_PRIORITY_BACKFILL} for {}; \
             queue dump: [{}]",
            job.entity_id.to_hex(),
            dump_jobs(&jobs)
        );
    }
    drop(queue);

    let embedder = Arc::new(RecordingEmbedder::default());
    let reconciler = PendingEmbeddingReconciler::new(
        Arc::clone(&vault),
        Arc::clone(&embedder) as Arc<dyn Embedder>,
    );

    let first = reconciler.reconcile_once()?;
    assert_eq!(
        (first.leased, first.embedded, first.filled),
        (3, 3, 3),
        "one attached embedder must backfill every pre-attach claim: {first:?}"
    );
    assert_eq!(first.stale_fills, 0, "no stale fills on cold attach");

    let expected_counts: BTreeMap<EntityId, usize> =
        fixture.claims().into_iter().map(|id| (id, 1)).collect();
    assert_eq!(
        embedder.counts(),
        expected_counts,
        "each pre-attach claim must be embedded exactly once"
    );

    let second = reconciler.reconcile_once()?;
    assert_eq!(
        (second.leased, second.embedded, second.filled),
        (0, 0, 0),
        "the second reconcile pass must be empty: {second:?}"
    );
    assert_eq!(
        embedder.counts(),
        expected_counts,
        "the second reconcile pass must not re-embed any claim"
    );

    // Post-fill the model-free channels enqueue nothing: the pending markers
    // are cleared, and the queue inspection above has already completed.
    for (label, _, result) in run_model_free_channels(&vault, &fixture)? {
        assert!(
            result.pending_vector_ids.is_empty(),
            "{label} channel must report no pending embeddings after backfill: {:?}",
            result.pending_vector_ids
        );
    }

    assert_eq!(
        vault.doctor()?.embedding_model_id,
        Some(MODEL_ID.to_owned()),
        "attach must stamp exactly one model_id@revision"
    );
    // Cheap invariance guard, not migration evidence: no engine path writes
    // MODEL rows on attach.
    assert_eq!(
        model_rows(&vault)?,
        models_before,
        "attaching an embedder must not write MODEL records"
    );

    Ok(())
}

#[test]
fn rung0_model_free_replay_is_bit_exact() -> Result<()> {
    let first = model_free_projections()?;
    let second = model_free_projections()?;

    assert_eq!(first.len(), 3, "three model-free channels are projected");
    for (left, right) in first.iter().zip(second.iter()) {
        assert_eq!(left.label, right.label);
        assert_eq!(
            left.result_ids, right.result_ids,
            "{} ordered result ids must replay bit-exact",
            left.label
        );
        assert_eq!(
            left.score_bits, right.score_bits,
            "{} score bits must replay bit-exact",
            left.label
        );
        assert_eq!(
            left.pending_ids, right.pending_ids,
            "{} ordered pending ids must replay bit-exact",
            left.label
        );
        assert_eq!(
            left.pending_tokens, right.pending_tokens,
            "{} pending token bytes must replay bit-exact",
            left.label
        );
    }

    Ok(())
}
