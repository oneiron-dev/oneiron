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
//!    non-empty token instead of pretending a semantic vector exists.
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

use std::collections::BTreeSet;

use crate::common::entity;
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeKind, EntityId, Result,
    ScoredEntity, TimeRange, Vault, VaultConfig, pipeline::RetrievalWithPendingVectors,
    temporal::TemporalAnchorMode,
};
use rmpv::Value;

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

fn rung0_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = DIMENSIONS;
    assert!(
        config.embedding_model.is_none(),
        "rung 0 is a genuinely vector-less vault: embedding_model must be None before open"
    );
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
        )?;
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
