//! [BOUNDED-CHANNEL-NARROWING-OMITS-CRITICALITY-STALE-DISCLOSURE]: a call
//! narrowed by the manifest's criticality tier asks that tier at the vector,
//! text and temporal fetches, so a claim of the other tier takes no rank in
//! the first blend; a run under every world asks the stale federated worlds
//! there too, so a claim of a world a terminal pact stamped stale takes none
//! either. Before, these channels decided whether to ask the call's scope by
//! a narrowing test that left both out: such a run fetched the claim
//! unasked, counted it as a candidate in scope, and the post-blend filter
//! that dropped it made the run read `FilterMatchedNone`, the defect class
//! of [PHONETIC-EXACT-HITS-UNSCOPED-BEFORE-BLEND].
//!
//! Each tier test first asks with the claim's own tier, and each stale-world
//! test first stamps another world stale: the narrowed fetch still finds the
//! claim.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test bounded_channel_narrowing_scope` (the
//! stale stamp is stored through a test door).

#![cfg(oneiron_test_support)]

use oneiron::entity_id::ForeignWorldId;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::RetrievalRunRecord;
use oneiron::test_doors::stale_world_stamp::stamp_world_stale;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    PipelineBuilder, TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};

const DAY: u64 = 86_400;
const ANCHOR: u64 = 1_700_000_000;
/// The temporal runs' clock: a day after the claim occurred and was learned.
const NOW: u64 = ANCHOR + DAY;
const DIMENSIONS: usize = 4;
/// The text runs' query word; the claim's indexed body holds it alone.
const WORD: &str = "quokka";
/// No rule of the shipped manifest names this predicate, so it resolves
/// critical by fallback (`tests/owner_approval_criticality_floor.rs`).
const UNDECLARED_PREDICATE: &str = "loop.alpha";
/// The foreign world the stale-world tests' claim is scoped to.
const CLAIM_WORLD: u8 = 0xf5;
/// A foreign world no claim names.
const OTHER_WORLD: u8 = 0xf6;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
}

/// A vault whose runs record their telemetry, so a test reads each run's
/// candidate count and empty reason.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    config.dimensions = DIMENSIONS;
    // A vector write needs a declared embedding model.
    config.embedding_model = Some("test/model@v1".to_owned());
    config.retrieval_telemetry_capture = true;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    Fixture { _dir: dir, vault }
}

/// The foreign-range world whose id is `byte` sixteen times.
fn foreign_world(byte: u8) -> ForeignWorldId {
    ForeignWorldId::from_entity_id(EntityId::from_bytes([byte; 16]).expect("FIXTURE: world id"))
        .expect("FIXTURE: a foreign-range world id")
}

/// `query` narrowed to the `critical` tier, or asking every tier on `None`.
fn in_tier(query: PipelineBuilder<'_>, tier: Option<bool>) -> PipelineBuilder<'_> {
    match tier {
        Some(critical) => query.criticality(critical),
        None => query,
    }
}

/// The query vector every vector run asks with.
fn query_vector() -> Vec<f32> {
    vec![1.0, 0.0, 0.0, 0.0]
}

/// What a run returned and what its record says of it.
#[derive(Debug, PartialEq, Eq)]
struct Run {
    ids: Vec<EntityId>,
    total_in_scope: usize,
    empty_reason: Option<String>,
}

/// A run that returned `id` alone, its one candidate in scope.
fn found(id: EntityId) -> Run {
    Run {
        ids: vec![id],
        total_in_scope: 1,
        empty_reason: None,
    }
}

/// A run that met no candidate in scope.
fn no_data() -> Run {
    Run {
        ids: Vec::new(),
        total_in_scope: 0,
        empty_reason: Some("NoData".to_owned()),
    }
}

impl Fixture {
    /// One live critical claim, the vault's only row any channel finds: its
    /// vector is the query's, its indexed body is [`WORD`], and it occurred
    /// and was learned at [`ANCHOR`].
    fn critical_claim(&self) -> EntityId {
        self.claim(None)
    }

    /// As [`Self::critical_claim`], scoped to the foreign `world`.
    fn claim_of_world(&self, world: ForeignWorldId) -> EntityId {
        self.claim(Some(world))
    }

    fn claim(&self, world: Option<ForeignWorldId>) -> EntityId {
        let vault = &self.vault;
        let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
        let subject = EntityId::now();
        for id in [actor.entity_ref(), subject] {
            vault
                .put_entity(
                    &id,
                    ENTITY_TYPE_PERSON,
                    TimeRange { start: 1, end: 1 },
                    1,
                    b"",
                )
                .expect("FIXTURE: put person");
        }
        let envelope = WriteEnvelope::new(
            actor,
            ClaimSource::UserStated,
            WriteProvenance::new(rmpv::Value::from("bounded channel narrowing"))
                .expect("FIXTURE: provenance"),
            ClaimApprovalStatus::Auto,
        );
        let mut candidate = ClaimCandidate::new(
            UNDECLARED_PREDICATE,
            ClaimSubject::Entity(subject),
            rmpv::Value::from("fact"),
            1.0,
        );
        if let Some(world) = world {
            candidate = candidate.with_world(world.entity_id());
        }
        let claim = EntityId::now();
        vault
            .batch()
            .claim_candidate(
                &claim,
                candidate,
                &envelope,
                TimeRange {
                    start: ANCHOR,
                    end: ANCHOR,
                },
                ANCHOR,
            )
            .commit()
            .expect("FIXTURE: write the claim");
        vault
            .put_vector(&claim, &query_vector())
            .expect("FIXTURE: put the claim's vector");
        vault
            .batch()
            .text(&claim, &[("body", WORD)])
            .commit()
            .expect("FIXTURE: index the claim's text");
        claim
    }

    /// A vector run in `tier` ([`in_tier`]).
    fn vector(&self, tier: Option<bool>) -> Run {
        self.recorded(in_tier(
            self.vault.query().search_vector(&query_vector(), 1),
            tier,
        ))
    }

    /// A text run in `tier`, with no recency blend.
    fn text(&self, tier: Option<bool>) -> Run {
        self.recorded(in_tier(
            self.vault.query().search_text(WORD, 1).boost_recency(0.0),
            tier,
        ))
    }

    /// A temporal run at [`ANCHOR`] in `tier`, with no recency blend.
    fn temporal(&self, tier: Option<bool>) -> Run {
        self.recorded(in_tier(
            self.vault
                .query()
                .with_temporal_now(NOW)
                .search_temporal(ANCHOR, ANCHOR, 1)
                .boost_recency(0.0),
            tier,
        ))
    }

    fn recorded(&self, query: PipelineBuilder<'_>) -> Run {
        let run = query
            .limit(10)
            .capture_retrieval_trace(true)
            .run_with_telemetry()
            .expect("query");
        let run_id = run
            .run_id
            .expect("FIXTURE: a captured run names its record");
        let record: RetrievalRunRecord = self
            .vault
            .retrieval_run(run_id)
            .expect("read the run record")
            .expect("FIXTURE: the run record is readable");
        Run {
            ids: run.value.into_iter().map(|row| row.id).collect(),
            total_in_scope: record.total_in_scope,
            empty_reason: record.empty_reason,
        }
    }
}

/// A vector run narrowed to the normal tier, whose only hit is a critical
/// claim, counts no candidate in scope and reads `NoData`.
#[test]
fn a_tier_narrowed_vector_run_counts_no_claim_of_the_other_tier() {
    let fixture = fixture();
    let claim = fixture.critical_claim();
    assert_eq!(
        fixture.vector(Some(true)),
        found(claim),
        "GUARD: narrowed to its own tier, the vector fetch finds the claim"
    );
    assert_eq!(
        fixture.vector(Some(false)),
        no_data(),
        "FAILBEFORE BOUNDED-CHANNEL-NARROWING-OMITS-CRITICALITY-STALE-DISCLOSURE: the vector \
         fetch left the tier unasked, so the critical claim counted as a candidate and the \
         post-blend filter made the run read FilterMatchedNone"
    );
}

/// A text run narrowed to the normal tier, whose only hit is a critical
/// claim, counts no candidate in scope and reads `NoData`.
#[test]
fn a_tier_narrowed_text_run_counts_no_claim_of_the_other_tier() {
    let fixture = fixture();
    let claim = fixture.critical_claim();
    assert_eq!(
        fixture.text(Some(true)),
        found(claim),
        "GUARD: narrowed to its own tier, the text scan finds the claim"
    );
    assert_eq!(
        fixture.text(Some(false)),
        no_data(),
        "FAILBEFORE BOUNDED-CHANNEL-NARROWING-OMITS-CRITICALITY-STALE-DISCLOSURE: the text \
         scan left the tier unasked, so the critical claim counted as a candidate and the \
         post-blend filter made the run read FilterMatchedNone"
    );
}

/// A temporal run narrowed to the normal tier, whose only hit is a critical
/// claim, counts no candidate in scope and reads `NoData`.
#[test]
fn a_tier_narrowed_temporal_run_counts_no_claim_of_the_other_tier() {
    let fixture = fixture();
    let claim = fixture.critical_claim();
    assert_eq!(
        fixture.temporal(Some(true)),
        found(claim),
        "GUARD: narrowed to its own tier, the temporal window finds the claim"
    );
    assert_eq!(
        fixture.temporal(Some(false)),
        no_data(),
        "FAILBEFORE BOUNDED-CHANNEL-NARROWING-OMITS-CRITICALITY-STALE-DISCLOSURE: the temporal \
         window left the tier unasked, so the critical claim counted as a candidate and the \
         post-blend filter made the run read FilterMatchedNone"
    );
}

/// A run under every world whose only hit is a claim of a world a terminal
/// pact stamped stale counts no candidate in scope and reads `NoData`. With
/// only another world stale, the narrowed fetch still finds the claim.
fn assert_stale_world_claim_counts_as_no_candidate(run: impl Fn(&Fixture) -> Run, fetch: &str) {
    let fixture = fixture();
    let world = foreign_world(CLAIM_WORLD);
    let claim = fixture.claim_of_world(world);
    stamp_world_stale(&fixture.vault, foreign_world(OTHER_WORLD))
        .expect("FIXTURE: stamp another world stale");
    assert_eq!(
        run(&fixture),
        found(claim),
        "GUARD: with another world stale, the {fetch} finds the claim of a live world"
    );
    stamp_world_stale(&fixture.vault, world).expect("FIXTURE: stamp the claim's world stale");
    assert_eq!(
        run(&fixture),
        no_data(),
        "FAILBEFORE BOUNDED-CHANNEL-NARROWING-OMITS-CRITICALITY-STALE-DISCLOSURE: the {fetch} \
         left the stale worlds unasked, so the stale world's claim counted as a candidate and \
         the post-blend filter made the run read FilterMatchedNone"
    );
}

#[test]
fn a_vector_run_counts_no_claim_of_a_stale_world() {
    assert_stale_world_claim_counts_as_no_candidate(|fixture| fixture.vector(None), "vector fetch");
}

#[test]
fn a_text_run_counts_no_claim_of_a_stale_world() {
    assert_stale_world_claim_counts_as_no_candidate(|fixture| fixture.text(None), "text scan");
}

#[test]
fn a_temporal_run_counts_no_claim_of_a_stale_world() {
    assert_stale_world_claim_counts_as_no_candidate(
        |fixture| fixture.temporal(None),
        "temporal window",
    );
}
