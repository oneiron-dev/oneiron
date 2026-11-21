//! [BOUNDED-CHANNEL-NARROWING-OMITS-CRITICALITY-STALE-DISCLOSURE]: a call
//! narrowed by the manifest's criticality tier asks that tier at the vector,
//! text and temporal fetches, so a claim of the other tier takes no rank in
//! the first blend. Before, these channels decided whether to ask the
//! call's scope by a narrowing test that left criticality out: an owner run
//! narrowed only by tier fetched the claim unasked, counted it as a
//! candidate in scope, and the post-blend filter that dropped it made the
//! run read `FilterMatchedNone`, the defect class of
//! [PHONETIC-EXACT-HITS-UNSCOPED-BEFORE-BLEND].
//!
//! Each test first asks with the claim's own tier: the narrowed fetch still
//! finds it.
//!
//! Run with `cargo test --locked -p oneiron --all-features --test
//! bounded_channel_narrowing_scope`.

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::RetrievalRunRecord;
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
        let claim = EntityId::now();
        vault
            .batch()
            .claim_candidate(
                &claim,
                ClaimCandidate::new(
                    UNDECLARED_PREDICATE,
                    ClaimSubject::Entity(subject),
                    rmpv::Value::from("fact"),
                    1.0,
                ),
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

    /// A vector run narrowed to the `critical` tier.
    fn vector(&self, critical: bool) -> Run {
        self.recorded(
            self.vault
                .query()
                .search_vector(&query_vector(), 1)
                .criticality(critical),
        )
    }

    /// A text run narrowed to the `critical` tier, with no recency blend.
    fn text(&self, critical: bool) -> Run {
        self.recorded(
            self.vault
                .query()
                .search_text(WORD, 1)
                .boost_recency(0.0)
                .criticality(critical),
        )
    }

    /// A temporal run at [`ANCHOR`] narrowed to the `critical` tier, with no
    /// recency blend.
    fn temporal(&self, critical: bool) -> Run {
        self.recorded(
            self.vault
                .query()
                .with_temporal_now(NOW)
                .search_temporal(ANCHOR, ANCHOR, 1)
                .boost_recency(0.0)
                .criticality(critical),
        )
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
        fixture.vector(true),
        found(claim),
        "GUARD: narrowed to its own tier, the vector fetch finds the claim"
    );
    assert_eq!(
        fixture.vector(false),
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
        fixture.text(true),
        found(claim),
        "GUARD: narrowed to its own tier, the text scan finds the claim"
    );
    assert_eq!(
        fixture.text(false),
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
        fixture.temporal(true),
        found(claim),
        "GUARD: narrowed to its own tier, the temporal window finds the claim"
    );
    assert_eq!(
        fixture.temporal(false),
        no_data(),
        "FAILBEFORE BOUNDED-CHANNEL-NARROWING-OMITS-CRITICALITY-STALE-DISCLOSURE: the temporal \
         window left the tier unasked, so the critical claim counted as a candidate and the \
         post-blend filter made the run read FilterMatchedNone"
    );
}
