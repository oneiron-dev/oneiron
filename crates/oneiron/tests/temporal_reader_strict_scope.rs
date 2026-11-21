//! [TEMPORAL-READER-OMITS-STRICT-SCOPE-CHECKS]: a temporal call narrowed by
//! a strict scope widens its window and cuts it to that scope, and the
//! window's reader asks the whole scope, so rows the scope refuses that fill
//! the widened bound nearer the anchor stop no round of the adaptive window:
//! it still grows to the eligible row behind them. Before, the reader asked
//! only the candidate filter, the criticality tier, the stale worlds, the
//! clamp and the made_by slice. A call narrowed by its entity types, its
//! world scope, or its occurred or learned range took the window with no
//! reader: the refused rows filled the bound in the first round and stopped
//! it there, and the scope's cut then dropped them all, so the run returned
//! nothing while an eligible row lay in a later round.
//!
//! Each test first asks with the eligible row alone in the vault (GUARD),
//! then adds [`FUSION_LIST_LENGTH`] rows the scope refuses at the anchor.
//! The reader asks the claim status gate before the checks that decode a
//! claim, so a claim whose stored body does not decode fails no read under a
//! world scope.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test temporal_reader_strict_scope` (the damaged
//! claim body is stored through a test door).

#![cfg(oneiron_test_support)]

use oneiron::entity_id::ForeignWorldId;
use oneiron::pipeline::{RetrievalParams, WorldScope};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::store::RetrievalRunRecord;
use oneiron::temporal::TemporalAnchorMode;
use oneiron::test_doors::claim_body_damage::damage_stored_claim_body;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    PipelineBuilder, TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};
use oneiron_retrieval::fusion::FUSION_LIST_LENGTH;

const DAY: u64 = 86_400;
const ANCHOR: u64 = 1_700_000_000;
/// The temporal runs' clock: a day after the anchor.
const NOW: u64 = ANCHOR + DAY;
/// How far from [`ANCHOR`] the eligible row occurred: past the first round's
/// 30 days at a 10-day sigma, inside the second's 60.
const BEHIND_THE_FIRST_ROUND: u64 = 45 * DAY;
/// When the eligible row occurred and was learned.
const ELIGIBLE_AT: u64 = ANCHOR - BEHIND_THE_FIRST_ROUND;
/// A range around [`ELIGIBLE_AT`] that leaves [`ANCHOR`] out.
const AROUND_THE_ELIGIBLE_ROW: (u64, u64) = (ELIGIBLE_AT - 5 * DAY, ELIGIBLE_AT + 5 * DAY);
/// The foreign world the refused claims of the world test are scoped to.
const FOREIGN_WORLD: u8 = 0xf5;
/// The predicate every claim states.
const PREDICATE: &str = "profile.nickname";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
}

/// A vault whose runs record their telemetry, so a test reads each run's
/// candidate count and empty reason.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    config.retrieval_telemetry_capture = true;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    Fixture { _dir: dir, vault }
}

/// The foreign-range world whose id is `byte` sixteen times.
fn foreign_world(byte: u8) -> ForeignWorldId {
    ForeignWorldId::from_entity_id(EntityId::from_bytes([byte; 16]).expect("FIXTURE: world id"))
        .expect("FIXTURE: a foreign-range world id")
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

impl Fixture {
    /// A person row that occurred and was learned at `at`: the temporal
    /// window finds it, and a claims-only call refuses it.
    fn person_at(&self, at: u64) -> EntityId {
        let person = EntityId::now();
        self.vault
            .put_entity(
                &person,
                ENTITY_TYPE_PERSON,
                TimeRange { start: at, end: at },
                at,
                b"",
            )
            .expect("FIXTURE: put the person");
        person
    }

    /// One live claim, scoped to `world`, that occurred and was learned at
    /// `at`, with no text and no vector: only the temporal window finds it.
    /// Its actor and subject rows occurred at the epoch, outside every
    /// window.
    fn claim_at(&self, world: Option<ForeignWorldId>, at: u64) -> EntityId {
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
            WriteProvenance::new(rmpv::Value::from("temporal reader strict scope"))
                .expect("FIXTURE: provenance"),
            ClaimApprovalStatus::Auto,
        );
        let mut candidate = ClaimCandidate::new(
            PREDICATE,
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
                TimeRange { start: at, end: at },
                at,
            )
            .commit()
            .expect("FIXTURE: write the claim");
        claim
    }

    /// An adaptive temporal run at [`ANCHOR`] narrowed by `scope`, with a
    /// 10-day sigma, no recency blend and a widened bound at the fusion
    /// floor: a widening multiple of 1 and no floor, so
    /// [`FUSION_LIST_LENGTH`] rows fill it.
    fn adaptive_temporal(&self, scope: impl Fn(PipelineBuilder<'_>) -> PipelineBuilder<'_>) -> Run {
        self.recorded(scope(
            self.vault
                .query()
                .with_temporal_now(NOW)
                .search_temporal_with_sigma(
                    ANCHOR,
                    ANCHOR + 1,
                    10 * DAY,
                    TemporalAnchorMode::Occurred,
                    1,
                )
                .temporal_adaptive(true)
                .boost_recency(0.0)
                .retrieval_params(RetrievalParams {
                    temporal_widening_multiple: 1,
                    temporal_widening_floor: 0,
                    ..RetrievalParams::shipped()
                }),
        ))
        .expect("query")
    }

    /// A temporal run at [`ANCHOR`] narrowed by `scope`, with no recency
    /// blend, handing back the run's error as its text.
    fn try_temporal(
        &self,
        scope: impl Fn(PipelineBuilder<'_>) -> PipelineBuilder<'_>,
    ) -> Result<Run, String> {
        self.recorded(scope(
            self.vault
                .query()
                .with_temporal_now(NOW)
                .search_temporal(ANCHOR, ANCHOR, 1)
                .boost_recency(0.0),
        ))
    }

    fn recorded(&self, query: PipelineBuilder<'_>) -> Result<Run, String> {
        let run = query
            .limit(10)
            .capture_retrieval_trace(true)
            .run_with_telemetry()
            .map_err(|error| error.to_string())?;
        let run_id = run
            .run_id
            .expect("FIXTURE: a captured run names its record");
        let record: RetrievalRunRecord = self
            .vault
            .retrieval_run(run_id)
            .expect("read the run record")
            .expect("FIXTURE: the run record is readable");
        Ok(Run {
            ids: run.value.into_iter().map(|row| row.id).collect(),
            total_in_scope: record.total_in_scope,
            empty_reason: record.empty_reason,
        })
    }
}

/// Asserts that a run narrowed by `scope` finds `eligible` alone in the
/// vault, and still finds it once `fill` has written [`FUSION_LIST_LENGTH`]
/// rows the scope refuses at the anchor.
fn assert_window_grows_past_refused_rows(
    fixture: &Fixture,
    eligible: EntityId,
    scope: impl Fn(PipelineBuilder<'_>) -> PipelineBuilder<'_>,
    fill: impl Fn(&Fixture),
    narrowed_by: &str,
) {
    assert_eq!(
        fixture.adaptive_temporal(&scope),
        found(eligible),
        "GUARD: alone in the vault, the eligible row is in the {narrowed_by} scope and inside \
         the adaptive window's later rounds"
    );
    for _ in 0..FUSION_LIST_LENGTH {
        fill(fixture);
    }
    assert_eq!(
        fixture.adaptive_temporal(&scope),
        found(eligible),
        "FAILBEFORE TEMPORAL-READER-OMITS-STRICT-SCOPE-CHECKS: the temporal window asked no \
         reader for the {narrowed_by} scope, so the rows it refuses filled the window's bound \
         in the first round and stopped it there, and the scope's cut dropped them all"
    );
}

/// A claims-only run grows past person rows at the anchor.
#[test]
fn a_type_narrowed_temporal_window_grows_past_rows_of_other_types() {
    let fixture = fixture();
    let claim = fixture.claim_at(None, ELIGIBLE_AT);
    assert_window_grows_past_refused_rows(
        &fixture,
        claim,
        |query| query.filter_types(&[ENTITY_TYPE_CLAIM]),
        |fixture| {
            fixture.person_at(ANCHOR);
        },
        "entity type",
    );
}

/// A base-reality run grows past claims of a foreign world at the anchor.
#[test]
fn a_base_world_temporal_window_grows_past_claims_of_another_world() {
    let fixture = fixture();
    let base = fixture.claim_at(None, ELIGIBLE_AT);
    assert_window_grows_past_refused_rows(
        &fixture,
        base,
        |query| query.world(WorldScope::Base),
        |fixture| {
            fixture.claim_at(Some(foreign_world(FOREIGN_WORLD)), ANCHOR);
        },
        "base world",
    );
}

/// A run narrowed to a learned range grows past claims learned outside it.
#[test]
fn a_learned_range_temporal_window_grows_past_claims_learned_outside_it() {
    let fixture = fixture();
    let claim = fixture.claim_at(None, ELIGIBLE_AT);
    let (start, end) = AROUND_THE_ELIGIBLE_ROW;
    assert_window_grows_past_refused_rows(
        &fixture,
        claim,
        |query| query.filter_learned_range(start, end),
        |fixture| {
            fixture.claim_at(None, ANCHOR);
        },
        "learned range",
    );
}

/// A run narrowed to an occurred range grows past claims that occurred
/// outside it.
#[test]
fn an_occurred_range_temporal_window_grows_past_claims_that_occurred_outside_it() {
    let fixture = fixture();
    let claim = fixture.claim_at(None, ELIGIBLE_AT);
    let (start, end) = AROUND_THE_ELIGIBLE_ROW;
    assert_window_grows_past_refused_rows(
        &fixture,
        claim,
        |query| query.filter_occurred_range(start, end),
        |fixture| {
            fixture.claim_at(None, ANCHOR);
        },
        "occurred range",
    );
}

/// The reader asks the claim status gate before the world filter decodes a
/// claim, as every other read does: a base-reality run reads a claim whose
/// stored body does not decode as no candidate, and its reader does not
/// fail the run on it.
#[test]
fn a_base_world_temporal_window_reads_past_an_undecodable_claim() {
    let fixture = fixture();
    let live = fixture.claim_at(None, ANCHOR);
    let damaged = fixture.claim_at(None, ANCHOR);
    damage_stored_claim_body(&fixture.vault, damaged)
        .expect("FIXTURE: damage the claim's stored body");
    assert_eq!(
        fixture.try_temporal(|query| query.world(WorldScope::Base)),
        Ok(found(live)),
        "GUARD: the claim status gate keeps the damaged claim out of the base-reality run \
         before the world filter would decode it"
    );
}
