//! RESEARCH-0651 contract item 1: the pipeline's scoring numbers are one
//! `RetrievalParams` value passed per call, `shipped()` by default, and
//! never persisted.
//!
//! On the testkit: each case opens its own copy of the empty fixture vault
//! and pins the temporal "now", so every run of a query scores the same rows
//! against the same clock.

use oneiron::memory::Effort;
use oneiron::pipeline::{RETRIEVAL_FORMULA_VERSION, RetrievalParams, retrieval_knob_schema};
use oneiron::{EntityId, Error, TimeRange, Vault};
use oneiron_testkit::{FixtureVault, fixture_cache};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DAY: u64 = 86_400;

fn put_row(vault: &Vault, id: EntityId, occurred: u64, learned_at: u64) -> TestResult {
    vault.put_entity(
        &id,
        1,
        TimeRange {
            start: occurred,
            end: occurred,
        },
        learned_at,
        b"payload",
    )?;
    Ok(())
}

/// The ids and score bits of one run, best first.
fn ranked(results: &[oneiron::pipeline::ScoredEntity]) -> Vec<(EntityId, u32)> {
    results
        .iter()
        .map(|scored| (scored.id, scored.score.to_bits()))
        .collect()
}

fn ids(results: &[(EntityId, u32)]) -> Vec<EntityId> {
    results.iter().map(|(id, _)| *id).collect()
}

/// A at the anchor but learned 200 days ago; B five days off the anchor but
/// learned yesterday. The shipped temporal blend weighs an old anchor's
/// proximity at about 0.97, so A leads; a set with no proximity weight
/// ranks by recency alone, so B leads.
struct TwoRowFixture {
    now: u64,
    anchor: u64,
    at_anchor: EntityId,
    recent: EntityId,
}

fn two_rows(vault: &Vault, now: u64) -> Result<TwoRowFixture, Box<dyn std::error::Error>> {
    let anchor = now - 200 * DAY;
    // [0xA1; 16]..[0xA6; 16] hold the vault's seeded system agents.
    let at_anchor = EntityId::from_bytes([0xD1; 16])?;
    let recent = EntityId::from_bytes([0xB2; 16])?;
    put_row(vault, at_anchor, anchor, anchor)?;
    put_row(vault, recent, anchor + 5 * DAY, now - DAY)?;
    Ok(TwoRowFixture {
        now,
        anchor,
        at_anchor,
        recent,
    })
}

fn temporal_run(
    vault: &Vault,
    fixture: &TwoRowFixture,
    params: Option<RetrievalParams>,
) -> Result<Vec<(EntityId, u32)>, Box<dyn std::error::Error>> {
    let mut query = vault
        .query()
        .with_temporal_now(fixture.now)
        .search_temporal(fixture.anchor, fixture.anchor, 2)
        // The blend's own recency signal would also favour B; off, the
        // order is the temporal channel's.
        .boost_recency(0.0);
    if let Some(params) = params {
        query = query.retrieval_params(params);
    }
    Ok(ranked(&query.run()?))
}

#[test]
fn shipped_params_are_todays_numbers_and_change_nothing() -> TestResult {
    let shipped = RetrievalParams::shipped();
    assert_eq!(shipped.temporal_floor, 0.05);
    assert_eq!(shipped.recency_decay_tau_secs, 28.0 * 86_400.0);
    assert_eq!(shipped.alpha_base, 0.7);
    assert_eq!(shipped.alpha_range, 0.3);
    assert_eq!(shipped.alpha_tau_secs, 90.0 * 86_400.0);
    assert_eq!(shipped.ppr_damping, 0.15_f32);
    assert_eq!(shipped.temporal_widening_multiple, 8);
    assert_eq!(shipped.temporal_widening_floor, 4_000);
    assert_eq!(shipped.cosine_ghost_vector_threshold, 0.3_f32);
    assert_eq!(shipped.context_pack_min_vector_score_gap_ratio, 0.1_f32);
    assert_eq!(shipped.context_pack_anomalous_repeat_run, 32);
    assert_eq!(RetrievalParams::default(), shipped);
    assert_eq!(RETRIEVAL_FORMULA_VERSION, 1);
    shipped.validate()?;
    assert_eq!(shipped.digest()?, RetrievalParams::shipped().digest()?);
    // One schema row per field, each named by its serde key.
    let fields = serde_json::to_value(shipped)?;
    let fields = fields.as_object().ok_or("params serialize as an object")?;
    let schema = retrieval_knob_schema();
    assert_eq!(schema.len(), fields.len());
    for spec in schema {
        assert!(
            fields.contains_key(spec.path),
            "{} is not a field",
            spec.path
        );
    }
    // Serde refuses a set naming a knob that does not exist.
    let mut unknown = serde_json::to_value(shipped)?;
    unknown["rrf_k"] = serde_json::json!(60.0);
    assert!(serde_json::from_value::<RetrievalParams>(unknown).is_err());

    // Six rows around a 30-day-old anchor; each query runs without the call
    // and with the shipped set, and returns the same ids and score bits.
    let fixture = FixtureVault::empty(&fixture_cache!())?;
    let copy = fixture.copy()?;
    let vault = copy.open()?;
    let now = fixture.ended_at();
    let anchor = now - 30 * DAY;
    for (seed, occurred, learned_at) in [
        (0xC0, anchor, anchor),
        (0xC1, anchor + DAY, now - 2 * DAY),
        (0xC2, anchor - 3 * DAY, anchor - 3 * DAY),
        (0xC3, anchor + 4 * DAY, now - 10 * DAY),
        (0xC4, now - 3 * DAY, now - 3 * DAY),
        (0xC5, now - 6 * DAY, now - 40 * DAY),
    ] {
        put_row(
            &vault,
            EntityId::from_bytes([seed; 16])?,
            occurred,
            learned_at,
        )?;
    }
    let temporal = |params: Option<RetrievalParams>| -> Result<_, Box<dyn std::error::Error>> {
        let mut query = vault.query().with_temporal_now(now).search_temporal(
            anchor - 2 * DAY,
            anchor + 2 * DAY,
            6,
        );
        if let Some(params) = params {
            query = query.retrieval_params(params);
        }
        Ok(ranked(&query.run()?))
    };
    let plain = temporal(None)?;
    assert!(!plain.is_empty(), "the temporal query finds the fixture");
    assert_eq!(temporal(Some(shipped))?, plain);

    let worded = |params: Option<RetrievalParams>| -> Result<_, Box<dyn std::error::Error>> {
        // The effort dial's anchor reads the pinned now, not the wall clock.
        let mut query = vault
            .query()
            .with_temporal_now(now)
            .search_text("last week", 6)
            .limit(6)
            .retrieval_effort(Effort::Medium, &[]);
        if let Some(params) = params {
            query = query.retrieval_params(params);
        }
        Ok(ranked(&query.run()?))
    };
    let plain = worded(None)?;
    assert!(!plain.is_empty(), "the worded query finds the fixture");
    assert_eq!(worded(Some(shipped))?, plain);
    Ok(())
}

#[test]
fn a_candidate_set_passed_per_call_reorders_a_fixed_fixture() -> TestResult {
    let fixture = FixtureVault::empty(&fixture_cache!())?;
    let copy = fixture.copy()?;
    let vault = copy.open()?;
    let rows = two_rows(&vault, fixture.ended_at())?;

    let shipped = temporal_run(&vault, &rows, None)?;
    assert_eq!(ids(&shipped), [rows.at_anchor, rows.recent]);

    let recency_only = RetrievalParams {
        alpha_base: 0.0,
        alpha_range: 0.0,
        ..RetrievalParams::shipped()
    };
    let candidate = temporal_run(&vault, &rows, Some(recency_only))?;
    assert_eq!(ids(&candidate), [rows.recent, rows.at_anchor]);

    // Nothing was kept: the next call without a set scores as before.
    assert_eq!(temporal_run(&vault, &rows, None)?, shipped);
    Ok(())
}

#[test]
fn an_out_of_range_set_is_refused_before_any_read() -> TestResult {
    let shipped = RetrievalParams::shipped();
    let refused = [
        (
            "ppr_damping",
            RetrievalParams {
                ppr_damping: 1.5,
                ..shipped
            },
        ),
        (
            "temporal_floor",
            RetrievalParams {
                temporal_floor: f64::NAN,
                ..shipped
            },
        ),
        (
            "alpha_base + alpha_range",
            RetrievalParams {
                alpha_base: 0.8,
                ..shipped
            },
        ),
        (
            "context_pack_anomalous_repeat_run",
            RetrievalParams {
                context_pack_anomalous_repeat_run: 1,
                ..shipped
            },
        ),
    ];

    let fixture = FixtureVault::empty(&fixture_cache!())?;
    let copy = fixture.copy()?;
    let vault = copy.open()?;
    let rows = two_rows(&vault, fixture.ended_at())?;
    for (knob, params) in refused {
        assert!(
            matches!(params.validate(), Err(Error::InvalidConfig(_))),
            "{knob}: validate"
        );
        assert!(
            matches!(params.digest(), Err(Error::InvalidConfig(_))),
            "{knob}: digest"
        );
        let run = vault
            .query()
            .with_temporal_now(rows.now)
            .search_temporal(rows.anchor, rows.anchor, 2)
            .retrieval_params(params)
            .run();
        assert!(
            matches!(run, Err(Error::InvalidConfig(_))),
            "{knob}: the run is refused, got {run:?}"
        );
    }
    // The refusal kept nothing either.
    assert_eq!(
        ids(&temporal_run(&vault, &rows, None)?),
        [rows.at_anchor, rows.recent]
    );
    Ok(())
}

#[test]
fn the_fork_hash_names_the_params() -> TestResult {
    let fixture = FixtureVault::empty(&fixture_cache!())?;
    let copy = fixture.copy()?;
    let vault = copy.open_with(|clock| {
        let mut config = clock.vault_config();
        config.retrieval_telemetry_capture = true;
        config
    })?;
    let rows = two_rows(&vault, fixture.ended_at())?;
    let fork_hash = |params: RetrievalParams| -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let run = vault
            .query()
            .with_temporal_now(rows.now)
            .search_temporal(rows.anchor, rows.anchor, 2)
            .boost_recency(0.0)
            .capture_retrieval_trace(true)
            .retrieval_params(params)
            .run_with_telemetry()?;
        let run_id = run.run_id.ok_or("a capture run publishes its run id")?;
        let record = vault
            .retrieval_run(run_id)?
            .ok_or("the run record is readable")?;
        Ok(record.trace.ok_or("the run captured its trace")?.fork_hash)
    };
    let shipped = fork_hash(RetrievalParams::shipped())?;
    assert_eq!(fork_hash(RetrievalParams::shipped())?, shipped);
    let candidate = RetrievalParams {
        ppr_damping: 0.5,
        ..RetrievalParams::shipped()
    };
    assert_ne!(
        fork_hash(candidate)?,
        shipped,
        "a candidate set's trace never shares a shipped key"
    );
    Ok(())
}
