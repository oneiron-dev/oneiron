//! Row [RECALL-EXPANDED-ROW-FACTS-REREAD], the blend part: a blend that
//! boosts by salience and confidence reads both from one MessagePack parse of
//! each candidate's body.
//!
//! The fixture: four claims, each about its own PERSON, whose stored salience
//! falls and whose stored confidence rises in claim order. The first test
//! counts, per body, the blend's scalar reads and the body's parses through a
//! test door in `oneiron-retrieval`. The other two pin what the boosts read:
//! the blended stage ranks the claims by their stored salience and, in the
//! opposite order, by their stored confidence; a run that boosts salience
//! alone records no confidence component.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test blend_body_parsed_once`.

#![cfg(oneiron_test_support)]

use std::collections::HashMap;

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId,
    RetrievalScoreComponent, RetrievalSignal, TimeRange, Vault, VaultConfig,
};
use oneiron_retrieval::fusion::body_parse_work::count_body_parse_work;

const LEARNED_AT: u64 = 1_780_000_000;
const QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];
/// Each claim's cosine to [`QUERY`], strongest first.
const COSINES: [f32; 4] = [1.0, 0.6, 0.55, 0.1];
/// Each claim's stored salience: falling in claim order.
const SALIENCES: [f32; 4] = [0.9, 0.7, 0.5, 0.3];
/// Each claim's stored confidence: rising in claim order.
const CONFIDENCES: [f32; 4] = [0.2, 0.4, 0.6, 0.8];

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn seed_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("valid entity id")
}

fn occurred() -> TimeRange {
    TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    }
}

/// Four active claims, each about its own PERSON, at [`COSINES`] to the
/// query, with [`SALIENCES`] and [`CONFIDENCES`] stored in their bodies, in a
/// vault that records retrieval telemetry.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    claims: [EntityId; 4],
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    config.dimensions = QUERY.len();
    config.embedding_model = Some("test/model@v1".to_owned());
    config.map_size = 16 * 1024 * 1024;
    config.retrieval_telemetry_capture = true;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    let claims = [seed_id(0x31), seed_id(0x32), seed_id(0x33), seed_id(0x34)];
    for (index, (claim, cosine)) in claims.iter().zip(COSINES).enumerate() {
        let subject = seed_id(0x21 + index as u8);
        vault
            .put_entity(
                &subject,
                ENTITY_TYPE_PERSON,
                occurred(),
                LEARNED_AT,
                b"subject",
            )
            .expect("subject entity");
        let mut body = ClaimBody::new(
            "profile.note",
            ClaimSubject::Entity(subject),
            rmpv::Value::from(format!("note {index}")),
            CONFIDENCES[index],
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("claim body");
        body.salience = Some(SALIENCES[index]);
        vault
            .put_claim(claim, &body, occurred(), LEARNED_AT)
            .expect("claim");
        let vector = [cosine, (1.0 - cosine * cosine).sqrt(), 0.0, 0.0];
        vault
            .batch()
            .vector(claim, &vector)
            .commit()
            .expect("claim vector");
    }
    vault
        .set_indexed_idle_delay_ms(0)
        .expect("idle publish delay");
    let published = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("idle publish of staged vectors");
    assert!(
        published.failed.is_empty(),
        "FIXTURE: every claim vector is published: {:?}",
        published.failed
    );
    Fixture {
        _dir: dir,
        vault,
        claims,
    }
}

/// The blended-stage score components of a captured vector search that
/// boosts salience, and confidence when `confidence` is set, keyed by claim.
fn blended_components(
    fixture: &Fixture,
    confidence: bool,
) -> Result<HashMap<[u8; 16], Vec<RetrievalScoreComponent>>, Box<dyn std::error::Error>> {
    let mut query = fixture
        .vault
        .query()
        .search_vector(&QUERY, 10)
        .boost_salience();
    if confidence {
        query = query.boost_confidence();
    }
    let run = query
        .capture_retrieval_trace(true)
        .limit(10)
        .run_with_telemetry()?;
    assert_eq!(run.value.len(), 4, "FIXTURE: every claim is returned");
    let run_id = run
        .run_id
        .ok_or("FIXTURE: a capture run publishes its run id")?;
    let record = fixture
        .vault
        .retrieval_run(run_id)?
        .ok_or("FIXTURE: the run record is readable")?;
    let trace = record.trace.ok_or("FIXTURE: the run captured its trace")?;
    let blended: HashMap<[u8; 16], Vec<RetrievalScoreComponent>> = trace
        .blended
        .candidates
        .iter()
        .map(|row| (row.result_id, row.components.clone()))
        .collect();
    assert_eq!(
        blended.len(),
        4,
        "FIXTURE: the blended stage lists every claim: {:?}",
        trace.blended.candidates
    );
    Ok(blended)
}

fn signal_rank(components: &[RetrievalScoreComponent], signal: RetrievalSignal) -> Option<u32> {
    components
        .iter()
        .find(|component| component.signal == signal)
        .map(|component| component.rank)
}

/// Each blend read of a candidate's body for its salience and confidence is
/// one MessagePack parse of that body.
#[test]
fn a_boosted_blend_parses_each_candidate_body_once() {
    let fixture = fixture();
    let (rows, work) = count_body_parse_work(|| {
        fixture
            .vault
            .query()
            .search_vector(&QUERY, 10)
            .boost_salience()
            .boost_confidence()
            .limit(10)
            .run()
    });
    let rows = rows.expect("boosted retrieval");
    assert_eq!(rows.len(), 4, "FIXTURE: every claim is returned: {rows:?}");
    let work: Vec<_> = work.into_values().collect();
    assert_eq!(
        work.iter().filter(|body| body.scalar_reads > 0).count(),
        4,
        "FIXTURE: the blend reads each claim's body for its scalars: {work:?}"
    );
    assert!(
        work.iter().all(|body| body.parses == body.scalar_reads),
        "each scalar read of a body parses it once, for salience and confidence together: {work:?}"
    );
}

/// The blended stage ranks the claims by the salience and the confidence
/// stored in their bodies: salience falls and confidence rises in claim
/// order, so each signal's ranks run opposite to the other's.
#[test]
fn the_boosts_rank_the_claims_by_their_stored_salience_and_confidence() -> TestResult {
    let fixture = fixture();
    let blended = blended_components(&fixture, true)?;
    for (index, claim) in fixture.claims.iter().enumerate() {
        let components = &blended[claim.as_bytes()];
        let place = u32::try_from(index)?;
        assert_eq!(
            signal_rank(components, RetrievalSignal::Salience),
            Some(place + 1),
            "claim {index} (salience {}) takes salience rank {}: {components:?}",
            SALIENCES[index],
            place + 1
        );
        assert_eq!(
            signal_rank(components, RetrievalSignal::Confidence),
            Some(4 - place),
            "claim {index} (confidence {}) takes confidence rank {}: {components:?}",
            CONFIDENCES[index],
            4 - place
        );
    }
    Ok(())
}

/// A run that boosts salience alone ranks by salience and records no
/// confidence component.
#[test]
fn a_salience_boost_alone_records_no_confidence_component() -> TestResult {
    let fixture = fixture();
    let blended = blended_components(&fixture, false)?;
    for (index, claim) in fixture.claims.iter().enumerate() {
        let components = &blended[claim.as_bytes()];
        assert_eq!(
            signal_rank(components, RetrievalSignal::Salience),
            Some(u32::try_from(index)? + 1),
            "claim {index} takes its salience rank: {components:?}"
        );
        assert_eq!(
            signal_rank(components, RetrievalSignal::Confidence),
            None,
            "claim {index} carries no confidence component without the confidence boost: {components:?}"
        );
    }
    Ok(())
}
