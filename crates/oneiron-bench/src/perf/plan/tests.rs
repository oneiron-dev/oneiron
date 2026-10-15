//! ONE-1579 plan-admission regressions.
//!
//! Every case here is a plan the harness must REFUSE at the door, plus the
//! boundary case next to it that it must admit — a floor nobody can cross and
//! nobody is accidentally blocked by.

use super::*;

/// A full run is defined at exactly `[1, 10, 100, 300]`. Omitting a rung,
/// reordering it, padding it or emptying it are all invalid full-run
/// plans; a synthetic smoke may use a smaller curve.
#[test]
fn perf_plan_requires_exact_full_scale_curve() {
    full_plan_fixture()
        .validate()
        .expect("the exact curve validates");

    for broken in [
        vec![1, 10, 100],
        vec![1, 10, 300],
        vec![1, 10, 300, 100],
        vec![300, 100, 10, 1],
        vec![1, 10, 100, 300, 1000],
        vec![1, 10, 100, 200],
    ] {
        let mut plan = full_plan_fixture();
        plan.sessions.curve = broken.clone();
        let error = plan
            .validate()
            .expect_err("a full run must refuse a curve that is not exactly [1,10,100,300]");
        match error {
            PlanError::SessionCurve { expected, found } => {
                assert_eq!(expected.as_slice(), REQUIRED_FULL_SESSION_CURVE.as_slice());
                assert_eq!(found, broken);
            }
            other => panic!("expected a session-curve refusal for {broken:?}, got {other}"),
        }
    }

    let mut empty = full_plan_fixture();
    empty.sessions.curve = Vec::new();
    assert_eq!(
        empty.validate().expect_err("an empty curve is refused"),
        PlanError::EmptySessionCurve
    );

    // The smoke contract is explicitly allowed smaller fixtures.
    let mut smoke = full_plan_fixture();
    smoke.mode = PlanMode::SyntheticSmoke;
    smoke.sessions.curve = vec![1, 4];
    smoke.corpus.indexed_docs = 48;
    smoke.corpus.queries = 8;
    smoke.gated_writes = GatedWritePlan {
        warmup: 2,
        measured: 6,
    };
    smoke.cache.events_path = None;
    smoke
        .validate()
        .expect("a synthetic smoke may use smaller fixtures");
}

#[test]
fn full_run_floors_and_axis_shape_are_enforced() {
    let mut under = full_plan_fixture();
    under.corpus.indexed_docs = 999;
    assert!(matches!(
        under.validate(),
        Err(PlanError::LatencyFloor { .. })
    ));

    let mut writes = full_plan_fixture();
    writes.gated_writes.measured = 9_999;
    assert!(matches!(
        writes.validate(),
        Err(PlanError::GatedWriteFloor { .. })
    ));

    let mut children = full_plan_fixture();
    children.resident_memory.ready_children = 9;
    assert!(matches!(
        children.validate(),
        Err(PlanError::ReadyChildren { .. })
    ));

    let mut candidates = full_plan_fixture();
    candidates.precision.candidates = vec![PrecisionCandidate::F32, PrecisionCandidate::F16];
    assert!(matches!(
        candidates.validate(),
        Err(PlanError::PrecisionCandidates { .. })
    ));

    let mut rungs = full_plan_fixture();
    rungs.cache.rungs = vec!["embedding".to_owned(), "embedding".to_owned()];
    assert!(matches!(
        rungs.validate(),
        Err(PlanError::DuplicateCacheRung { .. })
    ));

    let mut events = full_plan_fixture();
    events.cache.events_path = None;
    assert_eq!(
        events.validate().expect_err("a full run needs real events"),
        PlanError::MissingCacheEvents
    );

    let mut schema = full_plan_fixture();
    schema.schema = "something.else".to_owned();
    assert!(matches!(schema.validate(), Err(PlanError::Schema { .. })));
}
