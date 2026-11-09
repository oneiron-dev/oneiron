//! ONE-1579 plan-admission regressions.
//!
//! Every case here is a plan the harness must REFUSE at the door, plus the
//! boundary case next to it that it must admit — a floor nobody can cross and
//! nobody is accidentally blocked by.

use super::*;

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
