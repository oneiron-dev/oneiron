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

/// The retrieval and precision axes describe the SAME plan. A `k` larger
/// than the indexed corpus is refused at the door, so one axis can never
/// report a clamped k while the other keeps the original.
#[test]
fn a_k_larger_than_the_indexed_corpus_is_refused() {
    let mut plan = full_plan_fixture();
    plan.corpus.k = plan.corpus.indexed_docs + 1;
    let error = plan.validate().expect_err("k > indexed_docs is refused");
    assert_eq!(
        error,
        PlanError::KExceedsCorpus {
            k: FULL_RUN_MIN_INDEXED_DOCS + 1,
            indexed_docs: FULL_RUN_MIN_INDEXED_DOCS,
        }
    );

    // The same refusal applies to a smoke, whose corpus is small.
    let mut smoke = full_plan_fixture();
    smoke.mode = PlanMode::SyntheticSmoke;
    smoke.sessions.curve = vec![1, 4];
    smoke.corpus.indexed_docs = 8;
    smoke.corpus.queries = 4;
    smoke.corpus.k = 10;
    smoke.gated_writes = GatedWritePlan {
        warmup: 1,
        measured: 2,
    };
    smoke.cache.events_path = None;
    assert!(matches!(
        smoke.validate(),
        Err(PlanError::KExceedsCorpus { .. })
    ));

    // k exactly at the corpus size is admissible.
    let mut edge = full_plan_fixture();
    edge.corpus.k = edge.corpus.indexed_docs;
    edge.precision.binary_prefix_breadth = Some(edge.corpus.indexed_docs);
    edge.validate().expect("k == indexed_docs is a valid plan");
}

/// Every query anchors on a document of its own, so a plan that asks for
/// more queries than it indexes is refused at the door rather than
/// answered with queries that wrap back onto documents already probed.
#[test]
fn a_plan_with_more_queries_than_documents_is_refused() {
    let mut plan = full_plan_fixture();
    plan.corpus.queries = plan.corpus.indexed_docs + 1;
    assert_eq!(
        plan.validate()
            .expect_err("queries > indexed_docs is refused"),
        PlanError::QueriesExceedCorpus {
            queries: FULL_RUN_MIN_INDEXED_DOCS + 1,
            indexed_docs: FULL_RUN_MIN_INDEXED_DOCS,
        }
    );

    // A smoke is held to the same uniqueness constraint on its own scale.
    let mut smoke = full_plan_fixture();
    smoke.mode = PlanMode::SyntheticSmoke;
    smoke.sessions.curve = vec![1, 4];
    smoke.corpus.indexed_docs = 8;
    smoke.corpus.queries = 12;
    smoke.corpus.k = 4;
    smoke.precision.binary_prefix_breadth = Some(8);
    smoke.gated_writes = GatedWritePlan {
        warmup: 1,
        measured: 2,
    };
    smoke.cache.events_path = None;
    assert!(matches!(
        smoke.validate(),
        Err(PlanError::QueriesExceedCorpus { .. })
    ));

    // One query per indexed document is the boundary, and it is valid.
    smoke.corpus.queries = 8;
    smoke
        .validate()
        .expect("queries == indexed_docs is a valid plan");
}

/// ONE-1963: a full run measures the artifact it was built from. A plan
/// that names its own ready-child program is refused at the door, because
/// the wake and ready-children axes would otherwise describe a different
/// binary while carrying this artifact's build revision. The comparison is
/// still available — as a synthetic smoke, which says what it is.
#[test]
fn a_full_run_plan_may_not_name_its_own_child_program() {
    let child = ChildCommandPlan {
        program: "/usr/bin/other-bench".to_owned(),
        args: vec!["--listen={ready_addr}".to_owned()],
    };

    let mut plan = full_plan_fixture();
    plan.wake.child = Some(child.clone());
    assert_eq!(
        plan.validate()
            .expect_err("a full run must refuse a caller-supplied child"),
        PlanError::ChildOverrideNotAllowedInFullRun {
            program: "/usr/bin/other-bench".to_owned(),
        }
    );

    // The same plan as a synthetic smoke is admissible: a separate-binary
    // wake comparison is exactly what the smoke contract is for.
    let mut smoke = full_plan_fixture();
    smoke.wake.child = Some(child);
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
        .expect("a synthetic smoke may spawn another binary");

    // And a full run that names no child still validates.
    let mut bare = full_plan_fixture();
    bare.wake.child = None;
    bare.validate()
        .expect("the harness's own child is the default");
}

/// The binary-prefix stage must run at exactly the breadth named by the
/// plan. Values below k or past the indexed corpus are refused before the
/// plan hash can identify one request while the axis silently measures
/// another.
#[test]
fn an_out_of_range_binary_prefix_breadth_is_refused_at_admission() {
    for breadth in [9, FULL_RUN_MIN_INDEXED_DOCS + 1] {
        let mut plan = full_plan_fixture();
        plan.precision.binary_prefix_breadth = Some(breadth);
        assert_eq!(
            plan.validate()
                .expect_err("an out-of-range breadth must be refused"),
            PlanError::BinaryPrefixBreadthOutOfRange {
                breadth,
                k: 10,
                indexed_docs: FULL_RUN_MIN_INDEXED_DOCS,
            }
        );
    }

    for breadth in [10, FULL_RUN_MIN_INDEXED_DOCS] {
        let mut plan = full_plan_fixture();
        plan.precision.binary_prefix_breadth = Some(breadth);
        plan.validate()
            .expect("both inclusive breadth boundaries are admissible");
    }

    // An omitted breadth still resolves to 4*k. A tiny smoke that cannot
    // hold that default must name a smaller in-range breadth explicitly;
    // it is never clamped behind the plan's back.
    let mut smoke = full_plan_fixture();
    smoke.mode = PlanMode::SyntheticSmoke;
    smoke.sessions.curve = vec![1];
    smoke.corpus.indexed_docs = 20;
    smoke.corpus.queries = 4;
    smoke.gated_writes = GatedWritePlan {
        warmup: 1,
        measured: 2,
    };
    smoke.cache.events_path = None;
    assert_eq!(
        smoke
            .validate()
            .expect_err("the 4*k default exceeds this smoke corpus"),
        PlanError::BinaryPrefixBreadthOutOfRange {
            breadth: 40,
            k: 10,
            indexed_docs: 20,
        }
    );
    smoke.precision.binary_prefix_breadth = Some(20);
    smoke
        .validate()
        .expect("an explicit in-range smoke breadth is admissible");
}

/// A ready child arms its hold the moment it connects, which can be at the
/// very start of the parent's accept window. A hold that does not outlast
/// that window plus the sampling margin is refused.
#[test]
fn a_child_hold_that_cannot_outlast_the_sampling_phase_is_refused() {
    let mut plan = full_plan_fixture();
    plan.wake.timeout_ms = 20_000;
    plan.wake.hold_ms = 20_000;
    let error = plan
        .validate()
        .expect_err("a hold equal to the accept timeout is refused");
    match error {
        PlanError::ChildHoldTooShort {
            hold_ms,
            minimum_ms,
            timeout_ms,
        } => {
            assert_eq!(hold_ms, 20_000);
            assert_eq!(timeout_ms, 20_000);
            assert_eq!(minimum_ms, minimum_child_hold_ms(20_000));
            assert!(minimum_ms > hold_ms);
        }
        other => panic!("expected a child-hold refusal, got {other}"),
    }

    let mut exact = full_plan_fixture();
    exact.wake.timeout_ms = 20_000;
    exact.wake.hold_ms = minimum_child_hold_ms(20_000);
    exact
        .validate()
        .expect("a hold exactly at the floor is admissible");

    let mut short = full_plan_fixture();
    short.wake.hold_ms = 1;
    assert!(matches!(
        short.validate(),
        Err(PlanError::ChildHoldTooShort { .. })
    ));
}
