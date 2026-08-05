//! Deterministic, authority-boundary, and frozen-parity fixtures for the
//! clustering tool.
//!
//! The `v1_parity` fixture below is FROZEN and fully self-contained: local
//! vectors, local expectations, no external legacy code, runtime data, or
//! shared fixture file. Because `distance::cosine_similarity` SIMD-dispatches
//! per target arch (AVX2 / NEON / scalar), the fixture asserts cohort
//! MEMBERSHIP and ORDERING, never exact-bit cosine values.

use crate::claim::{ClaimSubject, predicate_root};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::test_util::entity;

use super::*;

/// Two axis-aligned unit directions with a fixed 4-dimensional frame. Vectors
/// are written by hand so the intended pairwise geometry is readable at the
/// fixture: `axis(0.0)` and `axis(1.0)` are orthogonal (cosine 0), and small
/// angle deltas stay well above the 0.82 floor.
fn axis(radians: f32) -> Vec<f32> {
    vec![radians.cos(), radians.sin(), 0.0, 0.0]
}

fn claim(seed: u8, predicate: &str, embedding: Vec<f32>) -> ClusterClaim {
    ClusterClaim {
        claim_id: entity(seed),
        subject: ClaimSubject::Entity(entity(0x70)),
        predicate: predicate.to_owned(),
        world: None,
        facet: None,
        embedding,
    }
}

fn ids(cohort: &ClaimCohort) -> Vec<EntityId> {
    cohort.member_ids.clone()
}

/// One row of the frozen `v1_parity` expectation.
struct ExpectedCohort {
    predicate_root: &'static str,
    world: Option<EntityId>,
    facet: Option<EntityId>,
    member_ids: Vec<EntityId>,
}

#[test]
fn empty_input_returns_empty_assignments() {
    let assignments = cluster_claims(&[], ClusterOptions::default()).expect("cluster empty");
    assert!(assignments.cohorts.is_empty());
}

#[test]
fn default_threshold_is_the_pinned_v1_contract() {
    assert_eq!(
        ClusterOptions::default().cohesion_threshold,
        CLUSTER_COHESION_THRESHOLD
    );
    assert!((CLUSTER_COHESION_THRESHOLD - 0.82).abs() < f32::EPSILON);
}

// ---------------------------------------------------------------------------
// Stage 1 — exact partitioning
// ---------------------------------------------------------------------------

#[test]
fn identical_embeddings_never_cross_a_partition_boundary() {
    // Every claim carries the SAME embedding, so only stage-1 exactness can
    // keep them apart. Subject, predicate root, world, and facet each get one
    // differing claim.
    let base = claim(0x01, "person.name", axis(0.0));

    let other_subject = ClusterClaim {
        claim_id: entity(0x02),
        subject: ClaimSubject::Entity(entity(0x71)),
        ..base.clone()
    };
    let other_predicate_root = ClusterClaim {
        claim_id: entity(0x03),
        predicate: "org.name".to_owned(),
        ..base.clone()
    };
    let other_world = ClusterClaim {
        claim_id: entity(0x04),
        world: Some(entity(0x80)),
        ..base.clone()
    };
    let other_facet = ClusterClaim {
        claim_id: entity(0x05),
        facet: Some(entity(0x90)),
        ..base.clone()
    };
    let edge_subject = ClusterClaim {
        claim_id: entity(0x06),
        subject: ClaimSubject::Edge {
            source: entity(0x70),
            kind: EdgeKind::About,
            target: entity(0x71),
        },
        ..base.clone()
    };

    let claims = [
        base,
        other_subject,
        other_predicate_root,
        other_world,
        other_facet,
        edge_subject,
    ];
    let assignments = cluster_claims(&claims, ClusterOptions::default()).expect("cluster");

    assert_eq!(
        assignments.cohorts.len(),
        6,
        "six exact buckets, six cohorts"
    );
    for cohort in &assignments.cohorts {
        assert_eq!(cohort.member_ids.len(), 1);
        assert!((cohort.cohesion - 1.0).abs() < f32::EPSILON);
    }
}

#[test]
fn predicate_leaf_is_dropped_so_siblings_share_a_partition() {
    // `person.name.given` and `person.name.family` share the root
    // `person.name`; the leaf is not part of the bucket.
    let claims = [
        claim(0x01, "person.name.given", axis(0.0)),
        claim(0x02, "person.name.family", axis(0.0)),
    ];
    let assignments = cluster_claims(&claims, ClusterOptions::default()).expect("cluster");

    assert_eq!(assignments.cohorts.len(), 1);
    assert_eq!(
        assignments.cohorts[0].partition.predicate_root,
        "person.name"
    );
    assert_eq!(
        ids(&assignments.cohorts[0]),
        vec![entity(0x01), entity(0x02)]
    );
}

// ---------------------------------------------------------------------------
// Stage 2 — complete-link grouping
// ---------------------------------------------------------------------------

#[test]
fn complete_link_refuses_the_chain_single_link_would_build() {
    // A—B and B—C are each above the floor, but A—C is far below it. Single
    // link would fuse all three through the bridge B; complete link must not.
    let a = axis(0.0);
    let b = axis(0.5);
    let c = axis(1.0);
    // Pin the intended geometry so a future edit to `axis` cannot silently
    // turn this into a different test.
    assert!(cosine_similarity(&a, &b) > CLUSTER_COHESION_THRESHOLD);
    assert!(cosine_similarity(&b, &c) > CLUSTER_COHESION_THRESHOLD);
    assert!(cosine_similarity(&a, &c) < CLUSTER_COHESION_THRESHOLD);

    let claims = [
        claim(0x01, "person.name", a),
        claim(0x02, "person.name", b),
        claim(0x03, "person.name", c),
    ];
    let assignments = cluster_claims(&claims, ClusterOptions::default()).expect("cluster");

    assert_eq!(
        assignments.cohorts.len(),
        2,
        "the bridge claim must not fuse the two ends"
    );
    assert_eq!(
        ids(&assignments.cohorts[0]),
        vec![entity(0x01), entity(0x02)]
    );
    assert_eq!(ids(&assignments.cohorts[1]), vec![entity(0x03)]);
}

#[test]
fn an_isolated_claim_stays_a_singleton_at_cohesion_one() {
    let claims = [
        claim(0x01, "person.name", axis(0.0)),
        claim(0x02, "person.name", vec![0.0, 1.0, 0.0, 0.0]),
    ];
    let assignments = cluster_claims(&claims, ClusterOptions::default()).expect("cluster");

    assert_eq!(assignments.cohorts.len(), 2);
    for cohort in &assignments.cohorts {
        assert_eq!(cohort.member_ids.len(), 1);
        assert!((cohort.cohesion - 1.0).abs() < f32::EPSILON);
    }
}

#[test]
fn reported_cohesion_is_the_worst_pair_in_the_cohort() {
    let a = axis(0.0);
    let b = axis(0.2);
    let c = axis(0.4);
    let worst = cosine_similarity(&a, &c);
    assert!(worst >= CLUSTER_COHESION_THRESHOLD);

    let claims = [
        claim(0x01, "person.name", a),
        claim(0x02, "person.name", b),
        claim(0x03, "person.name", c),
    ];
    let assignments = cluster_claims(&claims, ClusterOptions::default()).expect("cluster");

    assert_eq!(assignments.cohorts.len(), 1);
    let cohort = &assignments.cohorts[0];
    assert_eq!(cohort.member_ids.len(), 3);
    assert!(
        (cohort.cohesion - worst).abs() < 1e-5,
        "cohesion {} should be the minimum pair {worst}",
        cohort.cohesion
    );
}

#[test]
fn a_raised_threshold_splits_a_cohort_the_default_would_keep() {
    let claims = [
        claim(0x01, "person.name", axis(0.0)),
        claim(0x02, "person.name", axis(0.5)),
    ];

    let merged = cluster_claims(&claims, ClusterOptions::default()).expect("cluster default");
    assert_eq!(merged.cohorts.len(), 1);

    let split = cluster_claims(
        &claims,
        ClusterOptions {
            cohesion_threshold: 0.99,
        },
    )
    .expect("cluster strict");
    assert_eq!(split.cohorts.len(), 2);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn cohort_ids_and_ordering_survive_input_permutation() {
    let claims = vec![
        claim(0x01, "person.name", axis(0.0)),
        claim(0x02, "person.name", axis(0.1)),
        claim(0x03, "person.name", vec![0.0, 1.0, 0.0, 0.0]),
        claim(0x04, "org.name", axis(0.0)),
    ];
    let expected = cluster_claims(&claims, ClusterOptions::default()).expect("cluster");

    // Rotations plus a reversal cover both "same set, different order" and the
    // worst case for a greedy first-seen assignment.
    for rotation in 1..claims.len() {
        let mut permuted = claims.clone();
        permuted.rotate_left(rotation);
        let actual = cluster_claims(&permuted, ClusterOptions::default()).expect("cluster");
        assert_eq!(actual, expected, "rotation {rotation} changed the output");
    }

    let mut reversed = claims;
    reversed.reverse();
    let actual = cluster_claims(&reversed, ClusterOptions::default()).expect("cluster");
    assert_eq!(actual, expected, "reversal changed the output");
}

#[test]
fn cohort_id_separates_partitions_that_share_members() {
    // Same member list, different bucket ⇒ different id. Guards the domain
    // separation and the presence tags in the preimage.
    let partition = ClusterPartitionKey {
        subject: ClaimSubject::Entity(entity(0x70)),
        predicate_root: "person.name".to_owned(),
        world: None,
        facet: None,
    };
    let members = [entity(0x01), entity(0x02)];
    let base = cohort_id(&partition, &members);

    let worlded = cohort_id(
        &ClusterPartitionKey {
            world: Some(entity(0x80)),
            ..partition.clone()
        },
        &members,
    );
    let faceted = cohort_id(
        &ClusterPartitionKey {
            facet: Some(entity(0x80)),
            ..partition.clone()
        },
        &members,
    );
    let other_root = cohort_id(
        &ClusterPartitionKey {
            subject: partition.subject,
            predicate_root: "org.name".to_owned(),
            world: partition.world,
            facet: partition.facet,
        },
        &members,
    );
    let shorter = cohort_id(&partition, &members[..1]);

    for (label, other) in [
        ("world", worlded),
        ("facet", faceted),
        ("predicate_root", other_root),
        ("member count", shorter),
    ] {
        assert_ne!(base, other, "{label} must change the cohort id");
    }
    assert_eq!(
        base,
        cohort_id(&partition, &members),
        "id is a pure function"
    );
}

// ---------------------------------------------------------------------------
// Typed-error rejection (no panics, no partial output)
// ---------------------------------------------------------------------------

#[test]
fn mixed_dimensions_fail_with_dimension_mismatch() {
    let claims = [
        claim(0x01, "person.name", vec![1.0, 0.0, 0.0, 0.0]),
        claim(0x02, "person.name", vec![1.0, 0.0]),
    ];
    let error = cluster_claims(&claims, ClusterOptions::default()).expect_err("dimension mismatch");
    assert!(
        matches!(
            error,
            Error::DimensionMismatch {
                expected: 4,
                got: 2
            }
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn non_finite_components_fail_with_invalid_vector() {
    for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        let claims = [
            claim(0x01, "person.name", vec![1.0, 0.0, 0.0, 0.0]),
            claim(0x02, "person.name", vec![0.0, bad, 0.0, 0.0]),
        ];
        let error = cluster_claims(&claims, ClusterOptions::default()).expect_err("invalid vector");
        assert!(
            matches!(error, Error::InvalidVector { index: 1, .. }),
            "unexpected error for {bad}: {error:?}"
        );
    }
}

#[test]
fn an_empty_embedding_is_rejected() {
    let claims = [claim(0x01, "person.name", Vec::new())];
    let error = cluster_claims(&claims, ClusterOptions::default()).expect_err("empty embedding");
    assert!(
        matches!(error, Error::InvalidConfig(_)),
        "unexpected error: {error:?}"
    );
}

#[test]
fn out_of_range_thresholds_are_rejected() {
    let claims = [claim(0x01, "person.name", axis(0.0))];
    for threshold in [1.5_f32, -1.5, f32::NAN, f32::INFINITY] {
        let error = cluster_claims(
            &claims,
            ClusterOptions {
                cohesion_threshold: threshold,
            },
        )
        .expect_err("invalid threshold");
        assert!(
            matches!(error, Error::InvalidConfig(_)),
            "unexpected error for {threshold}: {error:?}"
        );
    }

    // The inclusive endpoints are valid.
    for threshold in [-1.0_f32, 1.0] {
        cluster_claims(
            &claims,
            ClusterOptions {
                cohesion_threshold: threshold,
            },
        )
        .expect("endpoint threshold is valid");
    }
}

#[test]
fn validation_precedes_grouping_so_no_partial_output_escapes() {
    // A well-formed pair that WOULD cluster, plus one malformed claim: the call
    // must fail outright rather than return the good cohort.
    let claims = [
        claim(0x01, "person.name", axis(0.0)),
        claim(0x02, "person.name", axis(0.1)),
        claim(0x03, "person.name", vec![f32::NAN, 0.0, 0.0, 0.0]),
    ];
    assert!(cluster_claims(&claims, ClusterOptions::default()).is_err());
}

// ---------------------------------------------------------------------------
// Authority boundary
// ---------------------------------------------------------------------------

#[test]
fn claims_in_clusters_out_no_decision() {
    // The returned structure carries assignments and diagnostics ONLY. This
    // test is the type-level guard: it destructures every public output field,
    // so adding a merge/split/operation-suggestion field to any of them breaks
    // this test at compile time.
    let claims = [
        claim(0x01, "person.name", axis(0.0)),
        claim(0x02, "person.name", axis(0.1)),
        claim(0x03, "person.name", vec![0.0, 1.0, 0.0, 0.0]),
    ];
    let assignments = cluster_claims(&claims, ClusterOptions::default()).expect("cluster");

    let ClusterAssignments { cohorts } = assignments;
    let mut seen = Vec::new();
    for cohort in cohorts {
        let ClaimCohort {
            cohort_id: _,
            partition:
                ClusterPartitionKey {
                    subject: _,
                    predicate_root: _,
                    world: _,
                    facet: _,
                },
            member_ids,
            cohesion,
        } = cohort;
        assert!(!member_ids.is_empty(), "a cohort is never empty");
        assert!(
            (-1.0..=1.0).contains(&cohesion),
            "cohesion {cohesion} is a similarity, not a verdict"
        );
        seen.extend(member_ids);
    }

    // Every input claim is assigned exactly once: a partition, not a filter.
    seen.sort_unstable();
    assert_eq!(seen, vec![entity(0x01), entity(0x02), entity(0x03)]);
}

// ---------------------------------------------------------------------------
// Frozen v1 parity
// ---------------------------------------------------------------------------

#[test]
fn v1_parity() {
    // FROZEN FIXTURE — self-contained by contract. Local vectors, local
    // expectations; membership and ordering only (cosine SIMD-dispatches per
    // arch, so exact-bit values are not portable).
    //
    // Layout, in ascending claim-id order. Note the roots: `predicate_root`
    // drops the LEAF, so `person.name.given` roots to `person.name` while
    // `org.legal_name` roots to `org`. Assert the pinning up front so a
    // vocabulary change fails LOUDLY here, one line above the fixture it
    // invalidates, rather than as five cryptic cohort mismatches.
    assert_eq!(predicate_root("person.name.given"), "person.name");
    assert_eq!(predicate_root("person.name.family"), "person.name");
    assert_eq!(predicate_root("person.name.nick"), "person.name");
    assert_eq!(predicate_root("org.legal_name"), "org");
    //
    //   0x01 person.name.given  world=None  facet=None   near-0 rad
    //   0x02 person.name.family world=None  facet=None   near-0 rad  → joins 0x01
    //   0x03 person.name.nick   world=None  facet=None   orthogonal  → singleton,
    //                                                                 same bucket
    //   0x04 person.name.given  world=0x80  facet=None   near-0 rad  → own bucket
    //   0x05 person.name.given  world=None  facet=0x90   near-0 rad  → own bucket
    //   0x06 org.legal_name     world=None  facet=None   near-0 rad  → own bucket
    let mut claims = vec![
        claim(0x01, "person.name.given", axis(0.0)),
        claim(0x02, "person.name.family", axis(0.1)),
        claim(0x03, "person.name.nick", vec![0.0, 1.0, 0.0, 0.0]),
        ClusterClaim {
            world: Some(entity(0x80)),
            ..claim(0x04, "person.name.given", axis(0.0))
        },
        ClusterClaim {
            facet: Some(entity(0x90)),
            ..claim(0x05, "person.name.given", axis(0.0))
        },
        claim(0x06, "org.legal_name", axis(0.0)),
    ];
    // Shuffled on purpose: the frozen expectation is order-independent.
    claims.swap(0, 5);
    claims.swap(1, 3);

    let assignments = cluster_claims(&claims, ClusterOptions::default()).expect("cluster");

    // Cohorts order by partition (encoded subject, predicate root, world,
    // facet), then by ascending member ids. All six share subject 0x70, so the
    // predicate root orders first: "org" < "person.name".
    let expected = [
        ExpectedCohort {
            predicate_root: "org",
            world: None,
            facet: None,
            member_ids: vec![entity(0x06)],
        },
        ExpectedCohort {
            predicate_root: "person.name",
            world: None,
            facet: None,
            member_ids: vec![entity(0x01), entity(0x02)],
        },
        ExpectedCohort {
            predicate_root: "person.name",
            world: None,
            facet: None,
            member_ids: vec![entity(0x03)],
        },
        ExpectedCohort {
            predicate_root: "person.name",
            world: None,
            facet: Some(entity(0x90)),
            member_ids: vec![entity(0x05)],
        },
        ExpectedCohort {
            predicate_root: "person.name",
            world: Some(entity(0x80)),
            facet: None,
            member_ids: vec![entity(0x04)],
        },
    ];

    assert_eq!(assignments.cohorts.len(), expected.len());
    for (cohort, want) in assignments.cohorts.iter().zip(expected) {
        assert_eq!(cohort.partition.predicate_root, want.predicate_root);
        assert_eq!(cohort.partition.world, want.world);
        assert_eq!(cohort.partition.facet, want.facet);
        assert_eq!(cohort.member_ids, want.member_ids);
        assert_eq!(
            cohort.cohort_id,
            cohort_id(&cohort.partition, &cohort.member_ids),
            "cohort id must be derived from partition + members"
        );
    }

    // Ties never resolve by luck: the two cohorts sharing the base
    // `person.name` bucket order by their first member id.
    assert_eq!(assignments.cohorts[1].member_ids[0], entity(0x01));
    assert_eq!(assignments.cohorts[2].member_ids[0], entity(0x03));
}
