//! Deterministic and authority-boundary fixtures for the clustering tool.

use crate::claim::ClaimSubject;
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

// ---------------------------------------------------------------------------
// Typed-error rejection (no panics, no partial output)
// ---------------------------------------------------------------------------

#[test]
fn the_permissive_duplicate_shape_that_broke_permutation_invariance_is_gone() {
    // The traced counterexample, kept as a regression pin. Two claims share an
    // id: A1 at 0 rad, A2 at `SPLIT` rad (cos(A1,A2) = 0.622, BELOW the 0.82
    // floor), plus B placed between them so cos(A1,B) = 0.955 and
    // cos(A2,B) = 0.826 — both ABOVE the floor. Under the old permissive
    // validator the stable sort left the tied pair in CALLER order, so B joined
    // whichever of A1/A2 came first and the cohort reported cohesion 0.955 or
    // 0.825 depending purely on input order. Both orders must now be rejected
    // identically, which is what restores the documented invariance.
    const SPLIT: f32 = 0.899_502; // acos(0.622)
    const BETWEEN: f32 = 0.301_137; // acos(0.955)

    // Same seed for a1/a2 — that is the duplicate under test.
    let a1 = claim(0x01, "person.name", axis(0.0));
    let a2 = claim(0x01, "person.name", axis(SPLIT));
    let b = claim(0x03, "person.name", axis(BETWEEN));

    // The geometry is the one the counterexample needs: B clears the floor
    // against BOTH tied claims, while the tied claims do not clear it against
    // each other — so cohort membership genuinely hinged on caller order.
    let cos = |x: &ClusterClaim, y: &ClusterClaim| {
        crate::distance::cosine_similarity(&x.embedding, &y.embedding)
    };
    assert!(cos(&a1, &b) >= CLUSTER_COHESION_THRESHOLD);
    assert!(cos(&a2, &b) >= CLUSTER_COHESION_THRESHOLD);
    assert!(cos(&a1, &a2) < CLUSTER_COHESION_THRESHOLD);

    for order in [vec![a1.clone(), a2.clone(), b.clone()], vec![a2, a1, b]] {
        assert!(
            matches!(
                cluster_claims(&order, ClusterOptions::default())
                    .expect_err("order-dependent duplicate shape"),
                Error::InvalidConfig(_)
            ),
            "every permutation of the duplicate shape must be rejected"
        );
    }
}
