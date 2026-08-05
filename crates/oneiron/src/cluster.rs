//! Pure, deterministic claim clustering — a PROPOSE-ONLY tool.
//!
//! The Dreamer calls this module to ask "which of these claims plausibly talk
//! about the same thing?" and gets back cohort assignments plus a cohesion
//! diagnostic. That is the whole contract. This module holds no vault handle,
//! opens no write transaction, calls no gate, and emits no merge, split, or
//! identity-topology operation: cosine selects a cohort FOR Dreamer judgment,
//! cosine never decides belief truth. Every merge/split/accumulate/escalate
//! decision stays with the Dreamer.
//!
//! Two stages:
//!
//! 1. **Exact partition.** Claims are bucketed by the canonical Dreamer key
//!    `(subject, predicate_root, world, facet)`. Nothing approximate happens
//!    here — a differing world or facet is a different bucket even when the
//!    embeddings are identical. `facet` is whatever the caller resolved from
//!    the claim's facet relation; `None` is a valid, common value.
//! 2. **Complete-link cosine grouping** inside each partition. Inputs are
//!    ordered by claim-id bytes, then greedily assigned: a candidate joins the
//!    first cohort whose members are ALL at least
//!    [`CLUSTER_COHESION_THRESHOLD`] similar to it. Complete-link is pinned
//!    deliberately — single-link/connected-components would chain two mutually
//!    incoherent claims together through a bridge claim.
//!
//! Determinism: sorting by claim id before grouping makes the output invariant
//! under input permutation, and [`CohortId`] is a domain-separated BLAKE3 hash
//! over the partition key plus the ascending member ids, so a cohort's identity
//! is stable across runs, processes, and architectures.

use std::collections::BTreeMap;

use crate::claim::{ClaimSubject, predicate_root};
use crate::distance::cosine_similarity;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Minimum pairwise cosine similarity required for two claims to share a
/// cohort. Pinned v1 contract value; complete-link, not single-link.
pub const CLUSTER_COHESION_THRESHOLD: f32 = 0.82;

/// Domain separator for [`CohortId`] derivation.
pub const CLUSTER_ID_DOMAIN: &[u8] = b"oneiron:claim-cohort:v1";

/// Cohesion reported for a cohort of one: a singleton is perfectly coherent
/// with itself, and the value is the identity element of the running minimum.
const SINGLETON_COHESION: f32 = 1.0;

/// Total-order projection of a [`ClusterPartitionKey`]: encoded subject bytes,
/// predicate root, world, facet. [`ClaimSubject`] is not `Ord`, so its pinned
/// wire encoding carries the ordering.
type PartitionOrd = (Vec<u8>, String, Option<EntityId>, Option<EntityId>);

/// Stage-1 bucket: the canonical Dreamer key. Two claims cluster only when
/// every field here matches exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterPartitionKey {
    /// Claim subject, compared exactly (entity or edge reference).
    pub subject: ClaimSubject,
    /// Grouping unit of the predicate.
    ///
    /// PARTITION: the ROOT, not the full predicate — `predicate_root` drops
    /// the LEAF, so `person.name.given` and `person.name.family` share the
    /// `person.name` bucket (DESIGN-PIN A0).
    pub predicate_root: String,
    /// World scope; `None` is base reality and is its own bucket.
    pub world: Option<EntityId>,
    /// Resolved facet; `None` is its own bucket.
    pub facet: Option<EntityId>,
}

/// One already-decoded claim descriptor plus its embedding. The caller decodes
/// claims and resolves facets; this module never reads storage.
#[derive(Debug, Clone, PartialEq)]
pub struct ClusterClaim {
    /// Durable CLAIM entity id. Also the deterministic ordering key.
    pub claim_id: EntityId,
    /// Claim subject.
    pub subject: ClaimSubject,
    /// Full dotted predicate; the module groups by its root (leaf dropped).
    pub predicate: String,
    /// World scope, absent for base reality.
    pub world: Option<EntityId>,
    /// Resolved by the caller from the claim's facet relation; absent is valid.
    pub facet: Option<EntityId>,
    /// Claim embedding. Every claim in one call must share its dimension.
    pub embedding: Vec<f32>,
}

/// Caller-tunable clustering knobs.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClusterOptions {
    /// Complete-link cosine floor in `[-1, 1]`.
    pub cohesion_threshold: f32,
}

impl Default for ClusterOptions {
    fn default() -> Self {
        Self {
            cohesion_threshold: CLUSTER_COHESION_THRESHOLD,
        }
    }
}

/// Stable cohort identity: domain-separated BLAKE3 over the partition key and
/// the cohort's ascending member ids. Derived, never constructed by callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CohortId([u8; 32]);

impl CohortId {
    /// Returns the raw 32-byte digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One proposed cohort. Assignments and diagnostics only — deliberately no
/// operation, verb, or suggestion field: the Dreamer decides what a cohort
/// means.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimCohort {
    /// Permutation-stable identity of this cohort.
    pub cohort_id: CohortId,
    /// Exact bucket every member shares.
    pub partition: ClusterPartitionKey,
    /// Member claim ids, ascending by id bytes.
    pub member_ids: Vec<EntityId>,
    /// Minimum pairwise cosine within the cohort; singleton = 1.0.
    pub cohesion: f32,
}

/// Full result of one clustering call: a partition of the input claims.
#[derive(Debug, Clone, PartialEq)]
pub struct ClusterAssignments {
    /// Cohorts ordered by partition key, then by ascending member ids.
    pub cohorts: Vec<ClaimCohort>,
}

/// Groups `claims` into cohorts.
///
/// Every input claim lands in exactly one cohort; empty input yields an empty
/// assignment set. The result is invariant under permutation of `claims`.
///
/// # Errors
///
/// Returns [`Error::InvalidConfig`] when the threshold is outside `[-1, 1]`
/// (NaN included) or every embedding is empty, [`Error::DimensionMismatch`]
/// when embedding dimensions differ, and [`Error::InvalidVector`] when a
/// component is NaN or infinite.
pub fn cluster_claims(
    claims: &[ClusterClaim],
    options: ClusterOptions,
) -> Result<ClusterAssignments> {
    validate_cluster_input(claims, options)?;

    let mut ordered: Vec<&ClusterClaim> = claims.iter().collect();
    ordered.sort_by_key(|claim| claim.claim_id);

    // BTreeMap keeps the partitions in `PartitionOrd` order, so cohort output
    // order needs no second sort.
    let mut partitions: BTreeMap<PartitionOrd, (ClusterPartitionKey, Vec<&ClusterClaim>)> =
        BTreeMap::new();
    for claim in ordered {
        partitions
            .entry(partition_ord(claim))
            .or_insert_with(|| (partition_of(claim), Vec::new()))
            .1
            .push(claim);
    }

    let mut cohorts = Vec::new();
    for (partition, members) in partitions.into_values() {
        // (members, running minimum pairwise cosine), in creation order.
        let mut open: Vec<(Vec<&ClusterClaim>, f32)> = Vec::new();

        'candidate: for claim in members {
            for (cohort_members, cohesion) in &mut open {
                let candidate_cohesion = complete_link_cohesion(&claim.embedding, cohort_members);
                if candidate_cohesion >= options.cohesion_threshold {
                    cohort_members.push(claim);
                    *cohesion = cohesion.min(candidate_cohesion);
                    continue 'candidate;
                }
            }
            open.push((vec![claim], SINGLETON_COHESION));
        }

        for (cohort_members, cohesion) in open {
            let member_ids: Vec<EntityId> =
                cohort_members.iter().map(|claim| claim.claim_id).collect();
            cohorts.push(ClaimCohort {
                cohort_id: cohort_id(&partition, &member_ids),
                partition: partition.clone(),
                member_ids,
                cohesion,
            });
        }
    }

    Ok(ClusterAssignments { cohorts })
}

/// Rejects malformed input before any grouping runs, so a bad vector fails with
/// a typed error instead of producing partial output.
fn validate_cluster_input(claims: &[ClusterClaim], options: ClusterOptions) -> Result<()> {
    let threshold = options.cohesion_threshold;
    if !(-1.0..=1.0).contains(&threshold) {
        return Err(Error::InvalidConfig(format!(
            "cluster cohesion threshold {threshold} is outside [-1, 1]"
        )));
    }

    let Some(first) = claims.first() else {
        return Ok(());
    };
    let dimensions = first.embedding.len();
    if dimensions == 0 {
        return Err(Error::InvalidConfig(
            "cluster claim embedding must not be empty".to_owned(),
        ));
    }

    for claim in claims {
        if claim.embedding.len() != dimensions {
            return Err(Error::DimensionMismatch {
                expected: dimensions,
                got: claim.embedding.len(),
            });
        }
        if let Some(error) = Error::invalid_vector_component(&claim.embedding) {
            return Err(error);
        }
    }

    Ok(())
}

/// Complete-link score: the WORST cosine between `candidate` and any current
/// member. A candidate joins only when this clears the threshold, which is what
/// stops single-link chaining.
///
/// Infallible by construction: [`validate_cluster_input`] has already rejected
/// mixed dimensions and non-finite components, so `cosine_similarity` cannot
/// see a malformed pair here. (The blueprint sketched `-> Result<f32>`; a
/// private always-`Ok` wrapper trips the workspace `unnecessary_wraps` deny.)
fn complete_link_cohesion(candidate: &[f32], members: &[&ClusterClaim]) -> f32 {
    members.iter().fold(SINGLETON_COHESION, |minimum, member| {
        minimum.min(cosine_similarity(candidate, &member.embedding))
    })
}

/// Domain-separated BLAKE3 over the partition key and the cohort's members.
/// Every variable-length field is length-prefixed and every optional field is
/// presence-tagged, so no two distinct cohorts share a preimage.
fn cohort_id(partition: &ClusterPartitionKey, sorted_members: &[EntityId]) -> CohortId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CLUSTER_ID_DOMAIN);
    hash_bytes(&mut hasher, &partition.subject.encode());
    hash_bytes(&mut hasher, partition.predicate_root.as_bytes());
    hash_optional_entity(&mut hasher, partition.world);
    hash_optional_entity(&mut hasher, partition.facet);
    hash_length(&mut hasher, sorted_members.len());
    for member in sorted_members {
        hasher.update(member.as_bytes());
    }
    CohortId(*hasher.finalize().as_bytes())
}

fn partition_of(claim: &ClusterClaim) -> ClusterPartitionKey {
    ClusterPartitionKey {
        subject: claim.subject,
        predicate_root: predicate_root(&claim.predicate).to_owned(),
        world: claim.world,
        facet: claim.facet,
    }
}

fn partition_ord(claim: &ClusterClaim) -> PartitionOrd {
    (
        claim.subject.encode(),
        predicate_root(&claim.predicate).to_owned(),
        claim.world,
        claim.facet,
    )
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hash_length(hasher, bytes.len());
    hasher.update(bytes);
}

fn hash_length(hasher: &mut blake3::Hasher, length: usize) {
    hasher.update(&(length as u64).to_le_bytes());
}

fn hash_optional_entity(hasher: &mut blake3::Hasher, entity: Option<EntityId>) {
    match entity {
        Some(entity) => {
            hasher.update(&[1]);
            hasher.update(entity.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

#[cfg(test)]
mod tests;
