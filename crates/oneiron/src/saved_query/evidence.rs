use oneiron_contracts::fingerprint::{LegacyDigest, purposes};
use serde_json::Value;

use crate::Vault;
use crate::entity_id::EntityId;
// Referenced only by intra-doc links on `compute_evidence_hash` and
// `verdict_memo`; gated so the name is in scope for rustdoc without being an
// unused import.
#[cfg(doc)]
use crate::error::Error;
use crate::error::Result;

use super::definition::{QueryScope, SavedQueryDefinition};
// Referenced only by an intra-doc link on `compute_evidence_hash`; gated so the
// name is in scope for rustdoc without being an unused import.
#[cfg(doc)]
use super::evaluator::SavedQueryEvaluator;
use super::storage::MEMOS;
use super::support::canonical_json_bytes;
use super::value_fingerprint::ClaimValueFingerprint;

/// One entity's evidence, narrowed to what a definition declared relevant.
#[derive(Debug, Clone, PartialEq)]
pub struct RelevantEvidence {
    /// The entity this evidence describes.
    pub entity_ref: EntityId,
    /// Live claim values for the declared predicates.
    pub claim_values: Vec<(String, Value)>,
    /// The same claims' ORIGINAL accepted values as lossless canonical bytes,
    /// sorted. Hashed beside `claim_values`, so a value their projection
    /// collapses still moves the evidence hash (FIX 10090); matching and the
    /// judge never read them.
    pub claim_value_fingerprints: Vec<(String, Vec<u8>)>,
    /// Outbound edge targets for the declared edge kinds.
    pub edge_targets: Vec<(String, EntityId)>,
    /// Per-exemplar fingerprint of the compared vectors. The string is a hex
    /// digest, not prose: its only job is to move when either vector moves, so
    /// a re-embedding invalidates the memo.
    pub semantic_inputs: Vec<(EntityId, String)>,
    /// The entity's OWN world/facet membership, narrowed to the effective
    /// scope. It is evidence, not a read filter: membership is what decides
    /// whether the entity is inside the query's reach at all, and putting it
    /// here is what makes moving between worlds invalidate the memo.
    pub scope_membership: QueryScope,
}

pub use crate::store::query_memos::SavedQueryDerivationEnvelope;
pub use crate::store::query_memos::VerdictMemoKey;

pub use crate::memory::query_records::MatchVerdict;

#[doc(hidden)]
pub use oneiron_records::saved_query::evidence::MatchDecision;

/// Result of evaluating one entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationOutcome {
    /// The decision.
    pub decision: MatchDecision,
    /// Hash the decision is memoized under.
    pub evidence_hash: [u8; EVIDENCE_HASH_LEN],
    /// Whether a stored memo answered without running the matcher.
    pub memo_hit: bool,
}

pub use crate::store::query_health::WakeEvaluationReport;

pub use crate::store::query_memos::EVIDENCE_HASH_LEN;
pub use crate::store::query_memos::VerdictMemoRow;

/// Hashes the definition version, its scope, and the relevant evidence.
///
/// Callers pass the definition AS EVALUATED — [`SavedQueryEvaluator`] narrows
/// `scope` to the owner's effective reach before calling. The scope is IN the
/// hash, not merely in the read path: the owner's reach can change without the
/// definition version moving, and a memo that survived that change would answer
/// with a verdict the owner is no longer entitled to. Evidence outside the
/// declared dependency set never reaches this function, which is what keeps
/// irrelevant movement from invalidating memos.
///
/// # Errors
///
/// [`Error::InvariantViolation`] when a claim value cannot be canonicalized.
pub fn compute_evidence_hash(
    definition: &SavedQueryDefinition,
    evidence: &RelevantEvidence,
) -> Result<[u8; EVIDENCE_HASH_LEN]> {
    // A stored memo key, so it keeps its bytes (K): SHA-256, the tag
    // `oneiron.saved_query.evidence.v2` first, every length a u64 big-endian.
    let mut digest = LegacyDigest::new(purposes::saved_query::EVIDENCE);
    digest
        .raw(&definition.schema_version.to_be_bytes())
        .raw(&definition.definition_version.to_be_bytes())
        .raw(definition.owner_actor.as_bytes());
    hash_scope(&mut digest, &definition.scope);
    digest.raw(evidence.entity_ref.as_bytes());
    hash_claim_values(&mut digest, &evidence.claim_values)?;
    hash_claim_value_fingerprints(&mut digest, &evidence.claim_value_fingerprints);
    hash_edge_targets(&mut digest, &evidence.edge_targets);
    hash_semantic_inputs(&mut digest, &evidence.semantic_inputs);
    hash_scope(&mut digest, &evidence.scope_membership);
    Ok(digest.finish())
}

/// The world count, then each world's 16 bytes; the facet count, then each
/// facet framed by its length.
fn hash_scope(digest: &mut LegacyDigest, scope: &QueryScope) {
    digest.len_u64_be(scope.worlds.len());
    for world in &scope.worlds {
        digest.raw(world.as_bytes());
    }
    digest.len_u64_be(scope.facets.len());
    for facet in &scope.facets {
        digest.len_u64_be(facet.len()).raw(facet.as_bytes());
    }
}

fn hash_claim_values(digest: &mut LegacyDigest, values: &[(String, Value)]) -> Result<()> {
    digest.len_u64_be(values.len());
    for (predicate, value) in values {
        let value = canonical_json_bytes(value)?;
        digest
            .len_u64_be(predicate.len())
            .raw(predicate.as_bytes())
            .len_u64_be(value.len())
            .raw(&value);
    }
    Ok(())
}

fn hash_claim_value_fingerprints(digest: &mut LegacyDigest, values: &[ClaimValueFingerprint]) {
    digest.len_u64_be(values.len());
    for (predicate, bytes) in values {
        digest
            .len_u64_be(predicate.len())
            .raw(predicate.as_bytes())
            .len_u64_be(bytes.len())
            .raw(bytes);
    }
}

fn hash_edge_targets(digest: &mut LegacyDigest, targets: &[(String, EntityId)]) {
    digest.len_u64_be(targets.len());
    for (kind, target) in targets {
        digest
            .len_u64_be(kind.len())
            .raw(kind.as_bytes())
            .raw(target.as_bytes());
    }
}

fn hash_semantic_inputs(digest: &mut LegacyDigest, inputs: &[(EntityId, String)]) {
    digest.len_u64_be(inputs.len());
    for (exemplar, fingerprint) in inputs {
        digest
            .raw(exemplar.as_bytes())
            .len_u64_be(fingerprint.len())
            .raw(fingerprint.as_bytes());
    }
}

/// Reads the memo stored under `key`, if any.
///
/// # Errors
///
/// Storage errors propagate; a malformed row is rejected as
/// [`Error::CorruptedIndex`] rather than silently treated as a miss — a memo
/// that cannot be read is not the same as a memo that says "no match".
pub fn verdict_memo(vault: &Vault, key: &VerdictMemoKey) -> Result<Option<VerdictMemoRow>> {
    let rtxn = vault.store.env.read_txn()?;
    MEMOS.get(&vault.store, &rtxn, key)
}

/// Persists a verdict memo.
///
/// # Errors
///
/// Storage errors propagate unchanged.
pub fn put_verdict_memo(vault: &Vault, row: &VerdictMemoRow) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        MEMOS.put(&vault.store, wtxn, &row.key, row)?;
        Ok(())
    })
}
