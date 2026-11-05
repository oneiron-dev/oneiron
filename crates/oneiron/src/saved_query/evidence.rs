use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

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
use super::support::{EVIDENCE_HASH_DOMAIN, canonical_json_bytes, hash_bytes, hash_len};
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

/// A verdict plus the reason it was reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchDecision {
    /// The verdict.
    pub verdict: MatchVerdict,
    /// Human-readable justification, persisted with the memo.
    pub why: String,
}

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
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_HASH_DOMAIN);
    hasher.update(definition.schema_version.to_be_bytes());
    hasher.update(definition.definition_version.to_be_bytes());
    hasher.update(definition.owner_actor.as_bytes());
    hash_scope(&mut hasher, &definition.scope);
    hasher.update(evidence.entity_ref.as_bytes());
    hash_claim_values(&mut hasher, &evidence.claim_values)?;
    hash_claim_value_fingerprints(&mut hasher, &evidence.claim_value_fingerprints);
    hash_edge_targets(&mut hasher, &evidence.edge_targets);
    hash_semantic_inputs(&mut hasher, &evidence.semantic_inputs);
    hash_scope(&mut hasher, &evidence.scope_membership);
    Ok(hasher.finalize().into())
}

fn hash_scope(hasher: &mut Sha256, scope: &QueryScope) {
    hash_len(hasher, scope.worlds.len());
    for world in &scope.worlds {
        hasher.update(world.as_bytes());
    }
    hash_len(hasher, scope.facets.len());
    for facet in &scope.facets {
        hash_bytes(hasher, facet.as_bytes());
    }
}

fn hash_claim_values(hasher: &mut Sha256, values: &[(String, Value)]) -> Result<()> {
    hash_len(hasher, values.len());
    for (predicate, value) in values {
        hash_bytes(hasher, predicate.as_bytes());
        hash_bytes(hasher, &canonical_json_bytes(value)?);
    }
    Ok(())
}

fn hash_claim_value_fingerprints(hasher: &mut Sha256, values: &[ClaimValueFingerprint]) {
    hash_len(hasher, values.len());
    for (predicate, bytes) in values {
        hash_bytes(hasher, predicate.as_bytes());
        hash_bytes(hasher, bytes);
    }
}

fn hash_edge_targets(hasher: &mut Sha256, targets: &[(String, EntityId)]) {
    hash_len(hasher, targets.len());
    for (kind, target) in targets {
        hash_bytes(hasher, kind.as_bytes());
        hasher.update(target.as_bytes());
    }
}

fn hash_semantic_inputs(hasher: &mut Sha256, inputs: &[(EntityId, String)]) {
    hash_len(hasher, inputs.len());
    for (exemplar, fingerprint) in inputs {
        hasher.update(exemplar.as_bytes());
        hash_bytes(hasher, fingerprint.as_bytes());
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
