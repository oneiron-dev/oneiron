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
use super::storage::{decode_memo_row, encode_memo_row, keys, meta_row, put_meta_row};
use super::support::{EVIDENCE_HASH_DOMAIN, canonical_json_bytes, hash_bytes, hash_len};

/// One entity's evidence, narrowed to what a definition declared relevant.
#[derive(Debug, Clone, PartialEq)]
pub struct RelevantEvidence {
    /// The entity this evidence describes.
    pub entity_ref: EntityId,
    /// Live claim values for the declared predicates.
    pub claim_values: Vec<(String, Value)>,
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

/// The `Of360DerivationEnvelope` shape, mirrored for saved-query verdicts.
///
/// Field-for-field the same envelope `extraction_eval.rs` established. It is
/// copied rather than shared on purpose: generalizing that type into a common
/// envelope would make one struct answerable to two evolving derivations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedQueryDerivationEnvelope {
    /// Hex evidence hash the verdict was derived from.
    pub content_hash: String,
    /// Model id for a judged verdict, or the matcher kind token otherwise.
    pub model_id: String,
    /// Evaluator version token.
    pub version: String,
    /// Hex digest of the canonical matcher specification.
    pub params_hash: String,
}

/// Memo identity: one verdict per (query, entity, evidence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerdictMemoKey {
    /// The saved query.
    pub query_ref: EntityId,
    /// The entity evaluated.
    pub entity_ref: EntityId,
    /// Hash over the definition version, effective scope, and relevant evidence.
    pub evidence_hash: [u8; EVIDENCE_HASH_LEN],
}

/// A stage-2 verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchVerdict {
    /// The entity is a member.
    Match,
    /// The entity is not a member.
    NoMatch,
}

impl MatchVerdict {
    /// Wire token for this verdict.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::NoMatch => "no_match",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "match" => Some(Self::Match),
            "no_match" => Some(Self::NoMatch),
            _ => None,
        }
    }
}

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

/// Progress report for a bounded wake batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeEvaluationReport {
    /// Entities evaluated in this batch.
    pub evaluated: u32,
    /// Evaluations answered by a memo.
    pub memo_hits: u32,
    /// Stage-2 judgements actually executed.
    pub judges_run: u32,
    /// Last entity visited when a bound stopped the batch early. `None` means
    /// the candidate set was exhausted.
    pub resume_after: Option<EntityId>,
}

/// A persisted verdict memo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictMemoRow {
    /// Memo identity.
    pub key: VerdictMemoKey,
    /// Definition version at evaluation time.
    pub definition_version: u64,
    /// Memoized verdict.
    pub verdict: MatchVerdict,
    /// Memoized justification.
    pub why: String,
    /// Local derivation envelope.
    pub envelope: SavedQueryDerivationEnvelope,
    /// Evaluation timestamp.
    pub evaluated_at: u64,
}

/// SHA-256-sized evidence hashes, matching CA-01's derivation contract.
pub const EVIDENCE_HASH_LEN: usize = 32;

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
    let Some(raw) = meta_row(vault, &keys::memo(key))? else {
        return Ok(None);
    };
    decode_memo_row(&raw).map(Some)
}

/// Persists a verdict memo.
///
/// # Errors
///
/// Storage errors propagate unchanged.
pub fn put_verdict_memo(vault: &Vault, row: &VerdictMemoRow) -> Result<()> {
    put_meta_row(vault, &keys::memo(&row.key), &encode_memo_row(row)?)
}
