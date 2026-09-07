//! Corpus scope for CLAIM records (ONE-1914): the AUDIENCE a claim belongs
//! to, carried as a typed nested entry inside the claim's engine-owned
//! `scope` map.
//!
//! The outer CLAIM body key stays `scope`. [`crate::claim::CLAIM_BODY_KEYS`]
//! is a closed 16-key storage ABI and this module adds nothing to it — no new
//! body key, no new entity type byte, no new edge kind, no new LMDB database.
//! Inside that opaque map, [`CLAIM_SCOPE_CORPUS_ID_KEY`] is the single
//! recognized corpus entry: exactly one 16-byte MessagePack Binary
//! [`EntityId`]. Every sibling entry (`sensitivity`, `evidence_taint`,
//! `federated_original_source`, `demotion_rung`, `pre_restamp_scope`, and
//! anything this crate does not recognize) stays opaque and is preserved
//! losslessly by the writer here.
//!
//! Absence is meaningful: a claim with no `corpus_id` entry is UNSCOPED —
//! core knowledge that belongs to every corpus, and query selection therefore
//! keeps it inside every selected corpus. Corpus scope splits claims by
//! audience, not by topic, and it is orthogonal to
//! [`crate::pipeline::WorldScope`], which stays the epistemic
//! (which-reality) axis and the codebase-membership clamp.

use rmpv::Value;

use crate::claim::{MapValue, single_map_value};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};

/// Nested key inside a CLAIM body's `scope` map carrying the corpus id.
///
/// This is NOT a top-level claim body key: the body vocabulary is the closed
/// set in [`crate::claim::CLAIM_BODY_KEYS`], and the corpus dimension lives
/// one level down, inside the opaque `scope` map.
pub const CLAIM_SCOPE_CORPUS_ID_KEY: &str = "corpus_id";

/// Identity wrapper over the [`EntityId`] naming a corpus.
///
/// A corpus is addressed by an ordinary entity id; this newtype exists to
/// keep the corpus dimension type-distinct at call sites, not to introduce a
/// new identifier space. It converts to and from [`EntityId`] losslessly and
/// allocates no entity type byte of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CorpusId(EntityId);

impl CorpusId {
    /// Wraps an entity id as a corpus id.
    #[must_use]
    pub const fn from_entity_id(id: EntityId) -> Self {
        Self(id)
    }

    /// Returns the wrapped entity id.
    #[must_use]
    pub const fn entity_id(self) -> EntityId {
        self.0
    }
}

impl From<EntityId> for CorpusId {
    fn from(id: EntityId) -> Self {
        Self(id)
    }
}

impl From<CorpusId> for EntityId {
    fn from(id: CorpusId) -> Self {
        id.0
    }
}

/// Merges `corpus_id` into a claim's `scope` map and returns the new map.
///
/// Every entry the caller already had is preserved in place and byte-for-byte
/// — this writer only owns the single [`CLAIM_SCOPE_CORPUS_ID_KEY`] entry.
/// Stamping a claim that already carries a corpus id REPLACES that entry
/// (including a pre-existing duplicated pair) rather than appending a second
/// one, so the result always decodes unambiguously. `None` starts a fresh
/// map.
///
/// Fail-closed on a `scope` that is present but not a map: this writer never
/// silently discards an opaque payload it cannot merge into. (The reader,
/// [`corpus_id_from_scope`], is deliberately more tolerant — see its docs.)
pub fn scope_with_corpus_id(scope: Option<Value>, corpus_id: CorpusId) -> Result<Value> {
    let mut entries = match scope {
        None => Vec::new(),
        Some(Value::Map(entries)) => entries,
        Some(_) => return Err(Error::InvalidClaimBody("scope must be a map")),
    };

    entries.retain(|(key, _)| key.as_str() != Some(CLAIM_SCOPE_CORPUS_ID_KEY));
    entries.push((
        Value::from(CLAIM_SCOPE_CORPUS_ID_KEY),
        Value::Binary(corpus_id.entity_id().as_bytes().to_vec()),
    ));
    Ok(Value::Map(entries))
}

/// Reads the corpus a claim's `scope` map is scoped to.
///
/// * missing key (no scope map, or a map without the corpus entry) =>
///   `Ok(None)` — the claim is unscoped/core;
/// * present and well formed => `Ok(Some(id))`;
/// * duplicated key, non-Binary value, a Binary that is not exactly 16 bytes,
///   or reserved entity-id bytes => [`Error::InvalidClaimBody`].
///
/// Reserved-id rejection reuses the crate's single rule,
/// [`EntityId::from_bytes`], exactly like the `world`/`rel` body keys do.
///
/// A `scope` value that is present but NOT a map reads as `Ok(None)`: it
/// carries no corpus entry, and the corpus dimension does not get to redefine
/// the shape of the surrounding opaque map. Unknown sibling entries are never
/// inspected.
pub fn corpus_id_from_scope(scope: Option<&Value>) -> Result<Option<CorpusId>> {
    let Some(Value::Map(entries)) = scope else {
        return Ok(None);
    };

    let value = match single_map_value(entries, CLAIM_SCOPE_CORPUS_ID_KEY) {
        MapValue::Missing => return Ok(None),
        MapValue::Duplicate => return Err(Error::InvalidClaimBody("duplicate corpus id")),
        MapValue::Present(value) => value,
    };

    let Value::Binary(bytes) = value else {
        return Err(Error::InvalidClaimBody(
            "corpus id must be MessagePack binary",
        ));
    };
    let raw: [u8; ENTITY_ID_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidClaimBody("corpus id must be a 16-byte corpus id"))?;
    let id =
        EntityId::from_bytes(raw).map_err(|_| Error::InvalidClaimBody("corpus id is reserved"))?;
    Ok(Some(CorpusId::from_entity_id(id)))
}

/// Corpus retrieval scope for one query, selected via
/// [`crate::PipelineBuilder::corpus`]. The default is [`CorpusScope::All`],
/// under which the filter is a no-op and results are exactly what they were
/// before a corpus was ever selectable.
///
/// Unscoped claims are UNIVERSAL: they carry no audience stamp, so every
/// corpus-selecting variant keeps them. Only [`CorpusScope::Unscoped`] runs
/// the other way, keeping core knowledge and removing every corpus-scoped
/// claim.
///
/// Non-CLAIM entities have no corpus and pass every scope untouched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum CorpusScope {
    /// Span every corpus — unscoped and corpus-scoped claims alike. The
    /// default.
    #[default]
    All,
    /// Only unscoped/core claims; every corpus-scoped claim is removed.
    Unscoped,
    /// Claims scoped to this corpus PLUS unscoped/core claims. Claims scoped
    /// to any OTHER corpus are removed.
    Corpus(CorpusId),
    /// Claims scoped to any of these corpora PLUS unscoped/core claims.
    AnyOf(Vec<CorpusId>),
}

impl CorpusScope {
    /// Normalizes the scope into its canonical form so two callers naming the
    /// same corpora filter identically: [`CorpusScope::AnyOf`] is sorted and
    /// deduplicated. An EMPTY `AnyOf` names no corpus at all and is rejected
    /// fail-closed with [`Error::InvalidConfig`] rather than silently
    /// behaving like [`CorpusScope::Unscoped`].
    pub(crate) fn canonicalize(self) -> Result<Self> {
        match self {
            Self::AnyOf(mut ids) => {
                if ids.is_empty() {
                    return Err(Error::InvalidConfig(
                        "corpus scope AnyOf must name at least one corpus".to_owned(),
                    ));
                }
                ids.sort_unstable();
                ids.dedup();
                Ok(Self::AnyOf(ids))
            }
            scope => Ok(scope),
        }
    }

    /// The scope predicate. `claim_scope` is the candidate's decoded corpus:
    /// `None` for an unscoped claim AND for every non-CLAIM entity, which is
    /// why non-claims pass every variant unchanged.
    pub(crate) fn matches(&self, claim_scope: Option<CorpusId>) -> bool {
        match self {
            Self::All => true,
            Self::Unscoped => claim_scope.is_none(),
            Self::Corpus(id) => claim_scope.is_none_or(|scope| scope == *id),
            Self::AnyOf(ids) => claim_scope.is_none_or(|scope| ids.contains(&scope)),
        }
    }
}

#[cfg(test)]
mod tests;
