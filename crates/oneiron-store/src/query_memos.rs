//! Standing-query memo values, exact codecs and response-carriage ownership.

use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value};

use crate::query_memo_codec::canonical_json_bytes;
use crate::query_memo_codec::hex_lower;
use crate::query_memo_codec::parse_entity_ref;
use crate::side_table;
use crate::side_table::codec::CodecError;
use crate::side_table::codec::RawValue;
use crate::side_table::key::SideKey;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

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
    /// Every row the evidence was read from (FIX 10089): the query, the
    /// candidate, each claim, edge target, exemplar, world and facet. The
    /// erase of any one takes this memo, its `why` included. `None` when the
    /// set is not known whole, and then every erase takes it.
    pub source_refs: Option<Vec<EntityId>>,
    /// Local derivation envelope.
    pub envelope: SavedQueryDerivationEnvelope,
    /// Evaluation timestamp.
    pub evaluated_at: u64,
}

/// SHA-256-sized evidence hashes, matching CA-01's derivation contract.
pub const EVIDENCE_HASH_LEN: usize = 32;

/// A stage-2 verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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

impl SideKey for VerdictMemoKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.query_ref.as_bytes());
        out.extend_from_slice(self.entity_ref.as_bytes());
        out.extend_from_slice(&self.evidence_hash);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (query_ref, rest) = bytes.split_at_checked(16)?;
        let (entity_ref, evidence_hash) = rest.split_at_checked(16)?;
        Some(Self {
            query_ref: EntityId::from_bytes(query_ref.try_into().ok()?).ok()?,
            entity_ref: EntityId::from_bytes(entity_ref.try_into().ok()?).ok()?,
            evidence_hash: evidence_hash.try_into().ok()?,
        })
    }
}

impl RawValue for VerdictMemoRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_memo_row(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_memo_row(bytes)?)
    }
}

pub fn encode_memo_row(row: &VerdictMemoRow) -> Result<Vec<u8>> {
    let mut root = JsonMap::new();
    root.insert(
        "query_ref".to_owned(),
        Value::String(row.key.query_ref.to_hex()),
    );
    root.insert(
        "entity_ref".to_owned(),
        Value::String(row.key.entity_ref.to_hex()),
    );
    root.insert(
        "evidence_hash".to_owned(),
        Value::String(hex_lower(&row.key.evidence_hash)),
    );
    root.insert(
        "definition_version".to_owned(),
        Value::from(row.definition_version),
    );
    root.insert(
        "verdict".to_owned(),
        Value::String(row.verdict.as_str().to_owned()),
    );
    root.insert("why".to_owned(), Value::String(row.why.clone()));
    // Absent while the sources are not known whole (FIX 10089).
    if let Some(sources) = &row.source_refs {
        let refs = sources.iter().map(|id| Value::String(id.to_hex()));
        root.insert("source_refs".to_owned(), Value::Array(refs.collect()));
    }
    root.insert(
        "envelope".to_owned(),
        serde_json::to_value(&row.envelope)
            .map_err(|_| Error::InvariantViolation("saved query envelope encode failed"))?,
    );
    root.insert("evaluated_at".to_owned(), Value::from(row.evaluated_at));
    canonical_json_bytes(&Value::Object(root))
}

pub fn decode_memo_row(raw: &[u8]) -> Result<VerdictMemoRow> {
    const CONTEXT: &str = "saved query verdict memo";
    let value = parse_row(raw, CONTEXT)?;
    Ok(VerdictMemoRow {
        key: VerdictMemoKey {
            query_ref: required_entity_ref(&value, "query_ref", CONTEXT)?,
            entity_ref: required_entity_ref(&value, "entity_ref", CONTEXT)?,
            evidence_hash: required_hash(&value, "evidence_hash", CONTEXT)?,
        },
        definition_version: required_u64(&value, "definition_version", CONTEXT)?,
        verdict: MatchVerdict::parse(&required_string(&value, "verdict", CONTEXT)?)
            .ok_or(Error::CorruptedIndex(CONTEXT))?,
        why: required_string(&value, "why", CONTEXT)?,
        source_refs: value
            .get("source_refs")
            .map(|refs| {
                refs.as_array()
                    .ok_or(Error::CorruptedIndex(CONTEXT))?
                    .iter()
                    .map(|id| parse_entity_ref(id).map_err(|_| Error::CorruptedIndex(CONTEXT)))
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?,
        envelope: serde_json::from_value(
            value
                .get("envelope")
                .cloned()
                .ok_or(Error::CorruptedIndex(CONTEXT))?,
        )
        .map_err(|_| Error::CorruptedIndex(CONTEXT))?,
        evaluated_at: required_u64(&value, "evaluated_at", CONTEXT)?,
    })
}

pub fn parse_row(raw: &[u8], context: &'static str) -> Result<Value> {
    serde_json::from_slice(raw).map_err(|_| Error::CorruptedIndex(context))
}

pub fn required_string(value: &Value, key: &str, context: &'static str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Error::CorruptedIndex(context))
}

pub fn required_actor_class(
    value: &Value,
    key: &str,
    context: &'static str,
) -> Result<EdgeActorClass> {
    match required_string(value, key, context)?.as_str() {
        "human" => Ok(EdgeActorClass::Human),
        "agent" => Ok(EdgeActorClass::Agent),
        "system" => Ok(EdgeActorClass::System),
        _ => Err(Error::CorruptedIndex(context)),
    }
}

pub fn required_u64(value: &Value, key: &str, context: &'static str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(Error::CorruptedIndex(context))
}

pub fn required_entity_ref(value: &Value, key: &str, context: &'static str) -> Result<EntityId> {
    let hex = required_string(value, key, context)?;
    EntityId::from_hex(&hex).map_err(|_| Error::CorruptedIndex(context))
}

pub fn required_hash(
    value: &Value,
    key: &str,
    context: &'static str,
) -> Result<[u8; EVIDENCE_HASH_LEN]> {
    let hex = required_string(value, key, context)?;
    if hex.len() != EVIDENCE_HASH_LEN * 2 {
        return Err(Error::CorruptedIndex(context));
    }
    let mut bytes = [0u8; EVIDENCE_HASH_LEN];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(
            hex.get(index * 2..index * 2 + 2)
                .ok_or(Error::CorruptedIndex(context))?,
            16,
        )
        .map_err(|_| Error::CorruptedIndex(context))?;
    }
    Ok(bytes)
}

/// Whose the memo is: its query, its candidate and every source row, or
/// `None` when the sources are not known whole.
pub fn owners(row: &VerdictMemoRow) -> Option<Vec<EntityId>> {
    let mut owners = vec![row.key.query_ref, row.key.entity_ref];
    owners.extend(row.source_refs.as_ref()?.iter().copied());
    owners.sort_unstable();
    owners.dedup();
    Some(owners)
}
