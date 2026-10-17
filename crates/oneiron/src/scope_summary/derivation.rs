//! Scope-summary derivation envelopes and change-driven re-derivation.

use super::codec::invalid;
use super::purpose::{SummaryPurpose, purpose_in_txn};
use super::request::{decode_request, encode_request, enqueue_in_txn, plan_in_txn};
use crate::dreamer_consolidation::scope_summary_evidence_in_txn;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault, WriteActor};
use rmpv::Value;
use serde::{Deserialize, Serialize};

const PROJECTION: SideTable<[u8; 32], Projection, Named> =
    SideTable::new(&side_table::SCOPE_SUMMARY_PROJECTION);

/// An exact input version, including the document frontier and the full
/// witnessed-text pin (child set, authors, revisions and stream finality).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummarySourceVersion {
    pub id: String,
    pub entity_type: Option<u8>,
    pub learned_at: Option<u64>,
    pub revision: Option<[u8; 32]>,
    pub record_hash: Option<[u8; 32]>,
    pub frontier: Option<Vec<u8>>,
    pub projected_text: Option<[u8; 32]>,
}

/// Retained birth envelope: input content, instruction/model parameters,
/// request trigger, exact source versions and the prior artifact, if any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummaryDerivation {
    pub request: Vec<u8>,
    pub trigger: [u8; 16],
    pub content_hash: [u8; 32],
    pub params_hash: [u8; 32],
    pub instruction: String,
    pub model: String,
    pub policy_frontier: [u8; 32],
    pub sources: Vec<SummarySourceVersion>,
    pub previous: Option<String>,
    pub recorded_at: u64,
    pub generated_text_hash: [u8; 32],
    pub generated_keep_hash: [u8; 32],
}

/// The summary's own document metadata. `keep` is read before every generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeSummaryMetadata {
    pub purpose: SummaryPurpose,
    pub keep: String,
    pub derivation: SummaryDerivation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Projection {
    request: Vec<u8>,
    current: String,
    observed: [u8; 32],
}

pub(super) fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| invalid("summary derivation encoding"))?;
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Value> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid("summary derivation decoding"))?;
    if !cursor.is_empty() {
        return Err(invalid("trailing summary derivation bytes"));
    }
    Ok(value)
}

pub(super) fn declaration(
    request: &super::ScopeSummaryRequest,
    purpose: &str,
    previous: Option<EntityId>,
) -> Value {
    let Value::Map(mut fields) = encode_request(request) else {
        unreachable!()
    };
    fields.push((Value::from("purpose"), Value::from(purpose)));
    fields.push((
        Value::from("previous"),
        previous.map_or(Value::Nil, |id| Value::from(id.to_hex())),
    ));
    Value::Map(fields)
}

pub(super) fn options(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    input: &Value,
) -> Result<(SummaryPurpose, Option<EntityId>, String, Option<String>)> {
    let fields = input
        .as_map()
        .ok_or_else(|| invalid("summary declaration is not a map"))?;
    let field = |name| {
        fields
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    };
    let purpose = field("purpose")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("summary declaration has no purpose"))?;
    let purpose = purpose_in_txn(vault, txn, purpose)?;
    let previous = match field("previous") {
        Some(Value::Nil) => None,
        Some(value) => Some(EntityId::from_hex(
            value
                .as_str()
                .ok_or_else(|| invalid("invalid prior summary"))?,
        )?),
        None => return Err(invalid("summary declaration has no prior field")),
    };
    let Some(previous) = previous else {
        return Ok((purpose, None, String::new(), None));
    };
    let meta = crate::entity_doc::summary_meta_in_txn(vault, txn, &previous)?;
    // A retired source may have withdrawn the old summary. Its retained
    // document is still the editor's history; it is never evidence text.
    let text = crate::entity_doc::summary_text_in_txn(vault, txn, &previous)?;
    let edited = (blake3::hash(text.as_bytes()).as_bytes() != &meta.derivation.generated_text_hash)
        .then_some(text);
    Ok((purpose, Some(previous), meta.keep, edited))
}

fn observation(vault: &Vault, txn: &mut heed::RwTxn<'_>, input: &Value) -> Result<[u8; 32]> {
    let plan = plan_in_txn(vault, txn, input)?;
    let evidence = scope_summary_evidence_in_txn(vault, txn, &plan.sources)?;
    plan.observation(&evidence.fingerprint()?)
}

pub(super) fn current_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &super::ScopeSummaryRequest,
    purpose: &str,
) -> Result<Option<EntityId>> {
    let key = *blake3::hash(&encode(&declaration(request, purpose, None))?).as_bytes();
    let Some(projection) = PROJECTION.get(&vault.store, txn, &key)? else {
        return Ok(None);
    };
    let id = EntityId::from_hex(&projection.current)?;
    let state = crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, txn, &id)?;
    if state.deleted || vault.archive_tombstone_in_txn(txn, &id)?.is_some() {
        return Ok(None);
    }
    Ok(Some(id))
}

pub(super) fn register_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: &Value,
    summary: EntityId,
) -> Result<()> {
    let request = decode_request(input)?;
    let (purpose, _, _, _) = options(vault, txn, input)?;
    let normalized = declaration(&request, &purpose.id, None);
    let request = encode(&normalized)?;
    let key = *blake3::hash(&request).as_bytes();
    let current_input = declaration(&decode_request(input)?, &purpose.id, Some(summary));
    let observed = observation(vault, txn, &current_input)?;
    PROJECTION.put(
        &vault.store,
        txn,
        &key,
        &Projection {
            request,
            current: summary.to_hex(),
            observed,
        },
    )
}

/// Called once at the commit boundary, after all source/HEAD/document edits.
/// An exact unchanged input is the impact gate: it queues and spends nothing.
/// A changed scope queues an ordinary Dreamer attempt, never writes prose.
pub(crate) fn rederive_changed_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    let rows = PROJECTION
        .iter_from(&vault.store, txn, b"")?
        .collect::<Result<Vec<_>>>()?;
    for (key, mut projection) in rows {
        let current = EntityId::from_hex(&projection.current)?;
        let state =
            crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, txn, &current)?;
        if state.deleted || vault.archive_tombstone_in_txn(txn, &current)?.is_some() {
            PROJECTION.delete(&vault.store, txn, &key)?;
            continue;
        }
        let normalized = decode(&projection.request)?;
        let request = decode_request(&normalized)?;
        let purpose = normalized
            .as_map()
            .and_then(|fields| {
                fields
                    .iter()
                    .find(|(key, _)| key.as_str() == Some("purpose"))
            })
            .and_then(|(_, value)| value.as_str())
            .ok_or_else(|| invalid("projection has no purpose"))?;
        let input = declaration(&request, purpose, Some(current));
        let observed = match observation(vault, txn, &input) {
            Ok(observed) => observed,
            // Source erasure, a lost grant or a deleted scope never blocks
            // the write that caused it. The queued attempt reports the refusal.
            Err(Error::EntityNotFound | Error::InvalidClaimBody(_) | Error::Record(_)) => {
                *blake3::hash(&encode(&input)?).as_bytes()
            }
            Err(error) => return Err(error),
        };
        if observed != projection.observed {
            enqueue_in_txn(vault, txn, input)?;
            projection.observed = observed;
            PROJECTION.put(&vault.store, txn, &key, &projection)?;
        }
    }
    Ok(())
}

impl Vault {
    /// Declares a fresh generation from the saved selector and live `keep`
    /// memo. It does not overwrite the old artifact or its editor history.
    pub fn rederive_scope_summary(
        &self,
        summary: EntityId,
        requester: WriteActor,
    ) -> Result<super::ScopeSummaryQueued> {
        self.with_write_txn_grouped(|txn| {
            crate::conversation_dag::actor_in_txn(&self.store, txn, requester)?;
            let metadata = crate::entity_doc::summary_meta_in_txn(self, txn, &summary)?;
            let mut request = decode_request(&decode(&metadata.derivation.request)?)?;
            request.requester = requester;
            enqueue_in_txn(
                self,
                txn,
                declaration(&request, &metadata.purpose.id, Some(summary)),
            )
        })
    }
}
