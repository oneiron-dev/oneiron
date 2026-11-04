//! Per-model-call evidence and replay records (FIX 12516).
//!
//! A record is a side-table row, never an entity, so BM25, vector recall and
//! Dreamer mining skip it by construction. Message occurrences own their bytes;
//! this row references them. Only a call that writes no message owns its
//! Reasoning bytes here, until the agent is erased.

use oneiron_model::llm::ReasoningPartKind;
use serde::{Deserialize, Serialize};

use super::replay_capsule::{CapsuleRungBinding, ReplayRoutePin};
use super::storage::ReadWorldUnknown;
use crate::compaction::output::OutputRef;
use crate::side_table::{self, Erased, ErasedForm, Named, SideKey, SideTable};
use crate::{EntityId, Error, ModelLocality, Result, Vault};

const SCHEMA: u8 = 1;
const MODEL_CALLS: SideTable<(EntityId, u64, u64), ModelCallRecord, Named> =
    SideTable::new(&side_table::CODE_RUN_MODEL_CALL);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCallReasoningPart {
    pub kind: ReasoningPartKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<OutputRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produced_row: Option<EntityId>,
}

impl ModelCallReasoningPart {
    /// The terminal part, either by reference to its message occurrence or as
    /// new bytes owned by a messageless call. Summary is an explicit provider
    /// tag, never inferred from text length or content.
    pub fn from_terminal(
        part: &crate::ContentPart,
        occurrence: Option<OutputRef>,
        produced_row: Option<EntityId>,
    ) -> Option<Self> {
        let crate::ContentPart::Reasoning {
            text,
            signature,
            reasoning_kind,
            data,
        } = part
        else {
            return None;
        };
        let kind = match reasoning_kind {
            ReasoningPartKind::Full
                if text.is_empty() && (signature.is_some() || data.is_some()) =>
            {
                ReasoningPartKind::Encrypted
            }
            other => *other,
        };
        if occurrence.is_some() {
            return Some(Self {
                kind,
                text: None,
                bytes: None,
                signature: signature.clone(),
                occurrence,
                produced_row,
            });
        }
        match kind {
            ReasoningPartKind::Count => Some(Self {
                kind,
                text: None,
                bytes: None,
                signature: None,
                occurrence: None,
                produced_row,
            }),
            ReasoningPartKind::Encrypted => {
                let (bytes, signature) = if let Some(data) = data {
                    (Some(data.as_bytes().to_vec()), signature.clone())
                } else {
                    (
                        signature.as_ref().map(|value| value.as_bytes().to_vec()),
                        None,
                    )
                };
                Some(Self {
                    kind,
                    text: None,
                    bytes,
                    signature,
                    occurrence: None,
                    produced_row,
                })
            }
            ReasoningPartKind::Full | ReasoningPartKind::Summary => Some(Self {
                kind,
                text: Some(text.clone()),
                bytes: None,
                signature: signature.clone(),
                occurrence: None,
                produced_row,
            }),
        }
    }

    fn validate(&self) -> Result<()> {
        let bodies = usize::from(self.text.is_some())
            + usize::from(self.bytes.is_some())
            + usize::from(self.occurrence.is_some());
        match self.kind {
            ReasoningPartKind::Count if bodies != 0 || self.signature.is_some() => {
                Err(invalid("count-only reasoning carries no body"))
            }
            ReasoningPartKind::Count => Ok(()),
            _ if bodies != 1 => Err(invalid(
                "a reasoning part needs exactly one body or reference",
            )),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModelCallInputPart {
    Reference {
        row: EntityId,
        occurrence: OutputRef,
    },
    NewBytes {
        body: Vec<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_type: Option<String>,
    },
    Unknown {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCallDigests {
    pub request_hash: [u8; 32],
    pub messages_digest: [u8; 32],
    pub system_digest: [u8; 32],
    pub tools_digest: [u8; 32],
}

/// Canonical request and prefix fingerprints used by replay admission.
pub fn model_call_digests(request: &crate::LlmRequest) -> Result<ModelCallDigests> {
    let invalid = || Error::InvalidConfig("model call request did not canonicalize".to_owned());
    let request_hash = request.canonical_hash().map_err(|_| invalid())?;
    let messages_digest =
        *blake3::hash(&crate::llm::canonical_json_bytes(&request.messages).map_err(|_| invalid())?)
            .as_bytes();
    let system = request
        .messages
        .iter()
        .filter(|message| message.role == crate::LlmMessageRole::System)
        .collect::<Vec<_>>();
    let system_digest =
        *blake3::hash(&crate::llm::canonical_json_bytes(&system).map_err(|_| invalid())?)
            .as_bytes();
    let tools_digest =
        *blake3::hash(&crate::llm::canonical_json_bytes(&request.tools).map_err(|_| invalid())?)
            .as_bytes();
    Ok(ModelCallDigests {
        request_hash,
        messages_digest,
        system_digest,
        tools_digest,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCallRecord {
    pub schema: u8,
    pub attempt: EntityId,
    pub lease_generation: u64,
    pub call_index: u64,
    pub digests: ModelCallDigests,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<ReplayRoutePin>,
    pub rung: CapsuleRungBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuing_login: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<bool>,
    pub captured_at: u64,
    pub usage: crate::LlmUsage,
    pub finish_reason: crate::FinishReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<EntityId>,
    #[serde(default)]
    pub produced_pending: bool,
    #[serde(default)]
    pub tool_rounds: bool,
    #[serde(default)]
    pub rounds_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_of: Option<(EntityId, u64)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_rows: Vec<EntityId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub produced_rows: Vec<EntityId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_parts: Vec<ModelCallInputPart>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasoning: Vec<ModelCallReasoningPart>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_world_epoch: Option<EntityId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_worlds: Option<Vec<EntityId>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_world_unknown: Vec<ReadWorldUnknown>,
    pub tools_present: bool,
    pub summary_requested: bool,
    #[serde(default)]
    pub erased: bool,
}

impl ModelCallRecord {
    pub fn key(&self) -> (EntityId, u64, u64) {
        (self.attempt, self.lease_generation, self.call_index)
    }

    pub fn locality(&self) -> ModelLocality {
        self.rung.locality
    }

    fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA {
            return Err(invalid("unknown model-call record schema"));
        }
        if self.erased {
            return Err(invalid("a new model-call record cannot be erased"));
        }
        for part in &self.input_parts {
            match part {
                ModelCallInputPart::NewBytes { body, .. } if body.is_empty() => {
                    return Err(invalid("a new input body cannot be empty"));
                }
                ModelCallInputPart::Unknown { reason } if reason.trim().is_empty() => {
                    return Err(invalid("an unknown input needs a reason"));
                }
                _ => {}
            }
        }
        if self.produced_pending && !self.produced_rows.is_empty() {
            return Err(invalid("produced refs cannot be both pending and present"));
        }
        for part in &self.reasoning {
            part.validate()?;
        }
        match (
            &self.read_world_epoch,
            &self.read_worlds,
            self.read_world_unknown.is_empty(),
        ) {
            (Some(_), Some(_), true) => Ok(()),
            (_, None, false) => Ok(()),
            _ => Err(invalid(
                "read-world evidence needs a complete snapshot or explicit causes",
            )),
        }
    }
}

impl ErasedForm for ModelCallRecord {
    fn into_erased(mut self) -> Result<Self> {
        self.erased = true;
        self.issuing_login = None;
        self.organization = None;
        self.project = None;
        self.credential_id = None;
        self.response_id = None;
        self.thread_id = None;
        self.previous_response_id = None;
        self.rung.prompt = None;
        self.actor = None;
        self.produced_pending = false;
        self.input_parts
            .retain(|part| !matches!(part, ModelCallInputPart::NewBytes { .. }));
        for part in &mut self.reasoning {
            part.text = None;
            part.bytes = None;
            part.signature = None;
        }
        // The OpenAI-compatible adapter passes arbitrary upstream usage
        // members and finish text through; an erased row keeps neither, only
        // the typed counters and a known reason shape.
        self.usage.raw_provider = Default::default();
        if matches!(self.finish_reason, crate::FinishReason::Other { .. }) {
            self.finish_reason = crate::FinishReason::Other {
                name: String::new(),
            };
        }
        Ok(self)
    }
}

/// Erases every model-call record stamped to `actor`. Message occurrences
/// belong to their MESSAGE and are not released here; inline reasoning and
/// replay-binding bytes are scrubbed. Undecodable rows stay unchanged.
pub(crate) fn erase_model_call_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    // The scan holds only a read borrow of the transaction; the
    // erasures land after it is gone.
    let mut stale = Vec::new();
    for row in MODEL_CALLS.iter_raw_from(&vault.store, wtxn, &[])? {
        let (key, bytes) = row?;
        let Some(key) = <(EntityId, u64, u64) as SideKey>::decode_key(&key) else {
            continue;
        };
        if let Ok(record) = MODEL_CALLS.decode_value(&bytes)
            && record.actor == Some(*actor)
            && !record.erased
        {
            stale.push((key, Erased::of(record)?));
        }
    }
    for (key, erased) in stale {
        // The Authored row's mask may have minted custody under the side-row
        // origin (FIX 6710); the erase revokes it before the row goes erased.
        let place = format!("side:{}", MODEL_CALLS.decl().name);
        let origin =
            crate::batch::secret_scan::side_row_origin(&place, &MODEL_CALLS.key_bytes(&key))?;
        crate::secret_custody::revoke_side_row_custody_in_txn(vault, wtxn, &origin, None)?;
        MODEL_CALLS.put_erased(&vault.store, wtxn, &key, erased)?;
    }
    Ok(())
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}

/// Writes one immutable call record. A retry must name a new call index; an
/// existing key is never overwritten.
pub fn record_model_call_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &ModelCallRecord,
) -> Result<()> {
    if record
        .actor
        .is_some_and(|actor| super::storage::actor_gone_in_txn(vault, &*txn, &actor))
    {
        return Ok(());
    }
    record.validate()?;
    let key = record.key();
    if MODEL_CALLS.get(&vault.store, txn, &key)?.is_some() {
        return Err(invalid("model-call record already exists"));
    }
    MODEL_CALLS.put(vault, txn, &key, record)
}

pub fn model_call_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &(EntityId, u64, u64),
) -> Result<Option<ModelCallRecord>> {
    MODEL_CALLS.get(&vault.store, txn, key)
}

/// Reads a record only when its stamped actor matches. Replay never reads
/// another actor's no-message reasoning (L07-A condition 6).
pub fn model_call_for_actor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &(EntityId, u64, u64),
    actor: EntityId,
) -> Result<Option<ModelCallRecord>> {
    Ok(model_call_in_txn(vault, txn, key)?.filter(|record| record.actor == Some(actor)))
}

pub fn model_calls_for_attempt_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: EntityId,
) -> Result<Vec<ModelCallRecord>> {
    let mut records = Vec::new();
    let mut undecodable = 0_usize;
    for row in MODEL_CALLS.iter_raw_from(&vault.store, txn, attempt.as_bytes())? {
        let (_, bytes) = row?;
        match MODEL_CALLS.decode_value(&bytes) {
            Ok(record) => records.push(record),
            Err(_) => undecodable += 1,
        }
    }
    if undecodable > 0 {
        tracing::warn!(
            undecodable,
            "model-call rows that do not decode read as none"
        );
    }
    Ok(records)
}
