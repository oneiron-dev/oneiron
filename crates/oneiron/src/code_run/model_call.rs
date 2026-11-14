//! Per-model-call evidence and replay records (FIX 12516).
//!
//! A record is a side-table row, never an entity, so BM25, vector recall and
//! Dreamer mining skip it by construction. Message occurrences own their bytes;
//! this row references them. Only a call that writes no message owns its
//! Reasoning bytes here, until the agent is erased.

use oneiron_model::llm::{LlmEndpointFlavor, ReasoningPartKind};
use serde::{Deserialize, Serialize};

use super::replay_capsule::{CapsuleRungBinding, ReplayRoutePin};
use super::storage::ReadWorldUnknown;
use crate::compaction::output::OutputRef;
use crate::side_table::{self, Erased, ErasedForm, Named, SideKey, SideTable};
use crate::{EntityId, Error, ModelLocality, Result, Vault};

mod signed_reasoning;

#[doc(hidden)]
use oneiron_records::code_run::model_call::invalid;
#[doc(hidden)]
pub use oneiron_records::code_run::model_call::{
    MODEL_CALL_SCHEMA, ModelCallDigests, ModelCallInputPart, ModelCallKind, ModelCallPartRef,
    ModelCallReasoningPart, ModelCallRecord, NativeReadDigests, NativeReadFailure,
    NativeReadOutcome, NativeReadRunSource,
};

const MODEL_CALLS: SideTable<(EntityId, u64, u64), ModelCallRecord, Named> =
    SideTable::new(&side_table::CODE_RUN_MODEL_CALL);

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

#[derive(Serialize)]
enum NativeLabels {
    Noul,
    Choice(Vec<String>),
}

#[derive(Serialize)]
struct NativeReadCanonical<'a> {
    state: &'a serde_json::Value,
    questions: Vec<(String, NativeLabels, Option<String>)>,
}

/// Canonical fingerprint of the actual reader-bound label-read pack.
pub fn native_read_digests(
    state: &serde_json::Value,
    questions: &[crate::llm::LabelReadout<'_>],
) -> Result<NativeReadDigests> {
    let invalid = || Error::InvalidConfig("native read request did not canonicalize".to_owned());
    let questions = questions
        .iter()
        .map(|question| {
            let labels = match question.labels {
                crate::llm::LabelSet::Noul => NativeLabels::Noul,
                crate::llm::LabelSet::Choice(options) => NativeLabels::Choice(options.to_vec()),
            };
            (
                question.text.to_owned(),
                labels,
                question.paired.map(|paired| paired.to_owned()),
            )
        })
        .collect::<Vec<_>>();
    let canonical = NativeReadCanonical { state, questions };
    let request_hash =
        *blake3::hash(&crate::llm::canonical_json_bytes(&canonical).map_err(|_| invalid())?)
            .as_bytes();
    Ok(NativeReadDigests { request_hash })
}

/// Canonical JSON-tree fingerprint of the actual built native-seat body.
/// This is not a hash of wire bytes, headers or credentials.
pub fn native_seat_read_digests(body: &serde_json::Value) -> Result<NativeReadDigests> {
    let canonical = crate::llm::canonical_json_bytes(body)
        .map_err(|_| invalid("native seat request did not canonicalize"))?;
    Ok(NativeReadDigests {
        request_hash: *blake3::hash(&canonical).as_bytes(),
    })
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
        self.store = None;
        self.endpoint = None;
        self.rung.prompt = None;
        self.actor = None;
        self.produced_pending = false;
        self.input_parts
            .retain(|part| !matches!(part, ModelCallInputPart::NewBytes { .. }));
        for part in &mut self.reasoning {
            part.text = None;
            part.bytes = None;
            part.signature = None;
            part.terminal_part = None;
            if matches!(&part.occurrence, Some(ModelCallPartRef::Custody { .. })) {
                part.occurrence = None;
            }
        }
        match &mut self.kind {
            ModelCallKind::Generate {
                usage,
                finish_reason,
                ..
            } => {
                // The OpenAI-compatible adapter passes arbitrary upstream usage
                // members and finish text through; an erased row keeps neither, only
                // the typed counters and a known reason shape.
                usage.raw_provider = Default::default();
                usage.call_metadata = None;
                if matches!(&*finish_reason, crate::FinishReason::Other { .. }) {
                    *finish_reason = crate::FinishReason::Other {
                        name: String::new(),
                    };
                }
            }
            // A native row keeps its source, hash, revision and failure; only
            // provider usage is scrubbed, and unknown stays unknown.
            ModelCallKind::LabelRead { outcome, .. }
            | ModelCallKind::SeatDecision { outcome, .. } => match outcome {
                NativeReadOutcome::Completed { usage } => {
                    usage.raw_provider = Default::default();
                    usage.call_metadata = None;
                }
                NativeReadOutcome::Failed {
                    usage: Some(usage), ..
                } => {
                    usage.raw_provider = Default::default();
                    usage.call_metadata = None;
                }
                NativeReadOutcome::Failed { usage: None, .. } => {}
            },
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
    erase_model_call_actor_as_in_txn(vault, wtxn, actor, None)
}

/// Carries the live actor scrub's custody revokes under the erase's actual owner act.
/// The declared scrub and restore/replay paths retain the local-only wrapper.
pub(crate) fn erase_model_call_actor_as_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
    act: Option<&crate::secret_custody::EraseOwnerAct<'_>>,
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
        crate::secret_custody::revoke_side_row_custody_in_txn(vault, wtxn, &origin, act)?;
        MODEL_CALLS.put_erased(&vault.store, wtxn, &key, erased)?;
    }
    Ok(())
}

/// Scrubs a call record whose reasoning is owned by the erased MESSAGE.
/// The typed occurrence, not a code-run output or an inferred source relation,
/// is the link. Custody minted by the row leaves before the tombstone lands.
pub(crate) fn erase_message_model_calls_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    message: &EntityId,
    act: Option<&crate::secret_custody::EraseOwnerAct<'_>>,
) -> Result<()> {
    let mut stale = Vec::new();
    for row in MODEL_CALLS.iter_raw_from(&vault.store, wtxn, &[])? {
        let (key, bytes) = row?;
        let Some(key) = <(EntityId, u64, u64) as SideKey>::decode_key(&key) else {
            continue;
        };
        if let Ok(record) = MODEL_CALLS.decode_value(&bytes)
            && !record.erased
            && record.reasoning.iter().any(|part| {
                matches!(
                    &part.occurrence,
                    Some(ModelCallPartRef::Message { message: owner, .. }) if owner == message
                )
            })
        {
            stale.push((key, Erased::of(record)?));
        }
    }
    for (key, erased) in stale {
        let place = format!("side:{}", MODEL_CALLS.decl().name);
        let origin =
            crate::batch::secret_scan::side_row_origin(&place, &MODEL_CALLS.key_bytes(&key))?;
        crate::secret_custody::revoke_side_row_custody_in_txn(vault, wtxn, &origin, act)?;
        MODEL_CALLS.put_erased(&vault.store, wtxn, &key, erased)?;
    }
    Ok(())
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
    // The whole-part custody and its sole reference commit together, even if
    // an enclosing writer catches a failed evidence write and keeps working.
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    let mut stored = record.clone();
    signed_reasoning::seal_signed_reasoning_in_txn(vault, &mut savepoint, &mut stored)?;
    for part in &mut stored.reasoning {
        part.terminal_part = None;
    }
    MODEL_CALLS.put(vault, &mut savepoint, &key, &stored)?;
    savepoint.commit()?;
    Ok(())
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
