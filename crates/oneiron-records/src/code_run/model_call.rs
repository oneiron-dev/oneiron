//! Moved from `crates/oneiron/src/code_run/model_call.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::code_run::storage::read_worlds::ReadWorldUnknown;
use crate::compaction::output::OutputRef;
use crate::dreamer_runner::step_replay::CapsuleRungBinding;
use crate::dreamer_runner::step_replay::ReplayRoutePin;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::LlmEndpointFlavor;
use oneiron_model::llm::ModelLocality;
use oneiron_model::llm::ReasoningPartKind;
use serde::Deserialize;
use serde::Serialize;

pub const MODEL_CALL_SCHEMA: u8 = 2;

/// Where a model output part is owned. A code-run output and a witnessed
/// MESSAGE are distinct stores; neither reference is synthesized from the other.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModelCallPartRef {
    Output { occurrence: OutputRef },
    Message { message: EntityId, part_index: u64 },
    Custody { handle: String },
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
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
    pub occurrence: Option<ModelCallPartRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produced_row: Option<EntityId>,
    /// The exact captured part before the record's display representation is
    /// selected. Only the writer may use it, and no serializer persists it.
    #[serde(skip)]
    pub(crate) terminal_part: Option<oneiron_model::llm::ContentPart>,
}

impl std::fmt::Debug for ModelCallReasoningPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelCallReasoningPart")
            .field("kind", &self.kind)
            .field("text", &self.text.as_ref().map(|_| "<redacted>"))
            .field("bytes", &self.bytes.as_ref().map(Vec::len))
            .field("signature", &self.signature.as_ref().map(|_| "<redacted>"))
            .field("occurrence", &self.occurrence)
            .field("produced_row", &self.produced_row)
            .field(
                "terminal_part",
                &self.terminal_part.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl ModelCallReasoningPart {
    /// The terminal part, either by reference to its message occurrence or as
    /// new bytes owned by a messageless call. Summary is an explicit provider
    /// tag, never inferred from text length or content.
    pub fn from_terminal(
        part: &oneiron_model::llm::ContentPart,
        occurrence: Option<OutputRef>,
        produced_row: Option<EntityId>,
    ) -> Option<Self> {
        let oneiron_model::llm::ContentPart::Reasoning {
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
                signature: None,
                occurrence: occurrence.map(|occurrence| ModelCallPartRef::Output { occurrence }),
                produced_row,
                terminal_part: None,
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
                terminal_part: Some(part.clone()),
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
                    terminal_part: Some(part.clone()),
                })
            }
            ReasoningPartKind::Full | ReasoningPartKind::Summary => Some(Self {
                kind,
                text: Some(text.clone()),
                bytes: None,
                signature: signature.clone(),
                occurrence: None,
                produced_row,
                terminal_part: Some(part.clone()),
            }),
        }
    }

    /// References the ordered part of a MESSAGE that the terminal already
    /// committed. The MESSAGE owns every byte, including opaque signatures.
    pub fn from_message_terminal(
        part: &oneiron_model::llm::ContentPart,
        message: EntityId,
        part_index: u64,
    ) -> Option<Self> {
        let oneiron_model::llm::ContentPart::Reasoning {
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
        Some(Self {
            kind,
            text: None,
            bytes: None,
            signature: None,
            occurrence: Some(ModelCallPartRef::Message {
                message,
                part_index,
            }),
            produced_row: Some(message),
            terminal_part: None,
        })
    }

    fn validate(&self) -> Result<()> {
        let bodies = usize::from(self.text.is_some()) + usize::from(self.bytes.is_some());
        let references = usize::from(self.occurrence.is_some());
        match self.kind {
            ReasoningPartKind::Count if bodies != 0 || self.signature.is_some() => {
                Err(invalid("count-only reasoning carries no body"))
            }
            ReasoningPartKind::Count => Ok(()),
            _ if bodies + references != 1 => Err(invalid(
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReadDigests {
    pub request_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeReadFailure {
    InvalidRequest,
    Auth,
    RateLimited,
    Timeout,
    ServerError,
    LabelRead(oneiron_model::llm::LabelReadFailure),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeReadOutcome {
    Completed {
        usage: oneiron_model::llm::LlmUsage,
    },
    Failed {
        failure: NativeReadFailure,
        usage: Option<oneiron_model::llm::LlmUsage>,
    },
}

/// The actual admission source of a native read, not a caller or payer guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeReadRunSource {
    Probe,
    Caller,
    HouseGate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModelCallKind {
    Generate {
        digests: ModelCallDigests,
        usage: oneiron_model::llm::LlmUsage,
        finish_reason: oneiron_model::llm::FinishReason,
    },
    LabelRead {
        run_source: NativeReadRunSource,
        digests: NativeReadDigests,
        revision: String,
        outcome: NativeReadOutcome,
    },
    SeatDecision {
        run_source: NativeReadRunSource,
        digests: NativeReadDigests,
        revision: String,
        outcome: NativeReadOutcome,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCallRecord {
    pub schema: u8,
    pub attempt: EntityId,
    pub lease_generation: u64,
    pub call_index: u64,
    pub kind: ModelCallKind,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<LlmEndpointFlavor>,
    pub captured_at: u64,
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
        if self.schema != MODEL_CALL_SCHEMA {
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
        match &self.kind {
            ModelCallKind::LabelRead { revision, .. }
            | ModelCallKind::SeatDecision { revision, .. }
                if revision.trim().is_empty() =>
            {
                return Err(invalid("a native read needs a revision"));
            }
            ModelCallKind::SeatDecision { run_source, .. }
                if *run_source != NativeReadRunSource::Caller =>
            {
                return Err(invalid("a seat decision needs its caller's run"));
            }
            _ => {}
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

pub fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
