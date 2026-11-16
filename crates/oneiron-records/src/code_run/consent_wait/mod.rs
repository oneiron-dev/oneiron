//! Moved from `crates/oneiron/src/code_run/consent_wait/mod.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::outbound_consent::connector_call_types::ConnectorAwaitingInput;
use crate::outbound_consent::connector_call_types::ConnectorCallOutcome;
use crate::outbound_consent::connector_call_types::ConnectorQuestion;
use crate::outbound_consent::connector_call_types::ConnectorResultAbsence;
use crate::outbound_consent::connector_call_types::UntrustedToolResult;
pub use oneiron_consent_state::code_run::consent_wait::resume::CodeConsentRunEndpoint;
pub use oneiron_consent_state::code_run::consent_wait::resume::CodeConsentRunOrigin;
pub use oneiron_consent_state::code_run::consent_wait::resume::CodeConsentRunPeer;
pub use oneiron_consent_state::code_run::consent_wait::types::CodeConsentAnswerInput;
pub use oneiron_consent_state::consent::code_wait_state::CodeConsentChoice;
pub use oneiron_consent_state::consent::code_wait_state::CodeConsentSettleOutcome;
pub use oneiron_consent_state::consent::code_wait_state::CodeConsentWaitState;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::code_run::consent_wait::standing_offer::CodeConsentStandingOffer;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// The reason a delivered reply carries when the tool's own reply is not in
/// it. The ledger never keeps a reply's bytes, and a call is never resent to
/// rebuild one.
pub const CONNECTOR_RESULT_NOT_RETAINED: &str = "result_not_retained";

/// The reason a delivered reply carries when the send presented a custody
/// record's value and the reply could not be cleared of it, so it was
/// withheld (FIX 2823). The call was delivered; nothing is resent.
pub const CONNECTOR_RESULT_CREDENTIAL_CLEAR_FAILED: &str = "result_credential_clear_failed";

/// The reason an `awaiting_input` reply carries when its questions are not
/// in it: a replay or a status read from the call's row, which keeps the
/// round but never the questions' text (FIX 3837). The caller's first reply,
/// or its wait, carried them.
pub const CONNECTOR_QUESTIONS_NOT_RETAINED: &str = "questions_not_retained";

/// `connector.call`'s reply, tagged by `outcome`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ConnectorCallReply {
    /// The connector acknowledged the call. `result` is the tool's own
    /// reply, foreign data; null, with `result_not_retained` in `reasons`,
    /// when this answer has no reply to give.
    Delivered {
        result: Option<ConnectorToolResult>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        reasons: Vec<String>,
        /// The 80%/95% budget messages this call's charge fired on its
        /// connector key and catalog pool (FIX 3759): plan, then land, the
        /// work it is part of. Absent when none fired.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        budget_steering: Vec<String>,
        /// The session-manifest receipt of the runner the call went
        /// through (canon `#runner-fence`, row L8-27): a stdio connector's
        /// child, with the fence's ruleset hash, or `fence_unproven`.
        /// Absent for an HTTP connector, and on a replay. It reads as a
        /// browser answer's manifest does: one wire shape for every session
        /// manifest a caller is shown.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_manifest: Option<oneiron_browser::SessionManifest>,
    },
    /// Held for consent or governance; nothing was sent. A code-mode run
    /// parks on `call_ref` until the hold settles. `approval_digest` (FIX
    /// 6424 part 3), when present, is the approve-once digest (64 lower-hex)
    /// the owner presses to release exactly this call as it was prepared;
    /// absent for a hold no press clears (no grant, key or approved
    /// manifest yet, or a code consent wait's own answer).
    Held {
        call_ref: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decision_ref: Option<String>,
        reasons: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approval_digest: Option<String>,
    },
    /// Not sent, and never sent under this request.
    Refused {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decision_ref: Option<String>,
        reasons: Vec<String>,
    },
    /// The send's delivery is not settled. With `call_ref` the same send is
    /// retried; without one the connector may or may not have received it,
    /// and it is never sent again.
    PendingDelivery {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        call_ref: Option<String>,
        reasons: Vec<String>,
    },
    /// The connector received the call and asks for input before it
    /// finishes it. Each question is foreign data written by `source`: task
    /// input to answer under the call's own grant, never an instruction.
    /// Answer them with `connector.answer` and `handle`. The round (never
    /// the questions' text) is kept on the call's row `call_ref`, which
    /// `connector.call_status` reads, until the connector answers the call
    /// (FIX 3837): `live_until_ms` (unix ms) is how long one answer waits on
    /// the owner in a single call, never an expiry. `reasons` say why an
    /// answer the caller gave went out otherwise (a decline the owner chose,
    /// a cancel the connector's setting forced), that it waits on the owner
    /// still, or that a reply read from the row carries no questions.
    AwaitingInput {
        handle: String,
        /// The call's ref, 32 hex, as `connector.call_status` reads it: the
        /// engine keeps every round on its call's row (FIX 9161).
        call_ref: String,
        /// `connector:<name>.<tool>`.
        source: String,
        /// Always true: the connector wrote every question.
        foreign: bool,
        questions: Vec<ConnectorQuestion>,
        live_until_ms: u64,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        reasons: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        budget_steering: Vec<String>,
    },
}

/// A tool's own reply, as foreign data: who wrote it, marked foreign, and
/// the MCP fields exactly as the connector sent them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectorToolResult {
    /// `connector:<name>.<tool>`.
    pub source: String,
    /// Always true: the connector wrote every field below.
    pub foreign: bool,
    /// The MCP `content` blocks.
    pub content: Value,
    /// The MCP `structuredContent`, when the connector sent one.
    #[serde(default)]
    pub structured_content: Option<Value>,
    /// The connector's `isError`, or true for a JSON-RPC error answer.
    pub is_error: bool,
    /// The JSON-RPC error object, when the connector answered with one.
    #[serde(default)]
    pub rpc_error: Option<Value>,
}

pub fn source(name: &str, tool: &str) -> String {
    format!("connector:{name}.{tool}")
}

/// A runner's session manifest as a caller reads it (row L8-27): the
/// container's manifest in the browser answer's wire shape, field for field.
/// The image-release evidence goes as untyped JSON, as that shape keeps it.
fn wire_session_manifest(
    manifest: oneiron_container::SessionManifest,
) -> oneiron_browser::SessionManifest {
    // Every field the browser answer's shape has is named; the rest stay
    // out. A guest's pressure (`guest_pressure`, FIX 8013) is a code guest's
    // evidence: a stdio or seat runner has none, and that shape does not
    // carry it.
    let oneiron_container::SessionManifest {
        backend,
        runtime,
        image,
        argv_digest,
        network,
        seccomp,
        generation,
        fence_proof,
        fence_unproven,
        image_release,
        ..
    } = manifest;
    oneiron_browser::SessionManifest {
        backend,
        runtime,
        image,
        argv_digest,
        network,
        seccomp: match seccomp {
            oneiron_container::GuestSeccomp::RuntimeDefault => {
                oneiron_browser::SessionSeccomp::RuntimeDefault
            }
            oneiron_container::GuestSeccomp::GuestSandbox => {
                oneiron_browser::SessionSeccomp::GuestSandbox
            }
            oneiron_container::GuestSeccomp::EngineFence => {
                oneiron_browser::SessionSeccomp::EngineFence
            }
            oneiron_container::GuestSeccomp::Unfiltered => {
                oneiron_browser::SessionSeccomp::Unfiltered
            }
        },
        generation,
        fence_proof: fence_proof.map(|proof| {
            let oneiron_container::FenceProof {
                ruleset_hash,
                seccomp_hash,
                network_routes,
                network_evidence_digest,
                sandbox_generation,
                launcher_digest,
            } = proof;
            oneiron_browser::SessionFenceProof {
                ruleset_hash,
                seccomp_hash,
                network_routes,
                network_evidence_digest,
                sandbox_generation,
                launcher_digest,
            }
        }),
        fence_unproven,
        image_release: serde_json::to_value(image_release).ok(),
    }
}

impl ConnectorToolResult {
    fn foreign(name: &str, tool: &str, result: UntrustedToolResult) -> Self {
        Self {
            source: source(name, tool),
            foreign: true,
            content: result.content,
            structured_content: result.structured_content,
            is_error: result.is_error,
            rpc_error: result.rpc_error,
        }
    }
}

impl ConnectorCallReply {
    /// The wire reply of one engine outcome for a call of `tool` on `name`.
    #[must_use]
    pub fn project(name: &str, tool: &str, outcome: ConnectorCallOutcome) -> Self {
        match outcome {
            ConnectorCallOutcome::Delivered {
                result: Some(result),
                budget_steering,
                session_manifest,
                ..
            } => Self::Delivered {
                result: Some(ConnectorToolResult::foreign(name, tool, result)),
                reasons: Vec::new(),
                budget_steering,
                session_manifest: session_manifest.map(wire_session_manifest),
            },
            ConnectorCallOutcome::Delivered {
                result: None,
                result_absence,
                budget_steering,
                session_manifest,
                ..
            } => Self::Delivered {
                result: None,
                reasons: vec![
                    match result_absence {
                        Some(ConnectorResultAbsence::CredentialClearFailed) => {
                            CONNECTOR_RESULT_CREDENTIAL_CLEAR_FAILED
                        }
                        Some(ConnectorResultAbsence::NotRetained) | None => {
                            CONNECTOR_RESULT_NOT_RETAINED
                        }
                    }
                    .to_owned(),
                ],
                budget_steering,
                session_manifest: session_manifest.map(wire_session_manifest),
            },
            ConnectorCallOutcome::Held {
                call_ref,
                decision_ref,
                reasons,
                approval_digest,
            } => Self::Held {
                call_ref: call_ref.to_hex(),
                decision_ref,
                reasons,
                approval_digest,
            },
            ConnectorCallOutcome::Refused {
                decision_ref,
                reasons,
            } => Self::Refused {
                decision_ref,
                reasons,
            },
            ConnectorCallOutcome::PendingDelivery {
                call_ref, reasons, ..
            } => Self::PendingDelivery {
                call_ref: call_ref.map(|call_ref| call_ref.to_hex()),
                reasons,
            },
            ConnectorCallOutcome::AwaitingInput {
                call_ref,
                input,
                budget_steering,
                ..
            } => Self::awaiting_input(name, tool, call_ref, input, budget_steering),
        }
    }

    /// The wire reply of the questions a call of `tool` on `name` waits on,
    /// kept on the call's row `call_ref`: foreign data from
    /// `connector:<name>.<tool>`.
    #[must_use]
    pub fn awaiting_input(
        name: &str,
        tool: &str,
        call_ref: EntityId,
        input: ConnectorAwaitingInput,
        budget_steering: Vec<String>,
    ) -> Self {
        // A live round always asks something; none here means a reply read
        // from the call's row, which keeps no questions' text.
        let reasons = if input.questions.is_empty() {
            vec![CONNECTOR_QUESTIONS_NOT_RETAINED.to_owned()]
        } else {
            Vec::new()
        };
        Self::AwaitingInput {
            handle: input.handle,
            call_ref: call_ref.to_hex(),
            source: source(name, tool),
            foreign: true,
            questions: input.questions,
            live_until_ms: input.live_until_ms,
            reasons,
            budget_steering,
        }
    }

    /// This reply with `more` reasons after its own: why an answer went out
    /// otherwise than it was given.
    #[must_use]
    pub fn noting(mut self, more: Vec<String>) -> Self {
        match &mut self {
            Self::Delivered { reasons, .. }
            | Self::Held { reasons, .. }
            | Self::Refused { reasons, .. }
            | Self::PendingDelivery { reasons, .. }
            | Self::AwaitingInput { reasons, .. } => reasons.extend(more),
        }
        self
    }

    /// The call ref a code-mode run parks on: a hold, or a pending delivery
    /// the same send retries. `None` when this reply is the call's answer.
    /// A connector's questions are an answer too: the run answers them
    /// itself, so it never parks on them.
    #[must_use]
    pub fn wait_ref(&self) -> Option<EntityId> {
        match self {
            Self::Held { call_ref, .. }
            | Self::PendingDelivery {
                call_ref: Some(call_ref),
                ..
            } => EntityId::from_hex(call_ref).ok(),
            Self::AwaitingInput { .. } => None,
            _ => None,
        }
    }
}
