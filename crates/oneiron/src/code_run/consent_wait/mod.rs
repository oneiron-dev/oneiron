//! Bound code consent waits (DOOR-079 1a, toward CODE-RUNTIME-03).
//!
//! A code-mode `connector.call` whose own gate holds it for consent alone
//! parks its run on a code consent wait, minted beside the held call in the
//! same writer. The wait binds the exact pending effect: its run and write
//! site, the frozen bytes' digest, the original caller and its instrument,
//! the governing key, grant and manifest. It asks every live vault owner one
//! shared TASK question with canon's confirm trio.
//!
//! The owner's answer is its own fact: authenticated from any surface the
//! owner is authenticated on, revalidated in the answering writer, bound to
//! the sealed wait, standing on the owner's own word on the ask, never from
//! the opener's lineage, first and once. The settlement is another: the
//! held effect runs once under its own current gate, with the answer's
//! code-bound one-shot approval and the original caller's own grant, and its
//! actual outcome settles the wait and wakes the run. The run's consumption
//! of that reply is the third: the step that parks seals the wait in its
//! replay commit, and the replay commit that takes the reply consumes it
//! once (1b, `replay.rs`).
//!
//! A browser act a press held binds the same way (FIX 10423, `browser.rs`):
//! its exact act, row, page and guest, settled by the served host's one
//! answered pass with the act's own answer.
//!
//! This module owns the control row; only it writes it.

mod binding;
mod browser;
mod host;
mod ledger;
mod replay;
mod settle;
mod types;

pub(crate) use self::binding::{
    CodeConsentDraft, attach_code_consent_ask_in_txn, code_consent_binds,
    code_consent_binds_held_browser, code_consent_binds_held_call, code_consent_wait_id,
    code_consent_waits_bound_to_in_txn, mint_code_consent_wait_in_txn,
    read_code_consent_wait_in_txn, record_code_consent_admission_in_txn,
};
pub use self::browser::{AdmittedBrowserAct, CodeConsentBrowserOutcome};
pub use self::host::CodeConsentEffectHost;
pub(crate) use self::replay::{
    CodeConsentResume, ParkedWait, code_consent_resume_evidence, consume_code_consent_wait_in_txn,
    consumed_external_code_reply, seal_parked_code_consent_in_txn, verify_code_consent_consumed,
    verify_parked_code_consent,
};
pub(crate) use self::settle::{
    CODE_WAIT_ORIGINAL_AUTHORITY_REFUSED, code_consent_admission_in_txn, offered_choices,
    original_authority_holds_in_txn, refuse_code_consent_wait_in_txn,
    settle_code_consent_wait_listing_in_txn,
};
pub use self::types::{
    CodeConsentAnswerInput, CodeConsentBrowserAction, CodeConsentChoice,
    CodeConsentSavedCredential, CodeConsentSettleOutcome, CodeConsentWaitState,
    CodeConsentWaitView,
};
pub(crate) use self::types::{
    CodeConsentCallSite, CodeConsentConnectorCall, CodeConsentPendingEffect, CodeConsentPrincipal,
    CodeConsentRememberOffer, CodeConsentWaitRow,
};

use crate::EntityId;
use crate::outbound_consent::{
    ConnectorAwaitingInput, ConnectorCallOutcome, ConnectorQuestion, ConnectorResultAbsence,
    UntrustedToolResult,
};
use serde::{Deserialize, Serialize};
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

pub(crate) fn source(name: &str, tool: &str) -> String {
    format!("connector:{name}.{tool}")
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
                ..
            } => Self::Delivered {
                result: Some(ConnectorToolResult::foreign(name, tool, result)),
                reasons: Vec::new(),
                budget_steering,
            },
            ConnectorCallOutcome::Delivered {
                result: None,
                result_absence,
                budget_steering,
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
                call_ref, input, ..
            } => Self::awaiting_input(name, tool, call_ref, input),
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
