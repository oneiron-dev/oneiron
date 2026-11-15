//! Moved from `crates/oneiron/src/outbound_consent/connector_call_types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::outbound_consent::connector_call_types::ConnectorCallRequest;
pub use oneiron_verb_wire::outbound_consent::connector_call_types::ConnectorSource;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// A connector's own reply to `tools/call`. Foreign data: the connector
/// wrote it, so it is untrusted, never instructions, and never stored in the
/// vault.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UntrustedToolResult {
    /// The MCP `content` blocks, as the connector sent them.
    pub content: Value,
    /// The MCP `structuredContent`, when the connector sent one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<Value>,
    /// The connector's `isError`, or true when it answered with a JSON-RPC
    /// error instead of a result.
    pub is_error: bool,
    /// The JSON-RPC error object the connector answered with, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc_error: Option<Value>,
}

/// One question a connector asked mid-call. Foreign data: the connector
/// wrote every field, so it is task input for the caller, never an
/// instruction and never an approval.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectorQuestion {
    /// The question's key in its round: `"0"` for a request on the reply
    /// stream, the connector's own key in a multi round-trip result.
    pub key: String,
    /// The connector's message.
    pub message: String,
    /// The JSON schema of the answer the connector asks for.
    pub requested_schema: Value,
}

/// The questions a connector answered a call with, as its host keeps them
/// for the caller: the live continuation's handle, the questions, and the
/// end of the round's live lease (unix ms): how long a synchronous answer
/// waits, never an expiry (FIX 3837).
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorAwaitingInput {
    pub handle: String,
    pub questions: Vec<ConnectorQuestion>,
    pub live_until_ms: u64,
}

/// Why a delivered call's outcome carries no reply (FIX 2823).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorResultAbsence {
    /// The reply is not retained: a replay of an already delivered call, or
    /// a settled call read back. Nothing is sent again to fetch it.
    NotRetained,
    /// The send presented a custody record's value, and the value could not
    /// be read again to clear it from the reply, so the reply is withheld.
    CredentialClearFailed,
}

/// What one connector call came to.
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectorCallOutcome {
    /// The connector acknowledged the call. `result` is its reply when this
    /// send carried one; a replay of an already delivered call has none.
    /// `result_absence` says why when `result` is `None`.
    Delivered {
        intent: Option<[u8; 32]>,
        result: Option<UntrustedToolResult>,
        result_absence: Option<ConnectorResultAbsence>,
        /// The budget messages this send's charge fired on its key and
        /// catalog pool (FIX 3759): the 80% plan and 95% land texts. Empty
        /// when none fired, and on a replay.
        budget_steering: Vec<String>,
    },
    /// Held for consent or governance. Nothing was sent. Once the hold may
    /// have cleared, `resume_connector_call` re-enters it.
    /// `approval_digest` (FIX 6424 part 3) is the approve-once digest, 64
    /// lower-hex, the Gate decision that held this prepared call names: the
    /// owner's press on it releases exactly this call. `None` for a hold no
    /// press clears here (before the call was prepared, or a code consent
    /// wait's own answer).
    Held {
        call_ref: EntityId,
        decision_ref: Option<String>,
        reasons: Vec<String>,
        approval_digest: Option<String>,
    },
    /// Not sent, and never will be under this request.
    Refused {
        decision_ref: Option<String>,
        reasons: Vec<String>,
    },
    /// The send's delivery is not settled. With a `call_ref`, resuming
    /// retries the same logical send; without one, the connector may or may
    /// not have received it and the ledger will not send it again.
    PendingDelivery {
        intent: [u8; 32],
        call_ref: Option<EntityId>,
        reasons: Vec<String>,
    },
    /// The connector received the call and asked for input before it would
    /// finish it. The send is delivered; the call's row `call_ref` keeps
    /// the round (never the questions' text) until the connector answers
    /// the call, and its caller polls it there (FIX 3837). A replay from the
    /// row carries no questions.
    AwaitingInput {
        call_ref: EntityId,
        intent: Option<[u8; 32]>,
        input: ConnectorAwaitingInput,
        budget_steering: Vec<String>,
    },
}
