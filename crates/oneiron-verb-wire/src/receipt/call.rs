//! Moved from `crates/oneiron/src/receipt/call.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::receipt_identity::ERASED_CALL_IDENTITY;
use serde::Deserialize;
use serde::Serialize;

/// The wire a call arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CallTransport {
    /// `/v1/core/facade/<verb>`.
    HttpFacade,
    /// An MCP `tools/call`.
    Mcp,
    /// A WS app-tier RPC.
    Ws,
    /// A raw OpenAI-compatible `/v1/chat/completions` call (FIX 3389).
    OpenAiProxy,
}

/// How a call ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CallOutcome {
    /// The call answered.
    Ok,
    /// The call was refused; `code` is the engine or transport error code
    /// the reply carried.
    Refused { code: String },
}

/// The attempt a call ran inside, as its receipt states it (OF-568 L4): the
/// try whose live run the call held, and the lease generation it held it at.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct CallAttemptRef {
    /// The attempt's id, as 32 hex.
    pub attempt: EntityId,
    /// The lease generation the call held it at.
    pub generation: u32,
}

/// `vault.receipts.get`'s one input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallReceiptRequest {
    /// The `call:<32hex>` ref a reply carried.
    pub receipt_ref: String,
}
