//! OF-538: one lasting receipt per wire call, reads included.
//!
//! Every reply the HTTP facade, the MCP `tools/call` door and the WS RPC door
//! give carries a `receipt_ref` (`call:<32hex>`) that names one row here: who
//! called, on which credential, which verb, how it ended, and digests of what
//! was asked and answered. Never the bodies themselves.
//!
//! The row is written by its OWN grouped write transaction after the call's
//! own work, so a refusal keeps its receipt even though the refused
//! operation's writer rolled back. The one exception is an anonymous
//! off-record session (ARCH-0052): a call inside one writes no row, and its
//! reply says so, rather than carrying a ref.
//!
//! The lookup ([`Memory::call_receipt`]) is scoped: the caller's bound actor
//! must be the receipt's actor, or the vault's live owner. Any other caller
//! reads `None`, exactly as for a ref that names nothing, so a guesser learns
//! nothing.

use serde::{Deserialize, Serialize};

use crate::memory::{
    Memory, MemoryError, MemoryResult, actor_is_vault_owner_in_txn, verify_actor_binding_in_txn,
};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// The prefix every call receipt ref carries.
pub const CALL_RECEIPT_REF_PREFIX: &str = "call:";

/// At most this many served row ids ride one receipt; the rest are dropped.
pub const MAX_CALL_RECEIPT_SERVED: usize = 256;

/// A verb, actor, credential or refusal code longer than this is cut at a
/// character boundary: these fields name things, and a caller-chosen path
/// must not size a vault row.
const MAX_CALL_RECEIPT_FIELD_BYTES: usize = 256;

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

/// One call's lasting receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallReceipt {
    /// `call:<32hex>`, the ref the reply carried.
    pub receipt_ref: String,
    /// Vault clock seconds when the receipt was written.
    pub at: u64,
    pub transport: CallTransport,
    /// The verb, tool or RPC method the call named, as the caller spelled it.
    pub verb: String,
    /// The caller's bound actor as 32 hex, or the credential's own principal
    /// when it is bound to none.
    pub actor_ref: String,
    /// `human`, `agent` or `system`, or `unbound`.
    pub actor_class: String,
    /// The presented credential's revocable id (a slip's id), when it has one.
    pub credential_ref: Option<String>,
    pub outcome: CallOutcome,
    /// BLAKE3 of the canonical input JSON, lowercase hex.
    pub request_digest: String,
    /// BLAKE3 of the answered result, lowercase hex, when the call answered.
    pub result_digest: Option<String>,
    /// The row ids the reply was derived from, when the transport knows
    /// them; at most [`MAX_CALL_RECEIPT_SERVED`].
    pub served: Vec<String>,
    /// OF-063: each `served` row this reader may read, as a typed record ref
    /// a UI can preview and open. Filled when the receipt is answered, under
    /// the reader's own scoped read, and never stored; a row the reader may
    /// not read has no ref here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub served_records: Vec<crate::lens::RecordRef>,
}

/// What a transport hands [`Vault::record_call_receipt`]: everything but the
/// ref and the time, which the vault mints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallReceiptInput {
    pub transport: CallTransport,
    pub verb: String,
    pub actor_ref: String,
    pub actor_class: String,
    pub credential_ref: Option<String>,
    pub outcome: CallOutcome,
    pub request_digest: String,
    pub result_digest: Option<String>,
    pub served: Vec<String>,
}

/// `vault.receipts.get`'s one input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallReceiptRequest {
    /// The `call:<32hex>` ref a reply carried.
    pub receipt_ref: String,
}

const CALL_RECEIPTS: SideTable<EntityId, CallReceipt, Named> =
    SideTable::new(&side_table::CALL_RECEIPT);

/// BLAKE3 of `value` serialized canonically (object keys sorted at every
/// depth), lowercase hex: the digest a receipt states for a JSON input or
/// result, stable however the caller ordered its keys.
#[must_use]
pub fn call_json_digest(value: &serde_json::Value) -> String {
    let mut hasher = blake3::Hasher::new();
    write_canonical(&mut hasher, value);
    hasher.finalize().to_hex().to_string()
}

/// BLAKE3 of raw bytes, lowercase hex: the digest of a body that is not JSON.
#[must_use]
pub fn call_bytes_digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn write_canonical(hasher: &mut blake3::Hasher, value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            hasher.update(b"{");
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    hasher.update(b",");
                }
                write_canonical(hasher, &serde_json::Value::String(key.clone()));
                hasher.update(b":");
                if let Some(item) = map.get(key) {
                    write_canonical(hasher, item);
                }
            }
            hasher.update(b"}");
        }
        serde_json::Value::Array(items) => {
            hasher.update(b"[");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    hasher.update(b",");
                }
                write_canonical(hasher, item);
            }
            hasher.update(b"]");
        }
        scalar => {
            // A scalar's JSON text is already canonical.
            hasher.update(scalar.to_string().as_bytes());
        }
    }
}

/// `text` cut to at most [`MAX_CALL_RECEIPT_FIELD_BYTES`] at a character
/// boundary.
fn bounded(mut text: String) -> String {
    if text.len() > MAX_CALL_RECEIPT_FIELD_BYTES {
        let mut end = MAX_CALL_RECEIPT_FIELD_BYTES;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// The id a `call:<32hex>` ref names; `None` for anything else.
fn call_receipt_id(receipt_ref: &str) -> Option<EntityId> {
    let hex = receipt_ref.strip_prefix(CALL_RECEIPT_REF_PREFIX)?;
    if hex.len() != 32 {
        return None;
    }
    EntityId::from_hex(hex).ok()
}

impl Vault {
    /// Writes one call's receipt and returns its `call:<32hex>` ref.
    ///
    /// Runs in its OWN grouped write transaction, which the transport opens
    /// after the call's own work has committed or rolled back: a refusal's
    /// receipt persists even though the refused operation's writer did not.
    /// A transport never calls this for a call inside an anonymous
    /// off-record session.
    pub fn record_call_receipt(&self, input: CallReceiptInput) -> Result<String> {
        let id = self.store.clock.entity_id()?;
        let receipt_ref = format!("{CALL_RECEIPT_REF_PREFIX}{}", id.to_hex());
        let mut served = input.served;
        served.truncate(MAX_CALL_RECEIPT_SERVED);
        let receipt = CallReceipt {
            receipt_ref: receipt_ref.clone(),
            at: self.store.clock.now_recorded_at(),
            transport: input.transport,
            verb: bounded(input.verb),
            actor_ref: bounded(input.actor_ref),
            actor_class: bounded(input.actor_class),
            credential_ref: input.credential_ref.map(bounded),
            outcome: match input.outcome {
                CallOutcome::Ok => CallOutcome::Ok,
                CallOutcome::Refused { code } => CallOutcome::Refused {
                    code: bounded(code),
                },
            },
            request_digest: input.request_digest,
            result_digest: input.result_digest,
            served: served.into_iter().map(bounded).collect(),
            served_records: Vec::new(),
        };
        self.with_write_txn_grouped(|txn| CALL_RECEIPTS.put(self, txn, &id, &receipt))?;
        Ok(receipt_ref)
    }
}

impl Memory<'_> {
    /// The call receipt `receipt_ref` names, scoped to this handle's bound
    /// actor: it reads a receipt only when it is that receipt's actor (same
    /// id, same class) or the vault's live owner. Every other receipt, a
    /// malformed ref and a ref that names nothing all read `None` alike.
    pub fn call_receipt(&self, receipt_ref: &str) -> MemoryResult<Option<CallReceipt>> {
        let Some(id) = call_receipt_id(receipt_ref) else {
            return Ok(None);
        };
        let vault = self.vault();
        let txn = vault
            .store
            .env
            .read_txn()
            .map_err(|error| MemoryError::from(crate::Error::from(error)))?;
        verify_actor_binding_in_txn(vault, &txn, self.actor(), self.actor_class())?;
        let Some(mut receipt) = CALL_RECEIPTS
            .get(&vault.store, &txn, &id)
            .map_err(MemoryError::from)?
        else {
            return Ok(None);
        };
        let own = receipt.actor_ref == self.actor().to_hex()
            && receipt.actor_class == self.actor_class().gate_actor_class();
        if !own && !actor_is_vault_owner_in_txn(vault, &txn, self.actor(), self.actor_class())? {
            return Ok(None);
        }
        // The receipt's snapshot ends before its served rows are read: each
        // is read through this handle's own lane, in a read of its own.
        drop(txn);
        receipt.served_records = self.served_record_refs(&receipt.served)?;
        Ok(Some(receipt))
    }

    /// The typed record refs of the `served` row ids this handle may read,
    /// in order (OF-063). An id that names no row, or a row this reader may
    /// not read, gets none, alike.
    fn served_record_refs(&self, served: &[String]) -> MemoryResult<Vec<crate::lens::RecordRef>> {
        let mut records = Vec::new();
        for id in served {
            if EntityId::from_hex(id).is_err() {
                continue;
            }
            match self.get_entity(id) {
                Ok(read) => {
                    records.extend(read.value.as_ref().map(crate::lens::RecordRef::from_view));
                }
                Err(error)
                    if error.code == crate::memory::MEMORY_CODE_NOT_FOUND
                        || error.code == crate::memory::MEMORY_CODE_BAD_REQUEST => {}
                Err(error) => return Err(error),
            }
        }
        Ok(records)
    }
}
