//! Lifted half of `oneiron::code_sandbox::egress::receipt` (core split, `oneiron-agent-runtime`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

pub use oneiron::code_sandbox::egress::receipt::*;
#[allow(unused_imports)]
use crate::ext::*;
use crate::EntityId;
use crate::Result;
use crate::Vault;

/// Methods of [`Vault`] that moved out of `oneiron` with `code_sandbox::egress::receipt` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxEgressReceiptVaultExt {
    /// A run desktop's takeover (CUA-001), returned to its agent: the
    /// record of who held it and for how long is the takeover's receipt.
    fn append_desktop_takeover_receipt(
        &self,
        run_id: EntityId,
        record: &serde_json::Value,
    ) -> Result<String>;
    /// A run desktop's takeover (CUA-001) still asked or held when the
    /// desktop went away: its record so far, inputs included, is the
    /// takeover's receipt, outcome `abandoned`.
    fn append_desktop_takeover_abandoned_receipt(
        &self,
        run_id: EntityId,
        record: &serde_json::Value,
    ) -> Result<String>;
    /// A run browser's takeover (CUA-001), returned to its agent: the record
    /// of who held it, for how long and how many inputs they sent is the
    /// takeover's receipt, as a desktop's is.
    fn append_browser_takeover_receipt(
        &self,
        run_id: EntityId,
        record: &serde_json::Value,
    ) -> Result<String>;
    /// A run browser's takeover (CUA-001) still asked or held when the
    /// browser went away with its door: its record so far is the takeover's
    /// receipt, outcome `abandoned`.
    fn append_browser_takeover_abandoned_receipt(
        &self,
        run_id: EntityId,
        record: &serde_json::Value,
    ) -> Result<String>;
    /// A run browser's demonstration (CUA E9) its seat's end closed, never
    /// given to the agent: the demonstration is its receipt, outcome
    /// `closed` (FIX 9409).
    fn append_browser_demonstration_closed_receipt(
        &self,
        run_id: EntityId,
        record: &serde_json::Value,
    ) -> Result<String>;
}

impl CodeSandboxEgressReceiptVaultExt for Vault {
    /// A run desktop's takeover (CUA-001), returned to its agent: the
    /// record of who held it and for how long is the takeover's receipt.
    fn append_desktop_takeover_receipt(
            &self,
            run_id: EntityId,
            record: &serde_json::Value,
        ) -> Result<String> {
            let body = serde_json::to_string(
                &serde_json::json!({"run_id": run_id.to_hex(), "takeover": record}),
            )
            .map_err(|e| crate::Error::InvalidConfig(e.to_string()))?;
            let hash = *blake3::hash(body.as_bytes()).as_bytes();
            self.append_sandbox_gate_receipt(run_id, "desktop_takeover", "returned", body, hash)
        }

    /// A run desktop's takeover (CUA-001) still asked or held when the
    /// desktop went away: its record so far, inputs included, is the
    /// takeover's receipt, outcome `abandoned`.
    fn append_desktop_takeover_abandoned_receipt(
            &self,
            run_id: EntityId,
            record: &serde_json::Value,
        ) -> Result<String> {
            let body = serde_json::to_string(
                &serde_json::json!({"run_id": run_id.to_hex(), "takeover": record}),
            )
            .map_err(|e| crate::Error::InvalidConfig(e.to_string()))?;
            let hash = *blake3::hash(body.as_bytes()).as_bytes();
            self.append_sandbox_gate_receipt(run_id, "desktop_takeover", "abandoned", body, hash)
        }

    /// A run browser's takeover (CUA-001), returned to its agent: the record
    /// of who held it, for how long and how many inputs they sent is the
    /// takeover's receipt, as a desktop's is.
    fn append_browser_takeover_receipt(
            &self,
            run_id: EntityId,
            record: &serde_json::Value,
        ) -> Result<String> {
            let body = serde_json::to_string(
                &serde_json::json!({"run_id": run_id.to_hex(), "takeover": record}),
            )
            .map_err(|e| crate::Error::InvalidConfig(e.to_string()))?;
            let hash = *blake3::hash(body.as_bytes()).as_bytes();
            self.append_sandbox_gate_receipt(run_id, "browser_takeover", "returned", body, hash)
        }

    /// A run browser's takeover (CUA-001) still asked or held when the
    /// browser went away with its door: its record so far is the takeover's
    /// receipt, outcome `abandoned`.
    fn append_browser_takeover_abandoned_receipt(
            &self,
            run_id: EntityId,
            record: &serde_json::Value,
        ) -> Result<String> {
            let body = serde_json::to_string(
                &serde_json::json!({"run_id": run_id.to_hex(), "takeover": record}),
            )
            .map_err(|e| crate::Error::InvalidConfig(e.to_string()))?;
            let hash = *blake3::hash(body.as_bytes()).as_bytes();
            self.append_sandbox_gate_receipt(run_id, "browser_takeover", "abandoned", body, hash)
        }

    /// A run browser's demonstration (CUA E9) its seat's end closed, never
    /// given to the agent: the demonstration is its receipt, outcome
    /// `closed` (FIX 9409).
    fn append_browser_demonstration_closed_receipt(
            &self,
            run_id: EntityId,
            record: &serde_json::Value,
        ) -> Result<String> {
            let body = serde_json::to_string(
                &serde_json::json!({"run_id": run_id.to_hex(), "demonstration": record}),
            )
            .map_err(|e| crate::Error::InvalidConfig(e.to_string()))?;
            let hash = *blake3::hash(body.as_bytes()).as_bytes();
            self.append_sandbox_gate_receipt(run_id, "browser_demonstration", "closed", body, hash)
        }
}
