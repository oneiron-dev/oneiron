//! Proxy receipts use the existing owner-local gate ledger.

use crate::policy_model::{PolicyClassifyDecision, PolicyVerdictCategory};
use crate::store::{GateDecisionId, GateDecisionRecord, GateSystemNoticeRecord};
use crate::{EntityId, Result, Vault};
use oneiron_container::SessionManifest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EgressReceipt {
    pub run_id: EntityId,
    pub operation: String,
    pub url: String,
    pub content_hash: [u8; 32],
    pub content_bytes: u64,
    pub decision: PolicyClassifyDecision,
    pub category: PolicyVerdictCategory,
    pub policy_receipt: Option<String>,
}
/// `body`'s whitespace as JSON `\uXXXX` escapes (every whitespace char is
/// in the BMP), so the text decodes to the same value.
fn escape_whitespace(body: &str) -> String {
    let mut escaped = String::with_capacity(body.len());
    for c in body.chars() {
        if c.is_whitespace() {
            escaped.push_str(&format!("\\u{:04x}", u32::from(c)));
        } else {
            escaped.push(c);
        }
    }
    escaped
}

impl Vault {
    pub fn append_sandbox_abandon_receipt(
        &self,
        run_id: EntityId,
        manifest: &SessionManifest,
    ) -> Result<String> {
        let body = serde_json::to_string(&serde_json::json!({"run_id": run_id.to_hex(), "status": "abandoned", "session_manifest": manifest}))
            .map_err(|e| crate::Error::InvalidConfig(e.to_string()))?;
        let hash = *blake3::hash(body.as_bytes()).as_bytes();
        self.append_sandbox_gate_receipt(run_id, "abandoned", "abandoned", body, hash)
    }

    pub fn append_sandbox_manifest_receipt(
        &self,
        run_id: EntityId,
        manifest: &SessionManifest,
    ) -> Result<String> {
        let body = serde_json::to_string(
            &serde_json::json!({"run_id": run_id.to_hex(), "session_manifest": manifest}),
        )
        .map_err(|e| crate::Error::InvalidConfig(e.to_string()))?;
        self.append_sandbox_gate_receipt(
            run_id,
            "session_manifest",
            "recorded",
            body,
            *blake3::hash(
                &serde_json::to_vec(manifest)
                    .map_err(|e| crate::Error::InvalidConfig(e.to_string()))?,
            )
            .as_bytes(),
        )
    }
    /// A run desktop's takeover (CUA-001), returned to its agent: the
    /// record of who held it and for how long is the takeover's receipt.
    pub fn append_desktop_takeover_receipt(
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
    pub fn append_desktop_takeover_abandoned_receipt(
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
    pub fn append_browser_takeover_receipt(
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
    pub fn append_browser_takeover_abandoned_receipt(
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
    pub fn append_egress_receipt(&self, receipt: &EgressReceipt) -> Result<String> {
        let body = serde_json::to_string(receipt)
            .map_err(|e| crate::Error::InvalidConfig(e.to_string()))?;
        self.append_sandbox_gate_receipt(
            receipt.run_id,
            "egress",
            receipt.decision.as_str(),
            body,
            receipt.content_hash,
        )
    }
    fn append_sandbox_gate_receipt(
        &self,
        run_id: EntityId,
        kind: &str,
        outcome: &str,
        body: String,
        digest: [u8; 32],
    ) -> Result<String> {
        let mut txn = self.store.env.write_txn()?;
        let created_at = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let decision_id = GateDecisionId::from_bytes(self.store.clock.ulid()?);
        let mut notices = Vec::new();
        // Compact JSON holds whitespace only inside its strings; escaped
        // there, no part of the body can be blank.
        let body = escape_whitespace(&body);
        let mut remaining = body.as_str();
        while !remaining.is_empty() {
            let mut end = remaining
                .len()
                .min(crate::store::GATE_SYSTEM_NOTICE_BODY_MAX_LEN);
            while !remaining.is_char_boundary(end) {
                end -= 1;
            }
            let (part, rest) = remaining.split_at(end);
            notices.push(GateSystemNoticeRecord {
                notice_type: kind.into(),
                channel: format!("sandbox.{kind}"),
                voice: "system".into(),
                audience: "audit".into(),
                body: part.to_owned(),
                row_ref: Some(format!("part:{}", notices.len())),
                setting_change_offer: None,
                policy_plane: None,
                policy_version: None,
                docs_url: None,
            });
            remaining = rest;
        }
        self.store.append_gate_decision_in_txn(
            &mut txn,
            &GateDecisionRecord {
                version: 0,
                decision_id,
                created_at,
                outcome: outcome.replace('-', "_"),
                reason_codes: vec![format!("gate.sandbox.{kind}")],
                receipt_reasons: Vec::new(),
                system_notices: notices,
                actor_class: "sandbox".into(),
                actor_ref: Some(run_id.to_hex()),
                content_kind: kind.into(),
                policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
                claim_id: None,
                grant_ref: None,
                diff_handle: digest.to_vec(),
                read_frontier_hash: [0; 32],
                redacted_at: None,
            },
        )?;
        txn.commit()?;
        Ok(format!("gate:{}", decision_id.to_hex()))
    }
}
