//! Proxy receipts use the existing owner-local gate ledger.

use crate::policy_model::PolicyClassifyDecision;
use crate::store::gate_reason::GateReceiptOutcome;
use crate::store::{
    GateEnginePart, GateReceipt, GateSystemNoticeRecord, PolicyBasis, ReceiptActor,
};
use crate::{EntityId, Result, Vault};
use oneiron_container::{CredentialEgressStatus, SessionManifest};

#[doc(hidden)]
pub use oneiron_records::code_sandbox::egress::receipt::EgressReceipt;

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

/// What one sandbox row records: its Gate receipt outcome, and the sandbox's
/// own word for it, kept on the row as the last segment of its reason code
/// `gate.sandbox.<kind>.<word>` (UC-03 D1 = A).
#[derive(Debug, Clone, Copy)]
pub(crate) struct SandboxReceiptOutcome {
    outcome: GateReceiptOutcome,
    word: &'static str,
}

impl SandboxReceiptOutcome {
    /// A fact of a run's life (a manifest recorded, a takeover returned or
    /// abandoned, a demonstration closed, a proposal made): the row decides
    /// nothing.
    pub(crate) const fn noted(word: &'static str) -> Self {
        Self {
            outcome: GateReceiptOutcome::Noted,
            word,
        }
    }

    /// An egress verdict, recorded as the policy model records it.
    const fn policy(decision: PolicyClassifyDecision) -> Self {
        Self {
            outcome: decision.ledger_outcome(),
            word: decision.ledger_str(),
        }
    }

    /// One credential forwarding or resolution: carried out is `Allow`,
    /// refused for its destination, arming or allowlist `Deny`, and a fault
    /// on the way `Noted`, since nothing decided it.
    fn credential_egress(status: CredentialEgressStatus) -> Self {
        let outcome = match status {
            CredentialEgressStatus::Forwarded | CredentialEgressStatus::Resolved => {
                GateReceiptOutcome::Allow
            }
            CredentialEgressStatus::InvalidDestination
            | CredentialEgressStatus::Unarmed
            | CredentialEgressStatus::AllowlistDenied => GateReceiptOutcome::Deny,
            CredentialEgressStatus::ResolverFailed
            | CredentialEgressStatus::EmptyMaterial
            | CredentialEgressStatus::TransportFailed
            | CredentialEgressStatus::TransportUnavailable => GateReceiptOutcome::Noted,
        };
        Self {
            outcome,
            word: status.as_str(),
        }
    }
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
        self.append_sandbox_gate_receipt(
            run_id,
            "abandoned",
            SandboxReceiptOutcome::noted("abandoned"),
            body,
            hash,
        )
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
            SandboxReceiptOutcome::noted("recorded"),
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
        self.append_sandbox_gate_receipt(
            run_id,
            "desktop_takeover",
            SandboxReceiptOutcome::noted("returned"),
            body,
            hash,
        )
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
        self.append_sandbox_gate_receipt(
            run_id,
            "desktop_takeover",
            SandboxReceiptOutcome::noted("abandoned"),
            body,
            hash,
        )
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
        self.append_sandbox_gate_receipt(
            run_id,
            "browser_takeover",
            SandboxReceiptOutcome::noted("returned"),
            body,
            hash,
        )
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
        self.append_sandbox_gate_receipt(
            run_id,
            "browser_takeover",
            SandboxReceiptOutcome::noted("abandoned"),
            body,
            hash,
        )
    }
    /// A run browser's demonstration (CUA E9) its seat's end closed, never
    /// given to the agent: the demonstration is its receipt, outcome
    /// `closed` (FIX 9409).
    pub fn append_browser_demonstration_closed_receipt(
        &self,
        run_id: EntityId,
        record: &serde_json::Value,
    ) -> Result<String> {
        let body = serde_json::to_string(
            &serde_json::json!({"run_id": run_id.to_hex(), "demonstration": record}),
        )
        .map_err(|e| crate::Error::InvalidConfig(e.to_string()))?;
        let hash = *blake3::hash(body.as_bytes()).as_bytes();
        self.append_sandbox_gate_receipt(
            run_id,
            "browser_demonstration",
            SandboxReceiptOutcome::noted("closed"),
            body,
            hash,
        )
    }
    pub fn append_egress_receipt(&self, receipt: &EgressReceipt) -> Result<String> {
        let body = serde_json::to_string(receipt)
            .map_err(|e| crate::Error::InvalidConfig(e.to_string()))?;
        self.append_sandbox_gate_receipt(
            receipt.run_id,
            "egress",
            SandboxReceiptOutcome::policy(receipt.decision),
            body,
            receipt.content_hash,
        )
    }
    /// One credential forwarding/resolution decision, as metadata only. The
    /// digest hashes the metadata JSON itself, never a transport or content
    /// claim.
    pub fn append_credential_egress_receipt(
        &self,
        run_id: EntityId,
        record: &oneiron_container::CredentialEgressRecord,
    ) -> Result<String> {
        let body = serde_json::to_string(&serde_json::json!({
            "run_id": run_id.to_hex(),
            "credential_egress": record,
        }))
        .map_err(|e| crate::Error::InvalidConfig(e.to_string()))?;
        let digest = *blake3::hash(body.as_bytes()).as_bytes();
        self.append_sandbox_gate_receipt(
            run_id,
            "credential_egress",
            SandboxReceiptOutcome::credential_egress(record.status),
            body,
            digest,
        )
    }
    fn append_sandbox_gate_receipt(
        &self,
        run_id: EntityId,
        kind: &str,
        outcome: SandboxReceiptOutcome,
        body: String,
        digest: [u8; 32],
    ) -> Result<String> {
        let mut txn = self.store.env.write_txn()?;
        let receipt =
            self.append_sandbox_gate_receipt_in_txn(&mut txn, run_id, kind, outcome, body, digest)?;
        txn.commit()?;
        Ok(receipt)
    }

    /// The shared receipt writer for an admission whose proof and receipts
    /// must be judged in the same write transaction.
    pub(crate) fn append_sandbox_gate_receipt_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        run_id: EntityId,
        kind: &str,
        outcome: SandboxReceiptOutcome,
        body: String,
        digest: [u8; 32],
    ) -> Result<String> {
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
        let SandboxReceiptOutcome { outcome, word } = outcome;
        let mut receipt = GateReceipt::with_reasons(
            outcome,
            kind.to_owned(),
            vec![
                format!("gate.sandbox.{kind}"),
                format!("gate.sandbox.{kind}.{word}"),
            ],
            ReceiptActor::Part(GateEnginePart::Sandbox, Some(run_id.to_hex())),
            digest.to_vec(),
            PolicyBasis::NOT_READ,
        );
        receipt.notices = notices;
        let record = self.store.record_gate_receipt_in_txn(txn, receipt)?;
        Ok(format!("gate:{}", record.decision_id.to_hex()))
    }
}
