//! OF-606: the support grant's receipts, in the standard Gate receipt family
//! (no new ledger).
//!
//! The customer's mint and revoke each land a Gate receipt in their own
//! writer, stamped with the approving owner and joined by `grant_ref` = the
//! support slip's id; the approver and the holder also sit in the slip's
//! logged claims. Each request a support slip is admitted on lands one in
//! its admission writer, stamped with the support PERSON and the class its
//! slip names, never as the customer and never as `host`. Reason codes take
//! the `gate.` prefix; every key:value detail rides a receipt-detail notice.

use super::*;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{
    GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, GateSystemNoticeRecord,
};

/// The Gate `content_kind` of every support grant receipt.
pub(crate) const SUPPORT_GRANT_CONTENT_KIND: &str = "support_grant";
/// The customer minted a support grant.
pub(crate) const SUPPORT_GRANT_REASON_MINTED: &str = "gate.support_grant.minted";
/// The customer revoked a support grant.
pub(crate) const SUPPORT_GRANT_REASON_REVOKED: &str = "gate.support_grant.revoked";
/// A request was admitted on a support grant.
pub(crate) const SUPPORT_GRANT_REASON_USED: &str = "gate.support_grant.used";
const USE_DIGEST_CONTEXT: &[u8] = b"oneiron/support-grant/use/v1\0";

/// One support grant receipt, as the door that acted reports it.
pub(super) struct SupportReceipt {
    pub(super) reason: &'static str,
    pub(super) outcome: &'static str,
    /// Who acted: the approving owner for a mint or revoke, the support
    /// PERSON for a use.
    pub(super) actor: EntityId,
    pub(super) actor_class: String,
    pub(super) slip_id: [u8; 32],
    /// What the act bound: the minted claims' digest, or the request's.
    pub(super) digest: [u8; 32],
    /// `key:value` details, each its own receipt-detail notice.
    pub(super) details: Vec<String>,
}

impl Vault {
    /// Appends `receipt` to the Gate ledger in the acting writer and answers
    /// its decision id.
    pub(super) fn append_support_receipt_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        receipt: SupportReceipt,
    ) -> Result<GateDecisionId> {
        let decision_id = GateDecisionId::from_bytes(self.store.clock.ulid()?);
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id,
            created_at: crate::ports::recorded_at_in_txn(&self.store, txn)?,
            outcome: receipt.outcome.to_owned(),
            reason_codes: vec![receipt.reason.to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: GateSystemNoticeRecord::receipt_details(
                SUPPORT_GRANT_CONTENT_KIND,
                receipt.details,
            ),
            actor_class: receipt.actor_class,
            actor_ref: Some(receipt.actor.to_hex()),
            content_kind: SUPPORT_GRANT_CONTENT_KIND.to_owned(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            claim_id: None,
            grant_ref: Some(slip_hex(&receipt.slip_id)),
            diff_handle: receipt.digest.to_vec(),
            read_frontier_hash: [0; 32],
            context: Default::default(),
            redacted_at: None,
        };
        self.store.append_gate_decision_in_txn(txn, &record)?;
        Ok(decision_id)
    }

    /// The use receipt of one request admitted on a support slip, in its
    /// admission writer: actor the support PERSON at its slip's class,
    /// `grant_ref` the slip, digest the request's own binding (slip, nonce,
    /// signed time). A slip with no delegation lands nothing.
    pub(super) fn receipt_support_use_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        claims: &SlipClaims,
        nonce: &[u8],
        timestamp: u64,
    ) -> Result<()> {
        if claims.delegation.is_none() {
            return Ok(());
        }
        let holder = EntityId::from_hex(&claims.holder_ref).map_err(|_| invalid_authority())?;
        let class = claims.actor_class.clone().ok_or_else(invalid_authority)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(USE_DIGEST_CONTEXT);
        hasher.update(&claims.slip_id);
        hasher.update(&(nonce.len() as u64).to_be_bytes());
        hasher.update(nonce);
        hasher.update(&timestamp.to_be_bytes());
        self.append_support_receipt_in_txn(
            txn,
            SupportReceipt {
                reason: SUPPORT_GRANT_REASON_USED,
                outcome: "approved",
                actor: holder,
                actor_class: class.clone(),
                slip_id: claims.slip_id,
                digest: *hasher.finalize().as_bytes(),
                details: vec![
                    format!("holder:{}", holder.to_hex()),
                    format!("class:{class}"),
                    format!("request_at:{timestamp}"),
                ],
            },
        )
        .map(drop)
    }
}

/// A slip id as receipts and doors name it: 64 lowercase hex.
pub(crate) fn slip_hex(slip_id: &[u8; 32]) -> String {
    crate::entity_id::bytes_to_hex_lower(slip_id)
}
