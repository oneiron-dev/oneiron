//! Exact source components for a claim-free gate-ledger clone. This reader
//! writes no live-vault state and follows no contextual entity references.

use heed::RoTxn;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::store::Store;

use super::ledger::{LEDGER, decode_gate_decision};
use super::orcb;
use super::types::GateDecisionId;

/// Component names are part of the segregated clone's source manifest, not
/// ordinary-vault restore classes or permission to copy another family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GateCloneComponent {
    StoredPrimary,
    OpenedPrimary,
    RetentionScope,
    ClaimRefs,
    PendingScrub,
}

impl GateCloneComponent {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::StoredPrimary => "gate_decision:v0:",
            Self::OpenedPrimary => "gate_decision:opened_messagepack",
            Self::RetentionScope => "gate_decision:retention_context:v1:",
            Self::ClaimRefs => "gate_decision_claim_refs:v0:",
            Self::PendingScrub => "gate_decision:pending_scrub:v1:",
        }
    }
}

impl Store {
    /// Streams only the claim-free partition, including its policy-sealed
    /// rows and bundle associations, in the caller's unchanged snapshot.
    /// Caller holds `gate_custody_read_guard` BEFORE opening that snapshot.
    /// Each component is borrowed only for its visit; no ledger is collected.
    pub(crate) fn for_each_claim_free_gate_clone_component_in_txn(
        &self,
        txn: &RoTxn<'_>,
        mut check: impl FnMut() -> Result<()>,
        mut visit: impl FnMut(GateDecisionId, GateCloneComponent, &[u8], &[u8]) -> Result<()>,
    ) -> Result<u64> {
        let mut decisions = 0_u64;
        for row in LEDGER.iter_from(self, txn, &[])? {
            check()?;
            let (decision, raw) = row?;
            let raw = Zeroizing::new(raw);
            // Claim envelopes carry a different, explicitly named partition.
            // Unknown/malformed envelope kinds are errors, never silent gaps.
            if orcb::is_orcb(&raw) && !orcb::is_policy_sealed(&raw) {
                if orcb::raw_claim_generation(&raw).is_none() {
                    return Err(orcb::corrupt());
                }
                continue;
            }
            let (record, opened) = if orcb::is_policy_sealed(&raw) {
                let custody = self.core.key_custody.local().ok_or_else(orcb::corrupt)?;
                let (record, plain) = orcb::decode_policy_source(custody, decision, &raw)?;
                (record, Some(plain))
            } else {
                (decode_gate_decision(&raw)?, None)
            };
            if record.decision_id != decision {
                return Err(Error::CorruptedIndex("gate decision ledger"));
            }
            if record.claim_id.is_some() {
                continue;
            }
            let key = decision.as_bytes();
            visit(decision, GateCloneComponent::StoredPrimary, &key, &raw)?;
            if let Some(opened) = opened {
                // Preserve ORIGINAL decrypted MessagePack, including any native
                // stored fields not represented by a reconstructed typed view.
                visit(decision, GateCloneComponent::OpenedPrimary, &key, &opened)?;
            }
            if let Some(scope) = self.gate_clone_retention_scope_in_txn(txn, decision)? {
                let scope = Zeroizing::new(scope);
                visit(decision, GateCloneComponent::RetentionScope, &key, &scope)?;
            }
            if let Some(refs) = self.gate_clone_claim_refs_in_txn(txn, decision)? {
                let refs = Zeroizing::new(refs);
                visit(decision, GateCloneComponent::ClaimRefs, &key, &refs)?;
            }
            self.for_each_gate_clone_scrub_in_txn(txn, decision, |key, value| {
                visit(decision, GateCloneComponent::PendingScrub, key, value)
            })?;
            decisions = decisions
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("legal clone decision count"))?;
        }
        Ok(decisions)
    }
}
