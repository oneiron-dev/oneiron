//! The VAD consolidation a committed settlement runs for the claim it
//! approved (FIX 7600, Engine 09:24): a held Keep's approval, an
//! ApproveAndKeep and a claim settlement all run it here. Consent is
//! committed before the consolidator opens its own writer, so a
//! consolidation that fails never reads as a refused settlement: the
//! settlement answers success, its outcome carries a pending-VAD
//! [`SettleWarning`] naming the claim, and the failure gets a key-only WARN.
//! [`Vault::consolidate_claim_vad`] on that claim runs it again; a retry with
//! unchanged evidence reuses the active reappraisal state.

use super::{SettleWarning, SettleWarningCode};
use crate::{EntityId, Vault};

impl Vault {
    /// Consolidates `claim`'s VAD after the settlement that approved it
    /// committed: `None` when it consolidated, else the pending-VAD warning
    /// the settlement's outcome carries.
    pub(crate) fn consolidate_settled_claim_vad(
        &self,
        claim: &EntityId,
        now: u64,
    ) -> Option<SettleWarning> {
        let error = self.consolidate_claim_vad_now(claim, now).err()?;
        let kind = error.kind();
        tracing::warn!(
            target: "oneiron::memory",
            ?kind,
            claim = %claim.to_hex(),
            "a committed settlement's VAD consolidation failed; the settlement stands and its VAD is pending"
        );
        Some(SettleWarning {
            code: SettleWarningCode::VadPending,
            claim_ref: claim.to_hex(),
            detail: format!(
                "The settlement committed; the claim's VAD consolidation failed ({kind:?}) and is pending: consolidate_claim_vad on this claim runs it again."
            ),
        })
    }
}
