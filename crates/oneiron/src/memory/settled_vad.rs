//! The VAD consolidation a committed settlement runs for the claim it
//! approved (FIX 7600, Engine 09:24): a held Keep's approval, an
//! ApproveAndKeep and a claim settlement all run it here. The approval's own
//! transaction writes the claim's consolidation debt, as a consent bundle's
//! does (FIX 11858, L01 10:45, L01 11:04), and consent is committed before the
//! consolidator opens its own writer, so a consolidation that fails never
//! reads as a refused settlement: the settlement answers success, its outcome
//! carries a pending-VAD [`SettleWarning`] naming the claim, the failure gets
//! a key-only WARN, and the debt stays for the housekeeping pass's
//! `ClaimVadDebt` sweep. [`Vault::consolidate_claim_vad`] on that claim runs
//! it at once; a retry with unchanged evidence reuses the active reappraisal
//! state.

use super::{SettleWarning, SettleWarningCode};
use crate::{EntityId, Vault};

impl Vault {
    /// Writes the consolidation debt of each claim in `claims` in the
    /// transaction that approves them (FIX 11858): a consolidation that fails
    /// after the commit, or never runs, stays owed.
    pub(crate) fn owe_settled_claim_vads_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        claims: &[EntityId],
    ) -> crate::error::Result<()> {
        let now = self.store.clock.now_recorded_at();
        crate::store::owe_claim_vad_in_txn(&self.store, wtxn, claims, now)
    }

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
            "a committed settlement's VAD consolidation failed; the settlement stands and its VAD is owed"
        );
        Some(SettleWarning {
            code: SettleWarningCode::VadPending,
            claim_ref: claim.to_hex(),
            detail: format!(
                "The settlement committed; the claim's VAD consolidation failed ({kind:?}) and stays owed: the housekeeping pass runs it again, and consolidate_claim_vad on this claim runs it now."
            ),
        })
    }
}
