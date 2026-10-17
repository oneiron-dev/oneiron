//! The signed instrument a request was admitted on, kept with the work it
//! queued, so that work's standing is the slip's own when it runs.
use super::{CapabilitySlip, VerifiedSlip, invalid_authority};
use crate::Vault;
use crate::error::Result;
use serde::{Deserialize, Serialize};

/// A slip, the challenge its holder signed and that signature, as the
/// request that was admitted on them presented them. It is no authority on
/// its own: each judgment verifies it again against the fold and clock of
/// its own snapshot, every caveat included, so revoking, expiring or
/// unbinding the slip stops what it queued.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationSlipBinding {
    slip: CapabilitySlip,
    challenge: Vec<u8>,
    signature: Vec<u8>,
}
impl std::fmt::Debug for InvocationSlipBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvocationSlipBinding")
            .field("slip", &self.slip)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Keeps the instrument a request was admitted on, for work it queues.
    /// It must verify now. The request's freshness window and nonce were
    /// judged once, by its admission, and are not judged again.
    pub fn bind_invocation_slip(
        &self,
        slip: &CapabilitySlip,
        challenge: &[u8],
        signature: &[u8],
    ) -> Result<InvocationSlipBinding> {
        let binding = InvocationSlipBinding {
            slip: slip.clone(),
            challenge: challenge.to_vec(),
            signature: signature.to_vec(),
        };
        let txn = self.store.env.read_txn()?;
        self.invocation_slip_in_txn(&txn, &binding)?;
        Ok(binding)
    }

    /// The slip `binding` keeps, verified again in a snapshot of its own, for
    /// a host that runs work the binding's request queued: a verb hook's
    /// settled call (ARCH-0080 §3 Ask). The request's freshness is not judged
    /// again; every other check is.
    pub fn verify_invocation_slip(&self, binding: &InvocationSlipBinding) -> Result<VerifiedSlip> {
        let txn = self.store.env.read_txn()?;
        self.invocation_slip_in_txn(&txn, binding)
    }

    /// The slip `binding` keeps, verified in `txn`: its mint's signer, every
    /// caveat, the holder's signature, and its standing at this snapshot's
    /// clock (expiry, revocation, vault and pact).
    pub(crate) fn invocation_slip_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        binding: &InvocationSlipBinding,
    ) -> Result<VerifiedSlip> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let signer = &fold
            .slips
            .mints
            .get(&binding.slip.claims.slip_id)
            .ok_or_else(invalid_authority)?
            .signer;
        let verified = binding.slip.verify(
            signer,
            &fold,
            self.instant_in_txn(txn)?.secs(),
            &binding.challenge,
            &binding.signature,
        )?;
        if !self.capability_slip_is_live_in_txn(txn, &verified)? {
            return Err(invalid_authority());
        }
        Ok(verified)
    }
}
