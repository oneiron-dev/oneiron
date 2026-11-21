//! The pre-mask body of each claim op a seal rewrites, read before the minted
//! pass rewrites any, so each apply reads its receipt against the body as written.

use zeroize::Zeroizing;

use super::super::MaskedClaimBodies;
use super::Seal;
use crate::batch::BatchOp;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::write_envelope::ClaimCandidate;

/// The pre-mask body of each claim op a seal rewrites, by op index, read
/// before the minted pass: the minted pass reports only what it rewrote
/// itself (`Masker::mask_ops`), and each apply reads its claim's preflight
/// receipt, and a candidate apply renews a MACHINE proof, against the body
/// as written (FIX 11356, RAW-CLAIM-PUT-MASK-REPLAY-MISMATCH).
pub(in crate::batch::secret_scan::mask) struct SealedClaimBodies(Vec<(usize, SealedClaimBody)>);

/// One claim op's body as written.
enum SealedClaimBody {
    /// A claim candidate op's candidate.
    Candidate(ClaimCandidate),
    /// A local CLAIM put's bytes, wiped when dropped.
    Put(Zeroizing<Vec<u8>>),
}

/// The body as written of each claim candidate op and each local CLAIM put
/// op in `ops` that a seal of `seals` (in op order) rewrites.
pub(in crate::batch::secret_scan::mask) fn claims_before(
    ops: &[BatchOp],
    seals: &[Seal],
) -> SealedClaimBodies {
    let mut before: Vec<(usize, SealedClaimBody)> = Vec::new();
    for seal in seals {
        if before.last().is_some_and(|(op, _)| *op == seal.index) {
            continue;
        }
        let body = match ops.get(seal.index) {
            Some(BatchOp::ClaimCandidate { candidate, .. }) => {
                SealedClaimBody::Candidate((**candidate).clone())
            }
            Some(op @ BatchOp::Put { data, .. }) if reports_claim_put(op) => {
                SealedClaimBody::Put(Zeroizing::new(data.clone()))
            }
            _ => continue,
        };
        before.push((seal.index, body));
    }
    SealedClaimBodies(before)
}

impl SealedClaimBodies {
    /// Writes into `masked`, the minted pass's report, the body as written of
    /// each claim op a seal rewrote and that pass left as written. The
    /// minted pass gives each claim candidate op one slot, in op order, and
    /// each local CLAIM put op one (`Masker::mask_ops`): an op's slot is its
    /// place among those ops.
    pub(in crate::batch::secret_scan::mask) fn report(
        self,
        ops: &[BatchOp],
        masked: &mut MaskedClaimBodies,
    ) -> Result<()> {
        let unaligned =
            || Error::InvariantViolation("a sealed claim op has no slot in the mask's report");
        for (index, before) in self.0 {
            let earlier = ops.get(..index).ok_or_else(unaligned)?;
            match (before, ops.get(index)) {
                (
                    SealedClaimBody::Candidate(pre),
                    Some(BatchOp::ClaimCandidate { id, candidate, .. }),
                ) => {
                    let slot = earlier
                        .iter()
                        .filter(|op| matches!(op, BatchOp::ClaimCandidate { .. }))
                        .count();
                    let (slot_id, rewritten) =
                        masked.candidates.get_mut(slot).ok_or_else(unaligned)?;
                    if *slot_id != *id {
                        return Err(unaligned());
                    }
                    if rewritten.is_none() && **candidate != pre {
                        *rewritten = Some(pre);
                    }
                }
                (SealedClaimBody::Put(pre), Some(op @ BatchOp::Put { id, data, .. }))
                    if reports_claim_put(op) =>
                {
                    let slot = earlier.iter().filter(|op| reports_claim_put(op)).count();
                    let (slot_id, rewritten) = masked.puts.get_mut(slot).ok_or_else(unaligned)?;
                    if *slot_id != *id {
                        return Err(unaligned());
                    }
                    if rewritten.is_none() && data.as_slice() != pre.as_slice() {
                        *rewritten = Some(pre);
                    }
                }
                _ => return Err(unaligned()),
            }
        }
        Ok(())
    }
}

/// Whether the minted pass reports `op` as a local CLAIM put: a CLAIM body
/// this door writes handles into (`Masker::mask_ops`).
fn reports_claim_put(op: &BatchOp) -> bool {
    matches!(
        op,
        BatchOp::Put {
            entity_type,
            allow_maintenance: false,
            hub_sync_imported: false,
            ..
        } if *entity_type == ENTITY_TYPE_CLAIM
    )
}

pub(super) fn unnamed() -> Error {
    Error::InvariantViolation("a seal no longer names its op's part")
}
