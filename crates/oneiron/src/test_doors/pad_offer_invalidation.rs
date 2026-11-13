//! Door for `tests/pad_offer_invalidation.rs` (FIX 22389): the home's grant
//! rows of one late joiner, and its ensure of an invalidation report that the
//! joiner itself sends, past the authority fold.

use crate::Vault;
use crate::error::Result;
use crate::sync::residence::bundle_access_test_door::ensure_as_target;
use crate::sync::residence::{InvalidPadOffer, PadAccessRequest};
use crate::world_keys::{PadAdmissionTarget, SealedBundleGeneration};

pub use crate::sync::residence::bundle_access_test_door::{GrantRow, grant_row, put_offer};

/// The home's ensure of a report from `target` itself, over the kept
/// `generation`, asking for no new row: each of `invalid` is an offer of
/// `generation` that `target` read from the home and could not use, by its
/// bytes.
///
/// # Errors
///
/// Storage errors.
pub fn report_invalid_offers(
    vault: &Vault,
    generation: SealedBundleGeneration,
    target: PadAdmissionTarget,
    invalid: &[Vec<u8>],
) -> Result<()> {
    let request = PadAccessRequest {
        target,
        generations: Some(Vec::new()),
        invalid: invalid
            .iter()
            .map(|grant| InvalidPadOffer {
                generation,
                grant: grant.clone(),
            })
            .collect(),
    };
    ensure_as_target(vault, &[generation], &request)
}
