//! The one cap-only admission rule, pure + door-side halves.

use crate::secret_record::types::CustodyClass;
use crate::secret_record::types::CustodyTier;
use crate::secret_record::types::SecretBinding;
use crate::secret_record::types::SecretCustodyFloor;
use crate::secret_record::types::SecretCustodyStatus;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::error::SecretError;

// ---------------------------------------------------------------------------
// The one admission rule
// ---------------------------------------------------------------------------

/// The one admission rule, pure: `Ok(requested)` iff `requested` is at or
/// below `floor.band_for(class).max` AND at or below
/// `binding.tier_ceiling`. The binding must be resolved from the record by
/// the caller (a missing binding is [`SecretError::SecretBindingDenied`](crate::error::SecretError::SecretBindingDenied),
/// settled before this call) — never caller-invented.
///
/// Rule (b) is a pure upper CAP: ONE-1919's floor keystone narrows the
/// band's `max` and treats `min` as informational, so a request below the
/// band's `min` — a SAFER tier — admits and is never forced upward.
/// Floors and ceilings only ever CAP exposure; there is no
/// minimum-exposure rule anywhere.
pub fn tier_admission(
    class: CustodyClass,
    requested: CustodyTier,
    binding: &SecretBinding,
    floor: &SecretCustodyFloor,
) -> Result<CustodyTier> {
    let band = floor.band_for(class);
    if requested > band.max || requested > binding.tier_ceiling {
        return Err(Error::Secret(SecretError::SecretTierDenied {
            class,
            requested,
            floor_min: band.min,
            floor_max: band.max,
            binding_ceiling: binding.tier_ceiling,
        }));
    }
    Ok(requested)
}
