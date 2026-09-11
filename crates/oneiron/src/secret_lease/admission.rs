//! The one cap-only admission rule, pure + door-side halves.

use crate::error::{Error, Result, SecretError};
use crate::secret_custody::{
    CustodyClass, CustodyTier, SecretBinding, SecretCustodyAdmission, SecretCustodyFloor,
    SecretCustodyStatus,
};

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

/// The door-side half of the admission rule: record liveness plus binding
/// resolution (rule (a)), then the pure tier gate (rules (b)+(c)).
#[allow(clippy::redundant_clone)]
pub(super) fn admit_record_use(
    rec: &SecretCustodyAdmission,
    effector: &str,
    requested: CustodyTier,
    floor: &SecretCustodyFloor,
) -> Result<()> {
    if rec.status != SecretCustodyStatus::Active {
        return Err(Error::Secret(SecretError::SecretCustodyNotActive {
            name: rec.name.clone(),
        }));
    }
    let binding = rec.binding_for(effector).ok_or_else(|| {
        Error::Secret(SecretError::SecretBindingDenied {
            effector: effector.to_owned(),
            secret_ref: rec.name.clone(),
        })
    })?;
    tier_admission(rec.class, requested, binding, floor)?;
    Ok(())
}
