//! Core half of `secret_lease::admission`: its store-layer items live in `oneiron_store::secret_lease::admission` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::secret_lease::admission::*;

use crate::error::{Error, Result, SecretError};
use crate::secret_record::SecretCustodyAdmission;
use crate::secret_record::{CustodyClass, CustodyTier, SecretBinding};
use crate::secret_record::{SecretCustodyFloor, SecretCustodyStatus};

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

/// The reveal half of the admission rule (OF-560): a reveal puts the value
/// into a model's context, which is a T1 lease. The class's live floor must
/// reach T1, and so must the widest binding the record carries: a record
/// with no binding (a masked secret) is capped by its floor alone, and one
/// whose every binding is doored is used at its door and never revealed.
/// A handle-only private copy never enters a model context, regardless of
/// the class's floor or an effector's use binding.
pub(crate) fn reveal_tier_admission(
    rec: &SecretCustodyAdmission,
    floor: &SecretCustodyFloor,
) -> Result<()> {
    if rec.status != SecretCustodyStatus::Active {
        return Err(Error::Secret(SecretError::SecretCustodyNotActive {
            name: rec.name.clone(),
        }));
    }
    if !rec.model_reveal_allowed {
        return Err(Error::Secret(SecretError::SecretDoorPolicyRefused {
            reason: "this secret is available to agents by handle only",
        }));
    }
    let requested = CustodyTier::T1Leased;
    let band = floor.band_for(rec.class);
    let binding_ceiling = rec
        .bindings
        .iter()
        .map(|binding| binding.tier_ceiling)
        .max()
        .unwrap_or(requested);
    if requested > band.max || requested > binding_ceiling {
        return Err(Error::Secret(SecretError::SecretTierDenied {
            class: rec.class,
            requested,
            floor_min: band.min,
            floor_max: band.max,
            binding_ceiling,
        }));
    }
    Ok(())
}
