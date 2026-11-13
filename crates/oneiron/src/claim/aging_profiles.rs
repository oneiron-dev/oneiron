//! Class-level aging policy data; claim classification stays predicate-root metadata.
use serde::{Deserialize, Serialize};

use super::{AccessFactorPolicy, ClaimAgingClass};
use crate::error::{Error, Result};

#[doc(hidden)]
pub use oneiron_verb_wire::claim::aging_profiles::ClaimAgingProfiles;
#[doc(hidden)]
pub(crate) use oneiron_verb_wire::claim::aging_profiles::validate_access_factor_policy;
