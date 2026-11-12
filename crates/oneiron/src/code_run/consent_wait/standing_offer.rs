//! The exact native action bound an owner may choose to remember.

use serde::{Deserialize, Serialize};

use crate::consent::{ActionClass, ActionEnvelope, ActorBound, BoundEnvelope, GrantBound};
use crate::error::Result;

#[doc(hidden)]
pub use oneiron_verb_wire::code_run::consent_wait::standing_offer::CodeConsentStandingOffer;
