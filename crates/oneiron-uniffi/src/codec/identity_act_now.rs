//! Owned opaque card output for the identity-settlement binding.

use oneiron::dreamer_runner::maintenance::identity::IdentityActNow;

use super::{Lift, OneironError, WireJson};

impl Lift<IdentityActNow> for crate::IdentityActNow {
    fn lift(value: IdentityActNow) -> Result<Self, OneironError> {
        Ok(match value {
            IdentityActNow::Settled { entity } => Self::Settled { entity },
            IdentityActNow::Unknown => Self::Unknown,
            IdentityActNow::Deciding { ask } => Self::Deciding { ask },
            IdentityActNow::NeedsPerson { ask, card } => Self::NeedsPerson {
                ask,
                card: WireJson::lift(card)?,
            },
        })
    }
}
