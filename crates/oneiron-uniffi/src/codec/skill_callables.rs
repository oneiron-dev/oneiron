//! Owned callable-contract output lifts for opaque schema JSON (FIX 12936).

use super::{Lift, OneironError, WireJson};

impl Lift<oneiron::skill::helper::CallableCardView> for crate::CallableCardView {
    fn lift(card: oneiron::skill::helper::CallableCardView) -> Result<Self, OneironError> {
        let oneiron::skill::helper::CallableCardView {
            skill,
            skill_id,
            version,
            desc,
            reference,
            arguments,
            returns,
        } = card;
        // Consume both opaque leaves before propagating an encoding error.
        let arguments = WireJson::lift(arguments);
        let returns = WireJson::lift(returns);
        let arguments = arguments?;
        let returns = returns?;
        Ok(Self {
            skill,
            skill_id,
            version,
            desc,
            reference,
            arguments,
            returns,
        })
    }
}
