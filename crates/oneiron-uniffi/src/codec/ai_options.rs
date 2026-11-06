//! Owned AI-options output lift for opaque model option JSON (FIX 12936).

use super::{Lift, OneironError, WireJson};

impl Lift<oneiron::task_verb::sdk::AiOptions> for crate::AiOptions {
    fn lift(options: oneiron::task_verb::sdk::AiOptions) -> Result<Self, OneironError> {
        let oneiron::task_verb::sdk::AiOptions {
            options,
            media_units_left,
        } = options;
        // Consume every opaque leaf before propagating an encoding error.
        let options: Vec<_> = options.into_iter().map(WireJson::lift).collect();
        let options = options.into_iter().collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            options,
            media_units_left,
        })
    }
}
