//! The setting keys `receipt` declares (restriction wave 8): the crate's build script lists each
//! row in the setting catalogue.

use super::call::MAX_ACTION_INPUT_ENTITIES;
use crate::setting::{Kind, lower_is_tighter};

fn default_max_input_entities() -> u32 {
    u32::try_from(MAX_ACTION_INPUT_ENTITIES).unwrap_or(u32::MAX)
}

crate::setting::setting_keys! {
    /// The most named entities one action's input digest versions: a call that names more states
    /// no input digest (OF-568). A higher cap captures wider calls at one revision read each.
    pub(crate) ACTION_MAX_INPUT_ENTITIES: u32 = "receipt.action.max_input_entities" {
        kind: Kind::new(default_max_input_entities).tighter(lower_is_tighter::<u32>),
    };
}
