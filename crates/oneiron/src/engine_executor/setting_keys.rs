//! The engine executor's owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue
//! reads from this file.

use super::checkpoint_read::CHECKPOINT_READ_MAX_LIMIT;
use crate::setting::{Kind, lower_is_tighter};

/// 128: a larger limit reads this many steps.
fn checkpoint_read_max_limit_default() -> u32 {
    CHECKPOINT_READ_MAX_LIMIT
}

crate::setting::setting_keys! {
    /// The most steps one checkpoint page carries. 128 by default: a larger limit reads this
    /// many, and `next_step` names where the following page starts. A raise is the looser
    /// direction, so an agent's raise waits on the owner's answer. A stored 0 reads as 1.
    pub(crate) CHECKPOINT_READ_MAX_LIMIT_SETTING: u32 = "engine_executor.checkpoint_read.max_limit" {
        kind: Kind::new(checkpoint_read_max_limit_default)
            .strictest(checkpoint_read_max_limit_default)
            .tighter(lower_is_tighter::<u32>),
    };
}
