//! The authority module's owner Setting keys (DESIGN 15-setting-primitive): rows the setting
//! catalogue reads from this file.

use super::SUPPORT_GRANT_MAX_TTL_SECS;
use crate::setting::{Kind, lower_is_tighter};

/// One day: the cap until the owner sets another.
fn one_day() -> u64 {
    SUPPORT_GRANT_MAX_TTL_SECS
}

crate::setting::setting_keys! {
    /// The longest support grant the owner can mint, in seconds (OF-606). The mint door reads
    /// it in its own writer and refuses a longer ask; a grant minted under it keeps its
    /// lifetime when the cap is lowered later. One day until the owner sets another; a value
    /// under one second reads as one second, and a row that does not decode reads as one day.
    /// A longer cap is the looser value, so only the owner raises it; an agent's raise waits
    /// on the owner's answer.
    pub(crate) SUPPORT_GRANT_MAX_TTL: u64 = "support.grant.max_ttl_secs" {
        kind: Kind::new(one_day).strictest(one_day).tighter(lower_is_tighter::<u64>),
    };
}
