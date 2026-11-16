//! The settings `dreamer_prefilter` keeps (DESIGN 15-setting-primitive, stage 1): each row is one
//! catalogue key, and the crate's build script lists it in the setting catalogue.

use super::config::PrefilterConfig;
use crate::setting::Kind;

crate::setting::setting_keys! {
    /// The Dreamer prefilter's screening policy: whether it screens, the score a turn must reach
    /// to be kept, and each axis's weight. The default screens and drops nothing.
    pub(crate) PREFILTER: PrefilterConfig = "dreamer.prefilter" {
        kind: Kind::new(PrefilterConfig::default),
    };
}
