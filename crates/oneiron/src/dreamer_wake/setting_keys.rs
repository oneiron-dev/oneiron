//! The settings `dreamer_wake` keeps (DESIGN 15-setting-primitive, stage 1): each row is one
//! catalogue key, and the crate's build script lists it in the setting catalogue.

use super::recipes::{WakeRecipePolicy, shipped_recipe_policy};
use super::sieve_doors::MAX_PAGE;
use crate::setting::{Kind, lower_is_tighter};

/// 1000: a page naming no limit, or a larger one, reads this many rows.
fn sieve_max_page_default() -> u32 {
    MAX_PAGE
}

crate::setting::setting_keys! {
    /// The three wake recipes' work budgets per receipt, the sieve audit's sampling and its rung
    /// instructions. Absent, the shipped recipe_policy_defaults.json decides.
    pub(crate) RECIPE_POLICY: WakeRecipePolicy = "dreamer.wake.recipe_policy" {
        kind: Kind::new(shipped_recipe_policy),
    };
    /// The most rows one owner page of the sieve queue, its retained readings or its receipts
    /// carries. 1000 by default: a page naming no limit, or a larger one, reads this many. A
    /// raise is the looser direction, so an agent's raise waits on the owner's answer. A stored
    /// 0 reads as 1.
    pub(crate) SIEVE_MAX_PAGE: u32 = "dreamer_wake.sieve.max_page" {
        kind: Kind::new(sieve_max_page_default)
            .strictest(sieve_max_page_default)
            .tighter(lower_is_tighter::<u32>),
    };
}
