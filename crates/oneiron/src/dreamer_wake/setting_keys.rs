//! The settings `dreamer_wake` keeps (DESIGN 15-setting-primitive, stage 1): each row is one
//! catalogue key, and the crate's build script lists it in the setting catalogue.

use super::recipes::{WakeRecipePolicy, shipped_recipe_policy};
use crate::setting::Kind;

crate::setting::setting_keys! {
    /// The three wake recipes' work budgets per receipt, the sieve audit's sampling and its rung
    /// instructions. Absent, the shipped recipe_policy_defaults.json decides.
    pub(crate) RECIPE_POLICY: WakeRecipePolicy = "dreamer.wake.recipe_policy" {
        kind: Kind::new(shipped_recipe_policy),
    };
}
