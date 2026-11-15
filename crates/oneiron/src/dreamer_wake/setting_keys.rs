//! The settings `dreamer_wake` keeps (DESIGN 15-setting-primitive, stages 1 and 2): each row is
//! one catalogue key, and the crate's build script lists it in the setting catalogue.

use super::policy::{AgentWakeRole, DreamerWakePolicy, shipped_wake_policy};
use super::projector::{ProjectorPolicy, shipped_projector_policy};
use super::recipes::{WakeRecipePolicy, shipped_recipe_policy};
use super::sieve::{SievePassBudgets, SieveScoring, shipped_sieve_budgets, shipped_sieve_scoring};
use crate::federation::EngineControlClass;
use crate::setting::{Kind, SetBy};

/// The wake policy's comparator: `a` is no wider than `b` unless it widens the Coach's reads.
/// The Coach's health check reads the sealed pads of every agent that does not wake as a
/// companion, and an agent with no cadence dial wakes as the absent role
/// (`memory::diary_read::coach_reads_pads_in_txn`). So a move of the absent role off companion
/// widens; every other field moves no access.
fn wake_policy_no_wider(a: &DreamerWakePolicy, b: &DreamerWakePolicy) -> bool {
    a.agent_cadence.absent_role == AgentWakeRole::Companion
        || b.agent_cadence.absent_role != AgentWakeRole::Companion
}

crate::setting::setting_keys! {
    /// The three wake recipes' work budgets per receipt, the sieve audit's sampling and its rung
    /// instructions. Absent, the shipped recipe_policy_defaults.json decides.
    pub(crate) RECIPE_POLICY: WakeRecipePolicy = "dreamer.wake.recipe_policy" {
        kind: Kind::new(shipped_recipe_policy),
    };
    /// The Dreamer's wake policy: the turn grain, the weave's triggers, waits and quiet windows,
    /// the role table of resident wakes, the recipe priority and the surprise floor. A holder of
    /// the wake cadence class moves it, except that its move of the absent role off companion
    /// widens the Coach's sealed-pad reads and asks. Absent, the shipped
    /// wake_policy_defaults.json decides.
    pub(crate) WAKE_POLICY: DreamerWakePolicy = "dreamer.wake.policy" {
        kind: Kind::new(shipped_wake_policy).custom(wake_policy_no_wider),
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
    };
    /// New statements a due window needs before the projector's wake writes. A holder of the
    /// maintenance cadence class moves it either way, as before: it moves no access, authority,
    /// money or identity, so its order is neutral. Absent, the shipped
    /// projector_policy_defaults.json decides.
    pub(crate) PROJECTOR_POLICY: ProjectorPolicy = "dreamer.projector.policy" {
        kind: Kind::new(shipped_projector_policy).neutral(),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
    };
    /// The sieve's three per-pass work budgets: turns, scanned timeline rows and text bytes. A
    /// holder of the work budget class lowers each at once, under the owner's row too; its raise
    /// asks. Absent, the shipped sieve_policy_defaults.json decides.
    pub(crate) SIEVE_BUDGETS: SievePassBudgets = "dreamer.sieve.budgets" {
        kind: Kind::new(shipped_sieve_budgets).each(),
        set_by: SetBy::Class(EngineControlClass::WorkBudget),
    };
    /// How the sieve scores a span: the interest of a date and a name, each rule's confidence and
    /// the uncertain band's edges, in percent. A new value scores the spans read after it; spans
    /// already queued keep their score. Absent, the shipped sieve_policy_defaults.json decides.
    pub(crate) SIEVE_SCORING: SieveScoring = "dreamer.sieve.scoring" {
        kind: Kind::new(shipped_sieve_scoring),
    };
}
