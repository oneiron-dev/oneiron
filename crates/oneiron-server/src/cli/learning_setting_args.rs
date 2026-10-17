//! `oneiron learning-settings`: the owner's learned-setting rows on a stopped
//! vault (`oneiron::learning_setting_doors`); a running server answers the
//! same at `/v1/owner/settings/learning`.

use clap::{Args, Subcommand, ValueEnum};

use crate::config::ServeArgs;

#[derive(Subcommand, Clone, Debug)]
pub enum LearningSettingsCommand {
    /// The catalog, each knob with the value the vault reads now, and your
    /// seed and pin rows.
    List(Box<LearningSettingListArgs>),
    /// Lay one seed or pin at the vault, a project or a task type, replacing
    /// the row of the same key, mode and scope.
    Put(Box<LearningSettingPutArgs>),
    /// Clear one row of a key, mode and scope.
    Clear(Box<LearningSettingClearArgs>),
}

/// A seed (a prior the fit starts from, weighted in runs) or a pin (the
/// value, whatever the fit says).
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum LearningSettingModeArg {
    Seed,
    Pin,
}

#[derive(Args, Clone, Debug)]
pub struct LearningSettingListArgs {
    /// Only this catalog key.
    #[arg(long)]
    pub key: Option<String>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct LearningSettingPutArgs {
    /// The catalog key, e.g. `health.loop.repeats`.
    pub key: String,
    pub mode: LearningSettingModeArg,
    /// Within the key's catalog bounds.
    pub value: f64,
    /// A seed's weight in runs; a pin takes none.
    #[arg(long)]
    pub weight_runs: Option<f64>,
    /// Your reason, kept as written.
    #[arg(long)]
    pub why: String,
    /// A project's id (32 hex): the row steers that project's work.
    #[arg(long, conflicts_with = "task_type")]
    pub project: Option<String>,
    /// A task type's node: the row steers that type's work.
    #[arg(long)]
    pub task_type: Option<String>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct LearningSettingClearArgs {
    pub key: String,
    pub mode: LearningSettingModeArg,
    #[arg(long, conflicts_with = "task_type")]
    pub project: Option<String>,
    #[arg(long)]
    pub task_type: Option<String>,

    #[command(flatten)]
    pub serve: ServeArgs,
}
