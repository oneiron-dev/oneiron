//! Campaign #5 interface bench task generation and smoke harness.

mod cli_and_pinned_config;
mod config_types;
mod eval_run;
mod reports_and_fixture_helpers;
mod taskgen;
#[cfg(test)]
mod tests_a;
#[cfg(test)]
mod tests_b;
mod wire_and_scoring;

pub(crate) use self::cli_and_pinned_config::run;

#[cfg(test)]
use self::{
    cli_and_pinned_config::*, config_types::*, eval_run::*, reports_and_fixture_helpers::*,
    taskgen::*, wire_and_scoring::*,
};
