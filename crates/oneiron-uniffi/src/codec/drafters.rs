//! Owned trainer settings in drafter output records.

use oneiron::drafter::{DrafterPolicy, DrafterStatus};

use super::{Lift, OneironError, WireJson, lift_record};

pub(crate) fn lift_drafter_policy(
    verb: &str,
    mut policy: DrafterPolicy,
) -> Result<crate::DrafterPolicy, OneironError> {
    let settings = take_settings(&mut policy)?;
    let mut output: crate::DrafterPolicy = lift_record(verb, &policy)?;
    restore_settings(&mut output, settings);
    Ok(output)
}

pub(crate) fn lift_drafter_status(
    verb: &str,
    mut status: DrafterStatus,
) -> Result<crate::DrafterStatus, OneironError> {
    let settings = take_settings(&mut status.policy)?;
    let mut output: crate::DrafterStatus = lift_record(verb, &status)?;
    restore_settings(&mut output.policy, settings);
    Ok(output)
}

fn take_settings(policy: &mut DrafterPolicy) -> Result<Option<WireJson>, OneironError> {
    policy
        .recipe
        .as_mut()
        .map(|recipe| WireJson::lift(std::mem::take(&mut recipe.settings)))
        .transpose()
}

fn restore_settings(policy: &mut crate::DrafterPolicy, settings: Option<WireJson>) {
    if let (Some(recipe), Some(settings)) = (policy.recipe.as_mut(), settings) {
        recipe.settings = settings;
    }
}
