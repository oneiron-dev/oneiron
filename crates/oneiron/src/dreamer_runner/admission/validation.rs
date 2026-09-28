use super::*;

pub(super) fn validate_admission_input(input: &AdmitDreamerAttempt) -> Result<()> {
    validate_budget_id(&input.budget_id)?;
    if input.reserve_units == 0 {
        return Err(invalid_dreamer_runner(
            "dreamer admission reserve_units must be > 0",
        ));
    }
    if input
        .started_milestone
        .as_ref()
        .is_some_and(|milestone| milestone.kind != DreamerMilestoneKind::Started)
    {
        return Err(invalid_dreamer_runner(
            "dreamer admission milestone must be started",
        ));
    }
    Ok(())
}
