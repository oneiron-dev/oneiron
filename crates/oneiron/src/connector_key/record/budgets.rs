//! Effector-budget rows: dimension/window/exhaust/reserve enums, EffectorBudget constructors, row and spend-unit validators.

use crate::error::Result;

use super::{invalid_body, normalize_connector_key};

#[doc(hidden)]
use oneiron_records::connector_key::record::budgets::CALENDAR_TZ_UTC;
#[doc(hidden)]
pub(in crate::connector_key) use oneiron_records::connector_key::record::budgets::validate_spend_unit;
#[doc(hidden)]
pub use oneiron_records::connector_key::record::budgets::{
    CalendarPeriod, ConnectorSpendBasis, EffectorBudget, EffectorBudgetDimension,
    EffectorBudgetOnExhaust, EffectorBudgetReservePolicy, EffectorBudgetWindow,
};

#[doc(hidden)]
pub use oneiron_verb_wire::connector_key::record::budgets::ConnectorSpendEstimate;

pub(in crate::connector_key) fn validate_budget_row(budget: &EffectorBudget) -> Result<()> {
    if budget.limit == 0 {
        return Err(invalid_body("budget limit must be at least 1"));
    }
    match (budget.dimension, budget.unit.as_deref()) {
        (EffectorBudgetDimension::Spend, Some(unit)) => validate_spend_unit(unit)?,
        (EffectorBudgetDimension::Spend, None) => {
            return Err(invalid_body("spend rows require a unit"));
        }
        (_, Some(_)) => return Err(invalid_body("unit only allowed on spend rows")),
        (_, None) => {}
    }
    if budget.reserve_policy.is_some() && budget.dimension != EffectorBudgetDimension::Spend {
        return Err(invalid_body("reserve_policy only allowed on spend rows"));
    }
    match &budget.window {
        EffectorBudgetWindow::Rolling { duration_s } => {
            if *duration_s == 0 {
                return Err(invalid_body("rolling window duration must be at least 1s"));
            }
        }
        EffectorBudgetWindow::Calendar { tz, .. } => {
            if let Some(tz) = tz.as_deref()
                && tz != CALENDAR_TZ_UTC
            {
                return Err(invalid_body("calendar tz must be UTC"));
            }
        }
    }
    if let Some(channel_class) = budget.channel_class.as_deref() {
        if normalize_connector_key(channel_class).is_empty() {
            return Err(invalid_body("channel_class must not be blank"));
        }
        // Same stored-form == index-form invariant as the connector token:
        // row matching compares against the normalized effect channel, so a
        // non-canonical stored narrowing would never match any dispatch.
        if channel_class != normalize_connector_key(channel_class) {
            return Err(invalid_body("channel_class must be stored normalized"));
        }
    }
    Ok(())
}

pub(in crate::connector_key) fn validate_suggested_budget_row(
    budget: &EffectorBudget,
) -> Result<()> {
    validate_budget_row(budget)?;
    if budget.dimension == EffectorBudgetDimension::Spend {
        return Err(invalid_body("suggested budget rows must be sends or rate"));
    }
    if budget.on_exhaust != EffectorBudgetOnExhaust::Refuse {
        return Err(invalid_body("suggested budget rows must refuse on exhaust"));
    }
    Ok(())
}
