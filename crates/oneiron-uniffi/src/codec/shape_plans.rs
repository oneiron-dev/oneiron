//! Owned manifest JSON and generated UI in a shape-plan card.

use oneiron::memory::ShapePlanCardView;
use oneiron::vault_shape::ShapeRow;
use serde_json::Value;

use super::{Lift, OneironError, WireJson, lift_record};

impl Lift<ShapePlanCardView> for crate::ShapePlanCardView {
    fn lift(mut value: ShapePlanCardView) -> Result<Self, OneironError> {
        let generated_ui = WireJson::lift(std::mem::take(&mut value.generated_ui));
        let row_json = value
            .plan
            .seed
            .rows
            .iter_mut()
            .chain(
                value
                    .plan
                    .items
                    .iter_mut()
                    .flat_map(|item| item.before.iter_mut().chain(item.after.iter_mut())),
            )
            .chain(value.plan.undeclared.iter_mut())
            .map(lift_row_json)
            .collect::<Vec<_>>();

        // Consume every opaque leaf before a conversion error can return.
        let generated_ui = generated_ui?;
        let row_json = row_json.into_iter().collect::<Result<Vec<_>, _>>()?;
        let mut output: Self = lift_record("vault.shape.plan.card", &value)?;
        output.generated_ui = generated_ui;
        let rows = output
            .plan
            .seed
            .rows
            .iter_mut()
            .chain(
                output
                    .plan
                    .items
                    .iter_mut()
                    .flat_map(|item| item.before.iter_mut().chain(item.after.iter_mut())),
            )
            .chain(output.plan.undeclared.iter_mut());
        for (row, json) in rows.zip(row_json) {
            if let crate::ShapeRow::Manifest { json: target, .. } = row {
                *target = json;
            }
        }
        Ok(output)
    }
}

fn lift_row_json(row: &mut ShapeRow) -> Result<Option<WireJson>, OneironError> {
    match row {
        ShapeRow::Manifest { json, .. } => match json.take() {
            None | Some(Value::Null) => Ok(None),
            Some(value) => WireJson::lift(value).map(Some),
        },
        _ => Ok(None),
    }
}
