//! Owned manifest JSON across shape plans, reads and apply receipts.

use oneiron::memory::{ShapeItemReceipt, ShapePlanCardView};
use oneiron::vault_shape::{ShapeApplyReceipt, ShapePlan, ShapeRead, ShapeRow};
use serde_json::Value;

use super::{Lift, OneironError, WireJson, lift_record};

impl Lift<ShapePlanCardView> for crate::ShapePlanCardView {
    fn lift(mut value: ShapePlanCardView) -> Result<Self, OneironError> {
        let generated_ui = WireJson::lift(std::mem::take(&mut value.generated_ui));
        let row_json = take_rows(plan_rows(&mut value.plan));

        let generated_ui = generated_ui?;
        let row_json = row_json?;
        let mut output: Self = lift_record("vault.shape.plan.card", &value)?;
        output.generated_ui = generated_ui;
        restore_rows(output_plan_rows(&mut output.plan), row_json);
        Ok(output)
    }
}

impl Lift<ShapePlan> for crate::ShapePlan {
    fn lift(mut value: ShapePlan) -> Result<Self, OneironError> {
        let row_json = take_rows(plan_rows(&mut value))?;
        let mut output: Self = lift_record("vault.shape.plan", &value)?;
        restore_rows(output_plan_rows(&mut output), row_json);
        Ok(output)
    }
}

impl Lift<ShapeRead> for crate::ShapeRead {
    fn lift(mut value: ShapeRead) -> Result<Self, OneironError> {
        let row_json = take_rows(
            value
                .seed
                .iter_mut()
                .flat_map(|seed| seed.seed.rows.iter_mut())
                .chain(value.live.rows.iter_mut())
                .chain(value.applies.iter_mut().flat_map(receipt_rows)),
        )?;
        let mut output: Self = lift_record("vault.shape.read", &value)?;
        restore_rows(
            output
                .seed
                .iter_mut()
                .flat_map(|seed| seed.seed.rows.iter_mut())
                .chain(output.live.rows.iter_mut())
                .chain(output.applies.iter_mut().flat_map(output_receipt_rows)),
            row_json,
        );
        Ok(output)
    }
}

impl Lift<ShapeApplyReceipt> for crate::ShapeApplyReceipt {
    fn lift(mut value: ShapeApplyReceipt) -> Result<Self, OneironError> {
        let row_json = take_rows(receipt_rows(&mut value))?;
        let mut output: Self = lift_record("shape apply receipt", &value)?;
        restore_rows(output_receipt_rows(&mut output), row_json);
        Ok(output)
    }
}

impl Lift<ShapeItemReceipt> for crate::ShapeItemReceipt {
    fn lift(mut value: ShapeItemReceipt) -> Result<Self, OneironError> {
        let item = &mut value.item.item;
        let row_json = take_rows(item.before.iter_mut().chain(item.after.iter_mut()))?;
        let mut output: Self = lift_record("vault.shape.items.receipt", &value)?;
        let item = &mut output.item.item;
        restore_rows(
            item.before.iter_mut().chain(item.after.iter_mut()),
            row_json,
        );
        Ok(output)
    }
}

fn plan_rows(plan: &mut ShapePlan) -> impl Iterator<Item = &mut ShapeRow> {
    plan.seed
        .rows
        .iter_mut()
        .chain(
            plan.items
                .iter_mut()
                .flat_map(|item| item.before.iter_mut().chain(item.after.iter_mut())),
        )
        .chain(plan.undeclared.iter_mut())
}

fn output_plan_rows(plan: &mut crate::ShapePlan) -> impl Iterator<Item = &mut crate::ShapeRow> {
    plan.seed
        .rows
        .iter_mut()
        .chain(
            plan.items
                .iter_mut()
                .flat_map(|item| item.before.iter_mut().chain(item.after.iter_mut())),
        )
        .chain(plan.undeclared.iter_mut())
}

fn receipt_rows(receipt: &mut ShapeApplyReceipt) -> impl Iterator<Item = &mut ShapeRow> {
    receipt.items.iter_mut().flat_map(|item| {
        item.item
            .before
            .iter_mut()
            .chain(item.item.after.iter_mut())
    })
}

fn output_receipt_rows(
    receipt: &mut crate::ShapeApplyReceipt,
) -> impl Iterator<Item = &mut crate::ShapeRow> {
    receipt.items.iter_mut().flat_map(|item| {
        item.item
            .before
            .iter_mut()
            .chain(item.item.after.iter_mut())
    })
}

pub(super) fn take_rows<'a>(
    rows: impl Iterator<Item = &'a mut ShapeRow>,
) -> Result<Vec<Option<WireJson>>, OneironError> {
    // Do not short-circuit while any sibling still owns opaque JSON.
    rows.map(lift_row_json)
        .collect::<Vec<_>>()
        .into_iter()
        .collect()
}

pub(super) fn restore_rows<'a>(
    rows: impl Iterator<Item = &'a mut crate::ShapeRow>,
    json: Vec<Option<WireJson>>,
) {
    for (row, json) in rows.zip(json) {
        if let crate::ShapeRow::Manifest { json: target, .. } = row {
            *target = json;
        }
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
