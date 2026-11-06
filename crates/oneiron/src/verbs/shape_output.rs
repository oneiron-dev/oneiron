//! Move native shape documents through the core SDK result boundary.

use serde_json::Value;

use crate::memory::{MemoryResult, ShapeItemReceipt, ShapePlanCardView};
use crate::vault_shape::{
    ShapeApplyReceipt, ShapeInboxGroup, ShapePlan, ShapePlanItem, ShapeRead, ShapeRow,
};

use super::encode;

type ItemJson = (Option<Value>, Option<Value>);

struct PlanJson {
    seed: Vec<Option<Value>>,
    items: Vec<ItemJson>,
    undeclared: Vec<Option<Value>>,
}

pub(super) fn read(mut output: ShapeRead) -> MemoryResult<Value> {
    let seed = output
        .seed
        .as_mut()
        .map(|seed| take_rows(&mut seed.seed.rows));
    let live = take_rows(&mut output.live.rows);
    let applies: Vec<_> = output.applies.iter_mut().map(take_receipt).collect();
    let mut encoded = encode(output)?;
    if let Some(seed) = seed {
        restore_rows(&mut encoded["seed"]["seed"]["rows"], seed);
    }
    restore_rows(&mut encoded["live"]["rows"], live);
    for (index, values) in applies.into_iter().enumerate() {
        restore_receipt(&mut encoded["applies"][index], values);
    }
    Ok(encoded)
}

pub(super) fn plan(mut output: ShapePlan) -> MemoryResult<Value> {
    let values = take_plan(&mut output);
    let mut encoded = encode(output)?;
    restore_plan(&mut encoded, values);
    Ok(encoded)
}

pub(super) fn receipt(mut output: ShapeApplyReceipt) -> MemoryResult<Value> {
    let values = take_receipt(&mut output);
    let mut encoded = encode(output)?;
    restore_receipt(&mut encoded, values);
    Ok(encoded)
}

pub(super) fn item(mut output: Option<ShapeItemReceipt>) -> MemoryResult<Value> {
    let values = output
        .as_mut()
        .map(|output| take_item(&mut output.item.item));
    let mut encoded = encode(output)?;
    if let Some(values) = values {
        restore_item(&mut encoded["item"]["item"], values);
    }
    Ok(encoded)
}

pub(super) fn card(mut output: ShapePlanCardView) -> MemoryResult<Value> {
    let values = take_plan(&mut output.plan);
    let mut encoded = encode(output)?;
    restore_plan(&mut encoded["plan"], values);
    Ok(encoded)
}

pub(super) fn groups(mut output: Vec<ShapeInboxGroup>) -> MemoryResult<Value> {
    let values: Vec<Vec<ItemJson>> = output
        .iter_mut()
        .map(|group| {
            group
                .members
                .iter_mut()
                .map(|member| take_item(&mut member.item))
                .collect()
        })
        .collect();
    let mut encoded = encode(output)?;
    for (group_index, members) in values.into_iter().enumerate() {
        for (member_index, values) in members.into_iter().enumerate() {
            restore_item(
                &mut encoded[group_index]["members"][member_index]["item"],
                values,
            );
        }
    }
    Ok(encoded)
}

fn take_plan(output: &mut ShapePlan) -> PlanJson {
    PlanJson {
        seed: take_rows(&mut output.seed.rows),
        items: output.items.iter_mut().map(take_item).collect(),
        undeclared: take_rows(&mut output.undeclared),
    }
}

fn restore_plan(encoded: &mut Value, values: PlanJson) {
    restore_rows(&mut encoded["seed"]["rows"], values.seed);
    for (index, values) in values.items.into_iter().enumerate() {
        restore_item(&mut encoded["items"][index], values);
    }
    restore_rows(&mut encoded["undeclared"], values.undeclared);
}

fn take_receipt(output: &mut ShapeApplyReceipt) -> Vec<ItemJson> {
    output
        .items
        .iter_mut()
        .map(|entry| take_item(&mut entry.item))
        .collect()
}

fn restore_receipt(encoded: &mut Value, values: Vec<ItemJson>) {
    for (index, values) in values.into_iter().enumerate() {
        restore_item(&mut encoded["items"][index]["item"], values);
    }
}

fn take_item(item: &mut ShapePlanItem) -> ItemJson {
    (
        item.before.as_mut().and_then(take_row),
        item.after.as_mut().and_then(take_row),
    )
}

fn restore_item(encoded: &mut Value, (before, after): ItemJson) {
    restore_row(&mut encoded["before"], before);
    restore_row(&mut encoded["after"], after);
}

fn take_rows(rows: &mut [ShapeRow]) -> Vec<Option<Value>> {
    rows.iter_mut().map(take_row).collect()
}

fn restore_rows(encoded: &mut Value, values: Vec<Option<Value>>) {
    for (index, value) in values.into_iter().enumerate() {
        restore_row(&mut encoded[index], value);
    }
}

fn take_row(row: &mut ShapeRow) -> Option<Value> {
    match row {
        ShapeRow::Manifest { json, .. } => json.as_mut().map(Value::take),
        _ => None,
    }
}

fn restore_row(encoded: &mut Value, value: Option<Value>) {
    if let Some(value) = value {
        encoded["json"] = value;
    }
}
