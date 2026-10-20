//! A chart at export: a bound chart's changed data written over its
//! retained chart part, and a live-born chart written through the native
//! writer and its seed rewritten to the chart's own form.

use super::{CHART_EXTENT, Work};
use crate::design_plan::{Cell, Column, ColumnKind, Dataset, Rect};
use crate::edit::xml::next_part;
use crate::live::LiveError;
use crate::live::held;
use crate::live::pptx::{ChartKind, DeckNode, NodeId, NodePayload, WRITTEN_FRAME};
use crate::live::reshape;
use crate::native_patch::{ChartFamily, Frame, NativeEdit, native_patch};
use crate::ooxml::XmlTree;

/// The one sheet of a live-born chart's embedded workbook.
const CHART_SHEET: &str = "Sheet1";

/// Write what a bound chart's data changed over its retained chart part,
/// the frame at `at` in `tree` (`part`'s slide as it reads now): its
/// changed series sequences through the checked chart writer where
/// same-length writes suffice, else the chart rewritten whole.
pub(super) fn project(
    work: &mut Work,
    id: NodeId,
    part: &str,
    (at, tree): (usize, &XmlTree),
    payload: &NodePayload,
) -> Result<(), LiveError> {
    let NodePayload::Chart { source, .. } = payload else {
        return Err(LiveError::Invalid(WRITTEN_FRAME));
    };
    let chart =
        held::chart_part(&work.package, part, tree, at).ok_or(LiveError::Invalid(WRITTEN_FRAME))?;
    let have = held::chart(&work.package, &chart).ok_or(LiveError::Invalid(WRITTEN_FRAME))?;
    // Data that lived outside the chart's own workbook moves into a
    // new one, as PowerPoint's Edit Data embeds it.
    let moved = matches!(&have, NodePayload::Chart { source: from, .. } if from != source);
    if moved || !reshape::same_data(&have, payload) {
        // Same-length writes through the checked chart writer where
        // they suffice; a shape or type change, moved data, a literal
        // sequence or a refused write rewrites the chart whole.
        let in_place = !moved
            && reshape::plan(&work.package, &chart, &have, payload).is_some_and(|writes| {
                writes.iter().all(|(series, target, values)| {
                    native_patch(
                        work.next_mut(),
                        &NativeEdit::SetSeries {
                            chart: &chart,
                            series: *series,
                            target: *target,
                            values: values.as_slice(),
                        },
                    )
                    .map(|report| work.changed.extend(report.changed_parts))
                    .is_ok()
                })
            });
        if !in_place {
            let mut done = Vec::new();
            let changed = reshape::chart(work.next_mut(), &chart, payload, &mut done)?;
            work.changed.extend(changed);
            work.converted(id, done);
        }
    }
    Ok(())
}

/// Write a live-born chart through the native writer as frame `id` at
/// `(x, y)` in `part`, then rewrite its seed to the chart's own family,
/// plots, x values and categories where the seed does not read as it.
pub(super) fn born(
    work: &mut Work,
    node: &DeckNode,
    (part, id): (&str, u32),
    (x, y): (i64, i64),
    payload: &NodePayload,
) -> Result<(), LiveError> {
    let NodePayload::Chart {
        categories, series, ..
    } = payload
    else {
        return Err(LiveError::Invalid(WRITTEN_FRAME));
    };
    let column = |name: &str, kind| Column {
        name: name.to_owned(),
        kind,
        unit: None,
        format: None,
    };
    let dataset = |columns: Vec<Column>, rows: Vec<Vec<Cell>>| Dataset {
        id: String::new(),
        columns,
        rows,
        missing: None,
        sources: Vec::new(),
        merges: Vec::new(),
    };
    // The native writer seeds the chart as a bar, line or pie chart
    // over its own workbook (categories 1 to n when it has none, one
    // empty series when it has none); the chart rewrite then gives it
    // its own family, plots, x values and categories, as PowerPoint
    // inserts a chart of any type.
    let family = match reshape::seed_family(payload) {
        ChartKind::Line => ChartFamily::Line,
        ChartKind::Pie => ChartFamily::Pie,
        _ => ChartFamily::Bar,
    };
    let points = series
        .iter()
        .map(|line| line.values.len().max(line.x.as_ref().map_or(0, Vec::len)))
        .max()
        .unwrap_or(0)
        .max(1);
    let labels: Vec<String> = if categories.is_empty() {
        (1..=points).map(|at| at.to_string()).collect()
    } else {
        categories.clone()
    };
    let mut columns = vec![column("", ColumnKind::Text)];
    if series.is_empty() {
        columns.push(column("", ColumnKind::Number));
    }
    columns.extend(
        series
            .iter()
            .map(|line| column(&line.name, ColumnKind::Number)),
    );
    let rows = labels
        .iter()
        .enumerate()
        .map(|(at, category)| {
            let mut row = vec![Cell::Text(category.clone())];
            if series.is_empty() {
                row.push(Cell::Missing);
            }
            row.extend(series.iter().map(|line| {
                line.values
                    .get(at)
                    .and_then(|value| value.as_ref()?.as_f64())
                    .map_or(Cell::Missing, Cell::Number)
            }));
            row
        })
        .collect();
    let data = dataset(columns, rows);
    let (cx, cy) = node.geometry.extent.unwrap_or(CHART_EXTENT);
    let name = node.name.clone().unwrap_or_else(|| "Chart".to_owned());
    let chart = next_part(&work.package, "ppt/charts/chart", ".xml")?;
    let workbook = next_part(
        &work.package,
        "ppt/embeddings/Microsoft_Excel_Worksheet",
        ".xlsx",
    )?;
    let report = native_patch(
        work.next_mut(),
        &NativeEdit::CreateChart {
            frame: Frame {
                slide: part,
                id,
                name: &name,
                bounds: Rect { x, y, cx, cy },
                placeholder: None,
            },
            family,
            dataset: &data,
            chart: &chart,
            workbook: &workbook,
            sheet: CHART_SHEET,
        },
    )?;
    work.changed.extend(report.changed_parts);
    if held::chart(&work.package, &chart).is_none_or(|read| !reshape::same_data(&read, payload)) {
        let changed = reshape::reseed(work.next_mut(), &chart, payload)?;
        work.changed.extend(changed);
    }
    Ok(())
}
