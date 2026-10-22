//! A chart frame's chart in the body's `charts` root, keyed by the frame's
//! identity (ARCH-0077: "Ordered category and series ids over one dataset;
//! caches and workbooks are projections"). Its frame's `payload` holds only
//! [`MARK`]. Each entry holds the chart's `family`, `source`, `plots` (each
//! plot's settings) and `view` (its 3D view), one value each;
//! `category_set`, its categories by point identity ([`categories`]);
//! `order`, a movable list of series identities; and `series`, a map from
//! series identity to that series' `name`, `family`, `x`, `size` (a bubble
//! series' sizes) and `bubble_3d`, one value each, whether it draws a set
//! of its own (`local`, its own set under `category_set`, kept while it
//! draws the chart's), and its values: by category point identity
//! (`cells`) for a series that draws categories, else one list (`values`).
//! Every value is written only where it changed, so concurrent writers'
//! series and category inserts, deletes and moves, writes of other series,
//! points or values, and writes of other fields of one series all join. A
//! series the order no longer lists is not part of the chart; its fields
//! stay where they were, so a concurrent write to one of them never brings
//! it back. The joined chart is read as it stands: how its export draws it
//! is derived when it is drawn, never written back by a reader.

mod categories;

use super::{child_list, child_map, invalid, json, keys, loro, node_id, order, put_json};
use crate::error::Result;
use categories::{json_or, key};
use loro::LoroMap;
use oneiron_docedit::live::{
    ChartKind, ChartSeries, LiveDeck, NodeId, NodePayload, effective_categories,
};
use std::collections::BTreeSet;

/// A chart frame's `payload` value: its chart is the `charts` entry.
pub(super) const MARK: &str = "chart";
const FAMILY: &str = "family";
const CATEGORY_SET: &str = "category_set";
const SOURCE: &str = "source";
const ORDER: &str = "order";
const SERIES: &str = "series";
const NAME: &str = "name";
const VALUES: &str = "values";
const CELLS: &str = "cells";
const LOCAL: &str = "local";
const X: &str = "x";
const SIZE: &str = "size";
const BUBBLE_3D: &str = "bubble_3d";
const PLOTS: &str = "plots";
const VIEW: &str = "view";

/// Whether a series of a chart of `family` draws categories: a scatter or
/// bubble series draws x values.
fn draws(family: ChartKind, line: &ChartSeries) -> bool {
    !line.family.unwrap_or(family).draws_x()
}

/// The chart `charts` holds for the frame `id`. A series listed twice is
/// held once, at its first place.
pub(super) fn read(charts: &LoroMap, id: NodeId) -> Result<NodePayload> {
    let entry = child_map(charts, &key(id)).ok_or_else(|| invalid("deck chart body"))?;
    let family: ChartKind = json(&entry, FAMILY)?;
    let chart_set = match child_map(&entry, CATEGORY_SET) {
        Some(map) => categories::read(&map)?,
        None => Default::default(),
    };
    let fields = child_map(&entry, SERIES);
    let mut seen = BTreeSet::new();
    let mut series = Vec::new();
    if let Some(list) = child_list(&entry, ORDER) {
        for held in order::ids(&list)? {
            let line = node_id(&held)?;
            if !seen.insert(line) {
                continue;
            }
            let map = fields
                .as_ref()
                .and_then(|fields| child_map(fields, &held))
                .ok_or_else(|| invalid("deck chart series"))?;
            let own = if json_or(&map, LOCAL, false)? {
                Some(match child_map(&map, CATEGORY_SET) {
                    Some(set) => categories::read(&set)?,
                    None => Default::default(),
                })
            } else {
                None
            };
            let line_family: Option<ChartKind> = json(&map, FAMILY)?;
            let set = own.as_ref().unwrap_or(&chart_set);
            let values = if !line_family.unwrap_or(family).draws_x() && !set.is_empty() {
                categories::read_values(child_map(&map, CELLS).as_ref(), set)?
            } else {
                json_or(&map, VALUES, Vec::new())?
            };
            series.push(ChartSeries {
                id: Some(line),
                name: json(&map, NAME)?,
                values,
                family: line_family,
                x: json(&map, X)?,
                categories: own,
                bubble_size: json_or(&map, SIZE, None)?,
                bubble_3d: json_or(&map, BUBBLE_3D, None)?,
            });
        }
    }
    Ok(NodePayload::Chart {
        family,
        categories: chart_set,
        series,
        source: json(&entry, SOURCE)?,
        plots: json_or(&entry, PLOTS, Vec::new())?,
        view: json_or(&entry, VIEW, None)?,
    })
}

/// Make `charts` hold `target`'s charts: an entry whose frame is gone or
/// holds no chart any more is deleted, and each chart is written unit by
/// unit ([`sync_chart`]).
pub(super) fn sync(charts: &LoroMap, target: &LiveDeck) -> Result<()> {
    for held in keys(charts) {
        if node_id(&held).map_or(true, |id| chart_of(target, id).is_none()) {
            charts.delete(&held).map_err(loro)?;
        }
    }
    for id in target.nodes.keys() {
        if let Some(chart) = chart_of(target, *id) {
            sync_chart(
                &charts.ensure_mergeable_map(&key(*id)).map_err(loro)?,
                chart,
            )?;
        }
    }
    Ok(())
}

/// The chart the node `id` holds.
fn chart_of(deck: &LiveDeck, id: NodeId) -> Option<&NodePayload> {
    deck.nodes
        .get(&id)?
        .payload
        .as_ref()
        .filter(|payload| matches!(payload, NodePayload::Chart { .. }))
}

/// One chart with the fewest writes: its chart fields where they changed,
/// its categories by point identity, its series order placed
/// ([`order::sync`]), and each series' fields, own categories and values
/// where they changed. A series the chart no longer holds leaves the order
/// only.
fn sync_chart(entry: &LoroMap, chart: &NodePayload) -> Result<()> {
    let NodePayload::Chart {
        family,
        categories: chart_set,
        series,
        source,
        plots,
        view,
    } = chart
    else {
        return Ok(());
    };
    put_json(entry, FAMILY, family)?;
    put_json(entry, PLOTS, plots)?;
    put_json(entry, VIEW, view)?;
    categories::sync(
        &entry.ensure_mergeable_map(CATEGORY_SET).map_err(loro)?,
        chart_set,
    )?;
    put_json(entry, SOURCE, source)?;
    let ids: Vec<String> = series
        .iter()
        .map(|line| {
            line.id
                .map(key)
                .ok_or_else(|| invalid("a deck chart series has no identity"))
        })
        .collect::<Result<_>>()?;
    order::sync(
        &entry.ensure_mergeable_movable_list(ORDER).map_err(loro)?,
        &ids,
    )?;
    let fields = entry.ensure_mergeable_map(SERIES).map_err(loro)?;
    for (line, held) in series.iter().zip(&ids) {
        let map = fields.ensure_mergeable_map(held).map_err(loro)?;
        put_json(&map, NAME, &line.name)?;
        put_json(&map, FAMILY, &line.family)?;
        put_json(&map, X, &line.x)?;
        put_json(&map, SIZE, &line.bubble_size)?;
        put_json(&map, BUBBLE_3D, &line.bubble_3d)?;
        put_json(&map, LOCAL, &line.categories.is_some())?;
        if let Some(own) = &line.categories {
            categories::sync(&map.ensure_mergeable_map(CATEGORY_SET).map_err(loro)?, own)?;
        }
        let set = effective_categories(chart_set, line);
        if draws(*family, line) && !set.is_empty() {
            categories::sync_values(
                &map.ensure_mergeable_map(CELLS).map_err(loro)?,
                set,
                &line.values,
            )?;
        } else {
            put_json(&map, VALUES, &line.values)?;
        }
    }
    Ok(())
}
