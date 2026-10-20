//! A chart frame's chart in the body's `charts` root, keyed by the frame's
//! identity (ARCH-0077: "Ordered category and series ids over one dataset;
//! caches and workbooks are projections"). Its frame's `payload` holds only
//! [`MARK`]. Each entry holds the chart's `family`, `categories` and
//! `source`, one value each; `order`, a movable list of series identities;
//! and `series`, a map from series identity to that series' `name`,
//! `values`, `family` and `x`, one value each. Every value is written only
//! where it changed, so concurrent writers' series inserts, deletes and
//! moves, writes of other series, and writes of other fields of one series
//! all join. A series the order no longer lists is not part of the chart;
//! its fields stay where they were, so a concurrent write to one of them
//! never brings it back. The joined chart is read as it stands: how its
//! export draws it is derived when it is drawn, never written back by a
//! reader.

use super::{child_list, child_map, invalid, json, keys, loro, node_id, order, put_json};
use crate::error::Result;
use loro::LoroMap;
use oneiron_docedit::live::{ChartSeries, LiveDeck, NodeId, NodePayload};
use std::collections::BTreeSet;

/// A chart frame's `payload` value: its chart is the `charts` entry.
pub(super) const MARK: &str = "chart";
const FAMILY: &str = "family";
const CATEGORIES: &str = "categories";
const SOURCE: &str = "source";
const ORDER: &str = "order";
const SERIES: &str = "series";
const NAME: &str = "name";
const VALUES: &str = "values";
const X: &str = "x";

/// The chart `charts` holds for the frame `id`. A series listed twice is
/// held once, at its first place.
pub(super) fn read(charts: &LoroMap, id: NodeId) -> Result<NodePayload> {
    let entry = child_map(charts, &key(id)).ok_or_else(|| invalid("deck chart body"))?;
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
            series.push(ChartSeries {
                id: Some(line),
                name: json(&map, NAME)?,
                values: json(&map, VALUES)?,
                family: json(&map, FAMILY)?,
                x: json(&map, X)?,
            });
        }
    }
    Ok(NodePayload::Chart {
        family: json(&entry, FAMILY)?,
        categories: json(&entry, CATEGORIES)?,
        series,
        source: json(&entry, SOURCE)?,
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
/// its series order placed ([`order::sync`]), and each series' fields where
/// they changed. A series the chart no longer holds leaves the order only.
fn sync_chart(entry: &LoroMap, chart: &NodePayload) -> Result<()> {
    let NodePayload::Chart {
        family,
        categories,
        series,
        source,
    } = chart
    else {
        return Ok(());
    };
    put_json(entry, FAMILY, family)?;
    put_json(entry, CATEGORIES, categories)?;
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
        put_json(&map, VALUES, &line.values)?;
        put_json(&map, FAMILY, &line.family)?;
        put_json(&map, X, &line.x)?;
    }
    Ok(())
}

fn key(id: NodeId) -> String {
    id.0.to_string()
}
