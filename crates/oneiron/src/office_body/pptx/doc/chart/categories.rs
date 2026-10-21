//! A chart's category sets in the body's `charts` root (ARCH-0077 :597,
//! "Chart categories and series | Ordered ids over one canonical dataset";
//! FIX 3493): a set is a map of its depth (`levels`), `order`, a movable
//! list of category point identities, and `points`, each point's labels by
//! its identity, one value each, written only where it changed. A category
//! series' values are held by point identity (`cells`), so a point moved
//! never gives a value another label, and concurrent writers' inserts,
//! deletes, moves and relabels of different points, and their values, join.
//! A point the order no longer lists is not part of its set; its fields
//! stay, as a removed series' do.

use super::super::{child_list, child_map, invalid, json, loro, node_id, order, put_json, string};
use crate::error::Result;
use loro::LoroMap;
use oneiron_docedit::live::{ChartCategories, ChartCategory, NodeId};
use serde::de::DeserializeOwned;
use std::collections::BTreeSet;

const LEVELS: &str = "levels";
const ORDER: &str = "order";
const POINTS: &str = "points";

pub(super) fn key(id: NodeId) -> String {
    id.0.to_string()
}

/// A JSON-encoded value written only by this schema's writers; absent
/// reads as `default`.
pub(super) fn json_or<T: DeserializeOwned>(map: &LoroMap, key: &str, default: T) -> Result<T> {
    match string(map, key) {
        None => Ok(default),
        Some(_) => json(map, key),
    }
}

/// The category set `map` holds. A point listed twice is held once, at its
/// first place.
pub(super) fn read(map: &LoroMap) -> Result<ChartCategories> {
    let level_count = json_or(map, LEVELS, 1_u32)?;
    let mut points = Vec::new();
    if let Some(list) = child_list(map, ORDER) {
        let labels = child_map(map, POINTS);
        let mut seen = BTreeSet::new();
        for held in order::ids(&list)? {
            let id = node_id(&held)?;
            if !seen.insert(id) {
                continue;
            }
            let levels = labels
                .as_ref()
                .map(|labels| json(labels, &held))
                .transpose()?
                .ok_or_else(|| invalid("deck chart category"))?;
            points.push(ChartCategory {
                id: Some(id),
                levels,
            });
        }
    }
    Ok(ChartCategories {
        level_count,
        points,
    })
}

/// Make `map` hold `set` with the fewest writes: its depth where it
/// changed, its order placed ([`order::sync`]), and each point's labels
/// where they changed.
pub(super) fn sync(map: &LoroMap, set: &ChartCategories) -> Result<()> {
    put_json(map, LEVELS, &set.level_count)?;
    let ids: Vec<String> = set
        .points
        .iter()
        .map(|point| {
            point
                .id
                .map(key)
                .ok_or_else(|| invalid("a deck chart category has no identity"))
        })
        .collect::<Result<_>>()?;
    order::sync(
        &map.ensure_mergeable_movable_list(ORDER).map_err(loro)?,
        &ids,
    )?;
    let labels = map.ensure_mergeable_map(POINTS).map_err(loro)?;
    for (point, held) in set.points.iter().zip(&ids) {
        put_json(&labels, held, &point.levels)?;
    }
    Ok(())
}

/// A category series' values held by its set's point identities, read in
/// the set's order: a point with no value held reads as a missing one.
pub(super) fn read_values(
    cells: Option<&LoroMap>,
    set: &ChartCategories,
) -> Result<Vec<Option<serde_json::Number>>> {
    set.points
        .iter()
        .map(|point| match (cells, point.id) {
            (Some(cells), Some(id)) => json_or(cells, &key(id), None),
            _ => Ok(None),
        })
        .collect()
}

/// Write a category series' values by its set's point identities, each
/// only where it changed.
pub(super) fn sync_values(
    cells: &LoroMap,
    set: &ChartCategories,
    values: &[Option<serde_json::Number>],
) -> Result<()> {
    for (at, point) in set.points.iter().enumerate() {
        let id = point
            .id
            .ok_or_else(|| invalid("a deck chart category has no identity"))?;
        put_json(cells, &key(id), &values.get(at).cloned().flatten())?;
    }
    Ok(())
}
