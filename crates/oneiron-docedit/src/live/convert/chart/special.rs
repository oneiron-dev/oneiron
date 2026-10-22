//! A chart's stock, surface and of-pie settlement (OF-510, FIX 3493 D9c):
//! each stock plot's prices bound to its series by identity, a series no
//! price takes drawn as a line on the stock plot's axes (Engine ruling
//! 10-22: nothing dropped, no count refused, a price no series draws left
//! empty on a receipt); surface series aligned on one category set by point
//! identity, a height a series lacks missing; an of-pie plot's custom split
//! kept to the points its first series still draws.

use crate::live::conversion::Conversion;
use crate::live::pptx::{
    ChartCategories, ChartCategory, ChartKind, ChartPlot, ChartSeries, NodeId, StockRoles,
    effective_categories, surface,
};
use crate::live::reshape::PlotTarget;
use std::collections::BTreeSet;

/// Each stock plot's prices as settlement binds them, the nth stock plot
/// by itself, and the series (by place in the written chart) no price
/// takes, to draw as lines.
pub(super) struct Stock {
    roles: Vec<(u32, StockRoles)>,
    pub(super) moved: Vec<usize>,
}

impl Stock {
    /// Where the series `id` stands among its stock plot's prices; 0 for
    /// any other series.
    pub(super) fn rank(&self, id: Option<NodeId>) -> usize {
        self.roles
            .iter()
            .find_map(|(_, roles)| roles.rank(id))
            .unwrap_or(0)
    }

    /// The settled plots with each stock plot's prices: a stock plot that
    /// holds no settings gets them.
    pub(super) fn apply(&self, settings: &mut Vec<ChartPlot>) {
        for &(nth, roles) in &self.roles {
            match settings
                .iter_mut()
                .find(|plot| plot.is(ChartKind::Stock, nth))
            {
                Some(plot) => plot.stock = Some(roles),
                None => {
                    let mut plot = ChartPlot::new(ChartKind::Stock, nth);
                    plot.stock = Some(roles);
                    settings.push(plot);
                }
            }
        }
    }
}

/// Bind each stock plot's prices (`targets`, the plots the chart takes;
/// `assign`, the plot each of `series` is drawn in): a price keeps its
/// series while that series is drawn in its plot, and a price no series
/// takes is filled by the plot's next series no price takes, in series
/// order. A plot that names no order takes one by its series count. A
/// series left over goes to a line plot (`moved`); a price left empty is
/// named on a receipt when it was not already empty (`held`, the plots as
/// the chart held them).
pub(super) fn stock(
    wanted: &[ChartPlot],
    held: &[ChartPlot],
    series: &[ChartSeries],
    (targets, assign): (&[PlotTarget], &[usize]),
    done: &mut Vec<Conversion>,
) -> Stock {
    let mut out = Stock {
        roles: Vec::new(),
        moved: Vec::new(),
    };
    let mut bound: BTreeSet<NodeId> = BTreeSet::new();
    let stocks = targets
        .iter()
        .enumerate()
        .filter(|(_, target)| target.kind == ChartKind::Stock)
        .map(|(at, _)| at);
    for (nth, at) in stocks.enumerate() {
        let nth = u32::try_from(nth).unwrap_or(u32::MAX);
        let members: Vec<usize> = (0..series.len())
            .filter(|&index| assign.get(index) == Some(&at))
            .collect();
        let ids: BTreeSet<NodeId> = members
            .iter()
            .filter_map(|&index| series[index].id)
            .collect();
        let had = |plots: &[ChartPlot]| {
            plots
                .iter()
                .find(|plot| plot.is(ChartKind::Stock, nth))
                .and_then(|plot| plot.stock)
        };
        let mut roles =
            had(wanted).unwrap_or_else(|| StockRoles::empty(StockRoles::order_for(members.len())));
        for slot in roles.slots_mut() {
            if slot.is_some_and(|id| !ids.contains(&id) || !bound.insert(id)) {
                *slot = None;
            }
        }
        let free: Vec<usize> = members
            .iter()
            .copied()
            .filter(|&index| series[index].id.is_some() && roles.rank(series[index].id).is_none())
            .collect();
        let mut free = free.into_iter();
        for slot in roles.slots_mut() {
            if slot.is_none()
                && let Some(index) = free.next()
            {
                *slot = series[index].id;
                bound.extend(series[index].id);
            }
        }
        out.moved.extend(free);
        let missing = roles.missing();
        if !missing.is_empty() && had(held).is_none_or(|was| was.missing() != missing) {
            done.push(Conversion::StockRolesMissing {
                nth,
                roles: missing,
            });
        }
        out.roles.push((nth, roles));
    }
    if !out.moved.is_empty() {
        done.push(Conversion::StockSeriesToLine {
            series: out
                .moved
                .iter()
                .map(|&index| series[index].name.clone())
                .collect(),
        });
    }
    out
}

/// The surface series of `lines` (each drawn in its `kinds` family)
/// standing on one category set: the ordered union of the sets they draw by
/// point identity (the chart's first, when one draws it, then each one's
/// own in series order; a point of no identity is its own), grown to the
/// longest one drawing its points by index. Each takes its value at each
/// point by identity (one drawing by index, by place), a point it does not
/// draw a missing height. In a chart of surface plots only the set is the
/// chart's; otherwise each surface series holds it, so no other plot's
/// categories change. Nothing when they already draw one set.
pub(super) fn align_surfaces(
    categories: &mut ChartCategories,
    lines: &mut [ChartSeries],
    kinds: &[ChartKind],
    done: &mut Vec<Conversion>,
) {
    let surfaces: Vec<usize> = (0..lines.len())
        .filter(|&index| surface(kinds[index]))
        .collect();
    let Some(&first) = surfaces.first() else {
        return;
    };
    let one = effective_categories(categories, &lines[first]);
    if surfaces
        .iter()
        .all(|&index| effective_categories(categories, &lines[index]) == one)
    {
        return;
    }
    let shared = surfaces
        .iter()
        .any(|&index| lines[index].categories.is_none());
    let sets: Vec<&ChartCategories> = shared
        .then_some(&*categories)
        .into_iter()
        .chain(
            surfaces
                .iter()
                .filter_map(|&index| lines[index].categories.as_ref()),
        )
        .collect();
    let mut seen: BTreeSet<NodeId> = BTreeSet::new();
    let mut points: Vec<ChartCategory> = Vec::new();
    for set in sets {
        for point in &set.points {
            match point.id {
                Some(id) if !seen.insert(id) => {}
                _ => points.push(point.clone()),
            }
        }
    }
    let mut union = ChartCategories {
        level_count: 1,
        points,
    };
    union.settle_depth();
    let by_index = surfaces
        .iter()
        .filter(|&&index| effective_categories(categories, &lines[index]).is_empty())
        .map(|&index| lines[index].values.len())
        .max()
        .unwrap_or(0);
    union.pad(by_index);
    let heights: Vec<Vec<Option<serde_json::Number>>> = surfaces
        .iter()
        .map(|&index| {
            let line = &lines[index];
            let set = effective_categories(categories, line);
            (0..union.len())
                .map(|at| {
                    let place = if set.is_empty() {
                        Some(at)
                    } else {
                        union.points[at].id.and_then(|id| set.position(id))
                    };
                    place.and_then(|place| line.values.get(place).cloned().flatten())
                })
                .collect()
        })
        .collect();
    let only = kinds.iter().all(|kind| surface(*kind));
    done.push(Conversion::SurfaceAligned { count: union.len() });
    for (&index, values) in surfaces.iter().zip(heights) {
        lines[index].values = values;
        lines[index].categories = (!only).then(|| union.clone());
    }
    if only {
        *categories = union;
    }
}

/// Each of-pie plot's custom split kept to the points the set its first
/// series draws still holds (`line_targets`, the plot each of `lines` is
/// drawn in, among `targets`); the points it drops are named on a receipt.
pub(super) fn settle_splits(
    settings: &mut [ChartPlot],
    categories: &ChartCategories,
    lines: &[ChartSeries],
    (targets, line_targets): (&[PlotTarget], &[usize]),
    done: &mut Vec<Conversion>,
) {
    let of_pies: Vec<usize> = targets
        .iter()
        .enumerate()
        .filter(|(_, target)| target.kind == ChartKind::OfPie)
        .map(|(at, _)| at)
        .collect();
    for plot in settings
        .iter_mut()
        .filter(|plot| plot.family == ChartKind::OfPie)
    {
        let Some(split) = &mut plot.custom_split else {
            continue;
        };
        let first = usize::try_from(plot.nth)
            .ok()
            .and_then(|nth| of_pies.get(nth))
            .and_then(|&target| line_targets.iter().position(|&at| at == target));
        let ids: BTreeSet<NodeId> = first
            .map(|at| effective_categories(categories, &lines[at]).ids())
            .into_iter()
            .flatten()
            .collect();
        let before = split.len();
        let mut seen = BTreeSet::new();
        split.retain(|id| ids.contains(id) && seen.insert(*id));
        if split.len() < before {
            done.push(Conversion::SplitPointsDropped {
                nth: plot.nth,
                count: before - split.len(),
            });
        }
    }
}
