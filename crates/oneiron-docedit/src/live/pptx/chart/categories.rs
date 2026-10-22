//! A chart's categories (ARCH-0077 :597, "Chart categories and series |
//! Ordered ids over one canonical dataset. Caches and embedded workbooks
//! are projections, not independently editable lists."): an ordered list
//! of category points, each a stable identity with its label at every
//! level, leaf (innermost) level first as `c:lvl` orders them. The chart
//! holds one set its category series share; a series may hold its own,
//! which it draws instead (`Some` of an empty set draws its points by
//! index). Equal labels never make two points one: a point is its
//! identity, never its label, its native `c:pt` index, its workbook cell or
//! its place. A category series holds one value per point of the set it
//! draws ([`effective_categories`]), so a point that moves takes its values
//! with it.

use super::{ChartKind, ChartSeries, Conflict, SeriesField};
use crate::live::pptx::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// One category point: its identity, and its label at each level, leaf
/// first. `None` is a level holding no label at this point (a group label
/// stated once for the points under it, or an absent cache point), never
/// the same as an empty label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChartCategory {
    /// Its identity within its set. A point written with none, as a new
    /// one is, is named by its writer before the write is logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<NodeId>,
    #[serde(default)]
    pub levels: Vec<Option<String>>,
}

/// An ordered set of category points: one level is a flat list, more a
/// hierarchy (`c:multiLvlStrRef`), each point holding `level_count` labels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChartCategories {
    /// How many levels each point holds, kept for a set of no points too.
    #[serde(default = "one_level")]
    pub level_count: u32,
    #[serde(default)]
    pub points: Vec<ChartCategory>,
}

fn one_level() -> u32 {
    1
}

impl Default for ChartCategories {
    fn default() -> Self {
        Self {
            level_count: 1,
            points: Vec::new(),
        }
    }
}

/// The part of one category point both sides of a fork wrote differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CategoryField {
    /// Its labels.
    Levels,
    /// Both sides moved it, to different places.
    Order,
    /// One side deleted it and the other wrote it.
    Existence,
}

impl ChartCategories {
    /// A flat set of new points, one per label.
    pub fn flat<S: Into<String>>(labels: impl IntoIterator<Item = S>) -> Self {
        Self {
            level_count: 1,
            points: labels
                .into_iter()
                .map(|label| ChartCategory {
                    id: None,
                    levels: vec![Some(label.into())],
                })
                .collect(),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.points.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    /// How many levels the set holds: at least one, and at least as many
    /// as its deepest point.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.points
            .iter()
            .map(|point| point.levels.len())
            .chain([usize::try_from(self.level_count).unwrap_or(usize::MAX), 1])
            .max()
            .unwrap_or(1)
    }

    /// Each point's leaf label; a point with none reads as empty text.
    #[must_use]
    pub fn labels(&self) -> Vec<String> {
        self.level(0)
            .map(|label| label.unwrap_or_default().to_owned())
            .collect()
    }

    /// One level's labels, point by point; `None` where a point holds none.
    pub(crate) fn level(&self, level: usize) -> impl Iterator<Item = Option<&str>> + '_ {
        self.points
            .iter()
            .map(move |point| point.levels.get(level).and_then(|label| label.as_deref()))
    }

    /// Whether both sets hold the same labels at every level, point by
    /// point, whatever their identities; a missing label reads as empty
    /// text, as a cache draws both.
    #[must_use]
    pub fn same_labels(&self, other: &Self) -> bool {
        let depth = self.depth().max(other.depth());
        self.len() == other.len()
            && (0..depth).all(|level| {
                self.level(level)
                    .map(Option::unwrap_or_default)
                    .eq(other.level(level).map(Option::unwrap_or_default))
            })
    }

    /// The identities its points hold, in order.
    pub(crate) fn ids(&self) -> Vec<NodeId> {
        self.points.iter().filter_map(|point| point.id).collect()
    }

    /// Where the point `id` sits.
    pub(crate) fn position(&self, id: NodeId) -> Option<usize> {
        self.points.iter().position(|point| point.id == Some(id))
    }

    /// The set as it is held: its depth recorded and every point holding
    /// that many levels.
    pub(crate) fn settle_depth(&mut self) {
        let depth = self.depth();
        self.level_count = u32::try_from(depth).unwrap_or(u32::MAX);
        for point in &mut self.points {
            point.levels.resize(depth, None);
        }
    }

    /// The set grown to `count` points with new points that hold no label
    /// and no identity yet (its writer names them); `true` when it grew.
    pub(crate) fn pad(&mut self, count: usize) -> bool {
        if self.points.len() >= count {
            return false;
        }
        let depth = self.depth();
        self.points.resize(
            count,
            ChartCategory {
                id: None,
                levels: vec![None; depth],
            },
        );
        true
    }

    /// Name, from `mint` and in order, each point that names no identity or
    /// one an earlier point names.
    pub(crate) fn name(&mut self, mint: &mut impl FnMut() -> NodeId) {
        let mut seen = BTreeSet::new();
        for point in &mut self.points {
            match point.id {
                Some(id) if seen.insert(id) => {}
                _ => {
                    let id = mint();
                    seen.insert(id);
                    point.id = Some(id);
                }
            }
        }
    }

    /// How many identities [`Self::name`] mints.
    pub(crate) fn unnamed(&self) -> u64 {
        let mut seen = BTreeSet::new();
        let unnamed = self
            .points
            .iter()
            .filter(|point| !point.id.is_some_and(|id| seen.insert(id)))
            .count();
        u64::try_from(unnamed).unwrap_or(u64::MAX)
    }
}

/// The categories `series` draws: its own when it holds a set, else the
/// chart's. The one resolver every check, settlement, draw, comparison,
/// layout and export reads.
#[must_use]
pub fn effective_categories<'a>(
    chart: &'a ChartCategories,
    series: &'a ChartSeries,
) -> &'a ChartCategories {
    series.categories.as_ref().unwrap_or(chart)
}

/// Whether `series`, in a chart of `family`, draws categories: every series
/// but a scatter or bubble series, which draws x values.
pub(crate) fn draws_categories(family: ChartKind, series: &ChartSeries) -> bool {
    !series.family.unwrap_or(family).draws_x()
}

/// The chart as its export draws it after concurrent writers joined: each
/// set grown with points of no label to the longest category series that
/// draws it, each such series' values ending in missing points up to its
/// set, and no x values on a category series. It names nothing: points a
/// draw adds are no identity's.
pub(super) fn drawn(family: ChartKind, chart: &mut ChartCategories, series: &mut [ChartSeries]) {
    let longest = series
        .iter()
        .filter(|line| draws_categories(family, line) && line.categories.is_none())
        .map(|line| line.values.len())
        .max()
        .unwrap_or(0);
    if !chart.is_empty() {
        chart.pad(longest);
    }
    for line in series.iter_mut() {
        if !draws_categories(family, line) {
            continue;
        }
        line.x = None;
        if let Some(own) = &mut line.categories
            && !own.is_empty()
        {
            own.pad(line.values.len());
        }
        let count = effective_categories(chart, line).len();
        if count > line.values.len() {
            line.values.resize(count, None);
        }
    }
}

/// Each category series' values by its points' identities; `None` for a
/// series that draws none (by index, or a scatter series).
fn keyed(
    family: ChartKind,
    chart: &ChartCategories,
    line: &ChartSeries,
) -> Option<BTreeMap<NodeId, Option<serde_json::Number>>> {
    let set = effective_categories(chart, line);
    if !draws_categories(family, line) || set.is_empty() {
        return None;
    }
    Some(
        set.points
            .iter()
            .enumerate()
            .filter_map(|(at, point)| Some((point.id?, line.values.get(at).cloned().flatten())))
            .collect(),
    )
}

/// One chart series as both sides of a fork wrote it, against its base.
pub(super) struct Sides<'a> {
    pub(super) family: [ChartKind; 3],
    pub(super) chart: [&'a ChartCategories; 3],
    pub(super) line: [&'a ChartSeries; 3],
}

/// Whether both sides wrote one series' values differently: point by point
/// through their identities where every side draws them by identity (a
/// moved point keeps its value), else as one list.
pub(super) fn values_compete(sides: &Sides<'_>) -> bool {
    let keyed: Vec<_> = (0..3)
        .map(|at| keyed(sides.family[at], sides.chart[at], sides.line[at]))
        .collect();
    match (&keyed[0], &keyed[1], &keyed[2]) {
        (Some(base), Some(head), Some(proposal)) => base
            .keys()
            .chain(head.keys())
            .chain(proposal.keys())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .any(|id| competing(&base.get(id), &head.get(id), &proposal.get(id))),
        _ => competing(
            &sides.line[0].values,
            &sides.line[1].values,
            &sides.line[2].values,
        ),
    }
}

/// The conflicts of one category set both sides wrote, `owner` naming it
/// (`None` the chart's, else the series that holds it): one point's labels
/// both sides wrote differently, one point both sides moved to different
/// places (among the points all three hold), or one point one side deleted
/// and the other wrote; and its depth both sides set differently, named by
/// `whole`. Points only one side inserted, deleted, moved or wrote join.
pub(super) fn set_conflicts(
    node: NodeId,
    owner: Option<NodeId>,
    [base, head, proposal]: [&ChartCategories; 3],
    whole: Conflict,
    out: &mut Vec<Conflict>,
) {
    if competing(&base.level_count, &head.level_count, &proposal.level_count) {
        out.push(whole);
    }
    let find = |set: &ChartCategories, id: NodeId| -> Option<Vec<Option<String>>> {
        set.position(id).map(|at| set.points[at].levels.clone())
    };
    let (in_head, in_proposal): (BTreeSet<NodeId>, BTreeSet<NodeId>) = (
        head.ids().into_iter().collect(),
        proposal.ids().into_iter().collect(),
    );
    let before = |set: &ChartCategories, id: NodeId| -> Option<NodeId> {
        set.ids()
            .into_iter()
            .filter(|other| in_head.contains(other) && in_proposal.contains(other))
            .take_while(|other| *other != id)
            .last()
    };
    for id in base.ids() {
        let category = |field| Conflict::CategoryVsCategory {
            node,
            owner,
            category: id,
            field,
        };
        let was = find(base, id);
        match (find(head, id), find(proposal, id)) {
            (Some(head_levels), Some(proposal_levels)) => {
                if competing(&was, &Some(head_levels), &Some(proposal_levels)) {
                    out.push(category(CategoryField::Levels));
                }
                if competing(&before(base, id), &before(head, id), &before(proposal, id)) {
                    out.push(category(CategoryField::Order));
                }
            }
            (None, Some(written)) | (Some(written), None) if Some(&written) != was.as_ref() => {
                out.push(category(CategoryField::Existence));
            }
            _ => {}
        }
    }
}

/// The category conflicts of one series both sides wrote: its own set's
/// points where every side holds one, else its draw both sides set
/// differently (its own set or the chart's, [`SeriesField::Categories`]).
pub(super) fn series_conflicts(
    node: NodeId,
    id: NodeId,
    sides: &Sides<'_>,
    out: &mut Vec<Conflict>,
) {
    let own = sides.line.map(|line| line.categories.as_ref());
    let whole = Conflict::SeriesVsSeries {
        node,
        series: id,
        field: SeriesField::Categories,
    };
    match own {
        [Some(base), Some(head), Some(proposal)] => {
            set_conflicts(node, Some(id), [base, head, proposal], whole, out);
        }
        [base, head, proposal] => {
            if competing(&base, &head, &proposal) {
                out.push(whole);
            }
        }
    }
}

/// Whether both sides wrote one value differently.
pub(super) fn competing<T: PartialEq>(base: &T, head: &T, proposal: &T) -> bool {
    base != head && base != proposal && head != proposal
}
