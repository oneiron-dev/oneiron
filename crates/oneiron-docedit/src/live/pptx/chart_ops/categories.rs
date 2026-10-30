//! Category edits applied by point identity, a whole set written over the
//! one a chart or series holds lowered to the edits that make it, and the
//! identities a writer gives the points a settlement adds (FIX 3493), a
//! live-born chart's drawn from its node (FIX 9164). A
//! point moved, inserted or deleted takes its value in every series that
//! draws its set with it, so a move never gives a value another label.

use super::super::chart::{
    ChartCategories, ChartCategory, ChartEdit, ChartKind, ChartSeries, draws_categories,
};
use super::super::table_ops::order;
use super::super::{NodeId, NodePayload};
use crate::live::LiveError;
use std::collections::BTreeSet;

const TAKEN: &str = "the category identity is taken";

/// The series, by index, that draw the set `owner` names: the chart's
/// (`None`) is drawn by every category series without its own.
fn drawers(family: ChartKind, series: &[ChartSeries], owner: Option<NodeId>) -> Vec<usize> {
    series
        .iter()
        .enumerate()
        .filter(|(_, line)| {
            draws_categories(family, line)
                && match owner {
                    None => line.categories.is_none(),
                    Some(id) => line.id == Some(id) && line.categories.is_some(),
                }
        })
        .map(|(at, _)| at)
        .collect()
}

/// The set `owner` names: the chart's, or the series `owner`'s own.
fn set_mut<'a>(
    chart: &'a mut ChartCategories,
    series: &'a mut [ChartSeries],
    owner: Option<NodeId>,
) -> Option<&'a mut ChartCategories> {
    match owner {
        None => Some(chart),
        Some(id) => series
            .iter_mut()
            .find(|line| line.id == Some(id))?
            .categories
            .as_mut(),
    }
}

/// The index right after the point `after` names: 0 for none, the end when
/// the set no longer holds it.
fn slot(set: &ChartCategories, after: Option<NodeId>) -> usize {
    match after {
        None => 0,
        Some(after) => set.position(after).map_or(set.len(), |at| at + 1),
    }
}

/// Apply one category edit to a chart's categories and series; any other
/// edit is not one and changes nothing (`Ok(false)`).
pub(super) fn apply(
    edit: &ChartEdit,
    family: ChartKind,
    chart: &mut ChartCategories,
    series: &mut [ChartSeries],
    mint: &mut impl FnMut() -> NodeId,
) -> Result<bool, LiveError> {
    match edit {
        ChartEdit::SetCategories { categories } => {
            let mut set = categories.clone();
            set.name(mint);
            *chart = set;
        }
        ChartEdit::SetSeriesCategories {
            series: id,
            categories,
        } => {
            let mut set = categories.clone();
            if let Some(set) = &mut set {
                set.name(mint);
            }
            if let Some(line) = series.iter_mut().find(|line| line.id == Some(*id)) {
                line.categories = set;
            }
        }
        ChartEdit::InsertCategory {
            owner,
            id,
            after,
            levels,
        } => {
            let id = match id {
                Some(id) => *id,
                None => mint(),
            };
            let drawn = drawers(family, series, *owner);
            let Some(set) = set_mut(chart, series, *owner) else {
                return Ok(true);
            };
            if set.position(id).is_some() {
                return Err(LiveError::Invalid(TAKEN));
            }
            let at = slot(set, *after);
            set.points.insert(
                at,
                ChartCategory {
                    id: Some(id),
                    levels: levels.clone(),
                },
            );
            for index in drawn {
                let values = &mut series[index].values;
                if at <= values.len() {
                    values.insert(at, None);
                }
            }
        }
        ChartEdit::DeleteCategory {
            owner,
            category: id,
        } => {
            let drawn = drawers(family, series, *owner);
            let Some(set) = set_mut(chart, series, *owner) else {
                return Ok(true);
            };
            let Some(at) = set.position(*id) else {
                return Ok(true);
            };
            set.points.remove(at);
            for index in drawn {
                let values = &mut series[index].values;
                if at < values.len() {
                    values.remove(at);
                }
            }
        }
        ChartEdit::MoveCategory {
            owner,
            category: id,
            after,
        } => {
            if *after == Some(*id) {
                return Ok(true);
            }
            let drawn = drawers(family, series, *owner);
            let Some(set) = set_mut(chart, series, *owner) else {
                return Ok(true);
            };
            let Some(from) = set.position(*id) else {
                return Ok(true);
            };
            let count = set.len();
            let point = set.points.remove(from);
            let to = slot(set, *after);
            set.points.insert(to, point);
            for index in drawn {
                let values = &mut series[index].values;
                if values.len() > from.min(to) {
                    if values.len() < count {
                        values.resize(count, None);
                    }
                    let value = values.remove(from);
                    values.insert(to, value);
                }
            }
        }
        ChartEdit::SetCategoryLevels {
            owner,
            category: id,
            levels,
        } => {
            if let Some(set) = set_mut(chart, series, *owner)
                && let Some(at) = set.position(*id)
            {
                set.points[at].levels.clone_from(levels);
            }
        }
        ChartEdit::ReserveCategories { .. } => {}
        _ => return Ok(false),
    }
    Ok(true)
}

/// The edits that make the set `held` (the chart's, or the series `owner`'s
/// own) into `wanted`: the points `wanted` drops deleted, the rest placed in
/// its order (a new one inserted with its labels, a held one moved only
/// where it is out of place), then each held point's labels written where
/// they differ. A point `wanted` names with an identity `held` does not
/// hold, with none, or with one an earlier point names, is new, under a
/// fresh identity from `mint`. A set of another depth is written whole.
pub(super) fn lower_set(
    owner: Option<NodeId>,
    held: &ChartCategories,
    wanted: &ChartCategories,
    mint: &mut impl FnMut() -> NodeId,
) -> Vec<ChartEdit> {
    if held.depth() != wanted.depth() {
        return vec![match owner {
            None => ChartEdit::SetCategories {
                categories: wanted.clone(),
            },
            Some(series) => ChartEdit::SetSeriesCategories {
                series,
                categories: Some(wanted.clone()),
            },
        }];
    }
    let held_ids = held.ids();
    let known: BTreeSet<NodeId> = held_ids.iter().copied().collect();
    let mut seen = BTreeSet::new();
    let points: Vec<ChartCategory> = wanted
        .points
        .iter()
        .map(|point| ChartCategory {
            id: Some(match point.id {
                Some(id) if known.contains(&id) && seen.insert(id) => id,
                _ => mint(),
            }),
            levels: point.levels.clone(),
        })
        .collect();
    let wanted_ids: Vec<NodeId> = points.iter().filter_map(|point| point.id).collect();
    let mut edits = Vec::new();
    order(
        &held_ids,
        &wanted_ids,
        &mut edits,
        |category| ChartEdit::DeleteCategory { owner, category },
        |category, after| ChartEdit::MoveCategory {
            owner,
            category,
            after,
        },
        |id, after| ChartEdit::InsertCategory {
            owner,
            id: Some(id),
            after,
            levels: points
                .iter()
                .find(|point| point.id == Some(id))
                .map_or_else(Vec::new, |point| point.levels.clone()),
        },
    );
    for point in &points {
        let Some(id) = point.id else {
            continue;
        };
        if let Some(at) = held.position(id)
            && held.points[at].levels != point.levels
        {
            edits.push(ChartEdit::SetCategoryLevels {
                owner,
                category: id,
                levels: point.levels.clone(),
            });
        }
    }
    edits
}

impl NodePayload {
    /// Name, from `mint` and in order, each category point a chart's sets
    /// hold with no identity or one an earlier point of its set names: the
    /// chart's set first, then each series' own in series order.
    pub(crate) fn name_categories(&mut self, mint: &mut impl FnMut() -> NodeId) {
        if let Self::Chart {
            categories, series, ..
        } = self
        {
            categories.name(mint);
            for line in series {
                if let Some(own) = &mut line.categories {
                    own.name(mint);
                }
            }
        }
    }

    /// How many identities [`Self::name_categories`] mints.
    pub(crate) fn unnamed_categories(&self) -> u64 {
        let Self::Chart {
            categories, series, ..
        } = self
        else {
            return 0;
        };
        series
            .iter()
            .filter_map(|line| line.categories.as_ref())
            .map(ChartCategories::unnamed)
            .fold(categories.unnamed(), u64::saturating_add)
    }
}

impl NodePayload {
    /// Every category identity a chart's sets name.
    pub(crate) fn category_ids(&self) -> BTreeSet<NodeId> {
        let Self::Chart {
            categories, series, ..
        } = self
        else {
            return BTreeSet::new();
        };
        series
            .iter()
            .filter_map(|line| line.categories.as_ref())
            .chain([categories])
            .flat_map(ChartCategories::ids)
            .collect()
    }
}

/// The identities the settlement of a live-born chart's write (its node's
/// creation, or a payload over no held chart) gives the category points it
/// adds (FIX 9164): each the hash of the chart node `node` and its ordinal,
/// top bit set, past every identity in `taken`, so every replay of the
/// operation, a fork's onto the head and a concurrent writer's alike, makes
/// the same points, and the deck mints only what the operation names
/// ([`super::super::DeckOp::unnamed`]).
pub(crate) fn born_points(node: NodeId, taken: BTreeSet<NodeId>) -> impl FnMut() -> NodeId {
    let mut next = 0_u64;
    move || loop {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron:chart-category:");
        hasher.update(&node.0.to_le_bytes());
        hasher.update(&next.to_le_bytes());
        next += 1;
        let mut word = [0_u8; 8];
        word.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
        let id = NodeId(u64::from_le_bytes(word) | 1 << 63);
        if !taken.contains(&id) {
            return id;
        }
    }
}
