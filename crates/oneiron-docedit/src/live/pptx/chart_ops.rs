//! Chart edits applied by series identity; a whole chart written over the
//! chart a node holds lowered to the edits that make it, before it is
//! logged; and the series identities a writer names before an edit is
//! logged, so every replay makes the same series.

use super::chart::{ChartEdit, ChartSeries};
use super::table_ops::order;
use super::{LiveDeck, NodeId, NodePayload};
use crate::live::LiveError;
use crate::live::conversion::Conversion;
use std::collections::BTreeSet;

const NO_CHART: &str = "the node holds no chart";
const TAKEN: &str = "the series identity is taken";

impl ChartEdit {
    /// How many identities applying this edit mints: one for an insertion
    /// that names none.
    pub(super) fn unnamed(&self) -> u64 {
        u64::from(matches!(self, Self::InsertSeries { id: None, .. }))
    }

    /// Name an insertion that names no identity, from `mint`.
    pub(super) fn name(&mut self, mint: &mut impl FnMut() -> NodeId) {
        if let Self::InsertSeries { id, .. } = self
            && id.is_none()
        {
            *id = Some(mint());
        }
    }

    /// Apply this edit to `chart`; an insertion that names no identity
    /// takes one from `mint`. An insertion naming an identity the chart
    /// holds refuses: identities are never reused.
    fn apply(
        &self,
        chart: &mut NodePayload,
        mint: &mut impl FnMut() -> NodeId,
    ) -> Result<(), LiveError> {
        let NodePayload::Chart {
            family,
            categories,
            series,
            source,
        } = chart
        else {
            return Err(LiveError::Invalid(NO_CHART));
        };
        match self {
            Self::InsertSeries {
                id,
                after,
                name,
                values,
                family: kind,
                x,
            } => {
                let id = match id {
                    Some(id) => *id,
                    None => mint(),
                };
                if position(series, id).is_some() {
                    return Err(LiveError::Invalid(TAKEN));
                }
                let at = slot(series, *after);
                series.insert(
                    at,
                    ChartSeries {
                        id: Some(id),
                        name: name.clone(),
                        values: values.clone(),
                        family: *kind,
                        x: x.clone(),
                    },
                );
            }
            Self::DeleteSeries { series: id } => series.retain(|line| line.id != Some(*id)),
            Self::MoveSeries { series: id, after } => {
                if *after != Some(*id)
                    && let Some(from) = position(series, *id)
                {
                    let line = series.remove(from);
                    let at = slot(series, *after);
                    series.insert(at, line);
                }
            }
            Self::SetSeriesName { series: id, name } => {
                if let Some(line) = find(series, *id) {
                    line.name.clone_from(name);
                }
            }
            Self::SetSeriesValues { series: id, values } => {
                if let Some(line) = find(series, *id) {
                    line.values.clone_from(values);
                }
            }
            Self::SetSeriesFamily {
                series: id,
                family: kind,
            } => {
                if let Some(line) = find(series, *id) {
                    line.family = *kind;
                }
            }
            Self::SetSeriesX { series: id, x } => {
                if let Some(line) = find(series, *id) {
                    line.x.clone_from(x);
                }
            }
            Self::SetFamily { family: kind } => *family = *kind,
            Self::SetCategories { categories: wanted } => categories.clone_from(wanted),
            Self::SetSource { source: wanted } => *source = *wanted,
        }
        Ok(())
    }
}

/// Where the series `id` sits in a chart's order.
fn position(series: &[ChartSeries], id: NodeId) -> Option<usize> {
    series.iter().position(|line| line.id == Some(id))
}

/// The series `id`, when the chart holds it.
fn find(series: &mut [ChartSeries], id: NodeId) -> Option<&mut ChartSeries> {
    series.iter_mut().find(|line| line.id == Some(id))
}

/// The index right after the series `after` names: 0 for none, the end
/// when the chart no longer holds it.
fn slot(series: &[ChartSeries], after: Option<NodeId>) -> usize {
    match after {
        None => 0,
        Some(after) => position(series, after).map_or(series.len(), |at| at + 1),
    }
}

/// Apply `edits` to the chart `node` holds, then settle it as a whole chart
/// written over it settles, returning what that did PowerPoint's way.
pub(super) fn edit_chart(
    deck: &mut LiveDeck,
    node: NodeId,
    edits: &[ChartEdit],
) -> Result<Vec<Conversion>, LiveError> {
    let found = deck.nodes.get(&node).ok_or(LiveError::UnknownNode)?;
    let held = match &found.payload {
        Some(held @ NodePayload::Chart { .. }) => held.clone(),
        _ => return Err(LiveError::Invalid(NO_CHART)),
    };
    let bound = found.binding.is_some();
    let mut chart = held.clone();
    let mut mint = || deck.mint();
    for edit in edits {
        edit.apply(&mut chart, &mut mint)?;
    }
    let (settled, done) = chart.settle(Some(&held), bound, &deck.opaque_parts)?;
    settled.check()?;
    deck.nodes
        .get_mut(&node)
        .ok_or(LiveError::UnknownNode)?
        .payload = Some(settled);
    Ok(done)
}

/// The edits that make the chart `held` into `wanted`: its family,
/// categories and data source where they differ; the series `wanted` drops
/// deleted and the rest placed in its order (a new one inserted with its
/// data, a held one moved only where it is out of place); then each held
/// series' name, values, family and x values written where they differ. A
/// series `wanted` names with an identity `held` does not hold, with none,
/// or with one an earlier series of it names, is new, under a fresh
/// identity from `mint`: never one an export's positions or equal data
/// suggest.
pub(super) fn lower_chart(
    held: &NodePayload,
    wanted: &NodePayload,
    mint: &mut impl FnMut() -> NodeId,
) -> Vec<ChartEdit> {
    let (
        NodePayload::Chart {
            family: held_family,
            categories: held_categories,
            series: held_series,
            source: held_source,
        },
        NodePayload::Chart {
            family,
            categories,
            series,
            source,
        },
    ) = (held, wanted)
    else {
        return Vec::new();
    };
    let mut edits = Vec::new();
    if family != held_family {
        edits.push(ChartEdit::SetFamily { family: *family });
    }
    if categories != held_categories {
        edits.push(ChartEdit::SetCategories {
            categories: categories.clone(),
        });
    }
    if source != held_source {
        edits.push(ChartEdit::SetSource { source: *source });
    }
    let held_ids: Vec<NodeId> = held_series.iter().filter_map(|line| line.id).collect();
    let known: BTreeSet<NodeId> = held_ids.iter().copied().collect();
    let mut seen = BTreeSet::new();
    let lines: Vec<ChartSeries> = series
        .iter()
        .map(|line| {
            let id = match line.id {
                Some(id) if known.contains(&id) && seen.insert(id) => id,
                _ => mint(),
            };
            ChartSeries {
                id: Some(id),
                ..line.clone()
            }
        })
        .collect();
    let wanted_ids: Vec<NodeId> = lines.iter().filter_map(|line| line.id).collect();
    order(
        &held_ids,
        &wanted_ids,
        &mut edits,
        |id| ChartEdit::DeleteSeries { series: id },
        |id, after| ChartEdit::MoveSeries { series: id, after },
        |id, after| {
            let line = lines.iter().find(|line| line.id == Some(id));
            ChartEdit::InsertSeries {
                id: Some(id),
                after,
                name: line.map_or_else(String::new, |line| line.name.clone()),
                values: line.map_or_else(Vec::new, |line| line.values.clone()),
                family: line.and_then(|line| line.family),
                x: line.and_then(|line| line.x.clone()),
            }
        },
    );
    for line in &lines {
        let Some(id) = line.id else {
            continue;
        };
        let Some(was) = held_series.iter().find(|was| was.id == Some(id)) else {
            continue;
        };
        if was.name != line.name {
            edits.push(ChartEdit::SetSeriesName {
                series: id,
                name: line.name.clone(),
            });
        }
        if was.values != line.values {
            edits.push(ChartEdit::SetSeriesValues {
                series: id,
                values: line.values.clone(),
            });
        }
        if was.family != line.family {
            edits.push(ChartEdit::SetSeriesFamily {
                series: id,
                family: line.family,
            });
        }
        if was.x != line.x {
            edits.push(ChartEdit::SetSeriesX {
                series: id,
                x: line.x.clone(),
            });
        }
    }
    edits
}

impl NodePayload {
    /// Name, from `mint` and in order, each series of a chart that names no
    /// identity or one an earlier series of it names: a writer's new
    /// series. Any other payload names nothing.
    pub(super) fn name_series(&mut self, mint: &mut impl FnMut() -> NodeId) {
        if let Self::Chart { series, .. } = self {
            let mut seen = BTreeSet::new();
            for line in series {
                match line.id {
                    Some(id) if seen.insert(id) => {}
                    _ => {
                        let id = mint();
                        seen.insert(id);
                        line.id = Some(id);
                    }
                }
            }
        }
    }

    /// How many identities [`Self::name_series`] mints.
    pub(super) fn unnamed_series(&self) -> u64 {
        let Self::Chart { series, .. } = self else {
            return 0;
        };
        let mut seen = BTreeSet::new();
        let unnamed = series
            .iter()
            .filter(|line| !line.id.is_some_and(|id| seen.insert(id)))
            .count();
        u64::try_from(unnamed).unwrap_or(u64::MAX)
    }
}
