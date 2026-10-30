//! Chart edits applied by series and category identity; a whole chart
//! written over the chart a node holds lowered to the edits that make it,
//! before it is logged; and the series and category identities a writer
//! names before an edit is logged, so every replay makes the same series
//! and points.

mod categories;

use super::chart::{ChartCategories, ChartEdit, ChartPlot, ChartSeries};
use super::table_ops::order;
use super::{LiveDeck, NodeId, NodePayload};
use crate::live::LiveError;
use crate::live::conversion::Conversion;
use categories::lower_set;
use std::collections::{BTreeSet, VecDeque};

const NO_CHART: &str = "the node holds no chart";
const TAKEN: &str = "the series identity is taken";

impl ChartEdit {
    /// How many identities applying this edit mints: one for an insertion
    /// that names none, and one for each category point a set it writes
    /// holds unnamed.
    pub(super) fn unnamed(&self) -> u64 {
        match self {
            Self::InsertSeries { id, categories, .. } => u64::from(id.is_none())
                .saturating_add(categories.as_ref().map_or(0, |set| set.unnamed())),
            Self::SetCategories { categories } => categories.unnamed(),
            Self::SetSeriesCategories { categories, .. } => {
                categories.as_ref().map_or(0, |set| set.unnamed())
            }
            Self::InsertCategory { id, .. } => u64::from(id.is_none()),
            _ => 0,
        }
    }

    /// Name, from `mint`, an insertion that names no identity and each
    /// category point a set it writes holds unnamed, in the order applying
    /// it would.
    pub(super) fn name(&mut self, mint: &mut impl FnMut() -> NodeId) {
        match self {
            Self::InsertSeries { id, categories, .. } => {
                if id.is_none() {
                    *id = Some(mint());
                }
                if let Some(set) = categories {
                    set.name(mint);
                }
            }
            Self::SetCategories { categories } => categories.name(mint),
            Self::SetSeriesCategories {
                categories: Some(set),
                ..
            } => set.name(mint),
            Self::InsertCategory { id, .. } if id.is_none() => *id = Some(mint()),
            _ => {}
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
            plots,
            view,
        } = chart
        else {
            return Err(LiveError::Invalid(NO_CHART));
        };
        if categories::apply(self, *family, categories, series, mint)? {
            return Ok(());
        }
        match self {
            Self::InsertSeries {
                id,
                after,
                name,
                values,
                family: kind,
                x,
                x_labels,
                plot,
                categories: own,
                bubble_size,
                bubble_3d,
            } => {
                let id = match id {
                    Some(id) => *id,
                    None => mint(),
                };
                let mut own = own.clone();
                if let Some(set) = &mut own {
                    set.name(mint);
                }
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
                        x_labels: x_labels.clone(),
                        plot: *plot,
                        categories: own,
                        bubble_size: bubble_size.clone(),
                        bubble_3d: *bubble_3d,
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
                // A series of another family takes that family's plot as
                // settlement places it.
                if let Some(line) = find(series, *id)
                    && line.family != *kind
                {
                    line.family = *kind;
                    line.plot = None;
                }
            }
            // X values written replace text ones (FIX 9277); labels written
            // are kept (FIX 10295).
            Self::SetSeriesX {
                series: id,
                x,
                x_labels,
            } => {
                if let Some(line) = find(series, *id) {
                    line.x.clone_from(x);
                    line.x_labels.clone_from(x_labels);
                }
            }
            // Settlement draws it in that plot, as the export does.
            Self::SetSeriesPlot { series: id, plot } => {
                if let Some(line) = find(series, *id) {
                    line.plot = Some(*plot);
                }
            }
            Self::SetSeriesBubbleSize {
                series: id,
                bubble_size,
            } => {
                if let Some(line) = find(series, *id) {
                    line.bubble_size.clone_from(bubble_size);
                }
            }
            Self::SetSeriesBubble3D {
                series: id,
                bubble_3d,
            } => {
                if let Some(line) = find(series, *id) {
                    line.bubble_3d = *bubble_3d;
                }
            }
            Self::SetPlot { plot } => {
                plots.retain(|held| !held.is(plot.family, plot.nth));
                if !plot.is_empty() {
                    plots.push(plot.clone());
                }
            }
            Self::SetView { view: wanted } => *view = *wanted,
            Self::SetFamily { family: kind } => *family = *kind,
            Self::SetSource { source: wanted } => *source = *wanted,
            // Applied above.
            Self::SetCategories { .. }
            | Self::SetSeriesCategories { .. }
            | Self::InsertCategory { .. }
            | Self::DeleteCategory { .. }
            | Self::MoveCategory { .. }
            | Self::SetCategoryLevels { .. }
            | Self::ReserveCategories { .. } => {}
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
/// written over it settles, returning what that did PowerPoint's way. The
/// points the settlement adds take the identities the edits reserve, in
/// order, else the deck's next.
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
    let (mut settled, done) = chart.settle(Some(&held), bound, &deck.opaque_parts)?;
    let mut reserved: VecDeque<NodeId> = edits
        .iter()
        .filter_map(|edit| match edit {
            ChartEdit::ReserveCategories { ids } => Some(ids.iter().copied()),
            _ => None,
        })
        .flatten()
        .collect();
    settled.name_categories(&mut || reserved.pop_front().unwrap_or_else(|| deck.mint()));
    settled.check()?;
    deck.nodes
        .get_mut(&node)
        .ok_or(LiveError::UnknownNode)?
        .payload = Some(settled);
    Ok(done)
}

/// Apply `edit` to `scratch` and log it in `edits`: a lowering builds its
/// edits over the chart as the edits so far leave it.
fn emit(
    edit: ChartEdit,
    scratch: &mut NodePayload,
    edits: &mut Vec<ChartEdit>,
    mint: &mut impl FnMut() -> NodeId,
) {
    // Every lowered edit names what it inserts: applying it mints nothing.
    let _ = edit.apply(scratch, mint);
    edits.push(edit);
}

/// The edits that make the chart `held` into `wanted`: its family and data
/// source where they differ; its categories by point identity ([`lower_set`]);
/// the series `wanted` drops deleted and the rest placed in its order (a new
/// one inserted with its data, a held one moved only where it is out of
/// place); then each held series' own categories by point identity, and its
/// name, values, family and x values written where they differ from the
/// chart as the edits before leave it (a moved point has taken its values
/// along). A series or point `wanted` names with an identity `held` does not
/// hold, with none, or with one an earlier one names, is new, under a fresh
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
            plots: held_plots,
            view: held_view,
        },
        NodePayload::Chart {
            family,
            categories,
            series,
            source,
            plots,
            view,
        },
    ) = (held, wanted)
    else {
        return Vec::new();
    };
    let mut scratch = held.clone();
    let mut edits = Vec::new();
    if family != held_family {
        emit(
            ChartEdit::SetFamily { family: *family },
            &mut scratch,
            &mut edits,
            mint,
        );
    }
    if source != held_source {
        emit(
            ChartEdit::SetSource { source: *source },
            &mut scratch,
            &mut edits,
            mint,
        );
    }
    if view != held_view {
        emit(
            ChartEdit::SetView { view: *view },
            &mut scratch,
            &mut edits,
            mint,
        );
    }
    // Each plot's settings where they differ, and a plot `wanted` no longer
    // names cleared.
    for plot in plots {
        if !held_plots.contains(plot) {
            emit(
                ChartEdit::SetPlot { plot: plot.clone() },
                &mut scratch,
                &mut edits,
                mint,
            );
        }
    }
    for plot in held_plots {
        if !plots.iter().any(|now| now.is(plot.family, plot.nth)) {
            emit(
                ChartEdit::SetPlot {
                    plot: ChartPlot::new(plot.family, plot.nth),
                },
                &mut scratch,
                &mut edits,
                mint,
            );
        }
    }
    for edit in lower_set(None, held_categories, categories, mint) {
        emit(edit, &mut scratch, &mut edits, mint);
    }
    // The category identities the lowering gave points `wanted` named
    // otherwise, for its custom splits (FIX 9375).
    let mut points: Vec<(NodeId, NodeId)> = Vec::new();
    if let NodePayload::Chart {
        categories: lowered,
        ..
    } = &scratch
    {
        renamed_points(categories, lowered, &mut points);
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
    let mut placed = Vec::new();
    order(
        &held_ids,
        &wanted_ids,
        &mut placed,
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
                x_labels: line.and_then(|line| line.x_labels.clone()),
                plot: line.and_then(|line| line.plot),
                categories: line.and_then(|line| line.categories.clone()),
                bubble_size: line.and_then(|line| line.bubble_size.clone()),
                bubble_3d: line.and_then(|line| line.bubble_3d),
            }
        },
    );
    for edit in placed {
        emit(edit, &mut scratch, &mut edits, mint);
    }
    for line in &lines {
        let Some(id) = line.id else {
            continue;
        };
        if !known.contains(&id) {
            continue;
        }
        let now = |scratch: &NodePayload| -> Option<ChartSeries> {
            match scratch {
                NodePayload::Chart { series, .. } => {
                    series.iter().find(|was| was.id == Some(id)).cloned()
                }
                _ => None,
            }
        };
        let Some(was) = now(&scratch) else {
            continue;
        };
        let own = match (&was.categories, &line.categories) {
            (Some(held), Some(wanted)) => lower_set(Some(id), held, wanted, mint),
            (held, wanted) if held != wanted => vec![ChartEdit::SetSeriesCategories {
                series: id,
                categories: wanted.clone(),
            }],
            _ => Vec::new(),
        };
        for edit in own {
            emit(edit, &mut scratch, &mut edits, mint);
        }
        let Some(was) = now(&scratch) else {
            continue;
        };
        if let (Some(wanted), Some(lowered)) = (&line.categories, &was.categories) {
            renamed_points(wanted, lowered, &mut points);
        }
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
        } else if let Some(plot) = line.plot
            && plot != was.plot.unwrap_or(0)
        {
            // Another plot of its family (FIX 10295); a family change
            // places it as settlement does.
            edits.push(ChartEdit::SetSeriesPlot { series: id, plot });
        }
        // Text x values written where they differ; none leaves them to the
        // x values, as before (FIX 10295).
        if was.x != line.x || (line.x_labels.is_some() && was.x_labels != line.x_labels) {
            edits.push(ChartEdit::SetSeriesX {
                series: id,
                x: line.x.clone(),
                x_labels: line.x_labels.clone(),
            });
        }
        if was.bubble_size != line.bubble_size {
            edits.push(ChartEdit::SetSeriesBubbleSize {
                series: id,
                bubble_size: line.bubble_size.clone(),
            });
        }
        if was.bubble_3d != line.bubble_3d {
            edits.push(ChartEdit::SetSeriesBubble3D {
                series: id,
                bubble_3d: line.bubble_3d,
            });
        }
    }
    // A stock plot's prices follow the series this lowering named anew,
    // and an of-pie plot's custom split the points it named anew (FIX
    // 9375), each where the chart no longer holds the old identity.
    let renamed: Vec<(NodeId, NodeId)> = series
        .iter()
        .zip(&lines)
        .filter_map(|(line, now)| Some((line.id?, now.id?)))
        .filter(|(was, now)| was != now && !wanted_ids.contains(was))
        .collect();
    let kept: BTreeSet<NodeId> = match &scratch {
        NodePayload::Chart {
            categories, series, ..
        } => categories
            .ids()
            .into_iter()
            .chain(
                series
                    .iter()
                    .filter_map(|line| line.categories.as_ref())
                    .flat_map(ChartCategories::ids),
            )
            .collect(),
        _ => BTreeSet::new(),
    };
    for plot in plots {
        let mut out = plot.clone();
        let mut moved = false;
        if let Some(roles) = &mut out.stock {
            for slot in roles.slots_mut() {
                if let Some(&(_, now)) = renamed.iter().find(|(was, _)| *slot == Some(*was)) {
                    *slot = Some(now);
                    moved = true;
                }
            }
        }
        if let Some(split) = &mut out.custom_split {
            for id in split.iter_mut() {
                if !kept.contains(&*id)
                    && let Some(&(_, now)) = points.iter().find(|(was, _)| *was == *id)
                {
                    *id = now;
                    moved = true;
                }
            }
        }
        if moved {
            emit(
                ChartEdit::SetPlot { plot: out },
                &mut scratch,
                &mut edits,
                mint,
            );
        }
    }
    edits
}

/// The identities a lowering gave, by place, the points of `wanted` it
/// named otherwise (`lowered` is the set it made): each named one and the
/// one it now holds.
fn renamed_points(
    wanted: &ChartCategories,
    lowered: &ChartCategories,
    out: &mut Vec<(NodeId, NodeId)>,
) {
    for (point, now) in wanted.points.iter().zip(&lowered.points) {
        if let (Some(was), Some(now)) = (point.id, now.id)
            && was != now
        {
            out.push((was, now));
        }
    }
}

/// `edits` to the chart `held` as its writer logs them: each whole set a
/// category setter writes over a set the chart holds then lowered to the
/// point edits that make it ([`lower_set`]), so it joins concurrent work on
/// those points.
pub(super) fn lower_edits(
    held: &NodePayload,
    edits: &[ChartEdit],
    mint: &mut impl FnMut() -> NodeId,
) -> Vec<ChartEdit> {
    let mut scratch = held.clone();
    let mut out = Vec::new();
    for edit in edits {
        let lowered = match (edit, &scratch) {
            (
                ChartEdit::SetCategories { categories: wanted },
                NodePayload::Chart { categories, .. },
            ) => lower_set(None, categories, wanted, mint),
            (
                ChartEdit::SetSeriesCategories {
                    series: id,
                    categories: Some(wanted),
                },
                NodePayload::Chart { series, .. },
            ) => match series
                .iter()
                .find(|line| line.id == Some(*id))
                .and_then(|line| line.categories.as_ref())
            {
                Some(own) => lower_set(Some(*id), own, wanted, mint),
                None => vec![edit.clone()],
            },
            _ => vec![edit.clone()],
        };
        for edit in lowered {
            emit(edit, &mut scratch, &mut out, mint);
        }
    }
    out
}

impl LiveDeck {
    /// Reserve, at the end of `edits` to the chart `node` holds, the
    /// identities from `mint` the chart's settlement after them gives the
    /// points it adds (a set grown to its longest series, x values turned to
    /// categories), so the logged edits name them and every replay makes the
    /// same points. Nothing when it adds none, or when the edits refuse.
    pub(super) fn reserve_categories(
        &self,
        node: NodeId,
        edits: &mut Vec<ChartEdit>,
        mint: &mut impl FnMut() -> NodeId,
    ) {
        let Some(found) = self.nodes.get(&node) else {
            return;
        };
        let Some(held @ NodePayload::Chart { .. }) = &found.payload else {
            return;
        };
        let mut chart = held.clone();
        let mut spare = 0_u64;
        let mut unused = || {
            spare += 1;
            NodeId(spare)
        };
        if edits
            .iter()
            .any(|edit| edit.apply(&mut chart, &mut unused).is_err())
        {
            return;
        }
        let Ok((settled, _)) =
            chart.settle(Some(held), found.binding.is_some(), &self.opaque_parts)
        else {
            return;
        };
        let count = settled.unnamed_categories();
        if count > 0 {
            edits.push(ChartEdit::ReserveCategories {
                ids: (0..count).map(|_| mint()).collect(),
            });
        }
    }
}

impl NodePayload {
    /// Name, from `mint` and in order, each series of a chart that names no
    /// identity or one an earlier series of it names (a writer's new
    /// series), then each category point its sets hold unnamed
    /// ([`Self::name_categories`]). Any other payload names nothing.
    pub(crate) fn name_series(&mut self, mint: &mut impl FnMut() -> NodeId) {
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
        self.name_categories(mint);
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
        u64::try_from(unnamed)
            .unwrap_or(u64::MAX)
            .saturating_add(self.unnamed_categories())
    }
}
