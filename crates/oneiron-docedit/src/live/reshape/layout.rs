//! How a rewritten chart's live series take its held ones (OF-510, FIX
//! 3492): the plots Change Chart Type lays out ([`plot_plan`]), the live
//! data each series writes ([`wanted`]), and each series' seat among the
//! held series by its identity ([`layout`]): its own XML series, which it
//! keeps, the one it is formatted after, and the one whose workbook cells
//! it writes. One resolution ([`resolve`]) drives both the workbook edit
//! and the chart rewrite.

use crate::design_plan::Cell;
use crate::edit::xml;
use crate::live::LiveError;
use crate::live::convert::place_ordinals;
use crate::live::held::{self, C, series_of};
use crate::live::pptx::{
    ChartCategories, ChartKind, ChartSeries, NodeId, NodePayload, WRITTEN_FRAME,
    effective_categories, positions,
};
use crate::ooxml::XmlTree;
use crate::retained_opc::Package;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn number_cells(values: &[Option<serde_json::Number>], count: usize) -> Vec<Cell> {
    (0..count)
        .map(|at| {
            values
                .get(at)
                .and_then(|value| value.as_ref()?.as_f64())
                .map_or(Cell::Missing, Cell::Number)
        })
        .collect()
}

/// Text labels as cells, one per point up to `count`: a missing or empty
/// label is a missing cell.
fn text_cells(labels: &[Option<String>], count: usize) -> Vec<Cell> {
    (0..count)
        .map(|at| match labels.get(at) {
            Some(Some(label)) if !label.is_empty() => Cell::Text(label.clone()),
            _ => Cell::Missing,
        })
        .collect()
}

/// One plot a chart rewrite writes: a held plot (`held`, its index among
/// the chart's plots) kept or converted to another family, or a new plot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::live) struct PlotTarget {
    pub(in crate::live) held: Option<usize>,
    pub(in crate::live) kind: ChartKind,
}

/// The plots a chart takes and the plot that draws each series, as
/// PowerPoint's Change Chart Type lays them out for a whole chart or for one
/// series. `held` is each held plot's family and series count; `resolved`
/// is each series' family. A held plot stays while a series is drawn in its
/// family; one no series is drawn in goes (FIX 12256), so the export never
/// writes a plot empty. One plot stays, so a chart emptied of its series
/// still reads back. A family no held plot draws gets a new plot after
/// them. When no held plot stays, the first is converted to the first
/// family. A chart with no series takes `family`. Each series stays in
/// `own`, the held plot it was drawn in,
/// while that plot draws its family; any other goes to the first plot of
/// its family with room for as many series as it held, else to that
/// family's last plot.
pub(in crate::live) fn plot_plan(
    held: &[(ChartKind, usize)],
    family: ChartKind,
    resolved: &[ChartKind],
    own: &[Option<usize>],
) -> (Vec<PlotTarget>, Vec<usize>) {
    let mut families: Vec<ChartKind> = Vec::new();
    for kind in resolved
        .iter()
        .copied()
        .chain(resolved.is_empty().then_some(family))
    {
        if !families.contains(&kind) {
            families.push(kind);
        }
    }
    let mut targets: Vec<PlotTarget> = held
        .iter()
        .enumerate()
        .filter(|(_, (kind, _))| families.contains(kind))
        .map(|(at, &(kind, _))| PlotTarget {
            held: Some(at),
            kind,
        })
        .collect();
    if targets.is_empty()
        && !held.is_empty()
        && let Some(&kind) = families.first()
    {
        targets.push(PlotTarget {
            held: Some(0),
            kind,
        });
    }
    for &kind in &families {
        if !targets.iter().any(|target| target.kind == kind) {
            targets.push(PlotTarget { held: None, kind });
        }
    }
    let room = |target: &PlotTarget| match target.held {
        Some(at) if held[at].0 == target.kind => held[at].1,
        _ => 0,
    };
    let mut taken = vec![0_usize; targets.len()];
    let mut assign: Vec<usize> = resolved
        .iter()
        .enumerate()
        .map(|(index, kind)| {
            let mine: Vec<usize> = (0..targets.len())
                .filter(|&at| targets[at].kind == *kind)
                .collect();
            let stays = own.get(index).copied().flatten().and_then(|plot| {
                mine.iter()
                    .copied()
                    .find(|&at| targets[at].held == Some(plot))
            });
            let at = stays
                .or_else(|| {
                    mine.iter()
                        .copied()
                        .find(|&at| taken[at] < room(&targets[at]))
                })
                .or_else(|| mine.last().copied())
                .unwrap_or(0);
            taken[at] += 1;
            at
        })
        .collect();
    // A plot no series is drawn in goes (FIX 12256): the export would
    // write it empty, and the reader would count it in each later series'
    // ordinal while the payload never shows it.
    let mut gone: Vec<usize> = (0..targets.len())
        .filter(|&at| !assign.contains(&at))
        .collect();
    if gone.len() == targets.len() && !targets.is_empty() {
        gone.remove(0);
    }
    if !gone.is_empty() {
        for index in assign.iter_mut() {
            let shift = gone.iter().filter(|&&at| at < *index).count();
            *index -= shift;
        }
        for &at in gone.iter().rev() {
            targets.remove(at);
        }
    }
    (targets, assign)
}

/// The first category slot any series of the chart holds.
pub(super) fn first_category(tree: &XmlTree) -> Option<usize> {
    let (_, plots) = held::plots(tree)?;
    plots
        .iter()
        .flat_map(|&(_, at)| series_of(tree, at))
        .find_map(|ser| xml::child(tree, ser, C, "cat"))
}

/// One live series' data as the rewrite writes it.
pub(super) struct Data {
    pub(super) name: String,
    /// Workbook columns (1-based) of its x values, its values and its
    /// bubble sizes.
    pub(super) x_col: Option<u32>,
    pub(super) y_col: u32,
    pub(super) size_col: Option<u32>,
    pub(super) x: Option<Vec<Cell>>,
    /// Whether its x values are text labels (FIX 9277), written as a
    /// `c:strRef` over text cells.
    pub(super) x_text: bool,
    pub(super) values: Vec<Cell>,
    /// A bubble series' sizes, one per point (a missing one a missing
    /// cell).
    pub(super) size: Option<Vec<Cell>>,
    /// The category set it draws, by its place among [`Wanted::sets`].
    pub(super) set: Option<usize>,
}

/// One category set a chart rewrite writes: the chart's (`own` `None`) or
/// one series' own (`own`, that series' place), as cells level by level
/// (leaf first, one cell per point), whether its flat labels stay numbers,
/// its points' identities, and its first column in a rebuilt workbook,
/// where its levels stand side by side, the outermost first.
pub(super) struct CategorySet {
    pub(super) own: Option<usize>,
    pub(super) numeric: bool,
    pub(super) levels: Vec<Vec<Cell>>,
    pub(super) ids: Vec<Option<NodeId>>,
    pub(super) col: u32,
}

impl CategorySet {
    /// How many points it holds.
    pub(super) fn count(&self) -> usize {
        self.levels.first().map_or(0, Vec::len)
    }

    /// Its leaf level's cells: a flat set's.
    pub(super) fn leaf(&self) -> &[Cell] {
        self.levels.first().map_or(&[], Vec::as_slice)
    }

    /// Whether it is a hierarchy, written as `c:multiLvlStrRef`.
    pub(super) fn multi(&self) -> bool {
        self.levels.len() > 1
    }

    /// The columns it takes in a rebuilt workbook.
    pub(super) fn width(&self) -> u32 {
        u32::try_from(self.levels.len()).unwrap_or(u32::MAX)
    }
}

/// The live data a chart rewrite writes: each series' family, each
/// category set a series draws (the chart's once, each series' own once),
/// and each series' cells on a rebuilt workbook's columns (each set's
/// levels, then each series' x column, a scatter or bubble series', its
/// values column and a bubble series' size column).
pub(super) struct Wanted {
    pub(super) resolved: Vec<ChartKind>,
    pub(super) sets: Vec<CategorySet>,
    pub(super) data: Vec<Data>,
}

/// Every series of the chart, its plots in document order, each plot's
/// series in document order, a stock plot's placeholder none
/// ([`series_of`]): the order a binding names them in.
pub(super) fn held_series(tree: &XmlTree) -> Vec<usize> {
    held::plots(tree).map_or_else(Vec::new, |(_, plots)| {
        plots
            .iter()
            .flat_map(|&(_, at)| series_of(tree, at))
            .collect()
    })
}

/// A category set as cells: a label stays a number when the set is flat,
/// its own held slot held numbers (else the chart's first), and every
/// label reads back as itself; a missing or empty label is a missing cell.
fn set_cells(set: &ChartCategories, held_numeric: bool, own: Option<usize>) -> CategorySet {
    let numeric = set.depth() == 1
        && held_numeric
        && set.level(0).all(|label| {
            label.is_some_and(|label| {
                label
                    .trim()
                    .parse::<f64>()
                    .is_ok_and(|value| held::label(&Cell::Number(value)) == label)
            })
        });
    let levels = (0..set.depth())
        .map(|level| {
            set.level(level)
                .map(|label| match label {
                    None | Some("") => Cell::Missing,
                    Some(label) => match label.parse::<f64>() {
                        Ok(value) if numeric => Cell::Number(value),
                        _ => Cell::Text(label.to_owned()),
                    },
                })
                .collect()
        })
        .collect();
    CategorySet {
        own,
        numeric,
        levels,
        ids: set.points.iter().map(|point| point.id).collect(),
        col: 0,
    }
}

pub(super) fn wanted(
    tree: &XmlTree,
    family: ChartKind,
    categories: &ChartCategories,
    series: &[ChartSeries],
    bound: &[NodeId],
) -> Wanted {
    let resolved: Vec<ChartKind> = series
        .iter()
        .map(|line| line.family.unwrap_or(family))
        .collect();
    // A set's labels stay numbers when its own held slot held numbers: its
    // own series', else the first series that draws it, else the chart's
    // first category slot's.
    let every = held_series(tree);
    let places = positions(bound);
    let numeric_slot = |slot: Option<usize>| -> Option<bool> {
        slot.and_then(|slot| held::descriptor(tree, slot))
            .map(|read| read.numeric && read.levels == 1)
    };
    let fallback = numeric_slot(first_category(tree)).unwrap_or(false);
    let mut sets: Vec<CategorySet> = Vec::new();
    let mut set_of: Vec<Option<usize>> = Vec::with_capacity(series.len());
    for (index, (line, kind)) in series.iter().zip(&resolved).enumerate() {
        let set = effective_categories(categories, line);
        if kind.draws_x() || set.is_empty() {
            set_of.push(None);
            continue;
        }
        let own = line.categories.is_some().then_some(index);
        let at = match sets.iter().position(|held| held.own == own) {
            Some(at) => at,
            None => {
                let slot = line
                    .id
                    .and_then(|id| places.get(&id).copied())
                    .and_then(|at| every.get(at).copied())
                    .and_then(|ser| xml::child(tree, ser, C, "cat"));
                sets.push(set_cells(set, numeric_slot(slot).unwrap_or(fallback), own));
                sets.len() - 1
            }
        };
        set_of.push(Some(at));
    }
    let mut next_col: u32 = 1;
    for set in &mut sets {
        set.col = next_col;
        next_col = next_col.saturating_add(set.width());
    }
    let mut take = || {
        let col = next_col;
        next_col = next_col.saturating_add(1);
        col
    };
    let data: Vec<Data> = series
        .iter()
        .zip(&resolved)
        .zip(set_of)
        .map(|((line, kind), set)| {
            let scatter = kind.draws_x();
            let size = line
                .bubble_size
                .as_ref()
                .filter(|_| *kind == ChartKind::Bubble);
            // Text x values stand where numbers would (FIX 9277).
            let labels = line
                .x_labels
                .as_ref()
                .filter(|_| scatter && line.x.is_none());
            let count = match (&line.x, scatter, set) {
                (Some(x), true, _) => x.len().max(line.values.len()),
                (None, true, _) => labels.map_or(0, Vec::len).max(line.values.len()),
                (_, false, None) => line.values.len(),
                (_, false, Some(set)) => sets[set].count(),
            }
            .max(size.map_or(0, Vec::len));
            let x = match (line.x.as_ref().filter(|_| scatter), labels) {
                (Some(x), _) => Some(number_cells(x, count)),
                (None, Some(labels)) => Some(text_cells(labels, count)),
                (None, None) => None,
            };
            let x_col = x.as_ref().map(|_| take());
            let y_col = take();
            let size = size.map(|size| number_cells(size, count));
            Data {
                name: line.name.clone(),
                x_col,
                y_col,
                size_col: size.as_ref().map(|_| take()),
                x,
                x_text: labels.is_some(),
                values: number_cells(&line.values, count),
                size,
                set,
            }
        })
        .collect();
    Wanted {
        resolved,
        sets,
        data,
    }
}

/// Where one live series sits among the held ones, by its identity. `held`
/// is its own retained series, as the chart's binding names it: it keeps
/// that series' idx and, drawn in that series' family, its bytes; a series
/// new to the chart holds none. `template` is the held series it is
/// formatted after: its own, else the last of its plot's, else the chart's
/// series at its position, else the chart's last. `cells` is the held
/// series whose workbook cells it writes: its own, else its template when
/// no surviving series holds that one, so a new series never takes a
/// survivor's cells.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Seat {
    pub(super) held: Option<usize>,
    pub(super) template: Option<usize>,
    pub(super) cells: Option<usize>,
}

/// A chart's held plots and how the live series take them: the plot area,
/// the held plots, the plots [`plot_plan`] lays out, the live series each
/// one draws (in order), and each live series' seat.
pub(super) struct Layout {
    pub(super) area: usize,
    pub(super) plots: Vec<(ChartKind, usize)>,
    pub(super) targets: Vec<PlotTarget>,
    pub(super) assigned: Vec<Vec<usize>>,
    pub(super) seats: Vec<Seat>,
}

/// How `series` (each of family `resolved`) take the held series of the
/// chart `tree` holds, each by its identity through `bound`, the identity
/// each held series holds in the part's own order ([`SeriesBinding`]):
/// every survivor is seated on its own series, in its own plot while that
/// plot draws its family, before any new series takes a template's cells.
///
/// [`SeriesBinding`]: crate::live::pptx::SeriesBinding
pub(super) fn layout(
    tree: &XmlTree,
    family: ChartKind,
    resolved: &[ChartKind],
    series: &[ChartSeries],
    bound: &[NodeId],
) -> Option<Layout> {
    let (area, plots) = held::plots(tree)?;
    let held_sers: Vec<Vec<usize>> = plots
        .iter()
        .map(|&(_, at)| series_of(tree, at).collect())
        .collect();
    let held_plots: Vec<(ChartKind, usize)> = plots
        .iter()
        .zip(&held_sers)
        .map(|(&(kind, _), sers)| (kind, sers.len()))
        .collect();
    let every = held_sers.concat();
    // Each held series' plot, by its place among them all; each live
    // series' own held series, by its place, through the binding.
    let plot_of: Vec<usize> = held_sers
        .iter()
        .enumerate()
        .flat_map(|(plot, sers)| std::iter::repeat_n(plot, sers.len()))
        .collect();
    let places = positions(bound);
    let own: Vec<Option<usize>> = series
        .iter()
        .map(|line| {
            line.id
                .and_then(|id| places.get(&id).copied())
                .filter(|&at| at < every.len())
        })
        .collect();
    let own_plots: Vec<Option<usize>> = own.iter().map(|at| at.map(|at| plot_of[at])).collect();
    let (mut targets, mut assign) = plot_plan(&held_plots, family, resolved, &own_plots);
    let settled = settled_places(&targets, &assign, resolved, series);
    place_ordinals(&mut targets, &mut assign, resolved, &settled);
    let mut assigned: Vec<Vec<usize>> = vec![Vec::new(); targets.len()];
    for (index, &target) in assign.iter().enumerate() {
        assigned[target].push(index);
    }
    let mut seats = vec![Seat::default(); resolved.len()];
    for (at, target) in targets.iter().enumerate() {
        let sers = target
            .held
            .map_or(&[][..], |plot| held_sers[plot].as_slice());
        for &index in &assigned[at] {
            let held = own.get(index).copied().flatten().map(|at| every[at]);
            seats[index] = Seat {
                held,
                template: held
                    .or_else(|| sers.last().copied())
                    .or_else(|| every.get(index).copied())
                    .or_else(|| every.last().copied()),
                cells: held,
            };
        }
    }
    let mut taken: BTreeSet<usize> = seats.iter().filter_map(|seat| seat.held).collect();
    for seat in &mut seats {
        if seat.cells.is_none()
            && let Some(template) = seat.template
            && taken.insert(template)
        {
            seat.cells = Some(template);
        }
    }
    Some(Layout {
        area,
        plots,
        targets,
        assigned,
        seats,
    })
}

/// The ordinal each of `series` (each of family `resolved`) names for
/// [`place_ordinals`] in each family whose series the payload groups by
/// plot otherwise than `targets` and `assign` draw them (a series the
/// settlement moved to another plot of its family, FIX 10295, or an of-pie
/// plot it drew once per split view, FIX 9375); none for every other
/// series, which stays where [`plot_plan`] put it.
fn settled_places(
    targets: &[PlotTarget],
    assign: &[usize],
    resolved: &[ChartKind],
    series: &[ChartSeries],
) -> Vec<Option<u32>> {
    let ordinal = |index: usize| series.get(index).and_then(|line| line.plot).unwrap_or(0);
    let mut out = vec![None; resolved.len()];
    let mut families: Vec<ChartKind> = Vec::new();
    for kind in resolved {
        if !families.contains(kind) {
            families.push(*kind);
        }
    }
    for kind in families {
        let members: Vec<usize> = (0..resolved.len())
            .filter(|&index| resolved[index] == kind && index < assign.len())
            .collect();
        let mut named: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        for &index in &members {
            named.entry(ordinal(index)).or_default().push(index);
        }
        let drawn: Vec<Vec<usize>> = (0..targets.len())
            .filter(|&at| targets[at].kind == kind)
            .map(|at| {
                members
                    .iter()
                    .copied()
                    .filter(|&index| assign[index] == at)
                    .collect::<Vec<usize>>()
            })
            .filter(|group| !group.is_empty())
            .collect();
        if named.into_values().collect::<Vec<_>>() != drawn {
            for &index in &members {
                out[index] = Some(ordinal(index));
            }
        }
    }
    out
}

/// One chart part as a rewrite reads it, and how the live series take its
/// held ones: the one snapshot both the workbook edit and the chart
/// rewrite read, so the cells a series writes and the XML series it keeps
/// are that same series'.
pub(super) struct Resolved {
    pub(super) bytes: Vec<u8>,
    pub(super) tree: XmlTree,
    pub(super) wanted: Wanted,
    pub(super) layout: Layout,
}

/// Read `chart` and resolve `payload`'s series over it by identity, through
/// `bound`: what each writes ([`wanted`], unless `read` gives it, as read
/// before an embed rewrote the part) and where each sits ([`layout`]).
pub(super) fn resolve(
    package: &Package,
    chart: &str,
    payload: &NodePayload,
    bound: &[NodeId],
    read: Option<Wanted>,
) -> Result<Resolved, LiveError> {
    let NodePayload::Chart {
        family,
        categories,
        series,
        ..
    } = payload
    else {
        return Err(LiveError::Invalid(WRITTEN_FRAME));
    };
    let (bytes, tree) = xml::read(package, chart)?;
    let wanted = match read {
        Some(read) => read,
        None => wanted(&tree, *family, categories, series, bound),
    };
    let layout = layout(&tree, *family, &wanted.resolved, series, bound)
        .ok_or(LiveError::Invalid(WRITTEN_FRAME))?;
    Ok(Resolved {
        bytes,
        tree,
        wanted,
        layout,
    })
}
