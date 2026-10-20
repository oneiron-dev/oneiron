//! How a rewritten chart's live series take its held ones (OF-510): the
//! plots Change Chart Type lays out ([`plot_plan`]), the live data each
//! series writes ([`wanted`]), and each series' seat among the held series
//! ([`layout`]): the XML series it keeps, the one it is formatted after,
//! and the one whose workbook cells it writes.

use crate::design_plan::Cell;
use crate::edit::xml;
use crate::live::held::{self, C, children};
use crate::live::pptx::{ChartKind, ChartSeries};
use crate::ooxml::XmlTree;
use std::collections::BTreeSet;

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
/// family, and a held plot no series is drawn in goes. A family no held
/// plot draws gets a new plot after them. When no held plot stays, the
/// first is converted to the first family. A chart with no series takes
/// `family`. Each series goes to the first plot of its family with room
/// for as many series as it held, else to that family's last plot.
pub(in crate::live) fn plot_plan(
    held: &[(ChartKind, usize)],
    family: ChartKind,
    resolved: &[ChartKind],
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
    let assign = resolved
        .iter()
        .map(|kind| {
            let mine: Vec<usize> = (0..targets.len())
                .filter(|&at| targets[at].kind == *kind)
                .collect();
            let at = mine
                .iter()
                .copied()
                .find(|&at| taken[at] < room(&targets[at]))
                .or_else(|| mine.last().copied())
                .unwrap_or(0);
            taken[at] += 1;
            at
        })
        .collect();
    (targets, assign)
}

/// The first category slot any series of the chart holds.
pub(super) fn first_category(tree: &XmlTree) -> Option<usize> {
    let (_, plots) = held::plots(tree)?;
    plots
        .iter()
        .flat_map(|&(_, at)| children(tree, at, C, "ser"))
        .find_map(|ser| xml::child(tree, ser, C, "cat"))
}

/// One live series' data as the rewrite writes it.
pub(super) struct Data {
    pub(super) name: String,
    /// Workbook columns (1-based) of its x values and its values.
    pub(super) x_col: Option<u32>,
    pub(super) y_col: u32,
    pub(super) x: Option<Vec<Cell>>,
    pub(super) values: Vec<Cell>,
}

/// The live data a chart rewrite writes: each series' family, whether the
/// categories stay numbers, the category cells, and each series' cells on
/// a rebuilt workbook's columns (categories in A, then each series' x
/// column, a scatter series', and values column).
pub(super) struct Wanted {
    pub(super) resolved: Vec<ChartKind>,
    pub(super) numeric_cats: bool,
    pub(super) category_cells: Vec<Cell>,
    pub(super) data: Vec<Data>,
}

pub(super) fn wanted(
    tree: &XmlTree,
    family: ChartKind,
    categories: &[String],
    series: &[ChartSeries],
) -> Wanted {
    let resolved: Vec<ChartKind> = series
        .iter()
        .map(|line| line.family.unwrap_or(family))
        .collect();
    // Categories stay numbers when the chart's were and every one reads
    // back as itself.
    let numeric_cats = first_category(tree)
        .and_then(|slot| held::points(tree, slot))
        .is_some_and(|points| points.numeric)
        && categories.iter().all(|category| {
            category
                .trim()
                .parse::<f64>()
                .is_ok_and(|value| held::label(&Cell::Number(value)) == *category)
        });
    let category_cells: Vec<Cell> = categories
        .iter()
        .map(|category| match category.parse::<f64>() {
            Ok(value) if numeric_cats => Cell::Number(value),
            _ if category.is_empty() => Cell::Missing,
            _ => Cell::Text(category.clone()),
        })
        .collect();
    let mut next_col: u32 = if categories.is_empty() { 1 } else { 2 };
    let mut take = || {
        let col = next_col;
        next_col = next_col.saturating_add(1);
        col
    };
    let data: Vec<Data> = series
        .iter()
        .zip(&resolved)
        .map(|(line, kind)| {
            let scatter = *kind == ChartKind::Scatter;
            let count = match (&line.x, scatter) {
                (Some(x), true) => x.len().max(line.values.len()),
                (None, true) => line.values.len(),
                _ if categories.is_empty() => line.values.len(),
                _ => categories.len(),
            };
            let x = line
                .x
                .as_ref()
                .filter(|_| scatter)
                .map(|x| number_cells(x, count));
            let x_col = x.as_ref().map(|_| take());
            Data {
                name: line.name.clone(),
                x_col,
                y_col: take(),
                x,
                values: number_cells(&line.values, count),
            }
        })
        .collect();
    Wanted {
        resolved,
        numeric_cats,
        category_cells,
        data,
    }
}

/// Where one live series sits among the held ones. `held` is the held
/// series in its plot slot, whose idx and order it keeps (and, in a kept
/// plot, its bytes). `template` is the held series it is formatted after:
/// its own, else the last of its plot's, else the chart's series at its
/// position, else the chart's last. `cells` is the held series whose
/// workbook cells it writes: its own, else its template when no other
/// live series holds that one.
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

pub(super) fn layout(tree: &XmlTree, family: ChartKind, resolved: &[ChartKind]) -> Option<Layout> {
    let (area, plots) = held::plots(tree)?;
    let held_sers: Vec<Vec<usize>> = plots
        .iter()
        .map(|&(_, at)| children(tree, at, C, "ser").collect())
        .collect();
    let held_plots: Vec<(ChartKind, usize)> = plots
        .iter()
        .zip(&held_sers)
        .map(|(&(kind, _), sers)| (kind, sers.len()))
        .collect();
    let (targets, assign) = plot_plan(&held_plots, family, resolved);
    let mut assigned: Vec<Vec<usize>> = vec![Vec::new(); targets.len()];
    for (index, &target) in assign.iter().enumerate() {
        assigned[target].push(index);
    }
    let every = held_sers.concat();
    let mut seats = vec![Seat::default(); resolved.len()];
    for (at, target) in targets.iter().enumerate() {
        let sers = target
            .held
            .map_or(&[][..], |plot| held_sers[plot].as_slice());
        for (slot, &index) in assigned[at].iter().enumerate() {
            let held = sers.get(slot).copied();
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
