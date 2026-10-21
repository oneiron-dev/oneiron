//! A chart payload settled into the form its export writes (OF-510): the
//! plots Change Chart Type lays out, categories and x values turned between
//! category and scatter series, and where the data lives.

use crate::design_plan::Cell;
use crate::live::LiveError;
use crate::live::conversion::Conversion;
use crate::live::held;
use crate::live::pptx::{
    ChartCategories, ChartCategory, ChartKind, ChartSeries, ChartSource, NodeId, NodePayload,
    WRITTEN_FRAME, effective_categories,
};
use crate::live::reshape;
use std::collections::BTreeMap;

/// A chart payload's plots as the reader lists them: its series' families
/// in runs, after an empty first plot when the chart's family is not its
/// first series'; and the plot each series is drawn in, by its identity.
fn held_plots(was: &NodePayload) -> (Vec<(ChartKind, usize)>, BTreeMap<NodeId, usize>) {
    let NodePayload::Chart { family, series, .. } = was else {
        return (Vec::new(), BTreeMap::new());
    };
    let mut runs: Vec<(ChartKind, usize)> = Vec::new();
    let mut own = BTreeMap::new();
    for line in series {
        let kind = line.family.unwrap_or(*family);
        match runs.last_mut() {
            Some((last, count)) if *last == kind => *count += 1,
            _ => runs.push((kind, 1)),
        }
        if let Some(id) = line.id {
            own.entry(id).or_insert(runs.len() - 1);
        }
    }
    if runs.first().is_none_or(|(first, _)| first != family) {
        runs.insert(0, (*family, 0));
        for plot in own.values_mut() {
            *plot += 1;
        }
    }
    (runs, own)
}

/// Categories as x values: their numbers when every one is a number, else
/// 1 to n (`true`), as a chart reads text x values.
fn x_of(categories: &[String]) -> (Vec<Option<serde_json::Number>>, bool) {
    let numbers: Option<Vec<Option<serde_json::Number>>> = categories
        .iter()
        .map(|category| {
            category
                .trim()
                .parse::<f64>()
                .ok()
                .map(serde_json::Number::from_f64)
        })
        .collect();
    match numbers {
        Some(x) => (x, false),
        None => (
            (1..=categories.len())
                .map(|at| u64::try_from(at).ok().map(serde_json::Number::from))
                .collect(),
            true,
        ),
    }
}

/// One x value as a category label: its number, else none.
fn x_label(value: &Option<serde_json::Number>) -> Option<String> {
    value
        .as_ref()
        .and_then(serde_json::Number::as_f64)
        .map(|value| held::label(&Cell::Number(value)))
}

/// A series' x values as a flat category set of new points.
fn x_categories(x: &[Option<serde_json::Number>]) -> ChartCategories {
    ChartCategories {
        level_count: 1,
        points: x
            .iter()
            .map(|value| ChartCategory {
                id: None,
                levels: vec![x_label(value)],
            })
            .collect(),
    }
}

/// Categories and x values turned between category and scatter series,
/// each series by the set it draws ([`effective_categories`]), never by
/// another series': a category series with x values and no categories to
/// draw takes its own x values as them (the chart's, when it draws the
/// chart's empty set and no earlier series gave it others; else its own),
/// and one that has categories drops its x values; a scatter series with no
/// x values takes the leaf labels of the set it would draw as them (higher
/// levels named as dropped), and holds no categories of its own. Then each
/// set is padded to the longest category series that draws it, and each
/// such series' values to its set. A chart of scatter plots only holds no
/// categories.
fn settle_categories(
    categories: &mut ChartCategories,
    lines: &mut [ChartSeries],
    kinds: &[ChartKind],
    any_category: bool,
    done: &mut Vec<Conversion>,
) {
    let chart_was_empty = categories.is_empty();
    // Scatter to category.
    let mut shared: Option<Vec<Option<serde_json::Number>>> = None;
    for (line, kind) in lines.iter_mut().zip(kinds) {
        if *kind == ChartKind::Scatter {
            continue;
        }
        let empty = match &line.categories {
            None => chart_was_empty,
            Some(own) => own.is_empty(),
        };
        if !empty {
            continue;
        }
        let Some(x) = line.x.take() else {
            continue;
        };
        let inherits = line.categories.is_none();
        if inherits && shared.is_none() {
            *categories = x_categories(&x);
            shared = Some(x);
            done.push(Conversion::XBecameCategories);
        } else if !(inherits && shared.as_ref() == Some(&x)) {
            line.categories = Some(x_categories(&x));
            done.push(Conversion::XBecameSeriesCategories {
                series: line.name.clone(),
            });
        }
    }
    // Category to scatter; a category series that still carries x values
    // draws its categories, and its x values go.
    let mut numbered: Option<bool> = None;
    let mut dropped = Vec::new();
    for (line, kind) in lines.iter_mut().zip(kinds) {
        if *kind == ChartKind::Scatter {
            if line.x.is_none() {
                let set = effective_categories(categories, line);
                if !set.is_empty() {
                    let (x, text) = x_of(&set.labels());
                    if set.depth() > 1 {
                        done.push(Conversion::CategoryLevelsDropped {
                            series: line.name.clone(),
                            levels: set.depth() - 1,
                        });
                    }
                    line.x = Some(x);
                    numbered = Some(numbered.unwrap_or(false) || text);
                }
            }
            line.categories = None;
            let count = line.values.len();
            if let Some(x) = line.x.as_mut()
                && x.len() < count
            {
                x.resize(count, None);
            }
        } else if line.x.take().is_some() {
            dropped.push(line.name.clone());
        }
    }
    if let Some(numbered) = numbered {
        done.push(Conversion::CategoriesBecameX { numbered });
    }
    if !dropped.is_empty() {
        done.push(Conversion::XDropped { series: dropped });
    }
    if any_category {
        let longest = lines
            .iter()
            .zip(kinds)
            .filter(|(line, kind)| **kind != ChartKind::Scatter && line.categories.is_none())
            .map(|(line, _)| line.values.len())
            .max()
            .unwrap_or(0);
        if !categories.is_empty() && categories.pad(longest) {
            done.push(Conversion::CategoriesPadded { count: longest });
        }
        for (line, kind) in lines.iter_mut().zip(kinds) {
            if *kind == ChartKind::Scatter {
                continue;
            }
            let count = line.values.len();
            if let Some(own) = &mut line.categories
                && !own.is_empty()
                && own.pad(count)
            {
                done.push(Conversion::SeriesCategoriesPadded {
                    series: line.name.clone(),
                    count,
                });
            }
            let points = effective_categories(categories, line).len();
            if line.values.len() < points {
                line.values.resize(points, None);
            }
        }
    } else if !categories.is_empty() {
        if numbered.is_none() {
            done.push(Conversion::CategoriesDropped);
        }
        *categories = ChartCategories::default();
    }
    categories.settle_depth();
    for line in lines.iter_mut() {
        if let Some(own) = &mut line.categories {
            own.settle_depth();
        }
    }
}

/// A chart payload written to a node, settled into the form its export
/// writes and reads back, with what it converted: the plots
/// [`reshape::plot_plan`] lays out (the series listed plot by plot, each
/// naming its family in a chart of several plots, the chart's family its
/// first plot's), categories and x values turned between category and
/// scatter series, categories padded to the longest category series, and
/// where the data lives. Data written to a chart read from its caches is
/// embedded, as PowerPoint's Edit Data does. `held` is the node's current
/// payload; a live-born chart (`None`) starts from its native seed, and its
/// data lives in its own workbook.
pub(in crate::live) fn settle_chart(
    held: Option<&NodePayload>,
    wanted: &NodePayload,
) -> Result<(NodePayload, Vec<Conversion>), LiveError> {
    let NodePayload::Chart {
        family,
        categories,
        series,
        source,
    } = wanted
    else {
        return Err(LiveError::Invalid(WRITTEN_FRAME));
    };
    let (plots, own, was) = match held {
        None => (
            vec![(reshape::seed_family(wanted), series.len())],
            BTreeMap::new(),
            None,
        ),
        Some(was @ NodePayload::Chart { .. }) => {
            let (plots, own) = held_plots(was);
            (plots, own, Some(was))
        }
        Some(_) => return Err(LiveError::Invalid(WRITTEN_FRAME)),
    };
    let mut done = Vec::new();
    let resolved: Vec<ChartKind> = series
        .iter()
        .map(|line| line.family.unwrap_or(*family))
        .collect();
    // A held series stays in the plot that drew it while it draws its
    // family.
    let own: Vec<Option<usize>> = series
        .iter()
        .map(|line| line.id.and_then(|id| own.get(&id).copied()))
        .collect();
    let (targets, assign) = reshape::plot_plan(&plots, *family, &resolved, &own);
    if was.is_some() {
        for target in &targets {
            match target.held {
                Some(at) if plots[at].0 != target.kind => {
                    done.push(Conversion::ChartTypeChanged {
                        from: plots[at].0,
                        to: target.kind,
                    });
                }
                Some(_) => {}
                None => done.push(Conversion::PlotAdded {
                    family: target.kind,
                }),
            }
        }
        for (at, &(kind, count)) in plots.iter().enumerate() {
            if count > 0 && !targets.iter().any(|target| target.held == Some(at)) {
                done.push(Conversion::PlotDropped { family: kind });
            }
        }
    }
    let combo = targets.len() > 1;
    let first = targets.first().map_or(*family, |target| target.kind);
    let mut order: Vec<usize> = (0..series.len()).collect();
    order.sort_by_key(|&index| assign[index]);
    if order.iter().enumerate().any(|(at, &index)| at != index) {
        done.push(Conversion::SeriesRegrouped);
    }
    let kinds: Vec<ChartKind> = order.iter().map(|&index| resolved[index]).collect();
    let mut lines: Vec<ChartSeries> = order
        .iter()
        .map(|&index| ChartSeries {
            family: combo.then_some(resolved[index]),
            ..series[index].clone()
        })
        .collect();
    let any_category = if kinds.is_empty() {
        first != ChartKind::Scatter
    } else {
        kinds.iter().any(|kind| *kind != ChartKind::Scatter)
    };
    let mut categories = categories.clone();
    settle_categories(&mut categories, &mut lines, &kinds, any_category, &mut done);
    let mut settled = NodePayload::Chart {
        family: first,
        categories,
        series: lines,
        source: *source,
    };
    let source = match was {
        None => {
            if *source != ChartSource::Workbook {
                done.push(Conversion::NewChartEmbedded);
            }
            ChartSource::Workbook
        }
        Some(was) => {
            let from = match was {
                NodePayload::Chart { source, .. } => *source,
                _ => ChartSource::Workbook,
            };
            let changed = !reshape::same_data(was, &settled);
            match (from, *source) {
                (ChartSource::Cached, asked) if changed || asked == ChartSource::Workbook => {
                    done.push(Conversion::ExternalDataEmbedded);
                    ChartSource::Workbook
                }
                (ChartSource::Literal, ChartSource::Workbook) => {
                    done.push(Conversion::LiteralDataEmbedded);
                    ChartSource::Workbook
                }
                (kept, asked) => {
                    if kept != asked {
                        done.push(Conversion::SourceKept { kept, asked });
                    }
                    kept
                }
            }
        }
    };
    if let NodePayload::Chart { source: at, .. } = &mut settled {
        *at = source;
    }
    Ok((settled, done))
}
