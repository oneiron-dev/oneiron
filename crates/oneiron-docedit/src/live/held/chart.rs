//! A chart frame's data as the live model holds it: its chart part, its
//! plots in document order, and each series' name, categories or x values
//! and values read from its caches and literals. A read names no series
//! identity: the import names each series once ([`bind`]), and an export
//! finds them again through the binding, never through a read.

use super::{C, FRAME_DATA, children};
use crate::design_plan::Cell;
use crate::edit::xml::{self, R};
use crate::live::pptx::{ChartKind, ChartSeries, ChartSource, NodeId, NodePayload, SeriesBinding};
use crate::native_patch::chart_data;
use crate::ooxml::XmlTree;
use crate::retained_opc::Package;

/// The chart part a chart frame's `c:chart` relates.
pub(crate) fn chart_part(
    package: &Package,
    part: &str,
    tree: &XmlTree,
    frame: usize,
) -> Option<String> {
    let data = xml::path(tree, frame, FRAME_DATA)?;
    let id = tree.nodes[xml::child(tree, data, C, "chart")?].attr_ns(R, "id")?;
    let kind = format!("{R}/chart");
    package
        .relationships(part)
        .ok()?
        .into_iter()
        .find(|rel| rel.id == id && !rel.external && rel.kind == kind)
        .map(|rel| rel.target)
}

/// The plot family a `c:plotArea` child is, when the live deck reads it.
pub(crate) fn plot_family(name: &str) -> Option<ChartKind> {
    Some(match name {
        "barChart" => ChartKind::Bar,
        "lineChart" => ChartKind::Line,
        "pieChart" => ChartKind::Pie,
        "areaChart" => ChartKind::Area,
        "scatterChart" => ChartKind::Scatter,
        "doughnutChart" => ChartKind::Doughnut,
        "radarChart" => ChartKind::Radar,
        _ => return None,
    })
}

/// A chart part's plots in document order: each family and its element.
/// `None` when a plot is one the live deck does not read.
pub(crate) fn plots(tree: &XmlTree) -> Option<(usize, Vec<(ChartKind, usize)>)> {
    let area = xml::path(tree, 0, &[(C, "chart"), (C, "plotArea")])?;
    let plots = tree.nodes[area]
        .children
        .iter()
        .copied()
        .filter(|&at| tree.nodes[at].namespace == C && tree.nodes[at].name.ends_with("Chart"))
        .map(|at| Some((plot_family(&tree.nodes[at].name)?, at)))
        .collect::<Option<Vec<_>>>()?;
    (!plots.is_empty()).then_some((area, plots))
}

/// One series sequence as its cache or literal holds it.
pub(crate) struct Points {
    pub(crate) cells: Vec<Cell>,
    pub(crate) numeric: bool,
    /// The cell reference, for a `c:strRef` or `c:numRef`.
    pub(crate) formula: Option<String>,
}

/// The sequence under a `c:tx`, `c:cat`, `c:val`, `c:xVal` or `c:yVal`
/// slot: a reference's cache, a literal, or a name's `c:v`. `None` when it
/// is unreadable (a multi-level reference, a reference without a cache, a
/// point outside its count).
pub(crate) fn points(tree: &XmlTree, slot: usize) -> Option<Points> {
    for &child in &tree.nodes[slot].children {
        let node = &tree.nodes[child];
        if node.namespace != C {
            continue;
        }
        let (numeric, data, formula) = match node.name.as_str() {
            "v" => {
                return Some(Points {
                    cells: vec![Cell::Text(node.text.clone())],
                    numeric: false,
                    formula: None,
                });
            }
            "strRef" => (false, xml::child(tree, child, C, "strCache")?, true),
            "numRef" => (true, xml::child(tree, child, C, "numCache")?, true),
            "strLit" => (false, child, false),
            "numLit" => (true, child, false),
            _ => continue,
        };
        let count = xml::child(tree, data, C, "ptCount")
            .and_then(|at| tree.nodes[at].attr("val")?.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let mut cells = vec![Cell::Missing; count];
        for pt in children(tree, data, C, "pt") {
            let idx: usize = tree.nodes[pt].attr("idx")?.trim().parse().ok()?;
            let text = xml::child(tree, pt, C, "v")
                .map_or_else(String::new, |v| tree.nodes[v].text.clone());
            *cells.get_mut(idx)? = if numeric {
                Cell::Number(text.trim().parse().ok()?)
            } else {
                Cell::Text(text)
            };
        }
        let formula = if formula {
            Some(
                tree.nodes[xml::child(tree, child, C, "f")?]
                    .text
                    .trim()
                    .to_owned(),
            )
        } else {
            None
        };
        return Some(Points {
            cells,
            numeric,
            formula,
        });
    }
    None
}

/// A series slot's points: `Some(None)` when the series has no such slot,
/// `None` when it has one the reader cannot read.
fn slot(tree: &XmlTree, ser: usize, name: &str) -> Option<Option<Points>> {
    match xml::child(tree, ser, C, name) {
        None => Some(None),
        Some(at) => points(tree, at).map(Some),
    }
}

fn numbers(cells: &[Cell]) -> Option<Vec<Option<serde_json::Number>>> {
    cells
        .iter()
        .map(|cell| match cell {
            Cell::Number(value) => serde_json::Number::from_f64(*value).map(Some),
            Cell::Missing => Some(None),
            Cell::Text(_) | Cell::Date(_) => None,
        })
        .collect()
}

/// A chart part's data as the live model holds it, read from its caches
/// and literals: the first plot's family, the categories every category
/// series shares, and each series' name and values, with a combo chart's
/// plot family and a scatter series' x values. A series with its own
/// categories, a text value, or a plot the reader does not read leaves the
/// chart without a live form.
pub(crate) fn chart(package: &Package, chart: &str) -> Option<NodePayload> {
    let (_, tree) = xml::read(package, chart).ok()?;
    let (_, plots) = plots(&tree)?;
    let family = plots.first()?.0;
    let combo = plots.len() > 1;
    let mut categories: Option<Vec<String>> = None;
    let mut series = Vec::new();
    let mut referenced = false;
    for &(plot, at) in &plots {
        let scatter = plot == ChartKind::Scatter;
        let (cat, val) = if scatter {
            ("xVal", "yVal")
        } else {
            ("cat", "val")
        };
        for ser in children(&tree, at, C, "ser") {
            let name = slot(&tree, ser, "tx")?;
            let held = slot(&tree, ser, cat)?;
            let values = slot(&tree, ser, val)?;
            referenced |= [&name, &held, &values]
                .into_iter()
                .flatten()
                .any(|points| points.formula.is_some());
            let values = values.map_or(Some(Vec::new()), |points| numbers(&points.cells))?;
            let x = match held {
                Some(points) if scatter && points.numeric => {
                    let mut x = numbers(&points.cells)?;
                    if x.len() < values.len() {
                        x.resize(values.len(), None);
                    }
                    Some(x)
                }
                Some(points) if !scatter => {
                    let held: Vec<String> = points.cells.iter().map(label).collect();
                    if *categories.get_or_insert_with(|| held.clone()) != held {
                        return None;
                    }
                    None
                }
                _ => None,
            };
            series.push(ChartSeries {
                id: None,
                name: name
                    .and_then(|points| points.cells.first().map(label))
                    .unwrap_or_default(),
                values,
                family: combo.then_some(plot),
                x,
            });
        }
    }
    let mut categories = categories.unwrap_or_default();
    // A category series holds no more values than there are categories.
    let longest = series
        .iter()
        .filter(|line| line.family.unwrap_or(family) != ChartKind::Scatter)
        .map(|line| line.values.len())
        .max()
        .unwrap_or(0);
    if !categories.is_empty() && categories.len() < longest {
        categories.resize(longest, String::new());
    }
    let source = if !referenced {
        ChartSource::Literal
    } else if chart_data(package, chart).is_ok() {
        ChartSource::Workbook
    } else {
        ChartSource::Cached
    };
    Some(NodePayload::Chart {
        family,
        categories,
        series,
        source,
    })
}

/// A category or series-name cell as live-model text.
pub(crate) fn label(cell: &Cell) -> String {
    match cell {
        Cell::Text(text) | Cell::Date(text) => text.clone(),
        Cell::Number(value) => value.to_string(),
        Cell::Missing => String::new(),
    }
}

/// Name each series of an imported chart from `mint`, in its part's own
/// order, and the binding that order takes; `None` for any other payload.
/// Called once, at import.
pub(crate) fn bind(
    payload: &mut Option<NodePayload>,
    mut mint: impl FnMut() -> NodeId,
) -> Option<SeriesBinding> {
    let Some(NodePayload::Chart { series, .. }) = payload else {
        return None;
    };
    let ids = series
        .iter_mut()
        .map(|line| {
            let id = mint();
            line.id = Some(id);
            id
        })
        .collect();
    Some(SeriesBinding { series: ids })
}
