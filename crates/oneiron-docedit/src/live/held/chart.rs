//! A chart frame's data as the live model holds it: its chart part, its
//! plots in document order, and each series' name, categories (flat or
//! multi-level, the chart's or its own) or x values and values read from
//! its caches and literals. A read names no series or category identity:
//! the import names each once ([`bind`]), and an export finds them again
//! through the binding, never through a read. A count a cache declares is
//! measured before it is expanded (FIX 8589).

mod families;

pub(crate) use families::{flag, plot as plot_settings, view};

use super::{C, FRAME_DATA, children};
use crate::design_plan::Cell;
use crate::edit::xml::{self, R};
use crate::live::LiveError;
use crate::live::pptx::{
    ChartCategories, ChartCategory, ChartKind, ChartSeries, ChartSource, NodeId, NodePayload,
    SeriesBinding, draws_categories, effective_categories,
};
use crate::native_patch::{Count, chart_data, declared, level_cache};
use crate::ooxml::XmlTree;
use crate::retained_opc::Package;
use oneiron_contracts::limit_ask::available_memory_bytes;

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
        "bar3DChart" => ChartKind::Bar3D,
        "line3DChart" => ChartKind::Line3D,
        "pie3DChart" => ChartKind::Pie3D,
        "area3DChart" => ChartKind::Area3D,
        "bubbleChart" => ChartKind::Bubble,
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

/// One series sequence as its cache or literal holds it: its cells level
/// by level, leaf first (a flat sequence holds one level).
pub(crate) struct Points {
    pub(crate) levels: Vec<Vec<Cell>>,
    pub(crate) numeric: bool,
    /// The cell reference, for a `c:strRef`, `c:numRef` or
    /// `c:multiLvlStrRef`.
    pub(crate) formula: Option<String>,
}

impl Points {
    /// Its leaf level: a flat sequence's points.
    pub(crate) fn cells(&self) -> &[Cell] {
        self.levels.first().map_or(&[], Vec::as_slice)
    }
}

/// A sequence slot as its reference or literal declares it, read without
/// expanding its points: whether it holds numbers, its reference, and how
/// many levels it holds.
pub(crate) struct Descriptor {
    pub(crate) numeric: bool,
    pub(crate) formula: Option<String>,
    pub(crate) levels: usize,
}

/// The data under a sequence slot, as declared.
enum Data {
    /// A name's literal `c:v`.
    Name(usize),
    /// A flat cache or literal: its point list, whether it holds numbers,
    /// and its `c:f`.
    Flat {
        data: usize,
        numeric: bool,
        formula: Option<usize>,
    },
    /// A multi-level reference: its cache and its `c:f`.
    Levels {
        cache: usize,
        formula: Option<usize>,
    },
}

/// The data the first sequence child of `slot` holds; `None` when there is
/// none, or a reference has no cache.
fn data(tree: &XmlTree, slot: usize) -> Option<Data> {
    for &child in &tree.nodes[slot].children {
        let node = &tree.nodes[child];
        if node.namespace != C {
            continue;
        }
        let formula = || xml::child(tree, child, C, "f");
        return Some(match node.name.as_str() {
            "v" => Data::Name(child),
            "strRef" => Data::Flat {
                data: xml::child(tree, child, C, "strCache")?,
                numeric: false,
                formula: Some(formula()?),
            },
            "numRef" => Data::Flat {
                data: xml::child(tree, child, C, "numCache")?,
                numeric: true,
                formula: Some(formula()?),
            },
            "strLit" => Data::Flat {
                data: child,
                numeric: false,
                formula: None,
            },
            "numLit" => Data::Flat {
                data: child,
                numeric: true,
                formula: None,
            },
            "multiLvlStrRef" => Data::Levels {
                cache: xml::child(tree, child, C, "multiLvlStrCache")?,
                formula: formula(),
            },
            _ => continue,
        });
    }
    None
}

/// A flat cache's or literal's declared count and its points (index and
/// text), read without expanding the count; `None` when a point's index or
/// number does not read, or lies past the count.
fn flat(tree: &XmlTree, data: usize, numeric: bool) -> Option<(Count, Vec<(usize, &str)>)> {
    let count =
        declared(xml::child(tree, data, C, "ptCount").and_then(|at| tree.nodes[at].attr("val")));
    let mut points = Vec::new();
    for pt in children(tree, data, C, "pt") {
        let idx: usize = tree.nodes[pt].attr("idx")?.trim().parse().ok()?;
        if matches!(count, Count::Points(count) if idx >= count) {
            return None;
        }
        let text = xml::child(tree, pt, C, "v").map_or("", |v| tree.nodes[v].text.as_str());
        if numeric {
            text.trim().parse::<f64>().ok()?;
        }
        points.push((idx, text));
    }
    Some((count, points))
}

fn text_of(tree: &XmlTree, at: Option<usize>) -> Option<String> {
    at.map(|at| tree.nodes[at].text.trim().to_owned())
}

/// The sequence under a slot as declared, its points not expanded: for the
/// readers that only ask what it is and where it lives. `None` when it is
/// unreadable as [`points`] finds it.
pub(crate) fn descriptor(tree: &XmlTree, slot: usize) -> Option<Descriptor> {
    Some(match data(tree, slot)? {
        Data::Name(_) => Descriptor {
            numeric: false,
            formula: None,
            levels: 1,
        },
        Data::Flat {
            data,
            numeric,
            formula,
        } => {
            flat(tree, data, numeric)?;
            Descriptor {
                numeric,
                formula: text_of(tree, formula),
                levels: 1,
            }
        }
        Data::Levels { cache, formula } => Descriptor {
            numeric: false,
            formula: text_of(tree, formula),
            levels: level_cache(tree, cache)?.levels.len().max(1),
        },
    })
}

/// A count a cache declares, when this machine can address it.
fn addressable(count: Count) -> Result<usize, LiveError> {
    match count {
        Count::Points(count) => Ok(count),
        Count::Unaddressable => Err(LiveError::MemoryFloor {
            reason: "a chart cache declares more points than this machine addresses",
            needed: None,
            available: None,
        }),
    }
}

/// Measure `count` more items of `T` and `owned` bytes of text they hold
/// against the memory the host has free, before any of it is allocated
/// (FIX 8589): bytes past this machine's address space, or past what the
/// host has free now, are a memory floor, never a count limit. The bytes
/// measured, and what the host had free where it says.
fn measure<T>(count: usize, owned: usize) -> Result<(u64, Option<u64>), LiveError> {
    let needed = count
        .checked_mul(size_of::<T>())
        .and_then(|bytes| bytes.checked_add(owned))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(LiveError::MemoryFloor {
            reason: "a chart cache declares more than this machine addresses",
            needed: None,
            available: None,
        })?;
    let available = available_memory_bytes();
    if let Some(free) = available
        && needed > free
    {
        return Err(LiveError::MemoryFloor {
            reason: "a chart cache declares more points than the memory this host has free",
            needed: Some(needed),
            available: Some(free),
        });
    }
    Ok((needed, available))
}

/// Room in `out` for `more` items of `T` and `owned` bytes of their text,
/// measured ([`measure`]) and reserved exactly before anything is written;
/// an allocator refusal is a memory floor.
fn reserve<T>(out: &mut Vec<T>, more: usize, owned: usize) -> Result<(), LiveError> {
    if more == 0 {
        return Ok(());
    }
    let (needed, available) = measure::<T>(more, owned)?;
    out.try_reserve_exact(more)
        .map_err(|_| LiveError::MemoryFloor {
            reason: "the allocator refused a chart cache's points",
            needed: Some(needed),
            available,
        })
}

/// `count` missing cells, measured and reserved first, with `owned` bytes
/// of text to come.
fn missing(count: usize, owned: usize) -> Result<Vec<Cell>, LiveError> {
    let mut cells = Vec::new();
    reserve(&mut cells, count, owned)?;
    cells.resize(count, Cell::Missing);
    Ok(cells)
}

/// The sequence under a `c:tx`, `c:cat`, `c:val`, `c:xVal` or `c:yVal`
/// slot: a reference's cache, a literal, a multi-level reference's levels,
/// or a name's `c:v`. `None` when it is unreadable (a reference without a
/// cache, a point outside its count). The count a cache declares is
/// measured before it is expanded: what the host cannot hold is a
/// [`LiveError::MemoryFloor`].
pub(crate) fn points(tree: &XmlTree, slot: usize) -> Result<Option<Points>, LiveError> {
    let Some(data) = data(tree, slot) else {
        return Ok(None);
    };
    match data {
        Data::Name(v) => Ok(Some(Points {
            levels: vec![vec![Cell::Text(tree.nodes[v].text.clone())]],
            numeric: false,
            formula: None,
        })),
        Data::Flat {
            data,
            numeric,
            formula,
        } => {
            let Some((count, read)) = flat(tree, data, numeric) else {
                return Ok(None);
            };
            let owned = if numeric {
                0
            } else {
                read.iter().map(|(_, text)| text.len()).sum()
            };
            let mut cells = missing(addressable(count)?, owned)?;
            for (idx, text) in read {
                cells[idx] = if numeric {
                    text.trim().parse().map_or(Cell::Missing, Cell::Number)
                } else {
                    Cell::Text(text.to_owned())
                };
            }
            Ok(Some(Points {
                levels: vec![cells],
                numeric,
                formula: text_of(tree, formula),
            }))
        }
        Data::Levels { cache, formula } => {
            let Some(read) = level_cache(tree, cache) else {
                return Ok(None);
            };
            let count = addressable(read.count)?;
            let mut levels = Vec::new();
            reserve(&mut levels, read.levels.len().max(1), 0)?;
            for points in read.levels {
                let owned = points.iter().map(|(_, text)| text.len()).sum();
                let mut cells = missing(count, owned)?;
                for (idx, text) in points {
                    cells[idx] = Cell::Text(text);
                }
                levels.push(cells);
            }
            if levels.is_empty() {
                levels.push(missing(count, 0)?);
            }
            Ok(Some(Points {
                levels,
                numeric: false,
                formula: text_of(tree, formula),
            }))
        }
    }
}

/// A series slot's points: `Some(None)` when the series has no such slot,
/// `None` when it has one the reader cannot read.
fn slot(tree: &XmlTree, ser: usize, name: &str) -> Result<Option<Option<Points>>, LiveError> {
    Ok(match xml::child(tree, ser, C, name) {
        None => Some(None),
        Some(at) => points(tree, at)?.map(Some),
    })
}

/// Cells as numbers, measured first; `None` when one is text.
fn numbers(cells: &[Cell]) -> Result<Option<Vec<Option<serde_json::Number>>>, LiveError> {
    let mut out = Vec::new();
    reserve(&mut out, cells.len(), 0)?;
    for cell in cells {
        out.push(match cell {
            Cell::Number(value) => match serde_json::Number::from_f64(*value) {
                Some(number) => Some(number),
                None => return Ok(None),
            },
            Cell::Missing => None,
            Cell::Text(_) | Cell::Date(_) => return Ok(None),
        });
    }
    Ok(Some(out))
}

/// A category slot's points as a category set of new points, leaf level
/// first, measured first: a missing cell holds no label.
fn categories_of(points: Points) -> Result<ChartCategories, LiveError> {
    let depth = points.levels.len().max(1);
    let count = points.cells().len();
    let each = depth
        .checked_mul(size_of::<Option<String>>())
        .ok_or(LiveError::MemoryFloor {
            reason: "a chart cache declares more levels than this machine addresses",
            needed: None,
            available: None,
        })?;
    let mut out: Vec<ChartCategory> = Vec::new();
    reserve(
        &mut out,
        count,
        count.checked_mul(each).unwrap_or(usize::MAX),
    )?;
    for _ in 0..count {
        out.push(ChartCategory {
            id: None,
            levels: Vec::with_capacity(depth),
        });
    }
    for level in points.levels {
        for (point, cell) in out.iter_mut().zip(level) {
            point.levels.push(match cell {
                Cell::Missing => None,
                Cell::Text(text) | Cell::Date(text) => Some(text),
                cell @ Cell::Number(_) => Some(label(&cell)),
            });
        }
    }
    let mut set = ChartCategories {
        level_count: u32::try_from(depth).unwrap_or(u32::MAX),
        points: out,
    };
    set.settle_depth();
    Ok(set)
}

/// `set` grown to `count` points of no label and no identity, measured
/// first.
fn grow_set(set: &mut ChartCategories, count: usize) -> Result<(), LiveError> {
    let more = count.saturating_sub(set.len());
    let each = set.depth().saturating_mul(size_of::<Option<String>>());
    reserve(&mut set.points, more, more.saturating_mul(each))?;
    set.pad(count);
    Ok(())
}

/// `values` grown to `count` with missing points, measured first.
fn grow_values(
    values: &mut Vec<Option<serde_json::Number>>,
    count: usize,
) -> Result<(), LiveError> {
    reserve(values, count.saturating_sub(values.len()), 0)?;
    if values.len() < count {
        values.resize(count, None);
    }
    Ok(())
}

/// A chart part's data as the live model holds it, read from its caches
/// and literals: the first plot's family, its categories, and each series'
/// name and values, with a combo chart's plot family, a scatter or bubble
/// series' x values, a bubble series' sizes (missing and negative ones
/// kept as data) and 3D flag, and a category series' own categories where
/// they are not the chart's; each plot's settings and the chart's 3D view. When every category series reads the same labels (multi-level
/// ones level by level), they are the chart's, once; otherwise the first
/// category series' are the chart's, and each series whose labels differ
/// (one with none, too) holds its own, never folded into the first's. A
/// text value, or a plot the reader does not read, leaves the chart without
/// a live form; a declared count the host cannot hold refuses
/// ([`LiveError::MemoryFloor`]).
pub(crate) fn chart(package: &Package, chart: &str) -> Result<Option<NodePayload>, LiveError> {
    let Ok((_, tree)) = xml::read(package, chart) else {
        return Ok(None);
    };
    let Some((_, plots)) = plots(&tree) else {
        return Ok(None);
    };
    let Some(&(family, _)) = plots.first() else {
        return Ok(None);
    };
    let combo = plots.len() > 1;
    let mut series = Vec::new();
    // The categories each category series' own `c:cat` reads.
    let mut read: Vec<Option<ChartCategories>> = Vec::new();
    let mut referenced = false;
    for &(plot, at) in &plots {
        let scatter = plot.draws_x();
        let bubble = plot == ChartKind::Bubble;
        let (cat, val) = if scatter {
            ("xVal", "yVal")
        } else {
            ("cat", "val")
        };
        for ser in children(&tree, at, C, "ser") {
            let (Some(name), Some(held), Some(values)) = (
                slot(&tree, ser, "tx")?,
                slot(&tree, ser, cat)?,
                slot(&tree, ser, val)?,
            ) else {
                return Ok(None);
            };
            // A bubble series' sizes: missing and negative sizes stay data.
            let Some(size) = (if bubble {
                slot(&tree, ser, "bubbleSize")?
            } else {
                Some(None)
            }) else {
                return Ok(None);
            };
            referenced |= [&name, &held, &values, &size]
                .into_iter()
                .flatten()
                .any(|points| points.formula.is_some());
            let mut bubble_size = match size {
                Some(points) => match numbers(points.cells())? {
                    Some(size) => Some(size),
                    None => return Ok(None),
                },
                None => None,
            };
            let values = match values {
                Some(points) => match numbers(points.cells())? {
                    Some(values) => values,
                    None => return Ok(None),
                },
                None => Vec::new(),
            };
            let (x, own) = match held {
                Some(points) if scatter && points.numeric => {
                    let Some(mut x) = numbers(points.cells())? else {
                        return Ok(None);
                    };
                    grow_values(&mut x, values.len())?;
                    (Some(x), None)
                }
                Some(points) if !scatter => (None, Some(categories_of(points)?)),
                _ => (None, None),
            };
            if let Some(size) = &mut bubble_size {
                grow_values(size, values.len())?;
            }
            series.push(ChartSeries {
                id: None,
                name: name
                    .and_then(|points| points.cells().first().map(label))
                    .unwrap_or_default(),
                values,
                family: combo.then_some(plot),
                x,
                categories: None,
                bubble_size,
                bubble_3d: bubble.then(|| flag(&tree, ser, "bubble3D")).flatten(),
            });
            read.push(own);
        }
    }
    let first = series
        .iter()
        .zip(&read)
        .position(|(line, own)| draws_categories(family, line) && own.is_some());
    let mut categories = first.and_then(|at| read[at].take()).unwrap_or_default();
    for (at, (line, own)) in series.iter_mut().zip(read).enumerate() {
        if !draws_categories(family, line) || Some(at) == first {
            continue;
        }
        line.categories = match own {
            Some(own) if own.depth() == categories.depth() && own.same_labels(&categories) => None,
            Some(own) => Some(own),
            None if categories.is_empty() => None,
            None => Some(ChartCategories::default()),
        };
    }
    // A category set holds no fewer points than the longest series that
    // draws it, and each such series one value per point.
    let longest = series
        .iter()
        .filter(|line| draws_categories(family, line) && line.categories.is_none())
        .map(|line| line.values.len())
        .max()
        .unwrap_or(0);
    if !categories.is_empty() {
        grow_set(&mut categories, longest)?;
    }
    for line in &mut series {
        if !draws_categories(family, line) {
            continue;
        }
        if let Some(own) = &mut line.categories
            && !own.is_empty()
        {
            grow_set(own, line.values.len())?;
        }
        let count = effective_categories(&categories, line).len();
        grow_values(&mut line.values, count)?;
    }
    let source = if !referenced {
        ChartSource::Literal
    } else if chart_data(package, chart).is_ok() {
        ChartSource::Workbook
    } else {
        ChartSource::Cached
    };
    Ok(Some(NodePayload::Chart {
        family,
        categories,
        series,
        source,
        plots: families::plots(&tree, &plots),
        view: view(&tree),
    }))
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
/// order, then each category point of the chart's set and of each series'
/// own, and the binding that order takes: each series and the category
/// identities it draws; `None` for any other payload. Called once, at
/// import.
pub(crate) fn bind(
    payload: &mut Option<NodePayload>,
    mut mint: impl FnMut() -> NodeId,
) -> Option<SeriesBinding> {
    let Some(chart @ NodePayload::Chart { .. }) = payload else {
        return None;
    };
    chart.name_series(&mut mint);
    let NodePayload::Chart {
        family,
        categories,
        series,
        ..
    } = chart
    else {
        return None;
    };
    Some(SeriesBinding {
        series: series.iter().filter_map(|line| line.id).collect(),
        categories: series
            .iter()
            .map(|line| {
                if draws_categories(*family, line) {
                    effective_categories(categories, line).ids()
                } else {
                    Vec::new()
                }
            })
            .collect(),
    })
}
