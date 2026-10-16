//! Classic chart parts: creation from a dataset, the series model read from
//! `c:ser`, point-wise cache rebuilds, and the re-import that compares a
//! cache with the workbook cells its reference names.
use super::table::graphic_frame;
use super::workbook::{CellKey, Range, Workbook, header, number};
use super::{ChartFamily, Frame, NativeRefusal, REL, Target, WorkbookReport};
use crate::design_plan::{Cell, ColumnKind, Dataset};
use crate::ooxml::{XmlTree, escape_text};
use crate::retained_opc::Package;
use std::collections::BTreeMap;

const C: &str = "http://schemas.openxmlformats.org/drawingml/2006/chart";
const DML: &str = "http://schemas.openxmlformats.org/drawingml/2006/main";

/// One series sequence as re-imported: its reference, its cache, and the
/// workbook cells the reference names, both in the sequence's kind.
#[derive(Debug, Clone, PartialEq)]
pub struct Sequence {
    pub reference: String,
    pub cache: Vec<Cell>,
    pub workbook: Vec<Cell>,
}

/// A series' workbook-backed sequences; literal or absent ones are `None`.
#[derive(Debug, Clone, PartialEq)]
pub struct SeriesData {
    pub name: Option<Sequence>,
    pub categories: Option<Sequence>,
    pub values: Option<Sequence>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChartData {
    pub series: Vec<SeriesData>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Text,
    Number,
}

#[derive(Debug)]
struct Seq {
    kind: Kind,
    reference: String,
    range: Range,
    /// The `c:strCache` / `c:numCache` node.
    cache: usize,
}

#[derive(Debug, Default)]
struct Series {
    name: Option<Seq>,
    categories: Option<Seq>,
    values: Option<Seq>,
    other: Vec<Seq>,
}

struct Model {
    bytes: Vec<u8>,
    tree: XmlTree,
    series: Vec<Series>,
    data_link: Option<String>,
}

impl Model {
    fn read(package: &Package, chart: &str) -> Result<Self, NativeRefusal> {
        let bytes = package
            .part(chart)?
            .ok_or(NativeRefusal::Stale("chart part missing"))?;
        let tree = XmlTree::parse(&bytes, package.limits().xml)?;
        tree.root(C, "chartSpace")
            .map_err(|_| NativeRefusal::UnsupportedChartFamily("not a classic chart part"))?;
        if tree.child(0, C, "pivotSource")?.is_some() {
            return Err(NativeRefusal::UnsupportedChartFamily("pivot chart"));
        }
        let data_link = tree
            .child(0, C, "externalData")?
            .and_then(|(_, node)| node.attr_ns(REL, "id").map(str::to_owned));
        let plot = tree
            .child(0, C, "chart")?
            .map(|(chart, _)| tree.child(chart, C, "plotArea"))
            .transpose()?
            .flatten()
            .ok_or(NativeRefusal::AmbiguousChartData("chart has no plot area"))?
            .0;
        let mut series = Vec::new();
        let mut references = 0usize;
        for (family, _) in tree
            .children(plot)
            .filter(|(_, node)| node.namespace == C && node.name.ends_with("Chart"))
        {
            for (ser, _) in tree.children(family).filter(|(_, node)| node.is(C, "ser")) {
                let mut entry = Series::default();
                for (slot, node) in tree.children(ser) {
                    let sequence = match node.name.as_str() {
                        "tx" | "cat" | "xVal" | "val" | "yVal" | "bubbleSize"
                            if node.namespace == C =>
                        {
                            sequence(&tree, slot)?
                        }
                        _ => continue,
                    };
                    references += usize::from(sequence.is_some());
                    match node.name.as_str() {
                        "tx" => entry.name = sequence,
                        "cat" | "xVal" => entry.categories = sequence,
                        "val" | "yVal" => entry.values = sequence,
                        _ => entry.other.extend(sequence),
                    }
                }
                series.push(entry);
            }
        }
        // Every cell reference in the part must be one the model rewrites.
        if tree.nodes.iter().filter(|node| node.name == "f").count() != references {
            return Err(NativeRefusal::AmbiguousChartData(
                "a cell reference outside the series data",
            ));
        }
        Ok(Self {
            bytes,
            tree,
            series,
            data_link,
        })
    }

    fn sequences(&self) -> impl Iterator<Item = &Seq> {
        self.series.iter().flat_map(|series| {
            series
                .name
                .iter()
                .chain(&series.categories)
                .chain(&series.values)
                .chain(&series.other)
        })
    }

    /// Cache values by point, `ptCount` long.
    fn cache(&self, seq: &Seq) -> Result<Vec<Cell>, NativeRefusal> {
        let tree = &self.tree;
        let count = tree
            .child(seq.cache, C, "ptCount")?
            .and_then(|(_, node)| node.attr("val")?.parse::<usize>().ok())
            .unwrap_or(0);
        if count != seq.range.cells().len() {
            return Err(NativeRefusal::AmbiguousChartData(
                "cache length disagrees with its range",
            ));
        }
        let mut out = vec![Cell::Missing; count];
        for (pt, node) in tree
            .children(seq.cache)
            .filter(|(_, node)| node.is(C, "pt"))
        {
            let slot = node
                .attr("idx")
                .and_then(|idx| idx.parse::<usize>().ok())
                .and_then(|idx| out.get_mut(idx))
                .ok_or(NativeRefusal::AmbiguousChartData(
                    "cache point outside its count",
                ))?;
            let text = tree
                .child(pt, C, "v")?
                .map_or_else(String::new, |(_, v)| v.text.clone());
            *slot =
                match seq.kind {
                    Kind::Text => Cell::Text(text),
                    Kind::Number => Cell::Number(text.trim().parse().map_err(|_| {
                        NativeRefusal::AmbiguousChartData("unreadable cached number")
                    })?),
                };
        }
        Ok(out)
    }
}

/// The workbook-backed sequence under a `c:tx`/`c:cat`/`c:val` slot; `None`
/// for a literal.
fn sequence(tree: &XmlTree, slot: usize) -> Result<Option<Seq>, NativeRefusal> {
    for (node, element) in tree.children(slot) {
        let (kind, cache) = match element.name.as_str() {
            "strRef" => (Kind::Text, "strCache"),
            "numRef" => (Kind::Number, "numCache"),
            "multiLvlStrRef" => {
                return Err(NativeRefusal::AmbiguousChartData("multi-level categories"));
            }
            _ => continue,
        };
        let reference = tree
            .child(node, C, "f")?
            .map(|(_, f)| f.text.trim().to_owned())
            .ok_or(NativeRefusal::AmbiguousChartData(
                "a reference without a formula",
            ))?;
        let range = Range::parse(&reference)?;
        let cache = tree
            .child(node, C, cache)?
            .ok_or(NativeRefusal::AmbiguousChartData(
                "a reference without a cache",
            ))?
            .0;
        return Ok(Some(Seq {
            kind,
            reference,
            range,
            cache,
        }));
    }
    Ok(None)
}

fn as_kind(kind: Kind, cell: Cell) -> Cell {
    match (kind, cell) {
        (Kind::Text, Cell::Number(value)) => Cell::Text(number(value)),
        (Kind::Text, Cell::Date(text)) => Cell::Text(text),
        (_, cell) => cell,
    }
}

/// The embedded workbook part behind `c:externalData`, refusing external,
/// non-xlsx and shared sources.
fn workbook_part(package: &Package, chart: &str, model: &Model) -> Result<String, NativeRefusal> {
    let link = model
        .data_link
        .as_deref()
        .ok_or(NativeRefusal::AmbiguousChartData(
            "the chart has no embedded workbook",
        ))?;
    let rel = package
        .relationships(chart)?
        .into_iter()
        .find(|rel| rel.id == link)
        .ok_or(NativeRefusal::AmbiguousChartData(
            "dangling chart data relationship",
        ))?;
    if rel.external {
        return Err(NativeRefusal::ExternalChartSource(
            "the chart data links outside the package",
        ));
    }
    if !rel.kind.ends_with("/package") {
        return Err(NativeRefusal::AmbiguousChartData(
            "embedded data is not an xlsx package",
        ));
    }
    let mut users = 0usize;
    let names: Vec<String> = package.names().map(str::to_owned).collect();
    for rels in names.iter().filter(|name| name.ends_with(".rels")) {
        let source = match rels.strip_prefix("_rels/") {
            Some(".rels") => String::new(),
            Some(_) => continue,
            None => match rels
                .strip_suffix(".rels")
                .and_then(|name| name.rsplit_once("/_rels/"))
            {
                Some((folder, file)) => format!("{folder}/{file}"),
                None => continue,
            },
        };
        users += package
            .relationships(&source)?
            .iter()
            .filter(|other| !other.external && other.target == rel.target)
            .count();
    }
    if users > 1 {
        return Err(NativeRefusal::SharedChartData);
    }
    Ok(rel.target)
}

fn open_workbook(package: &Package, part: &str) -> Result<Workbook, NativeRefusal> {
    let bytes = package
        .part(part)?
        .ok_or(NativeRefusal::AmbiguousChartData(
            "embedded workbook missing",
        ))?;
    Workbook::open(&bytes, package.limits())
}

/// Replace one sequence's values: the workbook cells, then every cache that
/// holds one of those cells, point by point.
pub(super) fn set_series(
    package: &mut Package,
    chart: &str,
    series: usize,
    target: Target,
    values: &[Cell],
) -> Result<(WorkbookReport, Vec<CellKey>), NativeRefusal> {
    let model = Model::read(package, chart)?;
    let entry = model
        .series
        .get(series)
        .ok_or(NativeRefusal::Stale("no such series"))?;
    let seq = match target {
        Target::Name => &entry.name,
        Target::Categories => &entry.categories,
        Target::Values => &entry.values,
    }
    .as_ref()
    .ok_or(NativeRefusal::AmbiguousChartData(
        "the sequence has no workbook source",
    ))?;
    let cells = seq.range.cells();
    if cells.len() != values.len() {
        return Err(NativeRefusal::LengthChange {
            have: cells.len(),
            want: values.len(),
        });
    }
    if seq.kind == Kind::Number
        && values
            .iter()
            .any(|value| matches!(value, Cell::Text(_) | Cell::Date(_)))
    {
        return Err(NativeRefusal::Invalid("text in a number sequence"));
    }
    let book = workbook_part(package, chart, &model)?;
    let writes: Vec<(CellKey, Cell)> = cells.iter().cloned().zip(values.iter().cloned()).collect();
    let (bytes, report) = open_workbook(package, &book)?.write(&book, &writes)?;
    let written: BTreeMap<CellKey, Cell> = writes.into_iter().collect();
    let mut edits = Vec::new();
    for seq in model.sequences() {
        let keys = seq.range.cells();
        if !keys.iter().any(|key| written.contains_key(key)) {
            continue;
        }
        let mut cache = model.cache(seq)?;
        for (slot, key) in cache.iter_mut().zip(&keys) {
            if let Some(value) = written.get(key) {
                *slot = as_kind(seq.kind, value.clone());
            }
        }
        let node = &model.tree.nodes[seq.cache];
        edits.push((
            node.span.clone(),
            cache_xml(&model, seq.cache, &node.qualified, &cache),
        ));
    }
    edits.sort_by_key(|(span, _)| span.start);
    let mut out = Vec::with_capacity(model.bytes.len());
    let mut at = 0;
    for (span, xml) in edits {
        out.extend_from_slice(&model.bytes[at..span.start]);
        out.extend_from_slice(xml.as_bytes());
        at = span.end;
    }
    out.extend_from_slice(&model.bytes[at..]);
    package.replace_xml_part(chart, out)?;
    package
        .replace_nested_package(&book, bytes)
        .map_err(NativeRefusal::Workbook)?;
    Ok((report, written.into_keys().collect()))
}

/// A cache element with new points; `formatCode` and `extLst` keep their bytes.
fn cache_xml(model: &Model, cache: usize, qualified: &str, values: &[Cell]) -> String {
    let p = qualified
        .rsplit_once(':')
        .map_or(String::new(), |(prefix, _)| format!("{prefix}:"));
    let keep = |name: &str| {
        model
            .tree
            .children(cache)
            .find(|(_, node)| node.is(C, name))
            .map_or(String::new(), |(_, node)| {
                String::from_utf8_lossy(&model.bytes[node.span.clone()]).into_owned()
            })
    };
    format!(
        "<{qualified}>{}{}{}</{qualified}>",
        keep("formatCode"),
        points(&p, values),
        keep("extLst")
    )
}

fn points(p: &str, values: &[Cell]) -> String {
    let mut out = format!("<{p}ptCount val=\"{}\"/>", values.len());
    for (idx, value) in values.iter().enumerate() {
        let text = match value {
            Cell::Missing => continue,
            Cell::Number(value) => number(*value),
            Cell::Text(text) | Cell::Date(text) => escape_text(text),
        };
        out.push_str(&format!("<{p}pt idx=\"{idx}\"><{p}v>{text}</{p}v></{p}pt>"));
    }
    out
}

/// Re-read sequences from the package: those holding a written cell, or all.
pub(super) fn read_back(
    package: &Package,
    chart: &str,
    written: Option<&[CellKey]>,
) -> Result<Vec<Sequence>, NativeRefusal> {
    let model = Model::read(package, chart)?;
    let book = open_workbook(package, &workbook_part(package, chart, &model)?)?;
    model
        .sequences()
        .filter(|seq| {
            written.is_none_or(|keys| seq.range.cells().iter().any(|key| keys.contains(key)))
        })
        .map(|seq| imported(&model, &book, seq))
        .collect()
}

fn imported(model: &Model, book: &Workbook, seq: &Seq) -> Result<Sequence, NativeRefusal> {
    Ok(Sequence {
        reference: seq.reference.clone(),
        cache: model.cache(seq)?,
        workbook: book
            .read(&seq.range.cells())?
            .into_iter()
            .map(|cell| as_kind(seq.kind, cell))
            .collect(),
    })
}

/// Every series of a chart as re-imported from the package.
pub fn chart_data(package: &Package, chart: &str) -> Result<ChartData, NativeRefusal> {
    let model = Model::read(package, chart)?;
    let book = open_workbook(package, &workbook_part(package, chart, &model)?)?;
    let read = |seq: &Option<Seq>| {
        seq.as_ref()
            .map(|seq| imported(&model, &book, seq))
            .transpose()
    };
    Ok(ChartData {
        series: model
            .series
            .iter()
            .map(|series| {
                Ok(SeriesData {
                    name: read(&series.name)?,
                    categories: read(&series.categories)?,
                    values: read(&series.values)?,
                })
            })
            .collect::<Result<_, NativeRefusal>>()?,
    })
}

/// A classic chart part for a dataset whose first column is the categories
/// and whose later columns are number series.
pub(super) fn create(
    family: ChartFamily,
    dataset: &Dataset,
    sheet: &str,
    link: &str,
) -> Result<Vec<u8>, NativeRefusal> {
    let Some((first, series)) = dataset.columns.split_first() else {
        return Err(NativeRefusal::Invalid(
            "a chart needs a category column and number columns",
        ));
    };
    if first.kind == ColumnKind::Number
        || series.is_empty()
        || series
            .iter()
            .any(|column| column.kind != ColumnKind::Number)
        || dataset.rows.is_empty()
    {
        return Err(NativeRefusal::Invalid(
            "a chart needs a category column and number columns",
        ));
    }
    if family == ChartFamily::Pie && series.len() != 1 {
        return Err(NativeRefusal::Invalid("a pie chart carries one series"));
    }
    let last = u32::try_from(dataset.rows.len() + 1)
        .map_err(|_| NativeRefusal::Invalid("too many rows"))?;
    let column = |at: usize| -> Vec<Cell> {
        dataset
            .rows
            .iter()
            .map(|row| row.get(at).cloned().unwrap_or(Cell::Missing))
            .collect()
    };
    let categories = Range::column(sheet, 1, (2, last));
    let category_cache: Vec<Cell> = column(0)
        .into_iter()
        .map(|cell| as_kind(Kind::Text, cell))
        .collect();
    // PowerPoint smooths a line series that does not say otherwise, which
    // draws a shape between points the data does not have.
    let smooth = if family == ChartFamily::Line {
        "<c:smooth val=\"0\"/>"
    } else {
        ""
    };
    let mut sers = String::new();
    for (at, col) in series.iter().enumerate() {
        let letter =
            u32::try_from(at + 2).map_err(|_| NativeRefusal::Invalid("too many columns"))?;
        let name = Range::column(sheet, letter, (1, 1));
        let values = Range::column(sheet, letter, (2, last));
        sers.push_str(&format!(
            "<c:ser><c:idx val=\"{at}\"/><c:order val=\"{at}\"/><c:tx><c:strRef><c:f>{}</c:f><c:strCache>{}</c:strCache></c:strRef></c:tx><c:cat><c:strRef><c:f>{}</c:f><c:strCache>{}</c:strCache></c:strRef></c:cat><c:val><c:numRef><c:f>{}</c:f><c:numCache><c:formatCode>General</c:formatCode>{}</c:numCache></c:numRef></c:val>{smooth}</c:ser>",
            escape_text(&name.formula()),
            points("c:", &[Cell::Text(header(col))]),
            escape_text(&categories.formula()),
            points("c:", &category_cache),
            escape_text(&values.formula()),
            points("c:", &column(at + 1)),
        ));
    }
    let axes = "<c:axId val=\"1\"/><c:axId val=\"2\"/>";
    let plot = match family {
        ChartFamily::Bar => format!(
            "<c:barChart><c:barDir val=\"col\"/><c:grouping val=\"clustered\"/><c:varyColors val=\"0\"/>{sers}{axes}</c:barChart>"
        ),
        ChartFamily::Line => format!(
            "<c:lineChart><c:grouping val=\"standard\"/><c:varyColors val=\"0\"/>{sers}<c:marker val=\"1\"/>{axes}</c:lineChart>"
        ),
        ChartFamily::Pie => format!(
            "<c:pieChart><c:varyColors val=\"1\"/>{sers}<c:firstSliceAng val=\"0\"/></c:pieChart>"
        ),
    };
    let axes = if family == ChartFamily::Pie {
        ""
    } else {
        "<c:catAx><c:axId val=\"1\"/><c:scaling><c:orientation val=\"minMax\"/></c:scaling><c:delete val=\"0\"/><c:axPos val=\"b\"/><c:numFmt formatCode=\"General\" sourceLinked=\"1\"/><c:tickLblPos val=\"nextTo\"/><c:crossAx val=\"2\"/><c:crosses val=\"autoZero\"/><c:auto val=\"1\"/><c:lblAlgn val=\"ctr\"/><c:lblOffset val=\"100\"/></c:catAx><c:valAx><c:axId val=\"2\"/><c:scaling><c:orientation val=\"minMax\"/></c:scaling><c:delete val=\"0\"/><c:axPos val=\"l\"/><c:majorGridlines/><c:numFmt formatCode=\"General\" sourceLinked=\"1\"/><c:tickLblPos val=\"nextTo\"/><c:crossAx val=\"1\"/><c:crosses val=\"autoZero\"/><c:crossBetween val=\"between\"/></c:valAx>"
    };
    let legend = if family == ChartFamily::Pie || series.len() > 1 {
        "<c:legend><c:legendPos val=\"r\"/><c:overlay val=\"0\"/></c:legend>"
    } else {
        ""
    };
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<c:chartSpace xmlns:c=\"{C}\" xmlns:a=\"{DML}\" xmlns:r=\"{REL}\"><c:roundedCorners val=\"0\"/><c:chart><c:autoTitleDeleted val=\"1\"/><c:plotArea><c:layout/>{plot}{axes}</c:plotArea>{legend}<c:plotVisOnly val=\"1\"/><c:dispBlanksAs val=\"gap\"/></c:chart><c:externalData r:id=\"{}\"><c:autoUpdate val=\"0\"/></c:externalData></c:chartSpace>",
        escape_text(link)
    )
    .into_bytes())
}

/// The chart's graphic frame, pointing at the chart part by `link`.
pub(super) fn frame_xml(frame: &Frame<'_>, link: &str) -> String {
    let inner = format!(
        "<c:chart xmlns:c=\"{C}\" xmlns:r=\"{REL}\" r:id=\"{}\"/>",
        escape_text(link)
    );
    graphic_frame(frame, C, &inner)
}
