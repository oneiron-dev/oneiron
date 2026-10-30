//! Native `a:tbl` tables: creation with merge rectangles, and merge-aware
//! cell text writes; a cell a merge covers keeps its own text under the
//! merge, as PowerPoint keeps it.
use super::workbook::{header, number};
use super::{Frame, Merge, NativeRefusal};
use crate::deck::Placeholder;
use crate::design_plan::{Cell, Dataset};
use crate::ooxml::{Node, XmlTree, escape_text};
use crate::retained_opc::Package;

const PML: &str = "http://schemas.openxmlformats.org/presentationml/2006/main";
const DML: &str = "http://schemas.openxmlformats.org/drawingml/2006/main";
const TABLE_URI: &str = "http://schemas.openxmlformats.org/drawingml/2006/table";

/// A self-contained `p:graphicFrame`: it declares its own prefixes, so it
/// is well formed whatever the slide binds.
pub(super) fn graphic_frame(frame: &Frame<'_>, uri: &str, inner: &str) -> String {
    let Frame {
        id,
        name,
        bounds,
        placeholder,
        ..
    } = *frame;
    format!(
        "<p:graphicFrame xmlns:p=\"{PML}\" xmlns:a=\"{DML}\"><p:nvGraphicFramePr><p:cNvPr id=\"{id}\" name=\"{}\"/><p:cNvGraphicFramePr><a:graphicFrameLocks noGrp=\"1\"/></p:cNvGraphicFramePr><p:nvPr>{}</p:nvPr></p:nvGraphicFramePr><p:xfrm><a:off x=\"{}\" y=\"{}\"/><a:ext cx=\"{}\" cy=\"{}\"/></p:xfrm><a:graphic><a:graphicData uri=\"{uri}\">{inner}</a:graphicData></a:graphic></p:graphicFrame>",
        escape_text(name),
        placeholder.map(placeholder_xml).unwrap_or_default(),
        bounds.x,
        bounds.y,
        bounds.cx,
        bounds.cy,
    )
}

/// `p:ph` for a layout placeholder; the implied `obj` type and index 0 are
/// left implied.
pub(crate) fn placeholder_xml(placeholder: &Placeholder) -> String {
    let mut out = String::from("<p:ph");
    if placeholder.kind != "obj" {
        out.push_str(&format!(" type=\"{}\"", escape_text(&placeholder.kind)));
    }
    if placeholder.idx != 0 {
        out.push_str(&format!(" idx=\"{}\"", placeholder.idx));
    }
    out + "/>"
}

/// What a native table shows (FIX 8577), shared by creation and by the
/// layout estimate so both read one table: every cell's own displayed text,
/// header row 0 first (a number as its column shows it, a missing cell as
/// the dataset's missing meaning), and each cell's place in the merges. A
/// cell a merge covers keeps its own text under the merge.
#[derive(Debug, Clone)]
pub(crate) struct TableLayout {
    /// Displayed text by row, then column.
    pub(crate) text: Vec<Vec<String>>,
    /// `(rowSpan, gridSpan)` of an anchor or a plain cell.
    spans: Vec<Vec<(usize, usize)>>,
    /// `(hMerge, vMerge)` of a cell a merge covers.
    covered: Vec<Vec<Option<(bool, bool)>>>,
}

impl TableLayout {
    pub(crate) fn of(dataset: &Dataset, merges: &[Merge]) -> Result<Self, NativeRefusal> {
        let cols = dataset.columns.len();
        let missing = dataset.missing.clone().unwrap_or_default();
        let mut text: Vec<Vec<String>> = vec![dataset.columns.iter().map(header).collect()];
        for row in &dataset.rows {
            if row.len() != cols {
                return Err(NativeRefusal::Invalid("dataset is not rectangular"));
            }
            text.push(
                row.iter()
                    .zip(&dataset.columns)
                    .map(|(cell, column)| match cell {
                        Cell::Missing => missing.clone(),
                        Cell::Number(value) => column.display(*value),
                        Cell::Text(text) | Cell::Date(text) => text.clone(),
                    })
                    .collect(),
            );
        }
        let rows = text.len();
        let mut covered = vec![vec![None::<(bool, bool)>; cols]; rows];
        let mut spans = vec![vec![(1usize, 1usize); cols]; rows];
        for merge in merges {
            if merge.rows == 0
                || merge.cols == 0
                || merge.rows.saturating_mul(merge.cols) < 2
                || merge.row >= rows
                || merge.col >= cols
                || merge.rows > rows - merge.row
                || merge.cols > cols - merge.col
            {
                return Err(NativeRefusal::UnsupportedMergeTopology(
                    "merge outside the grid",
                ));
            }
            for r in merge.row..merge.row + merge.rows {
                for c in merge.col..merge.col + merge.cols {
                    if covered[r][c].is_some() || spans[r][c] != (1, 1) {
                        return Err(NativeRefusal::UnsupportedMergeTopology(
                            "overlapping merges",
                        ));
                    }
                    if (r, c) == (merge.row, merge.col) {
                        continue;
                    }
                    covered[r][c] = Some((c > merge.col, r > merge.row));
                }
            }
            spans[merge.row][merge.col] = (merge.rows, merge.cols);
        }
        Ok(Self {
            text,
            spans,
            covered,
        })
    }

    pub(crate) fn rows(&self) -> usize {
        self.text.len()
    }

    pub(crate) fn cols(&self) -> usize {
        self.text.first().map_or(0, Vec::len)
    }

    /// The cells that show their text, each over its whole merged
    /// rectangle: `(row, col, rows, cols, text)`. A covered cell shows none.
    pub(crate) fn shown(&self) -> impl Iterator<Item = (usize, usize, usize, usize, &str)> + '_ {
        self.text.iter().enumerate().flat_map(move |(r, line)| {
            line.iter().enumerate().filter_map(move |(c, text)| {
                let (rows, cols) = self.spans[r][c];
                self.covered[r][c]
                    .is_none()
                    .then_some((r, c, rows, cols, text.as_str()))
            })
        })
    }
}

/// `total` EMU shared by `count` grid columns or rows as creation writes
/// them: equal shares, the last taking the remainder. `None` when there is
/// no line or a share would be under one EMU.
pub(crate) fn grid(total: i64, count: usize) -> Option<Vec<i64>> {
    let lines = i64::try_from(count).ok()?;
    if lines == 0 || total < lines {
        return None;
    }
    let share = total / lines;
    Some(
        (0..count)
            .map(|at| {
                if at + 1 == count {
                    total - share * (lines - 1)
                } else {
                    share
                }
            })
            .collect(),
    )
}

/// A table frame: a header row of column names, then the dataset rows.
pub(super) fn frame_xml(
    frame: &Frame<'_>,
    dataset: &Dataset,
    merges: &[Merge],
) -> Result<String, NativeRefusal> {
    let layout = TableLayout::of(dataset, merges)?;
    let (Some(widths), Some(heights)) = (
        grid(frame.bounds.cx, layout.cols()),
        grid(frame.bounds.cy, layout.rows()),
    ) else {
        return Err(NativeRefusal::Invalid("table bounds"));
    };
    let mut xml = String::from("<a:tbl><a:tblPr firstRow=\"1\"/><a:tblGrid>");
    for w in &widths {
        xml.push_str(&format!("<a:gridCol w=\"{w}\"/>"));
    }
    xml.push_str("</a:tblGrid>");
    for (r, line) in layout.text.iter().enumerate() {
        xml.push_str(&format!("<a:tr h=\"{}\">", heights[r]));
        for (c, text) in line.iter().enumerate() {
            let mut attrs = String::new();
            match (layout.covered[r][c], layout.spans[r][c]) {
                (Some((h_merge, v_merge)), _) => {
                    if h_merge {
                        attrs.push_str(" hMerge=\"1\"");
                    }
                    if v_merge {
                        attrs.push_str(" vMerge=\"1\"");
                    }
                }
                (None, (row_span, grid_span)) => {
                    if grid_span > 1 {
                        attrs.push_str(&format!(" gridSpan=\"{grid_span}\""));
                    }
                    if row_span > 1 {
                        attrs.push_str(&format!(" rowSpan=\"{row_span}\""));
                    }
                }
            }
            let body = if text.is_empty() {
                "<a:p/>".to_owned()
            } else {
                format!("<a:p><a:r><a:t>{}</a:t></a:r></a:p>", escape_text(text))
            };
            xml.push_str(&format!(
                "<a:tc{attrs}><a:txBody><a:bodyPr/><a:lstStyle/>{body}</a:txBody><a:tcPr/></a:tc>"
            ));
        }
        xml.push_str("</a:tr>");
    }
    xml.push_str("</a:tbl>");
    Ok(graphic_frame(frame, TABLE_URI, &xml))
}

/// Append a frame to the slide's shape tree; its id must be new in the slide.
pub(crate) fn insert_frame(
    package: &mut Package,
    slide: &str,
    id: u32,
    xml: &str,
) -> Result<(), NativeRefusal> {
    let bytes = package
        .part(slide)?
        .ok_or(NativeRefusal::Stale("slide part missing"))?;
    let tree = XmlTree::parse(&bytes, package.resources())?;
    let id = id.to_string();
    if tree
        .nodes
        .iter()
        .any(|node| node.is(PML, "cNvPr") && node.attr("id") == Some(id.as_str()))
    {
        return Err(NativeRefusal::Invalid("shape id already used in the slide"));
    }
    let tree_node = tree
        .nodes
        .iter()
        .find(|node| node.is(PML, "spTree") && !node.empty)
        .ok_or(NativeRefusal::Stale("slide has no shape tree"))?;
    let at = tree_node.content.end;
    let mut out = bytes[..at].to_vec();
    out.extend_from_slice(xml.as_bytes());
    out.extend_from_slice(&bytes[at..]);
    package.replace_xml_part(slide, out)?;
    Ok(())
}

/// Nodes inside `index`, in document order.
pub(super) fn within(tree: &XmlTree, index: usize) -> impl Iterator<Item = (usize, &Node)> {
    let span = tree.nodes[index].span.clone();
    tree.nodes
        .iter()
        .enumerate()
        .skip(index + 1)
        .take_while(move |(_, node)| node.span.start < span.end)
}

fn flag(node: &Node, name: &str) -> bool {
    matches!(node.attr(name), Some("1" | "true"))
}

fn span(node: &Node, name: &str) -> Result<usize, NativeRefusal> {
    node.attr(name).map_or(Ok(1), |value| {
        value
            .parse::<usize>()
            .ok()
            .filter(|span| *span >= 1)
            .ok_or(NativeRefusal::UnsupportedMergeTopology("invalid span"))
    })
}

/// Replace one cell's text, keeping what the text does not change. A cell
/// a merge covers takes its own text under the merge. The `a:fld` types a
/// field-aware cut removed whole (FIX 12227), if it did, ride back for the
/// outcome.
pub(super) fn set_cell(
    package: &mut Package,
    slide: &str,
    table: u32,
    (row, col): (usize, usize),
    expected: &str,
    value: &str,
) -> Result<Vec<String>, NativeRefusal> {
    let bytes = package
        .part(slide)?
        .ok_or(NativeRefusal::Stale("slide part missing"))?;
    let tree = XmlTree::parse(&bytes, package.resources())?;
    let id = table.to_string();
    let frame = tree
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.is(PML, "graphicFrame"))
        .find(|(index, _)| {
            within(&tree, *index)
                .find(|(_, node)| node.is(PML, "cNvPr"))
                .is_some_and(|(_, node)| node.attr("id") == Some(id.as_str()))
        })
        .map(|(index, _)| index)
        .ok_or(NativeRefusal::Stale("no table frame with that id"))?;
    let tbl = within(&tree, frame)
        .find(|(_, node)| node.is(DML, "tbl"))
        .map(|(index, _)| index)
        .ok_or(NativeRefusal::Stale("no table frame with that id"))?;
    let cols = tree.child(tbl, DML, "tblGrid")?.map_or(0, |(grid, _)| {
        tree.children(grid)
            .filter(|(_, node)| node.is(DML, "gridCol"))
            .count()
    });
    let cells: Vec<Vec<usize>> = tree
        .children(tbl)
        .filter(|(_, node)| node.is(DML, "tr"))
        .map(|(tr, _)| {
            tree.children(tr)
                .filter(|(_, node)| node.is(DML, "tc"))
                .map(|(tc, _)| tc)
                .collect()
        })
        .collect();
    if cols == 0 || cells.iter().any(|line| line.len() != cols) {
        return Err(NativeRefusal::UnsupportedMergeTopology(
            "a row does not fill the grid",
        ));
    }
    let mut owned = vec![vec![false; cols]; cells.len()];
    for (r, line) in cells.iter().enumerate() {
        for (c, &tc) in line.iter().enumerate() {
            let node = &tree.nodes[tc];
            if flag(node, "hMerge") || flag(node, "vMerge") {
                continue;
            }
            let (rows, span_cols) = (span(node, "rowSpan")?, span(node, "gridSpan")?);
            if rows > cells.len() - r || span_cols > cols.saturating_sub(c) {
                return Err(NativeRefusal::UnsupportedMergeTopology(
                    "merge outside the grid",
                ));
            }
            for (rr, row_cells) in cells.iter().enumerate().skip(r).take(rows) {
                for (cc, &other) in row_cells.iter().enumerate().skip(c).take(span_cols) {
                    if (rr, cc) == (r, c) {
                        continue;
                    }
                    let other = &tree.nodes[other];
                    let marked = match (rr > r, cc > c) {
                        (false, _) => flag(other, "hMerge"),
                        (true, false) => flag(other, "vMerge"),
                        (true, true) => flag(other, "hMerge") || flag(other, "vMerge"),
                    };
                    if !marked || owned[rr][cc] {
                        return Err(NativeRefusal::UnsupportedMergeTopology(
                            "continuation flags disagree with spans",
                        ));
                    }
                    owned[rr][cc] = true;
                }
            }
        }
    }
    for (r, line) in cells.iter().enumerate() {
        for (c, &tc) in line.iter().enumerate() {
            let node = &tree.nodes[tc];
            if (flag(node, "hMerge") || flag(node, "vMerge")) != owned[r][c] {
                return Err(NativeRefusal::UnsupportedMergeTopology(
                    "a continuation cell has no anchor",
                ));
            }
        }
    }
    let tc = *cells
        .get(row)
        .and_then(|line| line.get(col))
        .ok_or(NativeRefusal::Stale("no such cell"))?;
    let (body, _) = tree
        .child(tc, DML, "txBody")?
        .ok_or(NativeRefusal::Stale("cell has no text body"))?;
    let paragraphs: Vec<(usize, &Node)> = tree
        .children(body)
        .filter(|(_, node)| node.is(DML, "p"))
        .collect();
    let (Some(&(first, first_node)), Some(&(_, last_node))) =
        (paragraphs.first(), paragraphs.last())
    else {
        return Err(NativeRefusal::Stale("cell has no paragraph"));
    };
    let current = paragraphs
        .iter()
        .map(|(index, _)| {
            within(&tree, *index)
                .filter(|(_, node)| node.is(DML, "t"))
                .map(|(_, node)| node.text.as_str())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");
    if current != expected {
        return Err(NativeRefusal::Stale("cell text changed"));
    }
    // The cell's text through the deck's retained text mapping (FIX 8595):
    // its paragraphs' and runs' properties, attributes, namespace bindings,
    // `a:endParaRPr` and the bytes between paragraphs are kept, and only the
    // changed text is written. Where that mapping refuses, a field-aware cut
    // is tried first (FIX 12227): each field the change covers whole goes,
    // the new text written into an adjacent run, only when the cell then
    // reads exactly the requested text. Otherwise the cell is rebuilt from
    // its first paragraph's and first run's properties, as it was before.
    let (out, cut_fields) = match crate::edit::cell_text_cut(&bytes, &tree, body, value) {
        Some((out, cut_fields)) => (out, cut_fields),
        None => (
            rebuilt(&bytes, &tree, body, (first, first_node), last_node, value)?,
            Vec::new(),
        ),
    };
    package.replace_xml_part(slide, out)?;
    Ok(cut_fields)
}

/// The cell's paragraphs replaced by `value`'s lines, each with the first
/// paragraph's `a:pPr` and the first run's `a:rPr`.
fn rebuilt(
    bytes: &[u8],
    tree: &XmlTree,
    body: usize,
    (first, first_node): (usize, &Node),
    last_node: &Node,
    value: &str,
) -> Result<Vec<u8>, NativeRefusal> {
    let piece = |node: Option<(usize, &Node)>| {
        node.map_or("", |(_, node)| {
            std::str::from_utf8(&bytes[node.span.clone()]).unwrap_or("")
        })
    };
    let p_pr = piece(tree.child(first, DML, "pPr")?);
    let r_pr = piece(
        within(tree, body)
            .find(|(_, node)| node.is(DML, "r"))
            .map(|(run, _)| tree.child(run, DML, "rPr"))
            .transpose()?
            .flatten(),
    );
    let p = first_node.qualified.as_str();
    let a = p.strip_suffix('p').unwrap_or("");
    let mut out = bytes[..first_node.span.start].to_vec();
    for line in value.split('\n') {
        let run = if line.is_empty() {
            String::new()
        } else {
            format!("<{a}r>{r_pr}<{a}t>{}</{a}t></{a}r>", escape_text(line))
        };
        out.extend_from_slice(format!("<{p}>{p_pr}{run}</{p}>").as_bytes());
    }
    out.extend_from_slice(&bytes[last_node.span.end..]);
    Ok(out)
}
