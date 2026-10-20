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

/// A table frame: a header row of column names, then the dataset rows.
pub(super) fn frame_xml(
    frame: &Frame<'_>,
    dataset: &Dataset,
    merges: &[Merge],
) -> Result<String, NativeRefusal> {
    let cols = dataset.columns.len();
    // `None` is a missing cell; it shows the dataset's missing meaning.
    let mut grid: Vec<Vec<Option<String>>> =
        vec![dataset.columns.iter().map(|c| Some(header(c))).collect()];
    for row in &dataset.rows {
        if row.len() != cols {
            return Err(NativeRefusal::Invalid("dataset is not rectangular"));
        }
        grid.push(
            row.iter()
                .zip(&dataset.columns)
                .map(|(cell, column)| match cell {
                    Cell::Missing => None,
                    Cell::Number(value) => Some(column.display(*value)),
                    Cell::Text(text) | Cell::Date(text) => Some(text.clone()),
                })
                .collect(),
        );
    }
    let rows = grid.len();
    let (Ok(cx), Ok(cy)) = (i64::try_from(cols), i64::try_from(rows)) else {
        return Err(NativeRefusal::Invalid("table size"));
    };
    if cols == 0 || frame.bounds.cx < cx || frame.bounds.cy < cy {
        return Err(NativeRefusal::Invalid("table bounds"));
    }
    // (anchor, rowSpan, gridSpan) for an anchor; (hMerge, vMerge) otherwise.
    let mut role = vec![vec![None::<(bool, bool)>; cols]; rows];
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
                if role[r][c].is_some() || spans[r][c] != (1, 1) {
                    return Err(NativeRefusal::UnsupportedMergeTopology(
                        "overlapping merges",
                    ));
                }
                if (r, c) == (merge.row, merge.col) {
                    continue;
                }
                role[r][c] = Some((c > merge.col, r > merge.row));
            }
        }
        spans[merge.row][merge.col] = (merge.rows, merge.cols);
    }
    let width = frame.bounds.cx / cx;
    let height = frame.bounds.cy / cy;
    let mut xml = String::from("<a:tbl><a:tblPr firstRow=\"1\"/><a:tblGrid>");
    for c in 0..cols {
        let w = if c + 1 == cols {
            frame.bounds.cx - width * (cx - 1)
        } else {
            width
        };
        xml.push_str(&format!("<a:gridCol w=\"{w}\"/>"));
    }
    xml.push_str("</a:tblGrid>");
    for (r, line) in grid.iter().enumerate() {
        let h = if r + 1 == rows {
            frame.bounds.cy - height * (cy - 1)
        } else {
            height
        };
        xml.push_str(&format!("<a:tr h=\"{h}\">"));
        for (c, text) in line.iter().enumerate() {
            let mut attrs = String::new();
            match (role[r][c], spans[r][c]) {
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
            let text = text
                .as_deref()
                .or(dataset.missing.as_deref())
                .unwrap_or_default();
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
    let tree = XmlTree::parse(&bytes, package.limits().xml)?;
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

/// Replace one cell's paragraphs, keeping the first paragraph's and first
/// run's properties. A cell a merge covers takes its own text under the
/// merge.
pub(super) fn set_cell(
    package: &mut Package,
    slide: &str,
    table: u32,
    (row, col): (usize, usize),
    expected: &str,
    value: &str,
) -> Result<(), NativeRefusal> {
    let bytes = package
        .part(slide)?
        .ok_or(NativeRefusal::Stale("slide part missing"))?;
    let tree = XmlTree::parse(&bytes, package.limits().xml)?;
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
    let piece = |node: Option<(usize, &Node)>| {
        node.map_or("", |(_, node)| {
            std::str::from_utf8(&bytes[node.span.clone()]).unwrap_or("")
        })
    };
    let p_pr = piece(tree.child(first, DML, "pPr")?);
    let r_pr = piece(
        within(&tree, body)
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
    package.replace_xml_part(slide, out)?;
    Ok(())
}
