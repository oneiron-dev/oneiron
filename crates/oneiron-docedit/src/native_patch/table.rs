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
    let (Some(&(_, first_node)), Some(&(_, last_node))) = (paragraphs.first(), paragraphs.last())
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
    // its first paragraph/run template, except same-count lines and
    // count-changed unchanged outer and paired middle paragraphs reuse
    // their actual properties.
    // Unsupported coverage/properties fall back to the existing templates.
    let (out, cut_fields) = match crate::edit::cell_text_cut(&bytes, &tree, body, value) {
        Some((out, cut_fields)) => (out, cut_fields),
        None => (
            rebuilt(&bytes, &tree, body, &paragraphs, value)?,
            within(&tree, body)
                .filter(|(_, node)| {
                    node.is(DML, "fld")
                        && node.span.start >= first_node.span.start
                        && node.span.end <= last_node.span.end
                })
                .filter_map(|(_, node)| node.attr("type").map(str::to_owned))
                .collect(),
        ),
    };
    package.replace_xml_part(slide, out)?;
    Ok(cut_fields)
}

/// Rebuild with the first paragraph/run template (else the first field's).
/// Same-count lines keep their same-index paragraph properties and
/// each direct run/field/br's properties on the common character prefix/suffix
/// as static runs and breaks; the first line's replacement keeps the global template,
/// later lines use their paragraph's first run/field (else global).
/// With different counts, unchanged common whole-paragraph prefix/suffix
/// lines and paired middle lines keep their original paragraph and static
/// run properties; each paired middle replacement keeps the global run
/// template. Unpaired added lines use the first template. Unsupported
/// coverage or properties use the actual one-template render for same-count
/// later lines, then first; same-count first, count-changed outer and paired
/// middle lines fall to first.
/// Copied properties keep namespace bindings; removed field types are reported.
/// Whole field-free opaque retained segments keep their original XML and
/// namespace bindings.
/// A whole unchanged field-free paragraph keeps its original paragraph XML
/// bytes in place under the same direct text body when its full native text
/// (direct breaks as U+000B) equals the requested line and it holds zero
/// descendant DrawingML fields; omitted breaks still drop through the
/// existing prefix/suffix path.
/// Same-count lines also keep each original field-free inter-paragraph gap's
/// exact bytes in place when zero DrawingML `fld` nodes sit wholly inside
/// that gap; count-changing lines keep only matched outer head/tail gaps
/// wholly between two original head or two original tail paragraphs under
/// the same gate; gaps holding any such field and all middle, boundary,
/// added, removed or unmatched gaps keep the existing drop so field-removal
/// receipts stay truthful.
fn rebuilt(
    bytes: &[u8],
    tree: &XmlTree,
    body: usize,
    paragraphs: &[(usize, &Node)],
    value: &str,
) -> Result<Vec<u8>, NativeRefusal> {
    let (first, first_node) = paragraphs[0];
    let last_node = paragraphs[paragraphs.len() - 1].1;
    let piece = |node: Option<(usize, &Node)>| {
        node.map_or("", |(_, node)| {
            std::str::from_utf8(&bytes[node.span.clone()]).unwrap_or("")
        })
    };
    let source_run = within(tree, body)
        .find(|(_, node)| node.is(DML, "r"))
        .or_else(|| within(tree, body).find(|(_, node)| node.is(DML, "fld")));
    let run_xml = |selected: Option<(usize, &Node)>,
                   para_node: &Node,
                   text: &str|
     -> Result<String, NativeRefusal> {
        let r_pr = piece(
            selected
                .map(|(run, _)| tree.child(run, DML, "rPr"))
                .transpose()?
                .flatten(),
        );
        let (r, t, run_bindings) = match selected {
            Some((at, node)) => (
                node.child_name("r"),
                node.child_name("t"),
                format!(
                    "{}{}",
                    crate::edit::xml::inherited_bindings(bytes, tree, at),
                    crate::edit::xml::own_bindings(bytes, node),
                ),
            ),
            None => (
                para_node.child_name("r"),
                para_node.child_name("t"),
                String::new(),
            ),
        };
        let static_run = |part: &str| {
            format!(
                "<{r}{run_bindings}>{r_pr}<{t}>{}</{t}></{r}>",
                escape_text(part)
            )
        };
        if text.is_empty() {
            Ok(String::new())
        } else if !text.contains('\u{b}') {
            Ok(static_run(text))
        } else {
            let br = match selected {
                Some((_, node)) => node.child_name("br"),
                None => para_node.child_name("br"),
            };
            let line_break = format!("<{br}{run_bindings}>{r_pr}</{br}>");
            let mut out = String::new();
            for (index, part) in text.split('\u{b}').enumerate() {
                if index > 0 {
                    out.push_str(&line_break);
                }
                if !part.is_empty() {
                    out.push_str(&static_run(part));
                }
            }
            Ok(out)
        }
    };
    let render = |paragraph: (usize, &Node),
                  selected: Option<(usize, &Node)>,
                  line: &str|
     -> Result<String, NativeRefusal> {
        let (para, para_node) = paragraph;
        let p_pr = piece(tree.child(para, DML, "pPr")?);
        let run = run_xml(selected, para_node, line)?;
        let end = piece(tree.child(para, DML, "endParaRPr")?);
        let p = para_node.qualified.as_str();
        let p_bindings = crate::edit::xml::own_bindings(bytes, para_node);
        Ok(format!("<{p}{p_bindings}>{p_pr}{run}{end}</{p}>"))
    };
    let styled = |paragraph: (usize, &Node),
                  selected: Option<(usize, &Node)>,
                  line: &str|
     -> Option<String> {
        let (para, para_node) = paragraph;
        let p_pr = piece(tree.child(para, DML, "pPr").ok()?);
        let end = piece(tree.child(para, DML, "endParaRPr").ok()?);
        let p = para_node.qualified.as_str();
        let p_bindings = crate::edit::xml::own_bindings(bytes, para_node);
        let segments: Vec<(usize, &Node, Vec<char>)> = tree
            .children(para)
            .filter(|(_, node)| !node.is(DML, "pPr") && !node.is(DML, "endParaRPr"))
            .filter_map(|(at, node)| {
                if node.is(DML, "br") {
                    Some((at, node, vec!['\u{b}']))
                } else {
                    let text: Vec<char> = within(tree, at)
                        .filter(|(_, node)| node.is(DML, "t"))
                        .flat_map(|(_, node)| node.text.chars())
                        .collect();
                    if node.is(DML, "r") || node.is(DML, "fld") || !text.is_empty() {
                        Some((at, node, text))
                    } else {
                        None
                    }
                }
            })
            .collect();
        let old: Vec<char> = within(tree, para)
            .flat_map(|(_, node)| {
                if node.is(DML, "br") && node.parent == Some(para) {
                    vec!['\u{b}']
                } else if node.is(DML, "t") {
                    node.text.chars().collect::<Vec<char>>()
                } else {
                    Vec::new()
                }
            })
            .collect();
        if !segments
            .iter()
            .flat_map(|(_, _, text)| text.iter())
            .eq(old.iter())
        {
            return None;
        }
        let new: Vec<char> = line.chars().collect();
        if old == new && !within(tree, para).any(|(_, node)| node.is(DML, "fld")) {
            return Some(
                std::str::from_utf8(&bytes[para_node.span.clone()])
                    .ok()?
                    .to_owned(),
            );
        }
        let mut prefix = 0;
        while prefix < old.len() && prefix < new.len() && old[prefix] == new[prefix] {
            prefix += 1;
        }
        let mut suffix = 0;
        while suffix < old.len() - prefix
            && suffix < new.len() - prefix
            && old[old.len() - 1 - suffix] == new[new.len() - 1 - suffix]
        {
            suffix += 1;
        }
        {
            let mut position = 0;
            for (at, node, text) in &segments {
                let start = position;
                let end = position + text.len();
                if !node.is(DML, "r") && !node.is(DML, "fld") && !node.is(DML, "br") {
                    if within(tree, *at).any(|(_, node)| node.is(DML, "fld")) {
                        return None;
                    }
                    if end > prefix && start < old.len() - suffix {
                        return None;
                    }
                }
                position = end;
            }
        }
        let retained_runs = |from: usize, to: usize| -> Option<String> {
            let mut runs = String::new();
            let mut position = 0;
            for (at, node, text) in &segments {
                let start = position.max(from);
                let end = (position + text.len()).min(to);
                if start < end {
                    if node.is(DML, "r") || node.is(DML, "fld") || node.is(DML, "br") {
                        let part: String = text[start - position..end - position].iter().collect();
                        runs.push_str(&run_xml(Some((*at, *node)), para_node, &part).ok()?);
                    } else {
                        let raw = std::str::from_utf8(&bytes[node.span.clone()]).ok()?;
                        let mut owned = raw.to_owned();
                        let bindings = crate::edit::xml::inherited_bindings(bytes, tree, *at);
                        owned.insert_str(node.open_end - node.span.start - 1, &bindings);
                        runs.push_str(&owned);
                    }
                }
                position += text.len();
            }
            Some(runs)
        };
        let head = retained_runs(0, prefix)?;
        let middle = if prefix + suffix == new.len() {
            String::new()
        } else {
            let text: String = new[prefix..new.len() - suffix].iter().collect();
            run_xml(selected, para_node, &text).ok()?
        };
        let tail = retained_runs(old.len() - suffix, old.len())?;
        Some(format!(
            "<{p}{p_bindings}>{p_pr}{head}{middle}{tail}{end}</{p}>"
        ))
    };
    let paragraph_run = |para: usize| {
        within(tree, para)
            .find(|(_, node)| node.is(DML, "r"))
            .or_else(|| within(tree, para).find(|(_, node)| node.is(DML, "fld")))
            .or(source_run)
    };
    let new_count = value.split('\n').count();
    let same_count = paragraphs.len() == new_count;
    let (head, tail) = if same_count {
        (0, 0)
    } else {
        let paragraph_text = |para: usize, include_breaks: bool| {
            within(tree, para)
                .filter(|(_, node)| {
                    node.is(DML, "t")
                        || include_breaks && node.is(DML, "br") && node.parent == Some(para)
                })
                .map(|(_, node)| {
                    if node.is(DML, "br") {
                        "\u{b}"
                    } else {
                        node.text.as_str()
                    }
                })
                .collect::<String>()
        };
        let mut head = 0;
        for ((para, _), line) in paragraphs.iter().zip(value.split('\n')) {
            if paragraph_text(*para, line.contains('\u{b}')) != line {
                break;
            }
            head += 1;
        }
        let mut tail = 0;
        let remaining = (paragraphs.len() - head).min(new_count - head);
        for ((para, _), line) in paragraphs
            .iter()
            .rev()
            .zip(value.split('\n').rev())
            .take(remaining)
        {
            if paragraph_text(*para, line.contains('\u{b}')) != line {
                break;
            }
            tail += 1;
        }
        (head, tail)
    };
    let paired = (paragraphs.len() - head - tail).min(new_count - head - tail);
    let mut out = bytes[..first_node.span.start].to_vec();
    for (index, line) in value.split('\n').enumerate() {
        let gap_index = if index > 0 && (same_count || index < head) {
            Some(index)
        } else if !same_count && index > new_count - tail {
            Some(paragraphs.len() - (new_count - index))
        } else {
            None
        };
        if let Some(original) = gap_index {
            let gap_start = paragraphs[original - 1].1.span.end;
            let gap_end = paragraphs[original].1.span.start;
            let gap_has_field = within(tree, body).any(|(_, node)| {
                node.is(DML, "fld") && node.span.start >= gap_start && node.span.end <= gap_end
            });
            if !gap_has_field {
                out.extend_from_slice(&bytes[gap_start..gap_end]);
            }
        }
        let rendered = if same_count && index == 0 {
            match styled((first, first_node), source_run, line) {
                Some(xml) => xml,
                None => render((first, first_node), source_run, line)?,
            }
        } else if same_count && index > 0 {
            let actual = paragraphs[index];
            let actual_run = paragraph_run(actual.0);
            match styled(actual, actual_run, line) {
                Some(xml) => xml,
                None => match render(actual, actual_run, line) {
                    Ok(xml) => xml,
                    Err(_) => render((first, first_node), source_run, line)?,
                },
            }
        } else if !same_count && (index < head || index >= new_count - tail) {
            let actual = if index < head {
                paragraphs[index]
            } else {
                paragraphs[paragraphs.len() - (new_count - index)]
            };
            match styled(actual, paragraph_run(actual.0), line) {
                Some(xml) => xml,
                None => render((first, first_node), source_run, line)?,
            }
        } else if !same_count && index >= head && index < head + paired {
            match styled(paragraphs[index], source_run, line) {
                Some(xml) => xml,
                None => render((first, first_node), source_run, line)?,
            }
        } else {
            render((first, first_node), source_run, line)?
        };
        out.extend_from_slice(rendered.as_bytes());
    }
    out.extend_from_slice(&bytes[last_node.span.end..]);
    Ok(out)
}
