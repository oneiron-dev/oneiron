//! A written table's grid rewritten at export by row and column identity
//! (OF-510). Each row, column and cell the live table keeps is the retained
//! one its identity's binding names, wherever the order now puts it: a moved
//! or surviving row keeps its own height, cells and properties, and a
//! column its own width, never the ones of whatever held its old place.
//! Every cell's merge attributes are written again from the merges the
//! table draws, so no stale span or continuation flag survives a reshape.

use super::{close, frame_of, piece};
use crate::edit::xml::{self, A, P};
use crate::live::LiveError;
use crate::live::held::{children, table as held_table};
use crate::live::pptx::{
    TableBinding, TableBody, UNBOUND_GRID, WRITTEN_FRAME, WRITTEN_TABLE, positions,
};
use crate::native_patch::Merge;
use crate::ooxml::{Node, XmlTree, escape_text};
use crate::retained_opc::Package;
use std::ops::Range;

/// The merge attributes a cell's open tag is written without, then with
/// the ones the table draws.
const MERGE: &[&str] = &["gridSpan", "rowSpan", "hMerge", "vMerge"];

/// A cell's merge attributes: its spans when it anchors a merge, its
/// continuation flags when one covers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Flags {
    grid_span: usize,
    row_span: usize,
    h_merge: bool,
    v_merge: bool,
}

/// A cell no merge covers.
const PLAIN: Flags = Flags {
    grid_span: 1,
    row_span: 1,
    h_merge: false,
    v_merge: false,
};

impl Flags {
    /// The attributes a retained cell holds, as the native writer reads
    /// them.
    fn of(node: &Node) -> Self {
        Self {
            grid_span: held_table::span(node, "gridSpan"),
            row_span: held_table::span(node, "rowSpan"),
            h_merge: held_table::flag(node, "hMerge"),
            v_merge: held_table::flag(node, "vMerge"),
        }
    }

    /// The attributes as written, each preceded by a space.
    fn attributes(self) -> String {
        let mut out = String::new();
        if self.grid_span > 1 {
            out.push_str(&format!(r#" gridSpan="{}""#, self.grid_span));
        }
        if self.row_span > 1 {
            out.push_str(&format!(r#" rowSpan="{}""#, self.row_span));
        }
        if self.h_merge {
            out.push_str(r#" hMerge="1""#);
        }
        if self.v_merge {
            out.push_str(r#" vMerge="1""#);
        }
        out
    }

    /// Every cell's attributes in a `rows` by `cols` grid drawing `spans`,
    /// as the native writer writes a merge: the anchor its spans, a cell to
    /// its right `hMerge`, a cell below `vMerge`, one below and right both.
    fn grid(spans: &[Merge], rows: usize, cols: usize) -> Vec<Vec<Self>> {
        let mut out = vec![vec![PLAIN; cols]; rows];
        for span in spans {
            for (r, line) in out.iter_mut().enumerate().skip(span.row).take(span.rows) {
                for (c, cell) in line.iter_mut().enumerate().skip(span.col).take(span.cols) {
                    *cell = if (r, c) == (span.row, span.col) {
                        Self {
                            grid_span: span.cols,
                            row_span: span.rows,
                            ..PLAIN
                        }
                    } else {
                        Self {
                            h_merge: c > span.col,
                            v_merge: r > span.row,
                            ..PLAIN
                        }
                    };
                }
            }
        }
        out
    }
}

/// Rewrite the table in `slide`'s frame `native` to `wanted`, by identity.
/// `bound` names the identity at each grid row and column of the retained
/// XML: a kept column keeps its own `a:gridCol`, a kept row its own `a:tr`
/// (and what it holds besides cells), a kept cell its own `a:tc`. A new
/// column takes the last column's width; a new row the last row's height,
/// its cells their column's cell in the last row; a new cell in a kept row
/// its row's last cell's properties; each new cell its text and no other
/// merge attribute. Every cell's merge attributes become `spans`'. The
/// caller writes the kept cells' changed text after. With `fit`, the
/// frame's extent becomes the grid's, its columns' widths by its rows'
/// heights, as PowerPoint lays a table out; the extent written, when it
/// changed.
pub(in crate::live) fn table(
    package: &mut Package,
    slide: &str,
    native: u32,
    wanted: &TableBody,
    bound: &TableBinding,
    spans: &[Merge],
    fit: bool,
) -> Result<Option<(i64, i64)>, LiveError> {
    let refuse = LiveError::Invalid(WRITTEN_TABLE);
    let (bytes, tree) = xml::read(package, slide)?;
    let frame = frame_of(&tree, native).ok_or(LiveError::Invalid(WRITTEN_FRAME))?;
    let tbl = held_table::table_of(&tree, frame).ok_or(LiveError::Invalid(WRITTEN_FRAME))?;
    let (height, cols) = wanted.shape();
    if height == 0 || cols == 0 {
        return Err(refuse);
    }
    let grid = xml::child(&tree, tbl, A, "tblGrid").ok_or(refuse.clone())?;
    let widths: Vec<usize> = children(&tree, grid, A, "gridCol").collect();
    let rows: Vec<usize> = children(&tree, tbl, A, "tr").collect();
    let (Some(&last_col), Some(&last_row)) = (widths.last(), rows.last()) else {
        return Err(refuse);
    };
    if bound.rows.len() != rows.len() || bound.columns.len() != widths.len() {
        return Err(LiveError::Invalid(UNBOUND_GRID));
    }
    let row_at = positions(&bound.rows);
    let col_at = positions(&bound.columns);
    // Each wanted row's and column's retained index, `None` for a new one.
    let kept_rows: Vec<Option<usize>> = wanted
        .rows
        .iter()
        .map(|row| row_at.get(row).copied())
        .collect();
    let kept_cols: Vec<Option<usize>> = wanted
        .columns
        .iter()
        .map(|column| col_at.get(column).copied())
        .collect();
    let col_name = tree.nodes[last_col].qualified.clone();
    let mut grid_xml = xml::open_tag(&bytes, &tree.nodes[grid]);
    for kept in &kept_cols {
        match kept {
            Some(at) => grid_xml.extend_from_slice(piece(&bytes, &tree, widths[*at])),
            None => grid_xml.extend(
                format!(
                    r#"<{col_name} w="{}"/>"#,
                    xml::escape_attribute(tree.nodes[last_col].attr("w").unwrap_or("0"))
                )
                .into_bytes(),
            ),
        }
    }
    grid_xml.extend(close(&tree.nodes[grid]));
    let flags = Flags::grid(spans, height, cols);
    let mut rows_xml = Vec::new();
    for ((row, kept), flags) in wanted.rows.iter().zip(&kept_rows).zip(&flags) {
        let tr = kept.map_or(last_row, |at| rows[at]);
        let cells: Vec<usize> = children(&tree, tr, A, "tc").collect();
        rows_xml.extend(xml::open_tag(&bytes, &tree.nodes[tr]));
        for ((column, kept_col), want) in wanted.columns.iter().zip(&kept_cols).zip(flags) {
            let own = kept_col.and_then(|at| cells.get(at)).copied();
            match (kept, own) {
                (Some(_), Some(tc)) => rows_xml.extend(kept_cell(&bytes, &tree, tc, *want)),
                _ => {
                    let template = own.or(cells.last().copied()).ok_or(refuse.clone())?;
                    let text = wanted.cell(*row, *column);
                    rows_xml.extend(new_cell(&bytes, &tree, template, text, *want));
                }
            }
        }
        // A kept row keeps what it holds besides cells (its identity
        // extension); a new row copies none of the last row's.
        if kept.is_some() {
            for &child in &tree.nodes[tr].children {
                if !tree.nodes[child].is(A, "tc") {
                    rows_xml.extend_from_slice(piece(&bytes, &tree, child));
                }
            }
        }
        rows_xml.extend(close(&tree.nodes[tr]));
    }
    let mut out = xml::open_tag(&bytes, &tree.nodes[tbl]);
    let mut placed = false;
    for &child in &tree.nodes[tbl].children {
        let node = &tree.nodes[child];
        if node.is(A, "tblGrid") {
            out.extend_from_slice(&grid_xml);
        } else if node.is(A, "tr") {
            if !placed {
                out.extend_from_slice(&rows_xml);
                placed = true;
            }
        } else {
            out.extend_from_slice(piece(&bytes, &tree, child));
        }
    }
    out.extend(close(&tree.nodes[tbl]));
    let mut edits = vec![(tree.nodes[tbl].span.clone(), out)];
    // The frame's extent: each column's own width (a new one's the last
    // column's) summed, by each row's own height (a new one's the last
    // row's) summed.
    let size = |at: usize, name: &str| -> Option<i64> {
        tree.nodes[at].attr(name)?.trim().parse::<i64>().ok()
    };
    let wide = kept_cols.iter().try_fold(0_i64, |sum, kept| {
        sum.checked_add(size(kept.map_or(last_col, |at| widths[at]), "w")?)
    });
    let high = kept_rows.iter().try_fold(0_i64, |sum, kept| {
        sum.checked_add(size(kept.map_or(last_row, |at| rows[at]), "h")?)
    });
    let ext = xml::path(&tree, frame, &[(P, "xfrm"), (A, "ext")]);
    let fitted = match (fit, wide, high, ext) {
        (true, Some(cx), Some(cy), Some(ext))
            if size(ext, "cx") != Some(cx) || size(ext, "cy") != Some(cy) =>
        {
            let node = &tree.nodes[ext];
            edits.push(xml::set_attribute(&bytes, node, "cx", &cx.to_string()));
            edits.push(xml::set_attribute(&bytes, node, "cy", &cy.to_string()));
            Some((cx, cy))
        }
        _ => None,
    };
    let next = xml::splice(&bytes, edits)?;
    package.replace_xml_part(slide, next)?;
    let read = xml::read(package, slide)?.1;
    let shape = frame_of(&read, native)
        .and_then(|frame| held_table::table_cells(&read, frame))
        .map(|grid| (grid.len(), grid.iter().all(|row| row.len() == cols)));
    if shape != Some((height, true)) {
        return Err(refuse);
    }
    Ok(fitted)
}

/// `node`'s open tag without the named attributes.
fn open_without(bytes: &[u8], node: &Node, names: &[&str]) -> Vec<u8> {
    let open = xml::open_tag(bytes, node);
    let base = node.span.start;
    let mut cuts: Vec<Range<usize>> = names
        .iter()
        .filter_map(|name| node.attr_spans.get(*name))
        .map(|span| {
            let mut start = span.start - base;
            while start > 0 && open[start - 1].is_ascii_whitespace() {
                start -= 1;
            }
            start..span.end - base
        })
        .collect();
    cuts.sort_by_key(|cut| cut.start);
    let mut out = Vec::with_capacity(open.len());
    let mut at = 0;
    for cut in cuts {
        if cut.start >= at && cut.end <= open.len() {
            out.extend_from_slice(&open[at..cut.start]);
            at = cut.end;
        }
    }
    out.extend_from_slice(&open[at..]);
    out
}

/// `node`'s open tag with `want`'s merge attributes in place of its own.
fn open_with(bytes: &[u8], node: &Node, want: Flags) -> Vec<u8> {
    let mut out = open_without(bytes, node, MERGE);
    out.pop();
    out.extend(want.attributes().into_bytes());
    out.push(b'>');
    out
}

/// A kept cell: its own bytes, its open tag written again only where its
/// merge attributes are not `want`'s.
fn kept_cell(bytes: &[u8], tree: &XmlTree, tc: usize, want: Flags) -> Vec<u8> {
    let node = &tree.nodes[tc];
    if Flags::of(node) == want {
        return piece(bytes, tree, tc).to_vec();
    }
    let mut out = open_with(bytes, node, want);
    if !node.empty {
        out.extend_from_slice(&bytes[node.open_end..node.content.end]);
    }
    out.extend(close(node));
    out
}

/// A new cell from a template cell: its open tag with `want`'s merge
/// attributes, its body and first paragraph's properties, its first run's
/// properties on each line of `text`, and its cell properties.
fn new_cell(bytes: &[u8], tree: &XmlTree, tc: usize, text: &str, want: Flags) -> Vec<u8> {
    let node = &tree.nodes[tc];
    let a = xml::prefix(node);
    let q = |name: &str| xml::qualify(a, name);
    let part = |at: Option<usize>| at.map_or(&[][..], |at| piece(bytes, tree, at));
    let body = xml::child(tree, tc, A, "txBody");
    let first = body.and_then(|body| xml::child(tree, body, A, "p"));
    let body_pr = body.and_then(|body| xml::child(tree, body, A, "bodyPr"));
    let list = body.and_then(|body| xml::child(tree, body, A, "lstStyle"));
    let p_pr = first.and_then(|p| xml::child(tree, p, A, "pPr"));
    let end = first.and_then(|p| xml::child(tree, p, A, "endParaRPr"));
    let r_pr = body
        .and_then(|body| {
            crate::live::held::within(tree, body).find(|&at| tree.nodes[at].is(A, "r"))
        })
        .and_then(|run| xml::child(tree, run, A, "rPr"));
    let mut out = open_with(bytes, node, want);
    out.extend(format!("<{}>", q("txBody")).into_bytes());
    match body_pr {
        Some(at) => out.extend_from_slice(piece(bytes, tree, at)),
        None => out.extend(format!("<{}/>", q("bodyPr")).into_bytes()),
    }
    out.extend_from_slice(part(list));
    for line in text.split('\n') {
        out.extend(format!("<{}>", q("p")).into_bytes());
        out.extend_from_slice(part(p_pr));
        if !line.is_empty() {
            out.extend(format!("<{}>", q("r")).into_bytes());
            out.extend_from_slice(part(r_pr));
            out.extend(
                format!(
                    "<{t}>{}</{t}></{r}>",
                    escape_text(line),
                    t = q("t"),
                    r = q("r")
                )
                .into_bytes(),
            );
        }
        out.extend_from_slice(part(end));
        out.extend(format!("</{}>", q("p")).into_bytes());
    }
    out.extend(format!("</{}>", q("txBody")).into_bytes());
    out.extend_from_slice(part(xml::child(tree, tc, A, "tcPr")));
    out.extend(close(node));
    out
}
