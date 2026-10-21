//! Multi-level categories (`c:multiLvlStrRef`, FIX 3493): a hierarchy's
//! cache read level by level, leaf first as `c:lvl` orders them, each
//! level's missing points kept and never joined into one label; and its
//! reference, a rectangle of cells holding one line of cells per level, the
//! outermost level first, its points down the rows (the levels side by
//! side) or along the columns (the levels stacked). A cache is read without
//! expanding the count it declares; what expands it measures it first.

use super::super::NativeRefusal;
use super::super::workbook::{CellKey, Range};
use super::{C, Kind, Seq};
use crate::design_plan::Cell;
use crate::ooxml::XmlTree;
use oneiron_contracts::limit_ask::available_memory_bytes;

/// A point count as a cache declares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Count {
    /// A count this machine addresses; an absent or non-numeric count
    /// declares none.
    Points(usize),
    /// A number past what this machine addresses.
    Unaddressable,
}

/// A `c:ptCount` value as declared, never wrapped or clamped: digits past
/// this machine's address space are [`Count::Unaddressable`].
pub(crate) fn declared(text: Option<&str>) -> Count {
    let Some(text) = text.map(str::trim) else {
        return Count::Points(0);
    };
    match text.parse::<usize>() {
        Ok(count) => Count::Points(count),
        Err(_) if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) => {
            Count::Unaddressable
        }
        Err(_) => Count::Points(0),
    }
}

/// A multi-level cache as it is written: its declared count, and each
/// level's points (index and text), leaf level first, as sparse as the
/// cache holds them.
#[derive(Debug)]
pub(crate) struct LevelCache {
    pub(crate) count: Count,
    pub(crate) levels: Vec<Vec<(usize, String)>>,
}

fn child(tree: &XmlTree, at: usize, name: &str) -> Option<usize> {
    tree.nodes[at]
        .children
        .iter()
        .copied()
        .find(|&child| tree.nodes[child].is(C, name))
}

fn within<'t>(tree: &'t XmlTree, at: usize, name: &'t str) -> impl Iterator<Item = usize> + 't {
    tree.nodes[at]
        .children
        .iter()
        .copied()
        .filter(move |&child| tree.nodes[child].is(C, name))
}

/// The `c:multiLvlStrCache` at `cache`, read without expanding its count;
/// `None` when a point's index is not a number or lies past the count.
pub(crate) fn level_cache(tree: &XmlTree, cache: usize) -> Option<LevelCache> {
    let count = declared(child(tree, cache, "ptCount").and_then(|at| tree.nodes[at].attr("val")));
    let mut levels = Vec::new();
    for level in within(tree, cache, "lvl") {
        let mut points = Vec::new();
        for pt in within(tree, level, "pt") {
            let idx: usize = tree.nodes[pt].attr("idx")?.trim().parse().ok()?;
            if matches!(count, Count::Points(count) if idx >= count) {
                return None;
            }
            let text =
                child(tree, pt, "v").map_or_else(String::new, |v| tree.nodes[v].text.clone());
            points.push((idx, text));
        }
        levels.push(points);
    }
    Some(LevelCache { count, levels })
}

/// A multi-level reference's cells: how many levels and points it holds,
/// and its block's cells level by level (leaf first), each level's points
/// in order.
#[derive(Debug)]
pub(super) struct Block {
    pub(super) points: usize,
    pub(super) keys: Vec<CellKey>,
}

/// Room for `count` items of `T`, measured first: past the address space,
/// past the memory the host has free, or refused by the allocator, the
/// block is not read.
fn room<T>(count: usize) -> Result<Vec<T>, NativeRefusal> {
    let refused = NativeRefusal::AmbiguousChartData(
        "a category block larger than the memory this host has free",
    );
    let bytes = count
        .checked_mul(size_of::<T>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(refused.clone())?;
    if available_memory_bytes().is_some_and(|free| bytes > free) {
        return Err(refused);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(count).map_err(|_| refused)?;
    Ok(out)
}

/// The sequence a `c:multiLvlStrRef` at `node` names: its block, read
/// against its cache's levels and count. The block's orientation is the one
/// its shape allows (down the rows when both do).
pub(super) fn sequence(tree: &XmlTree, node: usize) -> Result<Seq, NativeRefusal> {
    let reference = child(tree, node, "f")
        .map(|f| tree.nodes[f].text.trim().to_owned())
        .ok_or(NativeRefusal::AmbiguousChartData(
            "a reference without a formula",
        ))?;
    let range = Range::parse_block(&reference)?;
    let cache = child(tree, node, "multiLvlStrCache").ok_or(NativeRefusal::AmbiguousChartData(
        "a reference without a cache",
    ))?;
    let read = level_cache(tree, cache).ok_or(NativeRefusal::AmbiguousChartData(
        "cache point outside its count",
    ))?;
    let Count::Points(points) = read.count else {
        return Err(NativeRefusal::AmbiguousChartData(
            "a category cache counts past this machine's address space",
        ));
    };
    let levels = read.levels.len();
    let ((first_col, first_row), (last_col, last_row)) = range.corners();
    let span = |first: u32, last: u32| usize::try_from(last - first).map_or(0, |span| span + 1);
    let (width, height) = (span(first_col, last_col), span(first_row, last_row));
    let down = if (width, height) == (levels, points) {
        true
    } else if (width, height) == (points, levels) {
        false
    } else {
        return Err(NativeRefusal::AmbiguousChartData(
            "the category block's shape disagrees with its cache",
        ));
    };
    let mut keys = room(
        levels
            .checked_mul(points)
            .ok_or(NativeRefusal::AmbiguousChartData(
                "a category block past this machine's address space",
            ))?,
    )?;
    for level in 0..levels {
        // The block holds the outermost level first, the leaf last.
        let line = u32::try_from(levels - 1 - level).unwrap_or(u32::MAX);
        for point in 0..points {
            let point = u32::try_from(point).unwrap_or(u32::MAX);
            let (col, row) = if down {
                (first_col + line, first_row + point)
            } else {
                (first_col + point, first_row + line)
            };
            keys.push(CellKey {
                sheet: range.sheet.clone(),
                col,
                row,
            });
        }
    }
    Ok(Seq {
        kind: Kind::Text,
        reference,
        range,
        cache,
        block: Some(Block { points, keys }),
    })
}

/// A multi-level cache's cells in its block's order: each level's points,
/// a missing one missing.
pub(super) fn cells(tree: &XmlTree, seq: &Seq, block: &Block) -> Result<Vec<Cell>, NativeRefusal> {
    let read = level_cache(tree, seq.cache).ok_or(NativeRefusal::AmbiguousChartData(
        "cache point outside its count",
    ))?;
    let mut out = room(block.keys.len())?;
    out.resize(block.keys.len(), Cell::Missing);
    for (level, points) in read.levels.into_iter().enumerate() {
        for (idx, text) in points {
            if let Some(cell) = level
                .checked_mul(block.points)
                .and_then(|at| at.checked_add(idx))
                .and_then(|at| out.get_mut(at))
            {
                *cell = Cell::Text(text);
            }
        }
    }
    Ok(out)
}
