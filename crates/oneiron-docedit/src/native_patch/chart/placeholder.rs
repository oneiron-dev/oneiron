//! A stock plot's placeholder series (OF-510, FIX 9374): a `c:ser` of a
//! `c:stockChart` holding neither categories nor values. The live deck
//! writes one in each price no series draws, so the plot keeps the three or
//! four series its schema asks for and every later price keeps its place
//! (PowerPoint reads a stock plot's prices by count and place). It is no
//! series: every reader of a chart's series skips it, and a stock plot's
//! price order counts it.

use super::C;
use crate::edit::xml;
use crate::ooxml::XmlTree;

/// Whether the `c:ser` at `ser` is a stock plot's placeholder: a series of
/// a `c:stockChart` with neither a `c:cat` nor a `c:val`.
pub(crate) fn stock_placeholder(tree: &XmlTree, ser: usize) -> bool {
    tree.nodes[ser]
        .parent
        .is_some_and(|plot| tree.nodes[plot].is(C, "stockChart"))
        && xml::child(tree, ser, C, "cat").is_none()
        && xml::child(tree, ser, C, "val").is_none()
}
