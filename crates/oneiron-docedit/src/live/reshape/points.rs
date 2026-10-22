//! A rewritten chart's category points (OF-510, FIX 3493): a multi-level
//! category slot written from its levels, and a surviving series' point
//! formatting and labels (`c:dPt`, `c:dLbl`) carried to its points' new
//! places by category identity, so a moved point keeps its own and a
//! deleted one's go with it.

use super::families::applied;
use super::layout::CategorySet;
use super::{Writer, int};
use crate::design_plan::Cell;
use crate::edit::xml::{self, Splice};
use crate::live::LiveError;
use crate::live::held::C;
use crate::live::pptx::{NodeId, SeriesBinding, positions};
use crate::native_patch::number;
use crate::ooxml::{XmlTree, escape_text};
use std::collections::BTreeMap;

impl Writer {
    /// A multi-level category slot: `reference` (none for a chart without
    /// a workbook) over a cache of every level, leaf first, each level's
    /// missing points left out.
    pub(super) fn levels(
        &self,
        slot: &str,
        reference: Option<&str>,
        levels: &[Vec<Cell>],
    ) -> String {
        let count = levels.first().map_or(0, Vec::len);
        let mut cache = format!(r#"<{} val="{count}"/>"#, self.el("ptCount"));
        for level in levels {
            cache.push_str(&format!("<{}>", self.el("lvl")));
            for (idx, cell) in level.iter().enumerate() {
                let text = match cell {
                    Cell::Missing => continue,
                    Cell::Number(value) => number(*value),
                    Cell::Text(text) | Cell::Date(text) => escape_text(text),
                };
                cache.push_str(&format!(
                    r#"<{pt} idx="{idx}"><{v}>{text}</{v}></{pt}>"#,
                    pt = self.el("pt"),
                    v = self.el("v")
                ));
            }
            cache.push_str(&format!("</{}>", self.el("lvl")));
        }
        let formula = reference.map_or_else(String::new, |reference| {
            format!("<{f}>{}</{f}>", escape_text(reference), f = self.el("f"))
        });
        format!(
            "<{s}><{r}>{formula}<{c}>{cache}</{c}></{r}></{s}>",
            s = self.el(slot),
            r = self.el("multiLvlStrRef"),
            c = self.el("multiLvlStrCache"),
        )
    }
}

/// A surviving series' points as its rewrite writes them: how many, and,
/// where its binding names the category points its held series drew, each
/// held point's new place (`None` for one gone).
pub(super) struct Points {
    pub(super) count: usize,
    pub(super) remap: Option<Vec<Option<usize>>>,
}

impl Points {
    /// Where the held point `idx` goes; `None` when it is gone.
    fn place(&self, idx: u32) -> Option<u32> {
        let at = usize::try_from(idx).ok()?;
        let to = match &self.remap {
            Some(remap) => remap.get(at).copied().flatten()?,
            None => Some(at).filter(|&at| at < self.count)?,
        };
        u32::try_from(to).ok()
    }
}

/// Each held category point's new place for the series `id`, drawing
/// `set`: through the category identities its held series drew, as its
/// binding names them. `None` without that evidence (a new series, a
/// scatter series, a binding that names none).
pub(super) fn remap(
    bound: &SeriesBinding,
    id: Option<NodeId>,
    set: Option<&CategorySet>,
) -> Option<Vec<Option<usize>>> {
    let at = *positions(&bound.series).get(&id?)?;
    let held = bound.categories.get(at).filter(|held| !held.is_empty())?;
    let places: BTreeMap<NodeId, usize> = set?
        .ids
        .iter()
        .enumerate()
        .filter_map(|(at, id)| Some(((*id)?, at)))
        .collect();
    Some(held.iter().map(|id| places.get(id).copied()).collect())
}

/// `element` (a `c:dPt` or `c:dLbl`) with its `c:idx` set to `to` and
/// `splices` (on the whole part's bytes, inside it) applied; its own bytes
/// when nothing changes.
fn reindexed(
    bytes: &[u8],
    tree: &XmlTree,
    element: usize,
    to: u32,
    mut splices: Vec<Splice>,
) -> Result<Vec<u8>, LiveError> {
    if let Some(idx) = xml::child(tree, element, C, "idx")
        && int(tree, element, "idx") != Some(to)
    {
        splices.push(xml::set_attribute(
            bytes,
            &tree.nodes[idx],
            "val",
            &to.to_string(),
        ));
    }
    if splices.is_empty() {
        return Ok(bytes[tree.nodes[element].span.clone()].to_vec());
    }
    applied(bytes, tree, element, splices)
}

/// The `name` elements (`dPt` or `dLbl`) among `children`, each carried to
/// its point's new place with the splices `retype` gives it (FIX 9276), in
/// point order; one whose point is gone goes.
pub(super) fn carried(
    bytes: &[u8],
    tree: &XmlTree,
    children: &[usize],
    name: &str,
    points: &Points,
    retype: &mut dyn FnMut(usize) -> Vec<Splice>,
) -> Result<Vec<u8>, LiveError> {
    let mut kept: Vec<(u32, Vec<u8>)> = Vec::new();
    for &at in children.iter().filter(|&&at| tree.nodes[at].is(C, name)) {
        let Some(to) = int(tree, at, "idx").and_then(|idx| points.place(idx)) else {
            continue;
        };
        kept.push((to, reindexed(bytes, tree, at, to, retype(at))?));
    }
    kept.sort_by_key(|(to, _)| *to);
    Ok(kept.into_iter().flat_map(|(_, element)| element).collect())
}
