//! The sheet titles a sheet layout leaves in the extended properties
//! (`docProps/app.xml`, FIX 3441). `TitlesOfParts` lists the part titles
//! in groups, and `HeadingPairs` names each group and counts its titles, in
//! order. The worksheets' group is told by its titles, the one group that
//! lists the worksheets in their old order, not by its heading, which
//! Excel writes in the user's language, nor by its count alone. A group
//! whose titles are all other sheets (the charts') lists them as laid out,
//! and in every other group a title that names a sheet (`Data!Print_Area`)
//! follows its rename and leaves with its deletion (FIX 9084).
use std::cell::Cell;

use super::{Book, EXTENDED_PROPERTIES, Result, refused};
use crate::edit::xml::{Splice, replace_text, set_attribute, splice};
use crate::ooxml::{Node, XmlTree, escape_text};
use crate::xlsx_shift::{SheetFate, retarget_sheets};

const VT: &str = "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes";

/// The sheets a layout moves, as the extended properties' titles name them.
pub(super) struct TitleMoves<'a> {
    /// The worksheets, in the order the workbook had them.
    pub(super) old: &'a [String],
    /// The worksheets, as laid out.
    pub(super) new: &'a [String],
    /// The other sheets (charts, dialogs, macros) as laid out; a layout
    /// keeps their names.
    pub(super) others: &'a [String],
    /// Every sheet, in the order the workbook had them.
    pub(super) order: &'a [String],
    /// What each sheet name, as the workbook had it, becomes.
    pub(super) fate: &'a dyn Fn(&str) -> SheetFate,
}

impl Book {
    /// List worksheets `moves.new` in place of `moves.old` in the extended
    /// properties: the worksheets' group's titles and count and the list's
    /// size change; a group of other sheets is listed as laid out; a title
    /// naming a renamed sheet names its new name, and one naming a deleted
    /// sheet leaves, with its group when it was the group's last. When no
    /// one group lists `moves.old`, the titles are dropped as before.
    pub(super) fn retitle_parts(&mut self, moves: &TitleMoves<'_>) -> Result<()> {
        let Some(part) = self
            .package
            .relationships("")?
            .into_iter()
            .find(|rel| !rel.external && rel.kind.ends_with("/extended-properties"))
            .map(|rel| rel.target)
        else {
            return Ok(());
        };
        let Some(bytes) = self.package.part(&part)? else {
            return Ok(());
        };
        let tree = XmlTree::parse(&bytes, self.package.resources())?;
        let Some(edits) = part_titles(&bytes, &tree, moves) else {
            return self.drop_part_titles();
        };
        if edits.is_empty() {
            return Ok(());
        }
        let value = splice(&bytes, edits)
            .map_err(|_| refused("the extended properties could not be rewritten"))?;
        self.package.replace_xml_part(&part, value)?;
        Ok(())
    }
}

/// The splices that carry the titles through `moves`: `moves.new` in place
/// of the worksheets' group, the one group whose titles are `moves.old` in
/// order, and every other group's titles moved with their sheets; `None`
/// when no one group reads so or the lists do not read as groups over the
/// titles.
fn part_titles(bytes: &[u8], tree: &XmlTree, moves: &TitleMoves<'_>) -> Option<Vec<Splice>> {
    let (old, new) = (moves.old, moves.new);
    let vector = |name: &str| {
        let (at, _) = tree.child(0, EXTENDED_PROPERTIES, name).ok()??;
        tree.child(at, VT, "vector").ok()?
    };
    let ((pairs, pairs_node), (listed, list)) = (vector("HeadingPairs")?, vector("TitlesOfParts")?);
    // Each group is a heading variant then a count variant.
    let variants: Vec<usize> = tree
        .children(pairs)
        .filter(|(_, node)| node.is(VT, "variant"))
        .map(|(at, _)| at)
        .collect();
    if variants.len() % 2 != 0 {
        return None;
    }
    let groups = variants
        .chunks(2)
        .map(|pair| {
            let (_, count) = tree.children(pair[1]).next()?;
            Some((count, count.text.trim().parse::<usize>().ok()?))
        })
        .collect::<Option<Vec<(&Node, usize)>>>()?;
    let titles: Vec<&Node> = tree
        .children(listed)
        .map(|(_, node)| node)
        .filter(|node| node.namespace == VT)
        .collect();
    if old.is_empty() || groups.iter().map(|&(_, n)| n).sum::<usize>() != titles.len() {
        return None;
    }
    let mut found = None;
    let mut first = 0;
    for (group, &(_, count)) in groups.iter().enumerate() {
        let slice = &titles[first..first + count];
        if slice.len() == old.len()
            && slice
                .iter()
                .zip(old)
                .all(|(title, name)| title.text == *name)
        {
            if found.is_some() {
                return None;
            }
            found = Some(group);
        }
        first += count;
    }
    let sheets = found?;
    let mut edits = Vec::new();
    let mut size = titles.len();
    let mut emptied = Vec::new();
    let mut first = 0;
    for (group, &(count_node, count)) in groups.iter().enumerate() {
        let slice = &titles[first..first + count];
        first += count;
        if group == sheets {
            if old != new {
                let element = &slice[0].qualified;
                let listed_titles: String = new
                    .iter()
                    .map(|name| format!("<{element}>{}</{element}>", escape_text(name)))
                    .collect();
                edits.push((
                    slice[0].span.start..slice[old.len() - 1].span.end,
                    listed_titles.into_bytes(),
                ));
                edits.extend(replace_text(bytes, count_node, &new.len().to_string())?);
                size = size - old.len() + new.len();
            }
            continue;
        }
        if !slice.is_empty() && slice.iter().all(|title| moves.others.contains(&title.text)) {
            // The group's sheets, in their laid-out order.
            let mut laid: Vec<&str> = slice.iter().map(|title| title.text.as_str()).collect();
            laid.sort_by_key(|name| moves.others.iter().position(|other| other == name));
            for (title, name) in slice.iter().zip(laid) {
                if title.text != name {
                    edits.extend(replace_text(bytes, title, name)?);
                }
            }
            continue;
        }
        let mut kept = count;
        for title in slice {
            let gone = Cell::new(false);
            let probe = |sheet: &str| {
                let fate = (moves.fate)(sheet);
                if fate == SheetFate::Delete {
                    gone.set(true);
                }
                fate
            };
            let moved = retarget_sheets(&title.text, moves.order, &probe);
            if gone.get() {
                edits.push((title.span.clone(), Vec::new()));
                kept -= 1;
            } else if let Some(text) = moved {
                edits.extend(replace_text(bytes, title, &text)?);
            }
        }
        if kept == count {
            continue;
        }
        size -= count - kept;
        if kept == 0 {
            emptied.push(group);
        } else {
            edits.extend(replace_text(bytes, count_node, &kept.to_string())?);
        }
    }
    // A group left with no title leaves with its heading.
    for &group in &emptied {
        let (heading, count) = (variants[2 * group], variants[2 * group + 1]);
        edits.push((
            tree.nodes[heading].span.start..tree.nodes[count].span.end,
            Vec::new(),
        ));
    }
    if !emptied.is_empty() && pairs_node.attr_spans.contains_key("size") {
        edits.push(set_attribute(
            bytes,
            pairs_node,
            "size",
            &(variants.len() - 2 * emptied.len()).to_string(),
        ));
    }
    if size != titles.len() && list.attr_spans.contains_key("size") {
        edits.push(set_attribute(bytes, list, "size", &size.to_string()));
    }
    Some(edits)
}
