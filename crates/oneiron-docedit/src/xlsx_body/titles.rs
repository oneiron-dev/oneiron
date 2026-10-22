//! The worksheet titles a sheet layout leaves in the extended properties
//! (`docProps/app.xml`, FIX 3441). `TitlesOfParts` lists the part titles
//! in groups, and `HeadingPairs` names each group and counts its titles, in
//! order. The worksheets' group is told by its titles, the one group that
//! lists the worksheets in their old order, not by its heading, which
//! Excel writes in the user's language, nor by its count alone.
use super::{Book, EXTENDED_PROPERTIES, Result, refused};
use crate::edit::xml::{Splice, replace_text, set_attribute, splice};
use crate::ooxml::{Node, XmlTree, escape_text};

const VT: &str = "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes";

impl Book {
    /// List worksheets `new` (in their laid-out order) in place of `old`
    /// (in the order the workbook had them) in the extended properties:
    /// the worksheets' group's titles and count and the list's size
    /// change, and every other group keeps its bytes. When no one group
    /// lists `old`, the titles are dropped as before.
    pub(super) fn retitle_parts(&mut self, old: &[String], new: &[String]) -> Result<()> {
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
        let Some(edits) = worksheet_titles(&bytes, &tree, old, new) else {
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

/// The splices listing `new` in place of the worksheets' group of titles,
/// the one group whose titles are `old` in order; `None` when no one group
/// reads so or the lists do not read as groups over the titles.
fn worksheet_titles(
    bytes: &[u8],
    tree: &XmlTree,
    old: &[String],
    new: &[String],
) -> Option<Vec<Splice>> {
    let vector = |name: &str| {
        let (at, _) = tree.child(0, EXTENDED_PROPERTIES, name).ok()??;
        tree.child(at, VT, "vector").ok()?
    };
    let ((pairs, _), (listed, list)) = (vector("HeadingPairs")?, vector("TitlesOfParts")?);
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
    for &(count_node, count) in &groups {
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
            found = Some((count_node, first));
        }
        first += count;
    }
    let (count_node, first) = found?;
    if old == new {
        return Some(Vec::new());
    }
    let slice = &titles[first..first + old.len()];
    let element = &slice[0].qualified;
    let listed_titles: String = new
        .iter()
        .map(|name| format!("<{element}>{}</{element}>", escape_text(name)))
        .collect();
    let mut edits = vec![(
        slice[0].span.start..slice[old.len() - 1].span.end,
        listed_titles.into_bytes(),
    )];
    edits.extend(replace_text(bytes, count_node, &new.len().to_string())?);
    if list.attr_spans.contains_key("size") {
        edits.push(set_attribute(
            bytes,
            list,
            "size",
            &(titles.len() - old.len() + new.len()).to_string(),
        ));
    }
    Some(edits)
}
