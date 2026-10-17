//! The app properties (`docProps/app.xml`) a slide's removal would leave
//! stale (FIX 2377): the slide, hidden-slide and notes counts, and the
//! slide's title among the document's part titles. Those titles are listed
//! by heading-pair groups. The slide titles are the group counting the
//! deck's slides (the last such group, as PowerPoint writes them after the
//! fonts and themes), and the removed slide's title sits at its list index
//! there. Properties that do not read so are left as they are: no reader
//! opens a deck by them.
use super::super::super::media::related;
use super::super::super::xml::{self, Splice};
use crate::edit::EditRefusal;
use crate::ooxml::{Node, XmlTree};
use crate::retained_opc::Package;

const EP: &str = "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties";
const VT: &str = "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes";

/// The app properties after the removal of the slide at `index` of the
/// `count` the presentation listed, `hidden` or shown, with `notes` or none.
pub(super) fn slide_removed(
    next: &mut Package,
    index: usize,
    count: usize,
    hidden: bool,
    notes: bool,
) -> Result<(), EditRefusal> {
    let Some(part) = related(next, "", "extended-properties")? else {
        return Ok(());
    };
    let Some(bytes) = next.part(&part)? else {
        return Ok(());
    };
    let Ok(tree) = XmlTree::parse(&bytes, next.limits().xml) else {
        return Ok(());
    };
    if tree.root(EP, "Properties").is_err() {
        return Ok(());
    }
    let mut edits = Vec::new();
    for (name, less) in [("Slides", true), ("HiddenSlides", hidden), ("Notes", notes)] {
        if less
            && let Ok(Some((_, node))) = tree.child(0, EP, name)
            && let Ok(was) = node.text.trim().parse::<u64>()
        {
            edits.push((
                node.content.clone(),
                was.saturating_sub(1).to_string().into_bytes(),
            ));
        }
    }
    edits.extend(title_edits(&tree, index, count));
    if !edits.is_empty() {
        next.replace_xml_part(&part, xml::splice(&bytes, edits)?)?;
    }
    Ok(())
}

/// The `Slides` count `package`'s app properties state, when they state one.
pub(in super::super) fn slide_count(package: &Package) -> Result<Option<u64>, EditRefusal> {
    let Some(part) = related(package, "", "extended-properties")? else {
        return Ok(None);
    };
    let Some(bytes) = package.part(&part)? else {
        return Ok(None);
    };
    let Ok(tree) = XmlTree::parse(&bytes, package.limits().xml) else {
        return Ok(None);
    };
    Ok(tree
        .child(0, EP, "Slides")
        .ok()
        .flatten()
        .and_then(|(_, node)| node.text.trim().parse().ok()))
}

/// The removed slide's title out of `TitlesOfParts`, and its group's count
/// one less; none when the lists do not read as groups over the titles.
fn title_edits(tree: &XmlTree, index: usize, count: usize) -> Vec<Splice> {
    let vector = |name: &str| {
        tree.child(0, EP, name)
            .ok()
            .flatten()
            .and_then(|(at, _)| tree.child(at, VT, "vector").ok().flatten())
    };
    let (Some((pairs, _)), Some((listed, titles))) =
        (vector("HeadingPairs"), vector("TitlesOfParts"))
    else {
        return Vec::new();
    };
    // Each group is a name variant then a count variant.
    let Some(groups) = tree
        .children(pairs)
        .filter_map(|(at, _)| tree.child(at, VT, "i4").ok().flatten())
        .map(|(_, node)| Some((node, node.text.trim().parse::<usize>().ok()?)))
        .collect::<Option<Vec<(&Node, usize)>>>()
    else {
        return Vec::new();
    };
    let names: Vec<&Node> = tree
        .children(listed)
        .map(|(_, node)| node)
        .filter(|node| node.is(VT, "lpstr"))
        .collect();
    if groups.iter().map(|&(_, n)| n).sum::<usize>() != names.len() {
        return Vec::new();
    }
    let Some(group) = groups.iter().rposition(|&(_, n)| n == count) else {
        return Vec::new();
    };
    let at = groups[..group].iter().map(|&(_, n)| n).sum::<usize>() + index;
    let Some(title) = names.get(at) else {
        return Vec::new();
    };
    let mut edits = vec![
        (title.span.clone(), Vec::new()),
        (
            groups[group].0.content.clone(),
            count.saturating_sub(1).to_string().into_bytes(),
        ),
    ];
    if let Some(size) = titles.attr_spans.get("size") {
        edits.push((
            size.clone(),
            format!("size=\"{}\"", names.len() - 1).into_bytes(),
        ));
    }
    edits
}
