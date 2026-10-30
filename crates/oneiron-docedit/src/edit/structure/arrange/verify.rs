//! Independent read-back checks for projector arrangement verbs.
//! Entry: `verify`.
//! Definitions live here; arrange preserves the old visibility-scoped bindings.

use super::*;
use crate::ooxml::XmlTree;
use crate::retained_opc::Relationship;

/// The independent check of every projector verb.
pub(in crate::edit::structure) fn verify(
    input: &Package,
    next: &Package,
    before: &DeckView,
    op: &StructureEdit<'_>,
    effects: &[Effect],
) -> Result<Vec<String>, EditRefusal> {
    let candidate = Package::open(&next.export()?, input.limits(), input.resources())?;
    let removed = match *op {
        StructureEdit::DeleteSlide { slide, .. } => released(input, &candidate, slide)?,
        _ => Vec::new(),
    };
    let changed = check::diff_removing(input, &candidate, &removed)?;
    let after = DeckView::read(&candidate)?;
    let fault = |why: &'static str| EditRefusal::ReadBack(why);
    let same = |a: &SlideView, b: &SlideView| {
        a.part == b.part
            && a.sld_id == b.sld_id
            && a.creation_id == b.creation_id
            && a.content_fingerprint == b.content_fingerprint
    };
    let mut allowed: Vec<String> = Vec::new();
    match *op {
        StructureEdit::AddSlide {
            after: anchor,
            layout,
            ..
        } => {
            let Some(Effect::SlideAdded { part, sld_id, .. }) = effects.first() else {
                return Err(fault("no slide was added"));
            };
            let presentation = related(input, "", "officeDocument")?
                .ok_or(EditRefusal::Missing("presentation"))?;
            allowed.extend([
                rels_name(&presentation),
                presentation,
                TYPES.to_owned(),
                part.clone(),
                rels_name(part),
            ]);
            // The app properties count one slide more when they changed.
            if let Some(props) = related(input, "", "extended-properties")?
                && changed.contains(&props)
            {
                if super::slides::slide_count(&candidate)?
                    != super::slides::slide_count(input)?.map(|count| count.saturating_add(1))
                {
                    return Err(fault("the app properties do not count the slide in"));
                }
                allowed.push(props);
            }
            let at = anchor
                .map(|slide| {
                    before
                        .slides
                        .iter()
                        .position(|view| view.part == slide)
                        .map(|at| at + 1)
                })
                .unwrap_or(Some(0))
                .ok_or(EditRefusal::Missing("slide"))?;
            let new = after
                .slides
                .get(at)
                .ok_or(fault("the new slide is not in place"))?;
            if new.part != *part
                || new.sld_id != *sld_id
                || !new.shapes.is_empty()
                || new.layout.as_deref() != Some(layout)
            {
                return Err(fault("the new slide is not as asked"));
            }
            let rest: Vec<&SlideView> = after.slides.iter().filter(|s| s.part != *part).collect();
            if rest.len() != before.slides.len()
                || !rest.iter().zip(&before.slides).all(|(a, b)| same(a, b))
            {
                return Err(fault("another slide changed"));
            }
        }
        StructureEdit::DeleteSlide { slide, .. } => {
            let presentation = related(input, "", "officeDocument")?
                .ok_or(EditRefusal::Missing("presentation"))?;
            allowed.extend([rels_name(&presentation), presentation]);
            if !removed.is_empty() {
                allowed.push(TYPES.to_owned());
            }
            allowed.extend(removed.iter().cloned());
            // The app properties count one slide fewer when they changed.
            if let Some(props) = related(input, "", "extended-properties")?
                && changed.contains(&props)
            {
                if super::slides::slide_count(&candidate)?
                    != super::slides::slide_count(input)?.map(|count| count.saturating_sub(1))
                {
                    return Err(fault("the app properties do not count the slide out"));
                }
                allowed.push(props);
            }
            let rest: Vec<&SlideView> = before.slides.iter().filter(|s| s.part != slide).collect();
            if after.slides.len() != rest.len()
                || !after.slides.iter().zip(rest).all(|(a, b)| same(a, b))
            {
                return Err(fault("the slide list is not the input less the slide"));
            }
        }
        StructureEdit::ReorderShape { target, index } => {
            allowed.push(target.slide.to_owned());
            let (old, new) = slide_pair(before, &after, target.slide)?;
            let who = |view: &SlideView| -> Vec<_> {
                let mut all: Vec<_> = view
                    .shapes
                    .iter()
                    .map(|s| (s.id, s.creation_id.clone(), s.name.clone()))
                    .collect();
                all.sort();
                all
            };
            if who(old) != who(new) {
                return Err(fault("the shapes on the slide changed"));
            }
            let moved = new
                .shapes
                .iter()
                .position(|s| s.id == Some(target.shape))
                .ok_or(fault("the shape is gone"))?;
            let siblings = direct(new, new.shapes[moved].group_path.last().copied());
            if siblings.iter().position(|&m| m == moved) != Some(index) {
                return Err(fault("the shape is not at the index"));
            }
        }
        StructureEdit::AddGroup { slide, group } => {
            allowed.push(slide.to_owned());
            let Some(Effect::ShapeAdded { id, creation_id }) = effects.first() else {
                return Err(fault("no group was added"));
            };
            let (old, new) = slide_pair(before, &after, slide)?;
            let added = new
                .shapes
                .iter()
                .find(|s| s.id == Some(*id))
                .ok_or(fault("the group is missing"))?;
            if added.creation_id.as_ref() != Some(creation_id)
                || added.name.as_deref() != Some(group.name)
                || !added.group_path.is_empty()
                || new.shapes.len() != old.shapes.len() + 1
            {
                return Err(fault("the group is not as asked"));
            }
            kept(old, new)?;
        }
        StructureEdit::CopyToSlide { target, to, .. } => {
            allowed.extend([to.to_owned(), rels_name(to)]);
            let (old_source, new_source) = slide_pair(before, &after, target.slide)?;
            if old_source.content_fingerprint != new_source.content_fingerprint {
                return Err(fault("the source slide changed"));
            }
            let (old, new) = slide_pair(before, &after, to)?;
            kept(old, new)?;
            for effect in effects {
                if let Effect::ShapeCopied { id, .. } = effect
                    && !new.shapes.iter().any(|s| s.id == Some(*id))
                {
                    return Err(fault("a copied shape is missing"));
                }
            }
            copied(input, &candidate, old_source, old, target.shape, effects)?;
        }
        StructureEdit::AddPicture { slide, picture } => {
            let (old, new) = slide_pair(before, &after, slide)?;
            let id = added(effects, old, new, picture.name, ShapeKind::Picture)?;
            let (_, tree) = xml::read(&candidate, slide)?;
            let at = check::find_shape(&tree, id).ok_or(fault("the picture is missing"))?;
            let embed = xml::path(&tree, at, &[(P, "blipFill"), (A, "blip")])
                .and_then(|blip| tree.nodes[blip].attr_ns(R, "embed"))
                .ok_or(fault("the picture names no media"))?;
            let link = candidate
                .relationships(slide)?
                .into_iter()
                .find(|rel| rel.id == embed && !rel.external)
                .ok_or(fault("the picture's relationship is missing"))?;
            if input
                .relationships(slide)?
                .iter()
                .any(|rel| rel.id == link.id)
                || input.part(&link.target)?.is_some()
                || candidate.part(&link.target)?.as_deref() != Some(picture.picture.bytes)
            {
                return Err(fault("the picture's media is not the asset in a new part"));
            }
            allowed.extend([
                slide.to_owned(),
                rels_name(slide),
                link.target,
                TYPES.to_owned(),
            ]);
        }
        StructureEdit::AddConnector { slide, connector } => {
            allowed.push(slide.to_owned());
            let (old, new) = slide_pair(before, &after, slide)?;
            let id = added(effects, old, new, connector.name, ShapeKind::Connector)?;
            let (_, tree) = xml::read(&candidate, slide)?;
            let at = check::find_shape(&tree, id).ok_or(fault("the connector is missing"))?;
            let prst = xml::path(&tree, at, &[(P, "spPr"), (A, "prstGeom")])
                .and_then(|geometry| tree.nodes[geometry].attr("prst"));
            let end = |local: &str| {
                xml::path(
                    &tree,
                    at,
                    &[(P, "nvCxnSpPr"), (P, "cNvCxnSpPr"), (A, local)],
                )
                .map(|node| {
                    let read = |name: &str| {
                        tree.nodes[node]
                            .attr(name)
                            .and_then(|value| value.parse::<u32>().ok())
                    };
                    (read("id"), read("idx"))
                })
            };
            // A creation-id end names the native id of the one non-group shape
            // holding it in the input (FIX 10386); the writer refused any other
            // case, so anything else here is a read-back fault.
            let resolve =
                |end: Option<(ShapeId<'_>, u32)>| -> Result<Option<(u32, u32)>, EditRefusal> {
                end.map(|(shape, site)| {
                    let id = match shape {
                        ShapeId::Native(id) => id,
                        ShapeId::Creation(guid) => {
                            let mut held = old
                                .shapes
                                .iter()
                                .filter(|shape| shape.creation_id.as_deref() == Some(guid));
                            let one = held.next().ok_or(fault("the connector names no shape"))?;
                            if held.next().is_some() || one.kind == ShapeKind::Group {
                                return Err(fault("the connector names no single shape"));
                            }
                            one.id.ok_or(fault("the connector names a shape with no id"))?
                        }
                    };
                    Ok((id, site))
                })
                .transpose()
            };
            let (start, end_asked) = (resolve(connector.start)?, resolve(connector.end)?);
            let asked =
                |end: Option<(u32, u32)>| end.map(|(shape, site)| (Some(shape), Some(site)));
            if prst != Some(connector.preset.name())
                || end("stCxn") != asked(start)
                || end("endCxn") != asked(end_asked)
            {
                return Err(fault("the connector is not as asked"));
            }
        }
        _ => return Err(EditRefusal::Invalid("the plan does not match the verb")),
    }
    if let Some(part) = changed.iter().find(|part| !allowed.contains(part)) {
        return Err(EditRefusal::PartDiffOutsideTransaction(part.clone()));
    }
    Ok(changed)
}

/// The parts a deleted slide must have released, read independently of the
/// writer: every input part the slide reaches that the candidate's root no
/// longer names, with its relationship part. A part a survivor still names,
/// even one the candidate lost, is not among them.
pub(super) fn released(
    input: &Package,
    candidate: &Package,
    slide: &str,
) -> Result<Vec<String>, EditRefusal> {
    let kept = candidate.reachable("")?;
    if kept.contains(slide) {
        return Ok(Vec::new());
    }
    let held: BTreeSet<&str> = input.names().collect();
    let mut released = Vec::new();
    for part in input.reachable(slide)? {
        if kept.contains(&part) || !held.contains(part.as_str()) {
            continue;
        }
        let rels = rels_name(&part);
        if held.contains(rels.as_str()) {
            released.push(rels);
        }
        released.push(part);
    }
    Ok(released)
}

pub(super) fn slide_pair<'v>(
    before: &'v DeckView,
    after: &'v DeckView,
    part: &str,
) -> Result<(&'v SlideView, &'v SlideView), EditRefusal> {
    let find = |view: &'v DeckView| view.slides.iter().find(|s| s.part == part);
    find(before)
        .zip(find(after))
        .ok_or(EditRefusal::ReadBack("the slide is gone"))
}

/// The one shape a creation verb appended to the shape tree, read back with
/// its effect's id and creation id and as asked, every kept shape as it was.
pub(super) fn added(
    effects: &[Effect],
    old: &SlideView,
    new: &SlideView,
    name: &str,
    kind: ShapeKind,
) -> Result<u32, EditRefusal> {
    let Some(Effect::ShapeAdded { id, creation_id }) = effects.first() else {
        return Err(EditRefusal::ReadBack("nothing was added"));
    };
    let shape = new
        .shapes
        .iter()
        .find(|s| s.id == Some(*id))
        .ok_or(EditRefusal::ReadBack("the new shape is missing"))?;
    if shape.kind != kind
        || shape.creation_id.as_ref() != Some(creation_id)
        || shape.name.as_deref() != Some(name)
        || !shape.group_path.is_empty()
        || new.shapes.len() != old.shapes.len() + 1
    {
        return Err(EditRefusal::ReadBack("the new shape is not as asked"));
    }
    kept(old, new)?;
    Ok(*id)
}

/// One side of a cross-slide copy: a part's bytes, its tree and its
/// relationships.
struct Side<'a> {
    bytes: &'a [u8],
    tree: &'a XmlTree,
    links: &'a [Relationship],
}

/// What a cross-slide copy may change inside the copied element: derived
/// from its declared effects and the destination as it was, never from the
/// bytes it wrote.
struct Remap<'a> {
    /// Each copied native id and the id its copy holds.
    ids: BTreeMap<u32, u32>,
    /// The creation ids the destination held before the copy.
    held: BTreeSet<&'a str>,
}

/// The namespace of `xmlns:x` declarations, which are bindings, not
/// attributes.
const XMLNS: &str = "http://www.w3.org/2000/xmlns/";

/// The copied element reads as its source (FIX 8582), from the input's
/// source part and the candidate's destination part: the same expanded
/// element names, attribute names and values, text and child order, and
/// the same bytes wherever no remap reaches. The remaps allowed are the
/// copy's own: the native ids it drew, a creation id the destination held,
/// relationship ids naming the same kind and target, and glue to a shape
/// the copy does not carry removed.
fn copied(
    input: &Package,
    candidate: &Package,
    source: &SlideView,
    destination: &SlideView,
    shape: u32,
    effects: &[Effect],
) -> Result<(), EditRefusal> {
    let fault = || EditRefusal::ReadBack("the copy does not read as its source");
    let ids: BTreeMap<u32, u32> = effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::ShapeCopied { from, id } => Some((*from, *id)),
            _ => None,
        })
        .collect();
    let root = source
        .shapes
        .iter()
        .find(|s| s.id == Some(shape))
        .ok_or_else(fault)?
        .node
        .index;
    let (source_bytes, source_tree) = xml::read(input, &source.part)?;
    let (copy_bytes, copy_tree) = xml::read(candidate, &destination.part)?;
    let copy = ids
        .get(&shape)
        .and_then(|&id| check::find_shape(&copy_tree, id))
        .ok_or_else(fault)?;
    let source_links = input.relationships(&source.part)?;
    let copy_links = candidate.relationships(&destination.part)?;
    let remap = Remap {
        ids,
        held: destination
            .shapes
            .iter()
            .filter_map(|s| s.creation_id.as_deref())
            .collect(),
    };
    let from = Side {
        bytes: &source_bytes,
        tree: &source_tree,
        links: &source_links,
    };
    let into = Side {
        bytes: &copy_bytes,
        tree: &copy_tree,
        links: &copy_links,
    };
    if same_copy(&from, &into, (root, copy), &remap) {
        Ok(())
    } else {
        Err(fault())
    }
}

/// Whether a copy's remap may reach this element.
fn remapped(node: &crate::ooxml::Node) -> bool {
    node.is(P, "cNvPr")
        || node.is(A16, "creationId")
        || node.is(A, "stCxn")
        || node.is(A, "endCxn")
        || node.attrs_ns.keys().any(|(ns, _)| ns == R)
}

/// An element's expanded attributes, its namespace declarations aside.
fn expanded(node: &crate::ooxml::Node) -> BTreeMap<&(String, String), &String> {
    node.attrs_ns
        .iter()
        .filter(|((ns, local), _)| ns != XMLNS && !(ns.is_empty() && local == "xmlns"))
        .collect()
}

/// The bytes between `node`'s kept children, in order, from its open tag to
/// its close tag; a dropped child's bytes go, the bytes around it join.
fn gaps(side: &Side<'_>, node: usize, kept: &[usize]) -> Vec<Vec<u8>> {
    let element = &side.tree.nodes[node];
    let mut out = Vec::new();
    let mut gap = Vec::new();
    let mut cursor = element.content.start;
    for &child in &element.children {
        let span = &side.tree.nodes[child].span;
        gap.extend_from_slice(&side.bytes[cursor..span.start]);
        cursor = span.end;
        if kept.contains(&child) {
            out.push(std::mem::take(&mut gap));
        }
    }
    gap.extend_from_slice(&side.bytes[cursor..element.content.end]);
    out.push(gap);
    out
}

fn same_copy(
    from: &Side<'_>,
    into: &Side<'_>,
    (at, copy): (usize, usize),
    remap: &Remap<'_>,
) -> bool {
    let (old, new) = (&from.tree.nodes[at], &into.tree.nodes[copy]);
    if old.namespace != new.namespace || old.name != new.name || old.text != new.text {
        return false;
    }
    let (old_attrs, new_attrs) = (expanded(old), expanded(new));
    if old_attrs.len() != new_attrs.len() {
        return false;
    }
    let drawn = |value: &str| {
        value
            .parse::<u32>()
            .ok()
            .and_then(|id| remap.ids.get(&id))
            .map(u32::to_string)
    };
    let link = |side: &Side<'_>, id: &str| {
        side.links
            .iter()
            .find(|rel| rel.id == id)
            .map(|rel| (rel.kind.clone(), rel.target.clone(), rel.external))
    };
    for (key, value) in &old_attrs {
        let Some(written) = new_attrs.get(key) else {
            return false;
        };
        let identity = old.is(P, "cNvPr") || old.is(A, "stCxn") || old.is(A, "endCxn");
        let same = match (key.0.as_str(), key.1.as_str()) {
            ("", "id") if identity => drawn(value).as_deref() == Some(written.as_str()),
            ("", "id") if old.is(A16, "creationId") => {
                value == written
                    || (remap.held.contains(value.as_str())
                        && !remap.held.contains(written.as_str()))
            }
            (ns, _) if ns == R => {
                link(from, value).is_some() && link(from, value) == link(into, written)
            }
            _ => value == written,
        };
        if !same {
            return false;
        }
    }
    // Glue to a shape the copy does not carry is removed.
    let kept: Vec<usize> = old
        .children
        .iter()
        .copied()
        .filter(|&child| {
            let node = &from.tree.nodes[child];
            !(node.is(A, "stCxn") || node.is(A, "endCxn"))
                || node
                    .attr("id")
                    .and_then(|id| id.parse::<u32>().ok())
                    .is_some_and(|id| remap.ids.contains_key(&id))
        })
        .collect();
    if kept.len() != new.children.len() || gaps(from, at, &kept) != gaps(into, copy, &new.children)
    {
        return false;
    }
    kept.iter().zip(&new.children).all(|(&child, &written)| {
        if timing::subtree(from.tree, child).any(|n| remapped(&from.tree.nodes[n])) {
            same_copy(from, into, (child, written), remap)
        } else {
            from.bytes[from.tree.nodes[child].span.clone()]
                == into.bytes[into.tree.nodes[written].span.clone()]
        }
    })
}

/// Every shape `old` held reads back in `new` with its identity and content.
pub(super) fn kept(old: &SlideView, new: &SlideView) -> Result<(), EditRefusal> {
    for shape in &old.shapes {
        let found = new
            .shapes
            .iter()
            .find(|s| s.id == shape.id && s.creation_id == shape.creation_id);
        if found.is_none_or(|s| s.content_fingerprint != shape.content_fingerprint) {
            return Err(EditRefusal::ReadBack("a kept shape changed"));
        }
    }
    Ok(())
}
