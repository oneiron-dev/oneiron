//! The live-deck projector's shape verbs: a sibling reorder (z-order), an
//! empty group framed over slide space, and a cross-slide copy that carries
//! its relationships and draws its native ids on the destination. With the
//! slide verbs in `slides/lifecycle.rs` and the picture and connector in
//! `born.rs`, each is checked here from the exported candidate: only its own
//! parts change, every other slide and shape reads back as it was, and the
//! written result reads back as asked.

use super::super::media::related;
use super::super::xml::{self, A, P, R};
use super::{
    A16, NewGroup, Plan, SHAPE_CREATION_EXT, StructureEdit, check, end_of, highest_id, mint_guid,
    position, shape_tree, timing,
};
use crate::deck::{DeckView, ShapeKind, ShapeView, SlideView};
use crate::edit::{EditRefusal, Effect, Xfrm};
use crate::retained_opc::{Package, rels_name};
use std::collections::{BTreeMap, BTreeSet};

const TYPES: &str = "[Content_Types].xml";

/// View indices of the direct members of `container` (`None`: the shape
/// tree), in document order.
fn direct(slide: &SlideView, container: Option<usize>) -> Vec<usize> {
    (0..slide.shapes.len())
        .filter(|&at| slide.shapes[at].group_path.last().copied() == container)
        .collect()
}

pub(super) fn reorder(
    next: &mut Package,
    slide: &SlideView,
    shape: &ShapeView,
    index: usize,
) -> Result<(Plan, Vec<Effect>), EditRefusal> {
    let at = position(slide, shape);
    let container = shape.group_path.last().copied();
    let siblings = direct(slide, container);
    let from = siblings
        .iter()
        .position(|&member| member == at)
        .ok_or(EditRefusal::Missing("shape"))?;
    if index >= siblings.len() {
        return Err(EditRefusal::Invalid("the index is past the last sibling"));
    }
    if from == index {
        return Err(EditRefusal::Invalid("the shape is already at that index"));
    }
    let (bytes, tree) = xml::read(next, &slide.part)?;
    let element = match container {
        None => shape_tree(&tree)?,
        Some(group) => slide.shapes[group].node.index,
    };
    if siblings
        .iter()
        .any(|&member| tree.nodes[slide.shapes[member].node.index].parent != Some(element))
    {
        return Err(EditRefusal::AmbiguousAnchor(
            "a sibling inside markup the view does not enter",
        ));
    }
    let rest: Vec<usize> = siblings.into_iter().filter(|&m| m != at).collect();
    let to = match rest.get(index) {
        Some(&member) => tree.nodes[slide.shapes[member].node.index].span.start,
        None => {
            let last = *rest.last().ok_or(EditRefusal::Missing("sibling"))?;
            tree.nodes[slide.shapes[last].node.index].span.end
        }
    };
    let span = tree.nodes[shape.node.index].span.clone();
    let moved = bytes[span.clone()].to_vec();
    next.replace_xml_part(
        &slide.part,
        xml::splice(&bytes, vec![(span, Vec::new()), (to..to, moved)])?,
    )?;
    Ok((Plan::Arranged, Vec::new()))
}

pub(super) fn add_group(
    next: &mut Package,
    slide: &SlideView,
    group: &NewGroup<'_>,
) -> Result<(Plan, Vec<Effect>), EditRefusal> {
    if !xml::writable(group.name) {
        return Err(EditRefusal::Invalid(
            "the name holds a character XML cannot carry",
        ));
    }
    super::transform::check_ranges(&Xfrm {
        offset: Some(group.offset),
        extent: Some(group.extent),
        ..Xfrm::default()
    })?;
    if group.extent.0 <= 0 || group.extent.1 <= 0 {
        return Err(EditRefusal::Invalid(
            "a group frame needs a positive extent",
        ));
    }
    let (bytes, tree) = xml::read(next, &slide.part)?;
    let id = highest_id(&tree)
        .max(group.high_water)
        .checked_add(1)
        .ok_or(EditRefusal::IdSpaceExhausted)?;
    let taken: Vec<&str> = slide
        .shapes
        .iter()
        .filter_map(|shape| shape.creation_id.as_deref())
        .collect();
    let creation_id = mint_guid(group.seed, &taken)?;
    let ((x, y), (cx, cy)) = (group.offset, group.extent);
    let element = format!(
        r#"<p:grpSp xmlns:p="{P}" xmlns:a="{A}"><p:nvGrpSpPr><p:cNvPr id="{id}" name="{}"><a:extLst><a:ext uri="{SHAPE_CREATION_EXT}"><a16:creationId xmlns:a16="{A16}" id="{creation_id}"/></a:ext></a:extLst></p:cNvPr><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{cx}" cy="{cy}"/><a:chOff x="{x}" y="{y}"/><a:chExt cx="{cx}" cy="{cy}"/></a:xfrm></p:grpSpPr></p:grpSp>"#,
        xml::escape_attribute(group.name),
    );
    let at = end_of(&tree, shape_tree(&tree)?);
    next.replace_xml_part(
        &slide.part,
        xml::splice(&bytes, vec![(at..at, element.into_bytes())])?,
    )?;
    Ok((Plan::Arranged, vec![Effect::ShapeAdded { id, creation_id }]))
}

/// The qualified attribute name `node` writes `(R, local)` with.
fn qualified<'n>(node: &'n crate::ooxml::Node, local: &str) -> Option<&'n str> {
    let value = node.attr_ns(R, local)?;
    node.attr_spans
        .keys()
        .find(|name| {
            name.rsplit_once(':').is_some_and(|(_, own)| own == local)
                && node.attr(name) == Some(value)
        })
        .map(String::as_str)
}

pub(super) fn copy_to_slide(
    next: &mut Package,
    before: &DeckView,
    from: usize,
    shape: &ShapeView,
    to: &str,
    high_water: u32,
    seed: &[u8],
) -> Result<(Plan, Vec<Effect>), EditRefusal> {
    let source = &before.slides[from];
    if source.part == to {
        return Err(EditRefusal::Invalid("the shape is already on that slide"));
    }
    let destination = before
        .slides
        .iter()
        .find(|view| view.part == to)
        .ok_or(EditRefusal::Missing("slide"))?;
    let input = next.clone();
    let (bytes, tree) = xml::read(&input, &source.part)?;
    let (target_bytes, target_tree) = xml::read(&input, to)?;
    let links = input.relationships(&source.part)?;
    let root = shape.node.index;
    let inside: Vec<usize> = timing::subtree(&tree, root).collect();
    let mut taken: Vec<String> = destination
        .shapes
        .iter()
        .filter_map(|shape| shape.creation_id.clone())
        .collect();

    // One new id per old id, in document order: a choice and its fallback
    // that share an id keep sharing it.
    let mut ids: BTreeMap<u32, u32> = BTreeMap::new();
    let mut high = highest_id(&target_tree).max(high_water);
    let mut effects = Vec::new();
    for &at in &inside {
        let node = &tree.nodes[at];
        if !node.is(P, "cNvPr") {
            continue;
        }
        let old = node
            .attr("id")
            .and_then(|id| id.parse::<u32>().ok())
            .ok_or(EditRefusal::Missing("shape id"))?;
        if !ids.contains_key(&old) {
            high = high.checked_add(1).ok_or(EditRefusal::IdSpaceExhausted)?;
            ids.insert(old, high);
            effects.push(Effect::ShapeCopied {
                from: old,
                id: high,
            });
        }
    }
    let mut edits: Vec<xml::Splice> = Vec::new();
    let mut related: BTreeMap<String, String> = BTreeMap::new();
    let mut unglued = Vec::new();
    for &at in &inside {
        let node = &tree.nodes[at];
        if node.is(P, "cNvPr") {
            if let Some(new) = node
                .attr("id")
                .and_then(|id| id.parse().ok())
                .and_then(|id: u32| ids.get(&id))
            {
                edits.push(xml::set_attribute(&bytes, node, "id", &new.to_string()));
            }
        } else if node.is(A16, "creationId")
            && let Some(guid) = node.attr("id")
            && taken.iter().any(|held| held == guid)
        {
            let fresh = {
                let refs: Vec<&str> = taken.iter().map(String::as_str).collect();
                mint_guid(&[seed, guid.as_bytes()].concat(), &refs)?
            };
            edits.push(xml::set_attribute(&bytes, node, "id", &fresh));
            taken.push(fresh);
        } else if node.is(A, "stCxn") || node.is(A, "endCxn") {
            match node.attr("id").and_then(|id| id.parse::<u32>().ok()) {
                Some(glued) if ids.contains_key(&glued) => {
                    edits.push(xml::set_attribute(
                        &bytes,
                        node,
                        "id",
                        &ids[&glued].to_string(),
                    ));
                }
                _ => {
                    edits.push((node.span.clone(), Vec::new()));
                    unglued.push(at);
                }
            }
        }
        let rel_attrs: Vec<String> = node
            .attrs_ns
            .keys()
            .filter(|(ns, _)| ns == R)
            .map(|(_, local)| local.clone())
            .collect();
        for local in rel_attrs {
            let Some(old) = node.attr_ns(R, &local) else {
                continue;
            };
            let id = match related.get(old) {
                Some(id) => id.clone(),
                None => {
                    let link = links
                        .iter()
                        .find(|rel| rel.id == old)
                        .ok_or(EditRefusal::Missing("relationship"))?;
                    let id = if link.external {
                        next.relate_external(to, &link.kind, &link.target)?
                    } else {
                        next.relate(to, &link.kind, &link.target)?
                    };
                    related.insert(old.to_owned(), id.clone());
                    id
                }
            };
            let name =
                qualified(node, &local).ok_or(EditRefusal::Invalid("a relationship attribute"))?;
            edits.push(xml::set_attribute(&bytes, node, name, &id));
        }
    }
    if !unglued.is_empty() {
        effects.push(Effect::Unglued { connector: None });
    }
    // Splice inside a copy of the element alone, so offsets are its own.
    let span = tree.nodes[root].span.clone();
    let mut local: Vec<xml::Splice> = edits
        .into_iter()
        .map(|(range, value)| ((range.start - span.start)..(range.end - span.start), value))
        .collect();
    // The source root's namespace bindings the element does not carry itself.
    let declared: String = tree.nodes[0]
        .attrs
        .iter()
        .filter(|(name, _)| {
            (name.as_str() == "xmlns" || name.starts_with("xmlns:"))
                && !tree.nodes[root].attrs.contains_key(name.as_str())
        })
        .map(|(name, value)| format!(" {name}=\"{}\"", xml::escape_attribute(value)))
        .collect();
    let open = tree.nodes[root].qualified.len() + 1;
    local.push((open..open, declared.into_bytes()));
    let element = xml::splice(&bytes[span], local)?;
    let at = end_of(&target_tree, shape_tree(&target_tree)?);
    next.replace_xml_part(to, xml::splice(&target_bytes, vec![(at..at, element)])?)?;
    Ok((Plan::Arranged, effects))
}

/// The independent check of every projector verb.
pub(super) fn verify(
    input: &Package,
    next: &Package,
    before: &DeckView,
    op: &StructureEdit<'_>,
    effects: &[Effect],
) -> Result<Vec<String>, EditRefusal> {
    let candidate = Package::open(&next.export()?, input.limits())?;
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
            let asked =
                |end: Option<(u32, u32)>| end.map(|(shape, site)| (Some(shape), Some(site)));
            if prst != Some(connector.preset.name())
                || end("stCxn") != asked(connector.start)
                || end("endCxn") != asked(connector.end)
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
fn released(input: &Package, candidate: &Package, slide: &str) -> Result<Vec<String>, EditRefusal> {
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

fn slide_pair<'v>(
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
fn added(
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

/// Every shape `old` held reads back in `new` with its identity and content.
fn kept(old: &SlideView, new: &SlideView) -> Result<(), EditRefusal> {
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
