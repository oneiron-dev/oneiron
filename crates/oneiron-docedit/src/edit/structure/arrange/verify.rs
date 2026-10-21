//! Independent read-back checks for projector arrangement verbs.
//! Entry: `verify`.
//! Definitions live here; arrange preserves the old visibility-scoped bindings.

use super::*;

/// The independent check of every projector verb.
pub(in crate::edit::structure) fn verify(
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
