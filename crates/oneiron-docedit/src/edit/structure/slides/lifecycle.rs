//! A blank slide over a layout, and a slide's removal from the list: the
//! live-deck projector's slide verbs.
//!
//! A blank slide holds an empty shape tree, the master's colour mapping and
//! a minted `p14:creationId`; it relates to its layout and takes a slide id
//! above the caller's high-water mark, and the app properties count it and
//! list its title. A removal takes the slide's list and section entries and
//! its presentation relationship away, then drops from the archive every
//! part the slide reaches that the package root no longer does: the slide,
//! its notes slide and comments, and media, charts or embeddings only it
//! used. A part another survivor still relates to stays. The app properties
//! lose the slide from their counts and titles, and the content types lose
//! each extension default no part uses any more. An emptied section stays,
//! as PowerPoint keeps one. Either way the app properties recount the
//! deck's words and paragraphs.

use super::super::super::check::declared_type;
use super::super::super::media::related;
use super::super::super::xml::{self, A, P, R};
use super::super::Plan;
use super::app_props::Text;
use super::{Lists, P14, SLIDE_CREATION_EXT, SLIDE_IDS, copy_with, custom_shows, mint_creation_id};
use crate::deck::DeckView;
use crate::edit::{EditRefusal, Effect};
use crate::ooxml::{Node, XmlTree};
use crate::retained_opc::Package;

const SLIDE_TYPE: &str = "application/vnd.openxmlformats-officedocument.presentationml.slide+xml";
const LAYOUT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml";

/// The lists that come before `p:sldIdLst` in `p:presentation`.
const BEFORE_SLIDES: [&str; 3] = ["sldMasterIdLst", "notesMasterIdLst", "handoutMasterIdLst"];

pub(in super::super) fn add_blank(
    next: &mut Package,
    before: &DeckView,
    after: Option<&str>,
    layout: &str,
    high_water: u32,
    seed: &[u8],
) -> Result<(Plan, Vec<Effect>), EditRefusal> {
    let input = next.clone();
    if declared_type(&input, layout)?.as_deref() != Some(LAYOUT_TYPE) {
        return Err(EditRefusal::Invalid(
            "the layout is not a slide layout part",
        ));
    }
    let lists = Lists::read(&input)?;
    let sld_id = lists
        .slides
        .iter()
        .map(|&(_, id)| id)
        .chain([high_water, SLIDE_IDS.start - 1])
        .max()
        .and_then(|high| high.checked_add(1))
        .filter(|id| SLIDE_IDS.contains(id))
        .ok_or(EditRefusal::IdSpaceExhausted)?;
    let taken: Vec<u32> = before.slides.iter().filter_map(|s| s.creation_id).collect();
    let creation_id = mint_creation_id(seed, &taken)?;
    let part = xml::next_part(&input, "ppt/slides/slide", ".xml")?;
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="{A}" xmlns:r="{R}" xmlns:p="{P}"><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree><p:extLst><p:ext uri="{SLIDE_CREATION_EXT}"><p14:creationId xmlns:p14="{P14}" val="{creation_id}"/></p:ext></p:extLst></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>"#
    );
    next.add_part(&part, SLIDE_TYPE, body.into_bytes())?;
    next.relate(&part, &format!("{R}/slideLayout"), layout)?;
    let link = next.relate(&lists.part, &format!("{R}/slide"), &part)?;
    let id = sld_id.to_string();

    // The list entry goes after `after`'s (or first), as a copy of a
    // neighbouring entry so it keeps the list's own prefixes.
    let links = input.relationships(&lists.part)?;
    let entry_of = |slide: &str| -> Result<usize, EditRefusal> {
        let mut found = lists.slides.iter().filter(|&&(at, _)| {
            lists.tree.nodes[at]
                .attr_ns(R, "id")
                .is_some_and(|rid| links.iter().any(|rel| rel.id == rid && rel.target == slide))
        });
        match (found.next(), found.next()) {
            (Some(&(at, _)), None) => Ok(at),
            _ => Err(EditRefusal::AmbiguousAnchor("the slide's list entry")),
        }
    };
    let anchor = after.map(entry_of).transpose()?;
    let mut edits = Vec::new();
    match (anchor, lists.slides.first()) {
        (Some(at), _) => {
            let node = &lists.tree.nodes[at];
            let point = node.span.end;
            edits.push((point..point, entry(&lists.bytes, node, &id, &link)?));
        }
        (None, Some(&(first, _))) => {
            let node = &lists.tree.nodes[first];
            let point = node.span.start;
            edits.push((point..point, entry(&lists.bytes, node, &id, &link)?));
        }
        (None, None) => {
            let prefix = xml::prefix(&lists.tree.nodes[0]);
            let inner = format!(
                r#"<{} xmlns:r="{R}" id="{id}" r:id="{link}"/>"#,
                xml::qualify(prefix, "sldId")
            );
            match xml::child(&lists.tree, 0, P, "sldIdLst") {
                Some(list) => {
                    edits.push(xml::insert_last(
                        &lists.bytes,
                        &lists.tree.nodes[list],
                        &inner,
                    ));
                }
                None => {
                    let point = BEFORE_SLIDES
                        .iter()
                        .filter_map(|name| xml::child(&lists.tree, 0, P, name))
                        .map(|at| lists.tree.nodes[at].span.end)
                        .max()
                        .ok_or(EditRefusal::Missing("slide master list"))?;
                    let list = xml::qualify(prefix, "sldIdLst");
                    edits.push((
                        point..point,
                        format!("<{list}>{inner}</{list}>").into_bytes(),
                    ));
                }
            }
        }
    }
    let section = match after {
        Some(slide) => {
            let anchor_id = before
                .slides
                .iter()
                .find(|view| view.part == slide)
                .map(|view| view.sld_id)
                .ok_or(EditRefusal::Missing("slide"))?;
            let mut placed = lists
                .sections
                .iter()
                .flatten()
                .filter(|&&(_, member)| member == anchor_id);
            match (placed.next(), placed.next()) {
                (Some(&(at, _)), None) => Some((at, false)),
                (None, _) => None,
                (Some(_), Some(_)) => {
                    return Err(EditRefusal::AmbiguousAnchor("the slide is in two sections"));
                }
            }
        }
        None => lists
            .sections
            .iter()
            .find_map(|section| section.first())
            .map(|&(at, _)| (at, true)),
    };
    if let Some((at, first)) = section {
        let node = &lists.tree.nodes[at];
        let point = if first {
            node.span.start
        } else {
            node.span.end
        };
        edits.push((
            point..point,
            copy_with(&lists.bytes, node, &[("id", id.as_str())])?,
        ));
    } else if !lists.sections.is_empty() {
        return Err(EditRefusal::ReorderUnsupported("a slide in no section"));
    }
    next.replace_xml_part(&lists.part, xml::splice(&lists.bytes, edits)?)?;
    let index = anchor
        .and_then(|at| lists.slides.iter().position(|&(entry, _)| entry == at))
        .map_or(0, |at| at + 1);
    super::app_props::slide_added(
        next,
        (index, lists.slides.len()),
        (false, false),
        None,
        Text::of_deck(before),
    )?;
    Ok((
        Plan::Arranged,
        vec![Effect::SlideAdded {
            part,
            sld_id,
            creation_id: Some(creation_id),
        }],
    ))
}

/// A list entry: a copy of `node` with the new id and relationship.
fn entry(bytes: &[u8], node: &Node, id: &str, link: &str) -> Result<Vec<u8>, EditRefusal> {
    let attribute =
        super::relationship_attribute(node).ok_or(EditRefusal::Invalid("a slide id entry"))?;
    copy_with(bytes, node, &[("id", id), (attribute, link)])
}

/// The parts of `package` that `slide` reaches and the package root does
/// not: what a slide the presentation no longer lists leaves behind. None
/// while the root still reaches the slide itself.
fn released(package: &Package, slide: &str) -> Result<Vec<String>, EditRefusal> {
    let kept = package.reachable("")?;
    if kept.contains(slide) {
        return Ok(Vec::new());
    }
    let held: std::collections::BTreeSet<&str> = package.names().collect();
    Ok(package
        .reachable(slide)?
        .into_iter()
        .filter(|part| !kept.contains(part) && held.contains(part.as_str()))
        .collect())
}

pub(in super::super) fn delete(
    next: &mut Package,
    before: &DeckView,
    slide: &str,
    expected: [u8; 32],
) -> Result<(Plan, Vec<Effect>), EditRefusal> {
    let input = next.clone();
    let view = before
        .slides
        .iter()
        .find(|view| view.part == slide)
        .ok_or(EditRefusal::Missing("slide"))?;
    if view.render_fingerprint != expected {
        return Err(EditRefusal::TargetChanged);
    }
    for other in before.slides.iter().filter(|other| other.part != slide) {
        if input
            .relationships(&other.part)?
            .iter()
            .any(|rel| !rel.external && rel.target == slide)
        {
            return Err(EditRefusal::Invalid("another slide links to the slide"));
        }
    }
    let lists = Lists::read(&input)?;
    let links = input.relationships(&lists.part)?;
    let names_slide = |node: &Node| {
        node.attr_ns(R, "id")
            .is_some_and(|id| links.iter().any(|rel| rel.id == id && rel.target == slide))
    };
    if !custom_shows(&lists, &names_slide).is_empty() {
        return Err(EditRefusal::Invalid("a custom show lists the slide"));
    }
    let mut entries = lists
        .slides
        .iter()
        .filter(|&&(at, id)| id == view.sld_id && names_slide(&lists.tree.nodes[at]));
    let (Some(&(entry, _)), None) = (entries.next(), entries.next()) else {
        return Err(EditRefusal::AmbiguousAnchor("the slide's list entry"));
    };
    let link = lists.tree.nodes[entry]
        .attr_ns(R, "id")
        .ok_or(EditRefusal::Invalid("a slide id entry"))?
        .to_owned();
    let index = lists
        .slides
        .iter()
        .position(|&(at, _)| at == entry)
        .ok_or(EditRefusal::Invalid("a slide id entry"))?;
    let hidden = input
        .part(slide)?
        .and_then(|bytes| XmlTree::parse(&bytes, input.limits().xml).ok())
        .is_some_and(|tree| matches!(tree.nodes[0].attr("show"), Some("0" | "false")));
    let notes = related(&input, slide, "notesSlide").is_ok_and(|notes| notes.is_some());
    let mut edits = vec![(lists.tree.nodes[entry].span.clone(), Vec::new())];
    edits.extend(
        lists
            .sections
            .iter()
            .flatten()
            .filter(|&&(_, member)| member == view.sld_id)
            .map(|&(at, _)| (lists.tree.nodes[at].span.clone(), Vec::new())),
    );
    next.replace_xml_part(&lists.part, xml::splice(&lists.bytes, edits)?)?;
    next.unrelate(&lists.part, &link)?;
    let released = released(next, slide)?;
    for part in &released {
        next.remove_part(part)?;
    }
    super::app_props::slide_removed(
        next,
        index,
        lists.slides.len(),
        (hidden, notes),
        Text::of_deck(before).less(Text::of_slide(view)),
    )?;
    if !released.is_empty() {
        next.prune_defaults()?;
    }
    Ok((
        Plan::Arranged,
        vec![Effect::SlideRemoved {
            part: slide.to_owned(),
            sld_id: view.sld_id,
        }],
    ))
}
