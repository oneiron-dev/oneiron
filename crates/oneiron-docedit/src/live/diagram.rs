//! SmartArt structure (OF-510, FIX 3697): nodes added, removed, re-levelled
//! or moved, as PowerPoint's text pane does, and a live-born SmartArt.
//!
//! A SmartArt's data part holds its model: a point per node (and per
//! assistant), a parent-of connection from each node to its parent (the
//! document point at the top) with a transition point at each end, and the
//! presentation points its layout made. An edit that keeps every node and
//! level writes the nodes' text in place ([`convert::smart_art_text`]).
//! Otherwise the model is rewritten: kept nodes keep their points and
//! presentation points, their connections retargeted to their new parent
//! and place; a new node gets a point, its two transition points and its
//! connection; a removed node's points, the presentation points made for
//! them and every connection naming one go. The cached drawing goes too,
//! and PowerPoint lays the diagram out again from its layout.
//!
//! Node identities are the data part's model ids. New ones are minted from
//! the SmartArt's held ids and the node's place, never from who made the
//! edit, so a fork's candidate and its landing mint the same ones.
//!
//! A live-born SmartArt is the engine's own outline list: its layout, quick
//! style and colour definitions are written here under oneiron URNs (no
//! Office layout file is copied: those are Microsoft's), with a data part
//! of its nodes and a graphic frame naming the four.

use super::LiveError;
use super::conversion::Conversion;
use super::convert::{self, DSP, paragraphs, text_body};
use super::held::{self, DGM, SmartArtPoints, children};
use super::pptx::{SmartArtNode, WRITTEN_FRAME};
use super::reshape::frame_of;
use crate::edit::xml::{self, A, P, R, next_part};
use crate::native_patch::insert_frame;
use crate::ooxml::XmlTree;
use crate::retained_opc::Package;
use std::collections::{BTreeMap, BTreeSet};

/// The engine's own SmartArt definitions (a CALLS row: no Office layout,
/// style or colour file is copied).
const LAYOUT_URN: &str = "urn:oneiron:smartart:layout:outline-list";
const STYLE_URN: &str = "urn:oneiron:smartart:style:plain";
const COLORS_URN: &str = "urn:oneiron:smartart:colors:accent1";
const DATA_TYPE: &str = "application/vnd.openxmlformats-officedocument.drawingml.diagramData+xml";
const LAYOUT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.drawingml.diagramLayout+xml";
const STYLE_TYPE: &str = "application/vnd.openxmlformats-officedocument.drawingml.diagramStyle+xml";
const COLORS_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.drawingml.diagramColors+xml";
/// A SmartArt's data part reads as no model the deck can rewrite.
const NO_MODEL: &str = "a SmartArt's data part has no document point or node list";
const READ_BACK: &str = "a rewritten SmartArt does not read back as the live nodes";

/// A GUID-form model id from a digest's first 16 bytes.
fn guid(digest: &[u8; 32]) -> String {
    let hex: String = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect();
    format!(
        "{{{}-{}-{}-{}-{}}}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The model id of `role` (a transition point, a connection, the document
/// point) derived from the node id it belongs to.
fn derived(node: &str, role: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron smartart point\0");
    hasher.update(node.as_bytes());
    hasher.update(b"\0");
    hasher.update(role.as_bytes());
    guid(hasher.finalize().as_bytes())
}

/// A new node's model id: from the held ids and its place, free of `taken`.
fn mint(held: &[&str], place: usize, taken: &BTreeSet<String>) -> String {
    let mut round = 0u64;
    loop {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron smartart node\0");
        for id in held {
            hasher.update(id.as_bytes());
            hasher.update(b"\0");
        }
        hasher.update(&u64::try_from(place).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(&round.to_le_bytes());
        let id = guid(hasher.finalize().as_bytes());
        if !taken.contains(&id) {
            return id;
        }
        round = round.saturating_add(1);
    }
}

/// SmartArt nodes written over `held` (empty for a live-born SmartArt), as
/// the text pane takes them: the first node at the top level and each at
/// most one level below the one before (deeper ones clamped), and every
/// node naming its model id. A node names a held id it keeps; one naming
/// none, an unknown id or one an earlier node took is new, minted here.
/// When no node names an id, nodes take the held ids by place.
pub(super) fn settle(
    held: &[SmartArtNode],
    wanted: &[SmartArtNode],
) -> (Vec<SmartArtNode>, Vec<Conversion>) {
    let held_ids: Vec<&str> = held.iter().filter_map(|node| node.id.as_deref()).collect();
    let by_place = wanted.iter().all(|node| node.id.is_none());
    let mut taken: BTreeSet<String> = BTreeSet::new();
    let mut previous: Option<u32> = None;
    let mut clamped = 0u32;
    let mut settled: Vec<SmartArtNode> = Vec::with_capacity(wanted.len());
    for (place, node) in wanted.iter().enumerate() {
        let level = previous.map_or(0, |before| node.level.min(before.saturating_add(1)));
        if level != node.level {
            clamped = clamped.saturating_add(1);
        }
        previous = Some(level);
        let named = if by_place {
            held_ids.get(place).copied()
        } else {
            node.id.as_deref()
        };
        let id = named
            .filter(|id| held_ids.contains(id) && !taken.contains(*id))
            .map(str::to_owned);
        if let Some(id) = &id {
            taken.insert(id.clone());
        }
        settled.push(SmartArtNode {
            text: node.text.clone(),
            level,
            id,
        });
    }
    taken.extend(held_ids.iter().copied().map(str::to_owned));
    for (place, node) in settled.iter_mut().enumerate() {
        if node.id.is_none() {
            let id = mint(&held_ids, place, &taken);
            taken.insert(id.clone());
            node.id = Some(id);
        }
    }
    let done = if clamped > 0 {
        vec![Conversion::SmartArtLevelsClamped { nodes: clamped }]
    } else {
        Vec::new()
    };
    (settled, done)
}

/// Each node's parent (`doc` at the top level) and its place among its
/// parent's children, from the nodes' levels.
fn placed<'n>(doc: &'n str, nodes: &'n [SmartArtNode]) -> Vec<(&'n str, u32)> {
    let mut stack: Vec<(u32, &str)> = Vec::new();
    let mut count: BTreeMap<&str, u32> = BTreeMap::new();
    let mut out = Vec::with_capacity(nodes.len());
    for node in nodes {
        while stack.last().is_some_and(|&(level, _)| level >= node.level) {
            stack.pop();
        }
        let parent = stack.last().map_or(doc, |&(_, id)| id);
        let place = count.entry(parent).or_insert(0);
        out.push((parent, *place));
        *place = place.saturating_add(1);
        stack.push((node.level, node.id.as_deref().unwrap_or_default()));
    }
    out
}

/// A new node's point, its transition points and its parent connection,
/// under the diagram prefix `dgm`.
struct Link {
    point: String,
    transitions: String,
    connection: String,
}

fn link(dgm: &str, node: &SmartArtNode, parent: &str, place: u32) -> Link {
    let q = |name: &str| xml::qualify(dgm, name);
    let id = node.id.as_deref().unwrap_or_default();
    let (cxn, par, sib) = (
        derived(id, "cxn"),
        derived(id, "parTrans"),
        derived(id, "sibTrans"),
    );
    let body = |inner: &str| {
        format!(
            r#"<{t}><a:bodyPr xmlns:a="{A}"/><a:lstStyle xmlns:a="{A}"/>{inner}</{t}>"#,
            t = q("t")
        )
    };
    let text = String::from_utf8_lossy(&paragraphs(&node.text, None, [&[], &[], &[]])).into_owned();
    let transition = |at: &str, kind: &str| {
        format!(
            r#"<{pt} modelId="{at}" type="{kind}" cxnId="{cxn}"><{pr}/><{sp}/>{}</{pt}>"#,
            body(&format!(r#"<a:p xmlns:a="{A}"/>"#)),
            pt = q("pt"),
            pr = q("prSet"),
            sp = q("spPr"),
        )
    };
    let point = format!(
        r#"<{pt} modelId="{id}"><{pr} phldrT="[Text]"/><{sp}/>{}</{pt}>"#,
        body(&text),
        pt = q("pt"),
        pr = q("prSet"),
        sp = q("spPr"),
    );
    let transitions = transition(&par, "parTrans") + &transition(&sib, "sibTrans");
    let connection = format!(
        r#"<{} modelId="{cxn}" srcId="{parent}" destId="{id}" srcOrd="{place}" destOrd="0" parTransId="{par}" sibTransId="{sib}"/>"#,
        q("cxn")
    );
    Link {
        point,
        transitions,
        connection,
    }
}

/// An element's bytes with these attributes set.
fn with_attributes(bytes: &[u8], node: &crate::ooxml::Node, set: &[(&str, &str)]) -> Vec<u8> {
    let start = node.span.start;
    let edits = set
        .iter()
        .map(|(name, value)| {
            let (range, value) = xml::set_attribute(bytes, node, name, value);
            (range.start - start..range.end - start, value)
        })
        .collect();
    xml::splice(&bytes[node.span.clone()], edits)
        .unwrap_or_else(|_| bytes[node.span.clone()].to_vec())
}

/// Write a SmartArt's nodes over the frame `native` on `slide`: their text
/// in place when every node and level is kept, else the model rewritten.
/// The parts it changed, and what it did.
pub(super) fn write(
    package: &mut Package,
    slide: &str,
    native: u32,
    wanted: &[SmartArtNode],
) -> Result<(Vec<String>, Vec<Conversion>), LiveError> {
    let tree = held::slide_tree(package, slide)?;
    let frame = frame_of(&tree, native).ok_or(LiveError::Invalid(WRITTEN_FRAME))?;
    let read = held::smart_art_of(package, slide, &tree, frame)
        .ok_or(LiveError::Invalid(WRITTEN_FRAME))?;
    let kept = read.points.len() == wanted.len()
        && read.points.iter().zip(wanted).all(|((id, was), now)| {
            now.id.as_deref() == Some(id.as_str()) && was.level == now.level
        });
    if kept {
        let (changed, written) = convert::smart_art_text(package, slide, native, wanted)?;
        let done = if written > 0 {
            vec![Conversion::SmartArtTextWritten { nodes: written }]
        } else {
            Vec::new()
        };
        return Ok((changed, done));
    }
    let drawing = xml::read(package, &read.data)?
        .1
        .nodes
        .iter()
        .find(|node| node.is(DSP, "dataModelExt"))
        .and_then(|node| node.attr("relId"))
        .map(str::to_owned);
    let mut changed = vec![read.data.clone()];
    let mut done = vec![restructure(package, &read, wanted)?];
    if let Some(drawing) = drop_drawing(package, slide, &read.data, drawing.as_deref())? {
        changed.push(drawing);
        done.push(Conversion::SmartArtDrawingDropped);
    }
    let tree = held::slide_tree(package, slide)?;
    let back =
        frame_of(&tree, native).and_then(|frame| held::smart_art_of(package, slide, &tree, frame));
    let same = back.is_some_and(|back| {
        back.points.len() == wanted.len()
            && back.points.iter().zip(wanted).all(|((id, was), now)| {
                now.id.as_deref() == Some(id.as_str()) && was.level == now.level
            })
    });
    if !same {
        return Err(LiveError::Invalid(READ_BACK));
    }
    Ok((changed, done))
}

/// Rewrite the data part's points and connections for `wanted` (see the
/// module notes); what it did.
fn restructure(
    package: &mut Package,
    read: &SmartArtPoints,
    wanted: &[SmartArtNode],
) -> Result<Conversion, LiveError> {
    let refuse = || LiveError::Invalid(NO_MODEL);
    let (bytes, model) = xml::read(package, &read.data)?;
    let list = xml::child(&model, 0, DGM, "ptLst").ok_or_else(refuse)?;
    let links = xml::child(&model, 0, DGM, "cxnLst");
    let points: Vec<usize> = children(&model, list, DGM, "pt").collect();
    let id_of = |at: usize| model.nodes[at].attr("modelId");
    let doc = points
        .iter()
        .copied()
        .find(|&pt| model.nodes[pt].attr("type") == Some("doc"))
        .and_then(id_of)
        .ok_or_else(refuse)?;
    let dgm = xml::prefix(&model.nodes[list]);
    let held_ids: BTreeSet<&str> = read.points.iter().map(|(id, _)| id.as_str()).collect();
    let wanted_at: BTreeMap<&str, usize> = wanted
        .iter()
        .enumerate()
        .filter_map(|(at, node)| Some((node.id.as_deref()?, at)))
        .collect();
    let places = placed(doc, wanted);
    let cxns: Vec<usize> = links.map_or_else(Vec::new, |links| {
        children(&model, links, DGM, "cxn").collect()
    });
    let parent_of = |at: usize| model.nodes[at].attr("type").unwrap_or("parOf") == "parOf";
    let linked: BTreeMap<&str, usize> = cxns
        .iter()
        .copied()
        .filter(|&cxn| parent_of(cxn))
        .filter_map(|cxn| Some((model.nodes[cxn].attr("destId")?, cxn)))
        .filter(|(dest, _)| held_ids.contains(dest))
        .collect();
    // What goes: removed nodes, their transition points, and the
    // presentation points made for any of them.
    let mut gone: BTreeSet<&str> = held_ids
        .iter()
        .copied()
        .filter(|id| !wanted_at.contains_key(id))
        .collect();
    let removed = u32::try_from(gone.len()).unwrap_or(u32::MAX);
    let removed_links: Vec<usize> = gone
        .iter()
        .filter_map(|id| linked.get(id).copied())
        .collect();
    for cxn in removed_links {
        for role in ["parTransId", "sibTransId"] {
            if let Some(point) = model.nodes[cxn].attr(role) {
                gone.insert(point);
            }
        }
    }
    let presented: Vec<&str> = points
        .iter()
        .copied()
        .filter(|&pt| {
            model.nodes[pt].attr("type") == Some("pres")
                && xml::child(&model, pt, DGM, "prSet")
                    .and_then(|set| model.nodes[set].attr("presAssocID"))
                    .is_some_and(|assoc| gone.contains(assoc))
        })
        .filter_map(id_of)
        .collect();
    gone.extend(presented);

    let mut point_list = xml::open_tag(&bytes, &model.nodes[list]);
    for &pt in &points {
        let node = &model.nodes[pt];
        match node.attr("modelId") {
            Some(id) if gone.contains(id) => {}
            Some(id) if held_ids.contains(id) => {
                let now = wanted_at.get(id).map(|&at| wanted[at].text.as_str());
                let was = read
                    .points
                    .iter()
                    .find(|(seen, _)| seen == id)
                    .map(|(_, node)| node.text.as_str());
                match now.filter(|now| Some(*now) != was) {
                    Some(text) => point_list.extend(point_with_text(&bytes, &model, pt, text)),
                    None => point_list.extend_from_slice(&bytes[node.span.clone()]),
                }
            }
            _ => point_list.extend_from_slice(&bytes[node.span.clone()]),
        }
    }
    let mut connections = match links {
        Some(links) => xml::open_tag(&bytes, &model.nodes[links]),
        None => format!("<{}>", xml::qualify(dgm, "cxnLst")).into_bytes(),
    };
    for &cxn in &cxns {
        let node = &model.nodes[cxn];
        // A kept node's parent link takes its new parent and place, even
        // when its old parent went.
        if parent_of(cxn)
            && let Some(&at) = node.attr("destId").and_then(|dest| wanted_at.get(dest))
        {
            let (parent, place) = places[at];
            let place = place.to_string();
            connections.extend(with_attributes(
                &bytes,
                node,
                &[("srcId", parent), ("srcOrd", place.as_str())],
            ));
            continue;
        }
        let names_gone = ["srcId", "destId", "parTransId", "sibTransId"]
            .iter()
            .any(|role| node.attr(role).is_some_and(|id| gone.contains(id)));
        if !names_gone {
            connections.extend_from_slice(&bytes[node.span.clone()]);
        }
    }
    // New nodes, and kept nodes no connection placed, are linked anew.
    let mut added = 0u32;
    for (node, &(parent, place)) in wanted.iter().zip(&places) {
        let Some(id) = node.id.as_deref() else {
            continue;
        };
        let fresh = !held_ids.contains(id);
        if !fresh && linked.contains_key(id) {
            continue;
        }
        let new = link(dgm, node, parent, place);
        if fresh {
            // A kept node keeps its own point; only its link is new.
            added = added.saturating_add(1);
            point_list.extend(new.point.into_bytes());
        }
        point_list.extend(new.transitions.into_bytes());
        connections.extend(new.connection.into_bytes());
    }
    point_list.extend(format!("</{}>", model.nodes[list].qualified).into_bytes());
    connections.extend(
        format!(
            "</{}>",
            links.map_or_else(
                || xml::qualify(dgm, "cxnLst"),
                |links| model.nodes[links].qualified.clone()
            )
        )
        .into_bytes(),
    );
    let mut edits = vec![(model.nodes[list].span.clone(), point_list)];
    match links {
        Some(links) => edits.push((model.nodes[links].span.clone(), connections)),
        None => {
            let end = model.nodes[list].span.end;
            edits.push((end..end, connections));
        }
    }
    // The cached drawing's link goes with it (`drop_drawing`).
    if let Some(ext) = model
        .nodes
        .iter()
        .position(|node| node.is(DSP, "dataModelExt"))
    {
        let cut = model.nodes[ext]
            .parent
            .filter(|&parent| {
                model.nodes[parent].is(A, "ext") && model.nodes[parent].children.len() == 1
            })
            .unwrap_or(ext);
        edits.push((model.nodes[cut].span.clone(), Vec::new()));
    }
    package.replace_xml_part(&read.data, xml::splice(&bytes, edits)?)?;
    Ok(Conversion::SmartArtRestructured { added, removed })
}

/// A kept point with its text body written to hold `text`.
fn point_with_text(bytes: &[u8], model: &XmlTree, pt: usize, text: &str) -> Vec<u8> {
    let node = &model.nodes[pt];
    let (edit, at) = match xml::child(model, pt, DGM, "t") {
        Some(body) => (
            text_body(bytes, model, body, text),
            model.nodes[body].span.clone(),
        ),
        None => {
            // CT_Pt: prSet, spPr, t, extLst.
            let t = xml::qualify(xml::prefix(node), "t");
            let mut element = format!(r#"<{t}><a:bodyPr xmlns:a="{A}"/>"#).into_bytes();
            element.extend(paragraphs(text, None, [&[], &[], &[]]));
            element.extend(format!("</{t}>").into_bytes());
            match xml::child(model, pt, DGM, "extLst") {
                Some(ext) => {
                    let start = model.nodes[ext].span.start;
                    (element, start..start)
                }
                None if node.empty => {
                    let (range, value) =
                        xml::insert_last(bytes, node, &String::from_utf8_lossy(&element));
                    (value, range)
                }
                None => (element, node.content.end..node.content.end),
            }
        }
    };
    let mut out = bytes[node.span.start..at.start].to_vec();
    out.extend(edit);
    out.extend_from_slice(&bytes[at.end..node.span.end]);
    out
}

/// Drop a SmartArt's cached drawing: the relationship `rel_id` its data
/// part named (from the slide, else the data part), and the drawing part
/// once nothing reads it. The drawing part, when one went.
fn drop_drawing(
    package: &mut Package,
    slide: &str,
    data: &str,
    rel_id: Option<&str>,
) -> Result<Option<String>, LiveError> {
    let Some(rel_id) = rel_id else {
        return Ok(None);
    };
    for source in [slide, data] {
        let Some(rel) = package
            .relationships(source)?
            .into_iter()
            .find(|rel| rel.id == rel_id && !rel.external && rel.kind.ends_with("/diagramDrawing"))
        else {
            continue;
        };
        package.unrelate(source, &rel.id)?;
        if package.part(&rel.target)?.is_some() && !package.reachable("")?.contains(&rel.target) {
            package.remove_part(&rel.target)?;
        }
        return Ok(Some(rel.target));
    }
    Ok(None)
}

/// Write a live-born SmartArt of `nodes` as the new graphic frame `id`
/// named `name` on `slide` at `offset` and `extent`: its data part, the
/// engine's layout, quick style and colours, and the slide's relationships
/// to them. The parts it wrote.
pub(super) fn born(
    package: &mut Package,
    slide: &str,
    (id, name): (u32, &str),
    (x, y): (i64, i64),
    (cx, cy): (i64, i64),
    nodes: &[SmartArtNode],
) -> Result<Vec<String>, LiveError> {
    let first = nodes
        .first()
        .and_then(|node| node.id.as_deref())
        .unwrap_or_default();
    let doc = derived(first, "doc");
    let (mut points, mut connections) = (String::new(), String::new());
    for (node, &(parent, place)) in nodes.iter().zip(&placed(&doc, nodes)) {
        let new = link("dgm", node, parent, place);
        points.push_str(&new.point);
        points.push_str(&new.transitions);
        connections.push_str(&new.connection);
    }
    let data_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><dgm:dataModel xmlns:dgm="{DGM}" xmlns:a="{A}" xmlns:r="{R}"><dgm:ptLst><dgm:pt modelId="{doc}" type="doc"><dgm:prSet loTypeId="{LAYOUT_URN}" loCatId="list" qsTypeId="{STYLE_URN}" qsCatId="simple" csTypeId="{COLORS_URN}" csCatId="accent1"/><dgm:spPr/><dgm:t><a:bodyPr/><a:lstStyle/><a:p/></dgm:t></dgm:pt>{points}</dgm:ptLst><dgm:cxnLst>{connections}</dgm:cxnLst><dgm:bg/><dgm:whole/></dgm:dataModel>"#
    );
    let mut parts = vec![slide.to_owned()];
    let mut rel_ids = Vec::new();
    for (stem, content_type, kind, body) in [
        ("data", DATA_TYPE, "diagramData", data_xml.as_str()),
        ("layout", LAYOUT_TYPE, "diagramLayout", LAYOUT_DEF),
        ("quickStyle", STYLE_TYPE, "diagramQuickStyle", STYLE_DEF),
        ("colors", COLORS_TYPE, "diagramColors", COLORS_DEF),
    ] {
        let part = next_part(package, &format!("ppt/diagrams/{stem}"), ".xml")?;
        package.add_part(&part, content_type, body.as_bytes().to_vec())?;
        rel_ids.push(package.relate(slide, &format!("{R}/{kind}"), &part)?);
        parts.push(part);
    }
    let [dm, lo, qs, cs] = [0, 1, 2, 3].map(|at| rel_ids.get(at).cloned().unwrap_or_default());
    let frame = format!(
        r#"<p:graphicFrame xmlns:p="{P}" xmlns:a="{A}"><p:nvGraphicFramePr><p:cNvPr id="{id}" name="{}"/><p:cNvGraphicFramePr/><p:nvPr/></p:nvGraphicFramePr><p:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{cx}" cy="{cy}"/></p:xfrm><a:graphic><a:graphicData uri="{DGM}"><dgm:relIds xmlns:dgm="{DGM}" xmlns:r="{R}" r:dm="{dm}" r:lo="{lo}" r:qs="{qs}" r:cs="{cs}"/></a:graphicData></a:graphic></p:graphicFrame>"#,
        xml::escape_attribute(name)
    );
    insert_frame(package, slide, id, &frame)?;
    Ok(parts)
}

/// The engine's outline list, self-authored over the published DrawingML
/// diagram schema (ECMA-376 Part 1, 21.4): each top-level node is a rounded
/// box, stacked top to bottom, its descendants the box's bullets.
const LAYOUT_DEF: &str = concat!(
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
    r#"<dgm:layoutDef xmlns:dgm="http://schemas.openxmlformats.org/drawingml/2006/diagram" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" uniqueId="urn:oneiron:smartart:layout:outline-list" defStyle="urn:oneiron:smartart:style:plain">"#,
    r#"<dgm:title val="Outline list"/><dgm:desc val="Each top-level node is a box, stacked top to bottom; its descendants are its bullets."/>"#,
    r#"<dgm:catLst><dgm:cat type="list" pri="100"/></dgm:catLst>"#,
    r#"<dgm:layoutNode name="outline">"#,
    r#"<dgm:varLst><dgm:resizeHandles val="exact"/></dgm:varLst>"#,
    r#"<dgm:alg type="lin"><dgm:param type="linDir" val="fromT"/><dgm:param type="nodeVertAlign" val="t"/></dgm:alg>"#,
    r#"<dgm:shape r:blip=""><dgm:adjLst/></dgm:shape><dgm:presOf/>"#,
    r#"<dgm:constrLst>"#,
    r#"<dgm:constr type="w" for="ch" forName="box" refType="w"/>"#,
    r#"<dgm:constr type="h" for="ch" forName="box" refType="h" fact="0.25"/>"#,
    r#"<dgm:constr type="h" for="ch" forName="gap" refType="h" refFor="ch" refForName="box" fact="0.15"/>"#,
    r#"<dgm:constr type="primFontSz" for="ch" forName="box" op="equ" val="36"/>"#,
    r#"<dgm:constr type="secFontSz" for="ch" forName="box" refType="primFontSz" refFor="ch" refForName="box" fact="0.8"/>"#,
    r#"</dgm:constrLst><dgm:ruleLst/>"#,
    r#"<dgm:forEach name="boxes" axis="ch" ptType="node">"#,
    r#"<dgm:layoutNode name="box" styleLbl="node1">"#,
    r#"<dgm:varLst><dgm:bulletEnabled val="1"/></dgm:varLst>"#,
    r#"<dgm:alg type="tx"><dgm:param type="parTxLTRAlign" val="l"/><dgm:param type="txAnchorVert" val="t"/></dgm:alg>"#,
    r#"<dgm:shape type="roundRect" r:blip=""><dgm:adjLst/></dgm:shape>"#,
    r#"<dgm:presOf axis="desOrSelf" ptType="node"/>"#,
    r#"<dgm:constrLst>"#,
    r#"<dgm:constr type="tMarg" refType="primFontSz" fact="0.25"/><dgm:constr type="bMarg" refType="primFontSz" fact="0.25"/>"#,
    r#"<dgm:constr type="lMarg" refType="primFontSz" fact="0.4"/><dgm:constr type="rMarg" refType="primFontSz" fact="0.4"/>"#,
    r#"</dgm:constrLst>"#,
    r#"<dgm:ruleLst><dgm:rule type="primFontSz" val="8" fact="NaN" max="NaN"/></dgm:ruleLst>"#,
    r#"</dgm:layoutNode>"#,
    r#"<dgm:forEach name="gaps" axis="followSib" ptType="sibTrans" cnt="1">"#,
    r#"<dgm:layoutNode name="gap"><dgm:alg type="sp"/><dgm:shape r:blip=""><dgm:adjLst/></dgm:shape><dgm:presOf/><dgm:constrLst/><dgm:ruleLst/></dgm:layoutNode>"#,
    r#"</dgm:forEach></dgm:forEach></dgm:layoutNode></dgm:layoutDef>"#,
);

/// The engine's plain quick style: flat, the theme's subtle line and fill.
const STYLE_DEF: &str = concat!(
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
    r#"<dgm:styleDef xmlns:dgm="http://schemas.openxmlformats.org/drawingml/2006/diagram" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" uniqueId="urn:oneiron:smartart:style:plain">"#,
    r#"<dgm:title val="Plain"/><dgm:desc val="Flat boxes in the theme's first fill and line."/>"#,
    r#"<dgm:catLst><dgm:cat type="simple" pri="100"/></dgm:catLst>"#,
    r#"<dgm:scene3d><a:camera prst="orthographicFront"/><a:lightRig rig="threePt" dir="t"/></dgm:scene3d>"#,
    r#"<dgm:styleLbl name="node1">"#,
    r#"<dgm:scene3d><a:camera prst="orthographicFront"/><a:lightRig rig="threePt" dir="t"/></dgm:scene3d><dgm:sp3d/><dgm:txPr/>"#,
    r#"<dgm:style><a:lnRef idx="1"><a:scrgbClr r="0" g="0" b="0"/></a:lnRef><a:fillRef idx="1"><a:scrgbClr r="0" g="0" b="0"/></a:fillRef>"#,
    r#"<a:effectRef idx="0"><a:scrgbClr r="0" g="0" b="0"/></a:effectRef><a:fontRef idx="minor"><a:schemeClr val="lt1"/></a:fontRef></dgm:style>"#,
    r#"</dgm:styleLbl></dgm:styleDef>"#,
);

/// The engine's colours: the theme's first accent, light text.
const COLORS_DEF: &str = concat!(
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
    r#"<dgm:colorsDef xmlns:dgm="http://schemas.openxmlformats.org/drawingml/2006/diagram" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" uniqueId="urn:oneiron:smartart:colors:accent1">"#,
    r#"<dgm:title val="Accent 1"/><dgm:desc val="Boxes in the theme's first accent."/>"#,
    r#"<dgm:catLst><dgm:cat type="accent1" pri="100"/></dgm:catLst>"#,
    r#"<dgm:styleLbl name="node1">"#,
    r#"<dgm:fillClrLst meth="repeat"><a:schemeClr val="accent1"/></dgm:fillClrLst>"#,
    r#"<dgm:linClrLst meth="repeat"><a:schemeClr val="lt1"/></dgm:linClrLst>"#,
    r#"<dgm:effectClrLst/><dgm:txLinClrLst/>"#,
    r#"<dgm:txFillClrLst meth="repeat"><a:schemeClr val="lt1"/></dgm:txFillClrLst><dgm:txEffectClrLst/>"#,
    r#"</dgm:styleLbl></dgm:colorsDef>"#,
);
