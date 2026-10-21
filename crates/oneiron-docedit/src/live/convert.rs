//! Deck edits PowerPoint performs, done its way where the live deck once
//! refused them (OF-510; the Office ruling of 10-18: the app's documented
//! behaviour is the spec, and where PowerPoint does an edit the deck takes
//! the nearest behaviour that does not refuse and names it on the edit's
//! receipt as a [`Conversion`]).
//!
//! An operation settles a chart payload into the form its export writes
//! and reads back ([`settle_chart`]): the plots Change Chart Type lays out
//! for the chart or one series, categories and x values turned between
//! category and scatter series, and where the data lives. The export
//! writes what the deck once held read only: an imported picture shown
//! with media the deck holds ([`show_held_media`]), a SmartArt's node text
//! ([`smart_art_text`]), and a chart's data embedded in a workbook of its
//! own ([`embed_workbook`]), the former workbook pruned once nothing reads
//! it and its data-label ranges unlinked into the labels' own text.

mod chart;

pub(super) use chart::settle_chart;

use super::LiveError;
use super::chart_labels;
use super::conversion::Conversion;
use super::held::{self, C, DGM, children};
use super::pptx::{HeldMedia, SmartArtNode, WRITTEN_FRAME};
use super::reshape::frame_of;
use super::svg_fallback;
use crate::edit::Digest;
use crate::edit::xml::{self, A, P, R, next_part};
use crate::native_patch::insert_frame;
use crate::ooxml::{XmlTree, escape_text};
use crate::retained_opc::Package;
use std::collections::BTreeSet;

/// The drawing part namespace of a SmartArt's cached shapes.
pub(super) const DSP: &str = "http://schemas.microsoft.com/office/drawing/2008/diagram";
const XLSX_TYPE: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

/// A SmartArt's text write names the nodes it reads, at their levels; a
/// node added, removed or moved rewrites the diagram (`diagram::write`).
pub(crate) const SMART_ART_NODES: &str =
    "a SmartArt's text write names the nodes it reads, at their levels";
/// A held picture shows an image part the retained package holds, by its
/// hash; anything else would point a picture at bytes that are not there.
pub(crate) const HELD_MEDIA: &str =
    "a held picture names an image part the deck holds, with its hash";

/// Whether a part name is an image a picture's blip may show.
pub(super) fn image_part(name: &str) -> bool {
    const IMAGES: &[&str] = &[
        "png", "jpg", "jpeg", "jpe", "jfif", "gif", "bmp", "tif", "tiff", "emf", "wmf", "svg",
        "webp", "wdp", "ico",
    ];
    name.rsplit_once('.')
        .is_some_and(|(_, ext)| IMAGES.iter().any(|known| ext.eq_ignore_ascii_case(known)))
}

/// The slide element `p:<local>` with this native id.
pub(super) fn element_of(tree: &XmlTree, native: u32, local: &str) -> Option<usize> {
    let id = native.to_string();
    (0..tree.nodes.len()).find(|&at| {
        tree.nodes[at].is(P, local)
            && xml::c_nv_pr(tree, at)
                .is_some_and(|c_nv_pr| tree.nodes[c_nv_pr].attr("id") == Some(id.as_str()))
    })
}

/// Point the picture `native` on `slide` at the held media part `media`
/// names, through the slide's image relationship to it (a new one when it
/// has none); an SVG part a picture of the deck shows over a raster, as
/// Office does ([`svg_fallback::show`]). Other media drops the SVG extension
/// the blip carried ([`svg_fallback::drop_svg`]); the media it showed keeps
/// its relationship, unreferenced, as new media leaves it. Whether anything
/// changed.
pub(super) fn show_held_media(
    package: &mut Package,
    slide: &str,
    native: u32,
    media: &HeldMedia,
) -> Result<bool, LiveError> {
    let refuse = LiveError::Invalid(HELD_MEDIA);
    if !image_part(&media.part)
        || package
            .part(&media.part)?
            .is_none_or(|bytes| Digest::of(&bytes) != media.hash)
    {
        return Err(refuse);
    }
    if let Some(changed) = svg_fallback::show(package, slide, native, &media.part)? {
        return Ok(changed);
    }
    let dropped = svg_fallback::drop_svg(package, slide, native)?;
    let (bytes, tree) = xml::read(package, slide)?;
    let picture = element_of(&tree, native, "pic").ok_or(LiveError::UnknownNode)?;
    let blip = xml::path(&tree, picture, &[(P, "blipFill"), (A, "blip")]).ok_or(refuse)?;
    let kind = format!("{R}/image");
    let rels = package.relationships(slide)?;
    let shown = tree.nodes[blip].attr_ns(R, "embed");
    if rels
        .iter()
        .any(|rel| Some(rel.id.as_str()) == shown && !rel.external && rel.target == media.part)
    {
        return Ok(dropped);
    }
    let id = match rels
        .into_iter()
        .find(|rel| !rel.external && rel.kind == kind && rel.target == media.part)
    {
        Some(rel) => rel.id,
        None => package.relate(slide, &kind, &media.part)?,
    };
    let node = &tree.nodes[blip];
    let attribute = node
        .attr_spans
        .keys()
        .find(|name| {
            name.rsplit_once(':')
                .is_some_and(|(_, local)| local == "embed")
        })
        .cloned()
        .unwrap_or_else(|| "r:embed".to_owned());
    let edit = xml::set_attribute(&bytes, node, &attribute, &id);
    package.replace_xml_part(slide, xml::splice(&bytes, vec![edit])?)?;
    Ok(true)
}

/// Write a live-born picture showing the held media `media` names as the
/// new `p:pic` `id` named `name` on `slide`, at `offset` and `extent`,
/// through the slide's image relationship to that part (a new one when it
/// has none); an SVG part a picture of the deck shows over a raster, as
/// Office does ([`svg_fallback::born_blip`]).
pub(super) fn born_held_picture(
    package: &mut Package,
    slide: &str,
    (id, name): (u32, &str),
    (x, y): (i64, i64),
    (cx, cy): (i64, i64),
    media: &HeldMedia,
) -> Result<(), LiveError> {
    if !image_part(&media.part)
        || package
            .part(&media.part)?
            .is_none_or(|bytes| Digest::of(&bytes) != media.hash)
    {
        return Err(LiveError::Invalid(HELD_MEDIA));
    }
    let blip = svg_fallback::born_blip(package, slide, &media.part)?;
    let picture = format!(
        r#"<p:pic xmlns:p="{P}" xmlns:a="{A}" xmlns:r="{R}"><p:nvPicPr><p:cNvPr id="{id}" name="{}"/><p:cNvPicPr><a:picLocks noChangeAspect="1"/></p:cNvPicPr><p:nvPr/></p:nvPicPr><p:blipFill>{blip}<a:stretch><a:fillRect/></a:stretch></p:blipFill><p:spPr><a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr></p:pic>"#,
        xml::escape_attribute(name)
    );
    insert_frame(package, slide, id, &picture)?;
    Ok(())
}

/// Paragraphs holding `text`, one per line: each in `p_pr`, its run in
/// `r_pr`, ending in `end`, under the DrawingML `prefix` (declared on each
/// paragraph when the body names none).
pub(super) fn paragraphs(
    text: &str,
    prefix: Option<&str>,
    [p_pr, r_pr, end]: [&[u8]; 3],
) -> Vec<u8> {
    let q = |name: &str| xml::qualify(prefix.unwrap_or("a"), name);
    let declare = if prefix.is_none() {
        format!(r#" xmlns:a="{A}""#)
    } else {
        String::new()
    };
    let mut out = Vec::new();
    for line in text.split('\n') {
        out.extend(format!("<{}{declare}>", q("p")).into_bytes());
        out.extend_from_slice(p_pr);
        if !line.is_empty() {
            out.extend(format!("<{}>", q("r")).into_bytes());
            out.extend_from_slice(r_pr);
            out.extend(
                format!(
                    "<{t}>{}</{t}></{r}>",
                    escape_text(line),
                    t = q("t"),
                    r = q("r")
                )
                .into_bytes(),
            );
        }
        out.extend_from_slice(end);
        out.extend(format!("</{}>", q("p")).into_bytes());
    }
    out
}

/// A text body (`dgm:t`, `dsp:txBody`) written to hold `text`: its open
/// tag, body and list properties kept, then a paragraph per line in its
/// first paragraph's properties, with one run in its first run's.
pub(super) fn text_body(bytes: &[u8], tree: &XmlTree, body: usize, text: &str) -> Vec<u8> {
    let node = &tree.nodes[body];
    let part = |at: Option<usize>| at.map_or(&[][..], |at| &bytes[tree.nodes[at].span.clone()]);
    let body_pr = xml::child(tree, body, A, "bodyPr");
    let list = xml::child(tree, body, A, "lstStyle");
    let first = xml::child(tree, body, A, "p");
    let p_pr = first.and_then(|p| xml::child(tree, p, A, "pPr"));
    let end = first.and_then(|p| xml::child(tree, p, A, "endParaRPr"));
    let r_pr = held::within(tree, body)
        .find(|&at| tree.nodes[at].is(A, "r"))
        .and_then(|run| xml::child(tree, run, A, "rPr"));
    let prefix = first.or(body_pr).map(|at| xml::prefix(&tree.nodes[at]));
    let mut out = xml::open_tag(bytes, node);
    match (body_pr, prefix) {
        (Some(_), _) => out.extend_from_slice(part(body_pr)),
        (None, Some(prefix)) => {
            out.extend(format!("<{}/>", xml::qualify(prefix, "bodyPr")).into_bytes());
        }
        (None, None) => out.extend(format!(r#"<a:bodyPr xmlns:a="{A}"/>"#).into_bytes()),
    }
    out.extend_from_slice(part(list));
    out.extend(paragraphs(
        text,
        prefix,
        [part(p_pr), part(r_pr), part(end)],
    ));
    out.extend(format!("</{}>", node.qualified).into_bytes());
    out
}

/// The drawing part a SmartArt's data part names (`dsp:dataModelExt`), by
/// a relationship of its slide or of the data part.
fn drawing_of(
    package: &Package,
    slide: &str,
    data: &str,
    model: &XmlTree,
) -> Result<Option<String>, LiveError> {
    let Some(id) = model
        .nodes
        .iter()
        .find(|node| node.is(DSP, "dataModelExt"))
        .and_then(|node| node.attr("relId"))
    else {
        return Ok(None);
    };
    for source in [slide, data] {
        if let Some(rel) = package
            .relationships(source)?
            .into_iter()
            .find(|rel| rel.id == id && !rel.external)
        {
            return Ok(Some(rel.target));
        }
    }
    Ok(None)
}

/// Write a SmartArt's node text, as PowerPoint's text pane does: each node
/// whose text `wanted` changes gets it in its data part point, and in the
/// shapes the drawing part draws for that node (the presentation points
/// associated with it). `wanted` holds the nodes the SmartArt reads, at
/// their levels. The parts it changed and the count of nodes written.
pub(super) fn smart_art_text(
    package: &mut Package,
    slide: &str,
    native: u32,
    wanted: &[SmartArtNode],
) -> Result<(Vec<String>, u32), LiveError> {
    let refuse = LiveError::Invalid(SMART_ART_NODES);
    let tree = held::slide_tree(package, slide)?;
    let frame = frame_of(&tree, native).ok_or(LiveError::Invalid(WRITTEN_FRAME))?;
    let read = held::smart_art_of(package, slide, &tree, frame)
        .ok_or(LiveError::Invalid(WRITTEN_FRAME))?;
    if read.points.len() != wanted.len()
        || read
            .points
            .iter()
            .zip(wanted)
            .any(|((_, was), now)| was.level != now.level)
    {
        return Err(refuse);
    }
    let edited: Vec<(&str, &str)> = read
        .points
        .iter()
        .zip(wanted)
        .filter(|((_, was), now)| was.text != now.text)
        .map(|((id, _), now)| (id.as_str(), now.text.as_str()))
        .collect();
    if edited.is_empty() {
        return Ok((Vec::new(), 0));
    }
    let (bytes, model) = xml::read(package, &read.data)?;
    let drawing = drawing_of(package, slide, &read.data, &model)?;
    let list = xml::child(&model, 0, DGM, "ptLst").ok_or(refuse.clone())?;
    let mut edits = Vec::new();
    let mut drawn: Vec<(BTreeSet<String>, &str)> = Vec::new();
    for &(id, text) in &edited {
        let point = children(&model, list, DGM, "pt")
            .find(|&pt| model.nodes[pt].attr("modelId") == Some(id))
            .ok_or(refuse.clone())?;
        match xml::child(&model, point, DGM, "t") {
            Some(body) => edits.push((
                model.nodes[body].span.clone(),
                text_body(&bytes, &model, body, text),
            )),
            None => {
                // CT_Pt: prSet, spPr, t, extLst.
                let t = xml::qualify(xml::prefix(&model.nodes[point]), "t");
                let mut element = format!(r#"<{t}><a:bodyPr xmlns:a="{A}"/>"#).into_bytes();
                element.extend(paragraphs(text, None, [&[], &[], &[]]));
                element.extend(format!("</{t}>").into_bytes());
                edits.push(match xml::child(&model, point, DGM, "extLst") {
                    Some(ext) => {
                        let at = model.nodes[ext].span.start;
                        (at..at, element)
                    }
                    None => xml::insert_last(
                        &bytes,
                        &model.nodes[point],
                        &String::from_utf8_lossy(&element),
                    ),
                });
            }
        }
        let presented: BTreeSet<String> = children(&model, list, DGM, "pt")
            .filter(|&pt| {
                model.nodes[pt].attr("type") == Some("pres")
                    && xml::child(&model, pt, DGM, "prSet")
                        .and_then(|set| model.nodes[set].attr("presAssocID"))
                        == Some(id)
            })
            .filter_map(|pt| model.nodes[pt].attr("modelId").map(str::to_owned))
            .collect();
        drawn.push((presented, text));
    }
    package.replace_xml_part(&read.data, xml::splice(&bytes, edits)?)?;
    let mut changed = vec![read.data.clone()];
    if let Some(drawing) = drawing {
        let (bytes, tree) = xml::read(package, &drawing)?;
        let mut edits = Vec::new();
        for (at, node) in tree.nodes.iter().enumerate() {
            if !node.is(DSP, "sp") {
                continue;
            }
            let Some(model_id) = node.attr("modelId") else {
                continue;
            };
            let Some(&(_, text)) = drawn.iter().find(|(ids, _)| ids.contains(model_id)) else {
                continue;
            };
            if let Some(body) = xml::child(&tree, at, DSP, "txBody") {
                edits.push((
                    tree.nodes[body].span.clone(),
                    text_body(&bytes, &tree, body, text),
                ));
            }
        }
        if !edits.is_empty() {
            package.replace_xml_part(&drawing, xml::splice(&bytes, edits)?)?;
            changed.push(drawing);
        }
    }
    Ok((changed, u32::try_from(edited.len()).unwrap_or(u32::MAX)))
}

/// Give a chart whose data lives outside a workbook of its own (a link to
/// external data, a workbook another chart shares, or literals) a new
/// embedded workbook holding `workbook`, as PowerPoint's Edit Data does:
/// its `c:externalData` names the new part, a former link is dropped, and
/// each title or label linked to a cell keeps its text, unlinked, so every
/// reference left is series data. The new part, and what it did.
pub(super) fn embed_workbook(
    package: &mut Package,
    chart: &str,
    workbook: Vec<u8>,
) -> Result<(String, Vec<Conversion>), LiveError> {
    let (bytes, tree) = xml::read(package, chart)?;
    let data = xml::child(&tree, 0, C, "externalData");
    let former = data
        .and_then(|at| tree.nodes[at].attr_ns(R, "id"))
        .and_then(|id| {
            package
                .relationships(chart)
                .ok()?
                .into_iter()
                .find(|rel| rel.id == id)
        });
    let mut done = vec![match &former {
        Some(rel) if rel.external => Conversion::ExternalDataEmbedded,
        Some(_) => Conversion::WorkbookUnshared,
        None => Conversion::LiteralDataEmbedded,
    }];
    let book = next_part(package, "ppt/embeddings/Microsoft_Excel_Worksheet", ".xlsx")?;
    package.add_part(&book, XLSX_TYPE, workbook)?;
    let link = package.relate(chart, &format!("{R}/package"), &book)?;
    let c = xml::prefix(&tree.nodes[0]);
    let element = format!(
        r#"<{d} xmlns:r="{R}" r:id="{link}"><{u} val="0"/></{d}>"#,
        d = xml::qualify(c, "externalData"),
        u = xml::qualify(c, "autoUpdate"),
    );
    let mut edits = vec![match data {
        Some(at) => (tree.nodes[at].span.clone(), element.into_bytes()),
        None => {
            // CT_ChartSpace: ... chart, spPr, txPr, externalData,
            // printSettings, userShapes, extLst.
            let before = tree.nodes[0].children.iter().copied().find(|&at| {
                tree.nodes[at].namespace == C
                    && matches!(
                        tree.nodes[at].name.as_str(),
                        "printSettings" | "userShapes" | "extLst"
                    )
            });
            match before {
                Some(at) => {
                    let start = tree.nodes[at].span.start;
                    (start..start, element.into_bytes())
                }
                None => xml::insert_last(&bytes, &tree.nodes[0], &element),
            }
        }
    }];
    // A title or label linked to a cell (a `c:tx` reference outside a
    // series) keeps its cached text as rich text.
    let mut unlinked = false;
    for (at, node) in tree.nodes.iter().enumerate() {
        if !node.is(C, "tx")
            || node
                .parent
                .is_some_and(|parent| tree.nodes[parent].is(C, "ser"))
            || xml::child(&tree, at, C, "strRef").is_none()
        {
            continue;
        }
        let text: String = held::points(&tree, at)?
            .map(|points| points.cells().iter().map(held::label).collect())
            .unwrap_or_default();
        let rich = format!(
            r#"<{tx}><{rich}><a:bodyPr xmlns:a="{A}"/><a:p xmlns:a="{A}"><a:r><a:t>{}</a:t></a:r></a:p></{rich}></{tx}>"#,
            escape_text(&text),
            tx = node.qualified,
            rich = xml::qualify(xml::prefix(node), "rich"),
        );
        edits.push((node.span.clone(), rich.into_bytes()));
        unlinked = true;
    }
    if unlinked {
        done.push(Conversion::TitleLinkDropped);
    }
    let budget = package.xml_replacement_budget(chart)?;
    let labels = chart_labels::unlink_ranges(&bytes, &tree, &mut edits, budget)?;
    if labels > 0 {
        done.push(Conversion::LabelRangesUnlinked { labels });
    }
    package.replace_xml_part(chart, xml::splice(&bytes, edits)?)?;
    if let Some(rel) = former {
        package.unrelate(chart, &rel.id)?;
        // The former workbook goes once no part reads it, as PowerPoint's
        // save drops an embedding nothing references; one another chart
        // still reads stays.
        if !rel.external
            && package.part(&rel.target)?.is_some()
            && !package.reachable("")?.contains(&rel.target)
        {
            package.remove_part(&rel.target)?;
            done.push(Conversion::WorkbookPruned { part: rel.target });
        }
    }
    Ok((book, done))
}
