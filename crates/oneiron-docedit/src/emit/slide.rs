//! Slide XML for emission: an empty slide whose root binds `p:`, `a:` and
//! `r:`, the shapes placed into its tree, and the presentation's slide list.
use super::{EmitError, REL};
use crate::deck::Placeholder;
use crate::design_plan::Rect;
use crate::native_patch::placeholder_xml;
use crate::ooxml::{XmlTree, escape_text};
use crate::retained_opc::{self, Package};

pub(super) const PML: &str = "http://schemas.openxmlformats.org/presentationml/2006/main";

/// A slide with only its shape tree's own group; units are appended in
/// placement order.
pub(super) fn empty_slide() -> Vec<u8> {
    br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>"#
        .to_vec()
}

/// One `a:p` per planned paragraph, and per line inside one, each run
/// tagged with the brief's language. Sizes, fonts and colours are the
/// template's.
pub(super) fn paragraphs(paragraphs: &[String], language: &str) -> String {
    paragraphs
        .iter()
        .flat_map(|paragraph| paragraph.split('\n'))
        .map(|line| {
            format!(
                r#"<a:p><a:r><a:rPr lang="{}" dirty="0"/><a:t>{}</a:t></a:r></a:p>"#,
                escape_text(language),
                escape_text(line)
            )
        })
        .collect()
}

/// A filled layout placeholder: geometry and body properties are inherited,
/// so the layout's own autofit metrics are never restated.
pub(super) fn placeholder_text(
    id: u32,
    name: &str,
    placeholder: &Placeholder,
    body: &str,
) -> String {
    format!(
        r#"<p:sp><p:nvSpPr><p:cNvPr id="{id}" name="{}"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr><p:nvPr>{}</p:nvPr></p:nvSpPr><p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/>{body}</p:txBody></p:sp>"#,
        escape_text(name),
        placeholder_xml(placeholder),
    )
}

/// An ordinary text shape at its planned bounds; it neither shrinks text nor
/// grows to fit it.
pub(super) fn text_box(id: u32, name: &str, bounds: Rect, body: &str) -> String {
    format!(
        r#"<p:sp><p:nvSpPr><p:cNvPr id="{id}" name="{}"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr><p:spPr>{}<a:prstGeom prst="rect"><a:avLst/></a:prstGeom><a:noFill/></p:spPr><p:txBody><a:bodyPr wrap="square"><a:noAutofit/></a:bodyPr><a:lstStyle/>{body}</p:txBody></p:sp>"#,
        escape_text(name),
        xfrm(bounds),
    )
}

/// A verified raster picture over its media relationship.
pub(super) fn picture(
    id: u32,
    name: &str,
    description: &str,
    placeholder: Option<&Placeholder>,
    placed: Rect,
    embed: &str,
) -> String {
    let (locks, ph) = match placeholder {
        Some(placeholder) => (r#" noGrp="1""#, placeholder_xml(placeholder)),
        None => ("", String::new()),
    };
    format!(
        r#"<p:pic><p:nvPicPr><p:cNvPr id="{id}" name="{}" descr="{}"/><p:cNvPicPr><a:picLocks{locks} noChangeAspect="1"/></p:cNvPicPr><p:nvPr>{ph}</p:nvPr></p:nvPicPr><p:blipFill><a:blip r:embed="{}"/><a:stretch><a:fillRect/></a:stretch></p:blipFill><p:spPr>{}<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr></p:pic>"#,
        escape_text(name),
        escape_text(description),
        escape_text(embed),
        xfrm(placed),
    )
}

fn xfrm(rect: Rect) -> String {
    format!(
        r#"<a:xfrm><a:off x="{}" y="{}"/><a:ext cx="{}" cy="{}"/></a:xfrm>"#,
        rect.x, rect.y, rect.cx, rect.cy
    )
}

/// Write `p:sldIdLst` with the new slides in plan order, where the schema
/// puts it: after the master id lists. An existing list must be empty.
pub(super) fn write_slide_list(
    package: &mut Package,
    presentation: &str,
    slides: &[(u32, String)],
) -> Result<(), EmitError> {
    let bytes = package
        .part(presentation)?
        .ok_or(retained_opc::Error::Edit("presentation part missing"))?;
    let tree = XmlTree::parse(&bytes, package.resources())?;
    tree.root(PML, "presentation")?;
    let root = &tree.nodes[0];
    let id = root.child_name("sldId");
    let items: String = slides
        .iter()
        .map(|(sld_id, link)| {
            format!(
                r#"<{id} xmlns:r="{REL}" id="{sld_id}" r:id="{}"/>"#,
                escape_text(link)
            )
        })
        .collect();
    let list = format!("<{0}>{items}</{0}>", root.child_name("sldIdLst"));
    let span = match tree.child(0, PML, "sldIdLst")? {
        Some((index, node)) => {
            if tree.children(index).next().is_some() {
                return Err(EmitError::TemplateSlides(Vec::new()));
            }
            node.span.clone()
        }
        None => {
            let at = tree
                .children(0)
                .filter(|(_, node)| {
                    node.namespace == PML
                        && matches!(
                            node.name.as_str(),
                            "sldMasterIdLst" | "notesMasterIdLst" | "handoutMasterIdLst"
                        )
                })
                .map(|(_, node)| node.span.end)
                .last()
                .ok_or(retained_opc::Error::Edit("presentation has no master list"))?;
            at..at
        }
    };
    let mut out = bytes[..span.start].to_vec();
    out.extend_from_slice(list.as_bytes());
    out.extend_from_slice(&bytes[span.end..]);
    package.replace_xml_part(presentation, out)?;
    Ok(())
}
