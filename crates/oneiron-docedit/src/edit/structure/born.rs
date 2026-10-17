//! The live-deck projector's creation verbs for what a preset shape cannot
//! carry: a picture over a new media part and slide relationship, and a
//! connector glued to shapes on its slide. Each is checked in
//! `arrange::verify` from the exported candidate.

use super::super::media::admit;
use super::super::xml::{self, A, P, R};
use super::{
    A16, NewConnector, NewPicture, Plan, SHAPE_CREATION_EXT, end_of, highest_id, mint_guid,
    shape_tree,
};
use crate::deck::{ShapeKind, SlideView};
use crate::design_plan::Rect;
use crate::edit::{EditRefusal, Effect, Xfrm};
use crate::retained_opc::Package;

/// PowerPoint's default connector style: theme references, no literal colour.
const CONNECTOR_STYLE: &str = r#"<p:style><a:lnRef idx="1"><a:schemeClr val="accent1"/></a:lnRef><a:fillRef idx="0"><a:schemeClr val="accent1"/></a:fillRef><a:effectRef idx="0"><a:schemeClr val="accent1"/></a:effectRef><a:fontRef idx="minor"><a:schemeClr val="tx1"/></a:fontRef></p:style>"#;

/// The new element's id, above the slide's ids and the high-water mark, and
/// a creation id no shape on the slide holds.
fn mint(
    tree: &crate::ooxml::XmlTree,
    slide: &SlideView,
    high_water: u32,
    seed: &[u8],
) -> Result<(u32, String), EditRefusal> {
    let id = highest_id(tree)
        .max(high_water)
        .checked_add(1)
        .ok_or(EditRefusal::IdSpaceExhausted)?;
    let taken: Vec<&str> = slide
        .shapes
        .iter()
        .filter_map(|shape| shape.creation_id.as_deref())
        .collect();
    Ok((id, mint_guid(seed, &taken)?))
}

fn frame(name: &str, offset: (i64, i64), extent: (i64, i64)) -> Result<(), EditRefusal> {
    if !xml::writable(name) {
        return Err(EditRefusal::Invalid(
            "the name holds a character XML cannot carry",
        ));
    }
    super::transform::check_ranges(&Xfrm {
        offset: Some(offset),
        extent: Some(extent),
        ..Xfrm::default()
    })
}

pub(super) fn add_picture(
    next: &mut Package,
    slide: &SlideView,
    new: &NewPicture<'_>,
) -> Result<(Plan, Vec<Effect>), EditRefusal> {
    frame(new.name, new.offset, new.extent)?;
    let ((x, y), (cx, cy)) = (new.offset, new.extent);
    let (extension, content_type, placed) = admit(&new.picture, Rect { x, y, cx, cy })?;
    let placed = if new.fit {
        placed
    } else {
        Rect { x, y, cx, cy }
    };
    let (bytes, tree) = xml::read(next, &slide.part)?;
    let (id, creation_id) = mint(&tree, slide, new.high_water, new.seed)?;
    let media = xml::next_part(next, "ppt/media/image", &format!(".{extension}"))?;
    next.add_part(&media, content_type, new.picture.bytes.to_vec())?;
    let embed = next.relate(&slide.part, &format!("{R}/image"), &media)?;
    let element = format!(
        r#"<p:pic xmlns:p="{P}" xmlns:a="{A}" xmlns:r="{R}"><p:nvPicPr><p:cNvPr id="{id}" name="{}" descr="{}"><a:extLst><a:ext uri="{SHAPE_CREATION_EXT}"><a16:creationId xmlns:a16="{A16}" id="{creation_id}"/></a:ext></a:extLst></p:cNvPr><p:cNvPicPr><a:picLocks noChangeAspect="1"/></p:cNvPicPr><p:nvPr/></p:nvPicPr><p:blipFill><a:blip r:embed="{}"/><a:stretch><a:fillRect/></a:stretch></p:blipFill><p:spPr><a:xfrm><a:off x="{}" y="{}"/><a:ext cx="{}" cy="{}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr></p:pic>"#,
        xml::escape_attribute(new.name),
        xml::escape_attribute(&new.picture.record.description),
        xml::escape_attribute(&embed),
        placed.x,
        placed.y,
        placed.cx,
        placed.cy,
    );
    let at = end_of(&tree, shape_tree(&tree)?);
    next.replace_xml_part(
        &slide.part,
        xml::splice(&bytes, vec![(at..at, element.into_bytes())])?,
    )?;
    Ok((Plan::Arranged, vec![Effect::ShapeAdded { id, creation_id }]))
}

pub(super) fn add_connector(
    next: &mut Package,
    slide: &SlideView,
    new: &NewConnector<'_>,
) -> Result<(Plan, Vec<Effect>), EditRefusal> {
    frame(new.name, new.offset, new.extent)?;
    if new.extent.0 < 0 || new.extent.1 < 0 {
        return Err(EditRefusal::Invalid(
            "a connector frame has no negative extent",
        ));
    }
    let ends: String = [("stCxn", new.start), ("endCxn", new.end)]
        .into_iter()
        .filter_map(|(local, end)| end.map(|end| (local, end)))
        .map(|(local, (shape, site))| {
            let glued = slide
                .shapes
                .iter()
                .any(|held| held.id == Some(shape) && held.kind != ShapeKind::Group);
            if glued {
                Ok(format!(r#"<a:{local} id="{shape}" idx="{site}"/>"#))
            } else {
                Err(EditRefusal::Missing("connector end shape"))
            }
        })
        .collect::<Result<_, _>>()?;
    let (bytes, tree) = xml::read(next, &slide.part)?;
    let (id, creation_id) = mint(&tree, slide, new.high_water, new.seed)?;
    let ((x, y), (cx, cy)) = (new.offset, new.extent);
    let flips = match (new.flip_h, new.flip_v) {
        (false, false) => "",
        (true, false) => r#" flipH="1""#,
        (false, true) => r#" flipV="1""#,
        (true, true) => r#" flipH="1" flipV="1""#,
    };
    let element = format!(
        r#"<p:cxnSp xmlns:p="{P}" xmlns:a="{A}"><p:nvCxnSpPr><p:cNvPr id="{id}" name="{}"><a:extLst><a:ext uri="{SHAPE_CREATION_EXT}"><a16:creationId xmlns:a16="{A16}" id="{creation_id}"/></a:ext></a:extLst></p:cNvPr><p:cNvCxnSpPr>{ends}</p:cNvCxnSpPr><p:nvPr/></p:nvCxnSpPr><p:spPr><a:xfrm{flips}><a:off x="{x}" y="{y}"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm><a:prstGeom prst="{}"><a:avLst/></a:prstGeom></p:spPr>{CONNECTOR_STYLE}</p:cxnSp>"#,
        xml::escape_attribute(new.name),
        new.preset.name(),
    );
    let at = end_of(&tree, shape_tree(&tree)?);
    next.replace_xml_part(
        &slide.part,
        xml::splice(&bytes, vec![(at..at, element.into_bytes())])?,
    )?;
    Ok((Plan::Arranged, vec![Effect::ShapeAdded { id, creation_id }]))
}
