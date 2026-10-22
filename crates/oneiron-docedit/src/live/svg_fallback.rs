//! A held SVG picture written as Office writes one (OF-510, FIX 5672):
//! PowerPoint shows an SVG through a raster `a:blip` that carries the SVG
//! in its `asvg:svgBlip` extension. Where a picture of the deck already
//! shows the held SVG part over a raster fallback, a picture the export
//! points at that part shows the same raster, the SVG in the extension and
//! both through the slide's image relationships. An SVG part no picture
//! shows over a raster is written as before, the blip naming the SVG alone:
//! drawing a raster for it needs an SVG renderer the deck does not carry.
//! A picture shown with other media drops the extension ([`drop_svg`]), so
//! PowerPoint draws what it now shows (FIX 5728).

use super::LiveError;
use super::convert::{HELD_MEDIA, element_of};
use super::held::children;
use crate::edit::xml::{self, A, P, R};
use crate::ooxml::{Node, XmlTree};
use crate::retained_opc::Package;

/// Office's SVG picture namespace.
const ASVG: &str = "http://schemas.microsoft.com/office/drawing/2016/SVG/main";
/// The extension URI Office writes `asvg:svgBlip` under.
const SVG_EXT: &str = "{96DAC541-7B7A-43D3-8B79-37D633B846F1}";

/// The raster part a picture of the deck shows for the SVG part `svg`: the
/// `a:blip` embed of a blip whose `asvg:svgBlip` extension names `svg`.
/// None for a part that is not an SVG, or one no picture shows so.
fn fallback(package: &Package, svg: &str) -> Option<String> {
    if !svg
        .rsplit_once('.')
        .is_some_and(|(_, ext)| ext.eq_ignore_ascii_case("svg"))
    {
        return None;
    }
    for name in package.names().filter(|name| name.ends_with(".xml")) {
        let Ok(Some(bytes)) = package.part(name) else {
            continue;
        };
        if !bytes.windows(7).any(|window| window == b"svgBlip") {
            continue;
        }
        let (Ok(tree), Ok(rels)) = (
            XmlTree::parse(&bytes, package.resources()),
            package.relationships(name),
        ) else {
            continue;
        };
        let target = |id: Option<&str>| {
            rels.iter()
                .find(|rel| !rel.external && Some(rel.id.as_str()) == id)
                .map(|rel| rel.target.as_str())
        };
        for at in (0..tree.nodes.len()).filter(|&at| tree.nodes[at].is(ASVG, "svgBlip")) {
            if target(tree.nodes[at].attr_ns(R, "embed")) != Some(svg) {
                continue;
            }
            // asvg:svgBlip in a:ext in a:extLst in a:blip.
            let raster = tree.nodes[at]
                .parent
                .and_then(|ext| tree.nodes[ext].parent)
                .and_then(|list| tree.nodes[list].parent)
                .filter(|&blip| tree.nodes[blip].is(A, "blip"))
                .and_then(|blip| target(tree.nodes[blip].attr_ns(R, "embed")));
            if let Some(raster) = raster
                && raster != svg
                && package.part(raster).ok().flatten().is_some()
            {
                return Some(raster.to_owned());
            }
        }
    }
    None
}

/// The slide's image relationship to `target`: a new one when it has none.
fn image_rel(package: &mut Package, slide: &str, target: &str) -> Result<String, LiveError> {
    let kind = format!("{R}/image");
    Ok(
        match package
            .relationships(slide)?
            .into_iter()
            .find(|rel| !rel.external && rel.kind == kind && rel.target == target)
        {
            Some(rel) => rel.id,
            None => package.relate(slide, &kind, target)?,
        },
    )
}

/// The `a:extLst` holding Office's SVG extension for the relationship `svg`.
fn extension_list(svg: &str) -> String {
    format!(r#"<a:extLst xmlns:a="{A}">{}</a:extLst>"#, extension(svg))
}

/// Office's SVG extension (`a:ext` holding `asvg:svgBlip`) for the
/// relationship `svg`.
fn extension(svg: &str) -> String {
    format!(
        r#"<a:ext xmlns:a="{A}" uri="{SVG_EXT}"><asvg:svgBlip xmlns:asvg="{ASVG}" xmlns:r="{R}" r:embed="{svg}"/></a:ext>"#
    )
}

/// The `asvg:svgBlip` of the blip `blip`'s Office SVG extension, if any.
pub(super) fn svg_blip(tree: &XmlTree, blip: usize) -> Option<usize> {
    xml::child(tree, blip, A, "extLst")
        .into_iter()
        .flat_map(|list| children(tree, list, A, "ext"))
        .find_map(|ext| xml::child(tree, ext, ASVG, "svgBlip"))
}

/// Drop Office's SVG extension from the blip of the picture `native` on
/// `slide`, which now shows other media: the `a:ext` holding `asvg:svgBlip`
/// goes (its `a:extLst` with it when it held nothing else; any other
/// extension stays), and the slide's relationship to the SVG once nothing
/// on the slide names it. The SVG part stays, for a picture that shows it
/// again. Whether anything changed.
pub(super) fn drop_svg(package: &mut Package, slide: &str, native: u32) -> Result<bool, LiveError> {
    let (bytes, tree) = xml::read(package, slide)?;
    let picture = element_of(&tree, native, "pic").ok_or(LiveError::UnknownNode)?;
    let Some(at) = xml::path(&tree, picture, &[(P, "blipFill"), (A, "blip")])
        .and_then(|blip| svg_blip(&tree, blip))
    else {
        return Ok(false);
    };
    // asvg:svgBlip in a:ext in a:extLst.
    let ext = tree.nodes[at]
        .parent
        .ok_or(LiveError::Invalid(HELD_MEDIA))?;
    let list = tree.nodes[ext]
        .parent
        .ok_or(LiveError::Invalid(HELD_MEDIA))?;
    let gone = if tree.nodes[list].children.len() == 1 {
        list
    } else {
        ext
    };
    let svg = tree.nodes[at].attr_ns(R, "embed").map(str::to_owned);
    let edit = (tree.nodes[gone].span.clone(), Vec::new());
    package.replace_xml_part(slide, xml::splice(&bytes, vec![edit])?)?;
    if let Some(svg) = svg {
        let (_, tree) = xml::read(package, slide)?;
        let named = tree
            .nodes
            .iter()
            .any(|node| node.attrs.values().any(|value| *value == svg));
        if !named
            && package
                .relationships(slide)?
                .iter()
                .any(|rel| rel.id == svg)
        {
            package.unrelate(slide, &svg)?;
        }
    }
    Ok(true)
}

/// The qualified name of an element's `r:embed` attribute, as it is written.
fn embed_name(node: &Node) -> String {
    node.attr_spans
        .keys()
        .find(|name| {
            name.rsplit_once(':')
                .is_some_and(|(_, local)| local == "embed")
        })
        .cloned()
        .unwrap_or_else(|| "r:embed".to_owned())
}

/// The `a:blip` a live-born picture showing the held part `media` writes on
/// `slide` (its prefixes `a` and `r` declared by the picture): the raster a
/// picture of the deck shows for the SVG, the SVG in its extension, or else
/// the part alone, as before.
pub(super) fn born_blip(
    package: &mut Package,
    slide: &str,
    media: &str,
) -> Result<String, LiveError> {
    let shown = image_rel(package, slide, media)?;
    Ok(match fallback(package, media) {
        Some(raster) => {
            let raster = image_rel(package, slide, &raster)?;
            format!(
                r#"<a:blip r:embed="{raster}">{}</a:blip>"#,
                extension_list(&shown)
            )
        }
        None => format!(r#"<a:blip r:embed="{shown}"/>"#),
    })
}

/// Point the picture `native` on `slide` at the raster a picture of the
/// deck shows for the SVG part `media`, the SVG in its blip's extension.
/// None when no picture shows `media` over a raster (the caller points the
/// blip at the part alone, as before); else whether anything changed.
pub(super) fn show(
    package: &mut Package,
    slide: &str,
    native: u32,
    media: &str,
) -> Result<Option<bool>, LiveError> {
    let Some(raster) = fallback(package, media) else {
        return Ok(None);
    };
    let blip_of = |tree: &XmlTree| -> Result<usize, LiveError> {
        let picture = element_of(tree, native, "pic").ok_or(LiveError::UnknownNode)?;
        xml::path(tree, picture, &[(P, "blipFill"), (A, "blip")])
            .ok_or(LiveError::Invalid(HELD_MEDIA))
    };
    let (bytes, tree) = xml::read(package, slide)?;
    let blip = blip_of(&tree)?;
    let rels = package.relationships(slide)?;
    let svg_at = svg_blip(&tree, blip);
    let names_media = |at: usize| {
        let id = tree.nodes[at].attr_ns(R, "embed");
        rels.iter()
            .any(|rel| !rel.external && Some(rel.id.as_str()) == id && rel.target == media)
    };
    if svg_at.is_some_and(names_media) {
        return Ok(Some(false));
    }
    let svg = image_rel(package, slide, media)?;
    let raster = image_rel(package, slide, &raster)?;
    // The SVG into the blip's extension, then the raster into its embed.
    let edit = match (svg_at, xml::child(&tree, blip, A, "extLst")) {
        (Some(at), _) => {
            xml::set_attribute(&bytes, &tree.nodes[at], &embed_name(&tree.nodes[at]), &svg)
        }
        (None, Some(list)) => xml::insert_last(&bytes, &tree.nodes[list], &extension(&svg)),
        (None, None) => xml::insert_last(&bytes, &tree.nodes[blip], &extension_list(&svg)),
    };
    package.replace_xml_part(slide, xml::splice(&bytes, vec![edit])?)?;
    let (bytes, tree) = xml::read(package, slide)?;
    let node = &tree.nodes[blip_of(&tree)?];
    let edit = xml::set_attribute(&bytes, node, &embed_name(node), &raster);
    package.replace_xml_part(slide, xml::splice(&bytes, vec![edit])?)?;
    Ok(Some(true))
}
