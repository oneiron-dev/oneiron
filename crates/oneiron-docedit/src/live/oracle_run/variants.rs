//! Fixture variants derived from a pinned baseline by narrow XML surgery:
//! unknown-XML probes beside the mutated shape (step 2), a modern comment
//! and a paragraph build (step 7), and a replaced theme font (step 4). Each
//! variant is itself a candidate, so PowerPoint vouches for the fixture
//! before any edit over it counts.

use super::record::{Res, text};
use crate::ooxml::XmlTree;
use crate::pptx_comments::{
    PptxAuthor, PptxCommentAction, PptxCommentEdit, PptxCommentLimits, PptxCommentTarget,
    SlideMints, comment_patch, inspect_pptx,
};
use crate::retained_opc::Package;
use std::cmp::Reverse;
use std::ops::Range;

pub(super) const P: &str = "http://schemas.openxmlformats.org/presentationml/2006/main";
pub(super) const A: &str = "http://schemas.openxmlformats.org/drawingml/2006/main";
pub(super) const P188: &str = "http://schemas.microsoft.com/office/powerpoint/2018/8/main";
pub(super) const PC: &str = "http://schemas.microsoft.com/office/powerpoint/2013/main/command";

/// The probes' own namespace: markup no Office build knows, carried in
/// extension lists where any reader must keep or ignore it.
pub(super) const PROBE_NS: &str = "urn:oneiron:deck-oracle:probe";
const PROBE_URI: &str = "{0B5E1F6C-4A27-4C1D-9C55-3D2E8A7F0510}";
/// The probe inside the mutated shape's `p:cNvPr`.
pub(super) const SHAPE_PROBE: &str = "shape";
/// The probe in the slide's own extension list.
pub(super) const SLIDE_PROBE: &str = "slide";

pub(super) const COMMENT_REL: &str =
    "http://schemas.microsoft.com/office/2018/10/relationships/comments";
pub(super) const AUTHORS: &str = "ppt/authors.xml";
pub(super) const COMMENT_TEXT: &str = "Deck oracle comment: keep me through the edit";
const COMMENT_ID: &str = "{5A0E1C3B-7D2F-4E8A-9B61-0C4D3E2F1A10}";
const AUTHOR_ID: &str = "{5A0E1C3B-7D2F-4E8A-9B61-0C4D3E2F1A11}";
const AUTHOR_NAME: &str = "Deck oracle";
/// When the fixture's comment was made: 2026-10-18T00:00:00.000Z.
const CREATED_MS: u64 = 1_792_281_600_000;
/// The slide creation id the comment variant mints when its slide has none.
const SLIDE_CREATION_ID: u32 = 3_051_000_510;

/// One part's text.
pub(super) fn part_text(package: &Package, name: &str) -> Res<String> {
    let bytes = package
        .part(name)
        .map_err(text)?
        .ok_or_else(|| format!("{name} is missing"))?;
    String::from_utf8(bytes).map_err(|_| format!("{name} is not UTF-8"))
}

pub(super) fn xml_tree(package: &Package, xml: &str) -> Res<XmlTree> {
    XmlTree::parse(xml.as_bytes(), package.resources()).map_err(text)
}

/// The presentation part, through the package's officeDocument
/// relationship.
pub(super) fn presentation_part(package: &Package) -> Res<String> {
    package
        .relationships("")
        .map_err(text)?
        .into_iter()
        .find(|rel| !rel.external && rel.kind.ends_with("/officeDocument"))
        .map(|rel| rel.target)
        .ok_or_else(|| "the package names no presentation part".to_owned())
}

/// Apply span replacements to `xml`, the last span first.
fn splice(xml: &str, mut edits: Vec<(Range<usize>, String)>) -> String {
    edits.sort_by_key(|(range, _)| Reverse(range.start));
    let mut out = xml.to_owned();
    for (range, value) in edits {
        out.replace_range(range, &value);
    }
    out
}

/// `package` with one part's XML replaced, exported.
fn rewrite(mut package: Package, part: &str, xml: String) -> Res<Vec<u8>> {
    package
        .replace_xml_part(part, xml.into_bytes())
        .map_err(text)?;
    package.export().map_err(text)
}

fn probe_ext(prefix: &str, ns: &str, name: &str) -> String {
    format!(
        "<{prefix}:ext xmlns:{prefix}=\"{ns}\" uri=\"{PROBE_URI}\"><op:probe xmlns:op=\"{PROBE_NS}\" n=\"{name}\"/></{prefix}:ext>"
    )
}

/// Splice whole `p:ext` elements into the slide's `p:extLst`, making one at
/// the end of `p:sld` (its last child in the schema) when it has none.
fn slide_exts(tree: &XmlTree, exts: &str) -> Res<(Range<usize>, String)> {
    let root = &tree.nodes[0];
    if !root.is(P, "sld") {
        return Err("the part is not a slide".to_owned());
    }
    let whole = format!("<p:extLst xmlns:p=\"{P}\">{exts}</p:extLst>");
    Ok(match tree.child(0, P, "extLst").map_err(text)? {
        Some((_, list)) if !list.empty => (list.content.end..list.content.end, exts.to_owned()),
        Some((_, list)) => (list.span.clone(), whole),
        None => (root.content.end..root.content.end, whole),
    })
}

/// The insertion that puts the shape probe last in the shape's `p:cNvPr`
/// (its `a:extLst` ends that element's sequence).
fn shape_probe(tree: &XmlTree, xml: &str, shape: u32) -> Res<(Range<usize>, String)> {
    let wanted = shape.to_string();
    let (at, node) = tree
        .nodes
        .iter()
        .enumerate()
        .find(|(_, node)| node.is(P, "cNvPr") && node.attr("id") == Some(wanted.as_str()))
        .ok_or_else(|| format!("no p:cNvPr with id {shape}"))?;
    let ext = probe_ext("a", A, SHAPE_PROBE);
    let list = format!("<a:extLst xmlns:a=\"{A}\">{ext}</a:extLst>");
    if node.empty {
        let open = xml
            .get(node.span.clone())
            .ok_or("the p:cNvPr span is outside the part")?;
        let head = open.trim_end().trim_end_matches("/>").trim_end();
        return Ok((
            node.span.clone(),
            format!("{head}>{list}</{}>", node.qualified),
        ));
    }
    Ok(match tree.child(at, A, "extLst").map_err(text)? {
        Some((_, found)) if !found.empty => (found.content.end..found.content.end, ext),
        Some((_, found)) => (found.span.clone(), list),
        None => (node.content.end..node.content.end, list),
    })
}

/// The baseline with a probe in `shape`'s non-visual properties and one in
/// the slide's extension list.
pub(super) fn probed(package: &Package, slide_part: &str, shape: u32) -> Res<Vec<u8>> {
    let xml = part_text(package, slide_part)?;
    let tree = xml_tree(package, &xml)?;
    let edits = vec![
        shape_probe(&tree, &xml, shape)?,
        slide_exts(&tree, &probe_ext("p", P, SLIDE_PROBE))?,
    ];
    rewrite(package.clone(), slide_part, splice(&xml, edits))
}

/// The slide one modern comment anchors to.
pub(super) struct CommentSlide<'a> {
    pub(super) part: &'a str,
    pub(super) sld_id: u32,
    /// The slide's `p14:creationId`, when it has one.
    pub(super) creation_id: Option<u32>,
}

/// The baseline with one modern comment thread on the slide, written by the
/// engine's comment writer ([`comment_patch`], FIX 3776) under the
/// fixture's pinned author, comment id, time and text: the author list, the
/// comment part and its relationship, the slide's `p188:commentRel`, and a
/// slide creation id for the anchor when the slide had none.
pub(super) fn commented(package: &Package, slide: &CommentSlide<'_>) -> Res<Vec<u8>> {
    let base = package.export().map_err(text)?;
    let limits = comment_limits(package);
    let number = inspect_pptx(&base, &limits, &crate::resource::Resources::measuring())
        .map_err(text)?
        .slides
        .iter()
        .find(|seen| seen.part == slide.part && seen.sld_id == slide.sld_id)
        .map(|seen| seen.slide)
        .ok_or_else(|| format!("{} is not a slide of the deck", slide.part))?;
    let mints = match slide.creation_id {
        Some(_) => Vec::new(),
        None => vec![(number, SLIDE_CREATION_ID)],
    };
    let edit = PptxCommentEdit {
        author: PptxAuthor {
            guid: AUTHOR_ID.to_owned(),
            name: AUTHOR_NAME.to_owned(),
        },
        thread_id: COMMENT_ID.to_owned(),
        comment_id: COMMENT_ID.to_owned(),
        at: CREATED_MS,
        action: PptxCommentAction::Add {
            target: PptxCommentTarget {
                slide: number,
                slide_creation_id: slide.creation_id,
                shape_creation_id: None,
                shape_fingerprint: None,
            },
            text: COMMENT_TEXT.to_owned(),
        },
    };
    comment_patch(
        &base,
        &[edit],
        SlideMints::Replay(&mints),
        &limits,
        &crate::resource::Resources::measuring(),
    )
    .map(|effects| effects.new_bytes)
    .map_err(text)
}

/// The comment writer's codec ceilings: the package's own.
fn comment_limits(package: &Package) -> PptxCommentLimits {
    let limits = package.limits();
    PptxCommentLimits {
        max_archive_bytes: limits.archive_bytes,
        max_part_bytes: limits.part_bytes,
        max_expanded_bytes: limits.expanded_bytes,
        max_xml_bytes: limits.part_bytes,
    }
}

/// The baseline with one click build on paragraph 0 of `spid`, built by
/// paragraph: the timing tree PowerPoint writes for "appear by paragraph".
pub(super) fn animated(package: &Package, slide_part: &str, spid: u32) -> Res<Vec<u8>> {
    let xml = part_text(package, slide_part)?;
    let tree = xml_tree(package, &xml)?;
    if tree.child(0, P, "timing").map_err(text)?.is_some() {
        return Err("the baseline slide already has a timing tree".to_owned());
    }
    // `p:timing` precedes the extension list, the last child of `p:sld`.
    let at = match tree.child(0, P, "extLst").map_err(text)? {
        Some((_, list)) => list.span.start,
        None => tree.nodes[0].content.end,
    };
    rewrite(
        package.clone(),
        slide_part,
        splice(&xml, vec![(at..at, timing_xml(spid))]),
    )
}

fn timing_xml(spid: u32) -> String {
    let effect = format!(
        r#"<p:par><p:cTn id="5" presetID="1" presetClass="entr" presetSubtype="0" fill="hold" grpId="0" nodeType="clickEffect"><p:stCondLst><p:cond delay="0"/></p:stCondLst><p:childTnLst><p:set><p:cBhvr><p:cTn id="6" dur="1" fill="hold"><p:stCondLst><p:cond delay="0"/></p:stCondLst></p:cTn><p:tgtEl><p:spTgt spid="{spid}"><p:txEl><p:pRg st="0" end="0"/></p:txEl></p:spTgt></p:tgtEl><p:attrNameLst><p:attrName>style.visibility</p:attrName></p:attrNameLst></p:cBhvr><p:to><p:strVal val="visible"/></p:to></p:set></p:childTnLst></p:cTn></p:par>"#
    );
    format!(
        r#"<p:timing xmlns:p="{P}"><p:tnLst><p:par><p:cTn id="1" dur="indefinite" restart="never" nodeType="tmRoot"><p:childTnLst><p:seq concurrent="1" nextAc="seek"><p:cTn id="2" dur="indefinite" nodeType="mainSeq"><p:childTnLst><p:par><p:cTn id="3" fill="hold"><p:stCondLst><p:cond delay="indefinite"/></p:stCondLst><p:childTnLst><p:par><p:cTn id="4" fill="hold"><p:stCondLst><p:cond delay="0"/></p:stCondLst><p:childTnLst>{effect}</p:childTnLst></p:cTn></p:par></p:childTnLst></p:cTn></p:par></p:childTnLst></p:cTn><p:prevCondLst><p:cond evt="onPrev" delay="0"><p:tgtEl><p:sldTgt/></p:tgtEl></p:cond></p:prevCondLst><p:nextCondLst><p:cond evt="onNext" delay="0"><p:tgtEl><p:sldTgt/></p:tgtEl></p:cond></p:nextCondLst></p:seq></p:childTnLst></p:cTn></p:par></p:tnLst><p:bldLst><p:bldP spid="{spid}" grpId="0" build="p"/></p:bldLst></p:timing>"#
    )
}

/// The theme part's bytes with its minor (body) Latin font set to `face`.
pub(super) fn retheme(package: &Package, theme: &str, face: &str) -> Res<Vec<u8>> {
    let xml = part_text(package, theme)?;
    let tree = xml_tree(package, &xml)?;
    let minor = tree
        .nodes
        .iter()
        .position(|node| node.is(A, "minorFont"))
        .ok_or("the theme has no a:minorFont")?;
    let (_, latin) = tree
        .child(minor, A, "latin")
        .map_err(text)?
        .ok_or("the theme's minor font has no a:latin")?;
    let span = latin
        .attr_spans
        .get("typeface")
        .cloned()
        .ok_or("the minor Latin font names no typeface")?;
    Ok(splice(&xml, vec![(span, format!("typeface=\"{face}\""))]).into_bytes())
}
