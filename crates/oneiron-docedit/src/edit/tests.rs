//! ONE-2528 acceptance: per verb, the edit changes only the declared fields
//! and parts (exact part sets), keeps identities, inherited values and
//! animation ranges, or refuses and leaves the package byte-identical. The
//! independent check refuses a write outside the declared elements.
use super::check::{Declared, find_shape};
use super::*;
use crate::deck::fixture::{GROUP_ROOT, NS, archive, limits, placeholder, rels, theme, xfrm};
use crate::deck::{DeckView, State};
use crate::design_plan::MediaType;
use crate::emit::tests::{png, record};
use crate::graphic::Origin;
use crate::ooxml::XmlTree;

pub(super) const SLIDE: &str = "ppt/slides/slide1.xml";
const SECOND: &str = "ppt/slides/slide2.xml";
const NOTES: &str = "ppt/notesSlides/notesSlide1.xml";
const OLD_MEDIA: &str = "ppt/media/image1.png";
const TEXT: &str = "Revenue grew\nCosts fell\nSee report\u{b}Page 1";
const BODY: &str = r#"<a:p><a:r><a:rPr lang="en-GB" b="1"/><a:t>Revenue </a:t></a:r><a:r><a:rPr lang="en-GB"/><a:t>grew</a:t></a:r></a:p><a:p><a:pPr lvl="1"/><a:r><a:rPr lang="en-GB" sz="1800"/><a:t>Costs fell</a:t></a:r><a:endParaRPr lang="en-GB" sz="1800"/></a:p><a:p><a:r><a:rPr lang="en-GB"/><a:t>See </a:t></a:r><a:r><a:rPr lang="en-GB"><a:hlinkClick r:id="rId9"/></a:rPr><a:t>report</a:t></a:r><a:br><a:rPr lang="en-GB"/></a:br><a:r><a:rPr lang="en-GB"/><a:t>Page </a:t></a:r><a:fld id="{B6F15528-21DE-4FAA-801E-634DDDAF4B2B}" type="slidenum"><a:rPr lang="en-GB"/><a:t>1</a:t></a:fld></a:p>"#;
const CREATION: &str = "{BB962C8B-B14F-4D97-AF65-F5344CB8AC3E}";
const MASTER_CLR: &str = r#"<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>"#;

fn text_box(id: u32, name: &str, frame: &str, body: &str) -> String {
    format!(
        r#"<p:sp><p:nvSpPr><p:cNvPr id="{id}" name="{name}"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr><p:spPr>{frame}<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr><p:txBody><a:bodyPr wrap="square"><a:normAutofit fontScale="92500"/></a:bodyPr><a:lstStyle/>{body}</p:txBody></p:sp>"#
    )
}

fn group(id: u32, name: &str, attrs: &str, (cx, cy): (i64, i64), inner: &str) -> String {
    format!(
        r#"<p:grpSp><p:nvGrpSpPr><p:cNvPr id="{id}" name="{name}"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm{attrs}><a:off x="1000000" y="1000000"/><a:ext cx="2000000" cy="2000000"/><a:chOff x="0" y="0"/><a:chExt cx="{cx}" cy="{cy}"/></a:xfrm></p:grpSpPr>{inner}</p:grpSp>"#
    )
}

fn plain(id: u32, name: &str, frame: &str) -> String {
    format!(
        r#"<p:sp><p:nvSpPr><p:cNvPr id="{id}" name="{name}"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr>{frame}<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr></p:sp>"#
    )
}

/// One click effect on paragraph 0 of shape 8 (built by paragraph) and one
/// on characters 0-3 of shape 9.
fn timing() -> String {
    let effect = |ctn: u32, spid: u32, range: &str, node: &str| {
        format!(
            r#"<p:par><p:cTn id="{ctn}" presetID="10" presetClass="entr" presetSubtype="0" fill="hold" grpId="0" nodeType="{node}"><p:stCondLst><p:cond delay="0"/></p:stCondLst><p:childTnLst><p:set><p:cBhvr><p:cTn id="{}" dur="1" fill="hold"><p:stCondLst><p:cond delay="0"/></p:stCondLst></p:cTn><p:tgtEl><p:spTgt spid="{spid}"><p:txEl>{range}</p:txEl></p:spTgt></p:tgtEl><p:attrNameLst><p:attrName>style.visibility</p:attrName></p:attrNameLst></p:cBhvr><p:to><p:strVal val="visible"/></p:to></p:set></p:childTnLst></p:cTn></p:par>"#,
            ctn + 1
        )
    };
    format!(
        r#"<p:timing><p:tnLst><p:par><p:cTn id="1" dur="indefinite" restart="never" nodeType="tmRoot"><p:childTnLst><p:seq concurrent="1" nextAc="seek"><p:cTn id="2" dur="indefinite" nodeType="mainSeq"><p:childTnLst><p:par><p:cTn id="3" fill="hold"><p:stCondLst><p:cond delay="indefinite"/></p:stCondLst><p:childTnLst><p:par><p:cTn id="4" fill="hold"><p:stCondLst><p:cond delay="0"/></p:stCondLst><p:childTnLst>{}{}</p:childTnLst></p:cTn></p:par></p:childTnLst></p:cTn></p:par></p:childTnLst></p:cTn><p:prevCondLst><p:cond evt="onPrev" delay="0"><p:tgtEl><p:sldTgt/></p:tgtEl></p:cond></p:prevCondLst><p:nextCondLst><p:cond evt="onNext" delay="0"><p:tgtEl><p:sldTgt/></p:tgtEl></p:cond></p:nextCondLst></p:seq></p:childTnLst></p:cTn></p:par></p:tnLst><p:bldLst><p:bldP spid="8" grpId="0" build="p"/></p:bldLst></p:timing>"#,
        effect(5, 8, r#"<p:pRg st="0" end="0"/>"#, "clickEffect"),
        effect(7, 9, r#"<p:charRg st="0" end="3"/>"#, "withEffect"),
    )
}

fn slide1() -> String {
    let title = r#"<p:sp><p:nvSpPr><p:cNvPr id="2" name="Title 1"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr><p:nvPr><p:ph type="title"/></p:nvPr></p:nvSpPr><p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang="en-GB"/><a:t>Quarterly review</a:t></a:r></a:p></p:txBody></p:sp>"#;
    let picture = format!(
        r#"<p:pic><p:nvPicPr><p:cNvPr id="6" name="Photo" descr="Old photo"/><p:cNvPicPr><a:picLocks noChangeAspect="1"/></p:cNvPicPr><p:nvPr/></p:nvPicPr><p:blipFill><a:blip r:embed="rId3"/><a:stretch><a:fillRect/></a:stretch></p:blipFill><p:spPr>{}<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr></p:pic>"#,
        xfrm(7_000_000, 1_000_000, 2_000_000, 1_000_000)
    );
    let connector = format!(
        r#"<p:cxnSp><p:nvCxnSpPr><p:cNvPr id="7" name="Link"/><p:cNvCxnSpPr><a:stCxn id="3" idx="2"/><a:endCxn id="6" idx="0"/></p:cNvCxnSpPr><p:nvPr/></p:nvCxnSpPr><p:spPr>{}<a:prstGeom prst="line"><a:avLst/></a:prstGeom></p:spPr></p:cxnSp>"#,
        xfrm(4_000_000, 3_000_000, 1_000_000, 1_000_000)
    );
    let shapes = [
        title.to_owned(),
        text_box(
            3,
            "Body",
            &xfrm(1_000_000, 2_000_000, 6_000_000, 2_000_000),
            BODY,
        ),
        group(
            4,
            "Scaled",
            "",
            (1_000_000, 1_000_000),
            &plain(5, "Inner", &xfrm(100_000, 100_000, 200_000, 200_000)),
        ),
        group(
            10,
            "Turned",
            r#" rot="5400000""#,
            (2_000_000, 2_000_000),
            &plain(11, "Spun", &xfrm(0, 0, 100_000, 100_000)),
        ),
        group(
            12,
            "Flat",
            "",
            (0, 1_000_000),
            &plain(13, "Squashed", &xfrm(0, 0, 100_000, 100_000)),
        ),
        picture,
        connector,
        text_box(
            8,
            "Built",
            &xfrm(1_000_000, 4_500_000, 3_000_000, 1_000_000),
            "<a:p><a:r><a:t>One</a:t></a:r></a:p><a:p><a:r><a:t>Two</a:t></a:r></a:p>",
        ),
        text_box(
            9,
            "Typed",
            &xfrm(5_000_000, 4_500_000, 3_000_000, 1_000_000),
            "<a:p><a:r><a:t>Spelled</a:t></a:r></a:p>",
        ),
    ]
    .concat();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sld {NS}><p:cSld><p:spTree>{GROUP_ROOT}{shapes}</p:spTree><p:extLst><p:ext uri="{CREATION}"><p14:creationId val="1001"/></p:ext></p:extLst></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>{}</p:sld>"#,
        timing()
    )
}

fn slide2() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sld {NS}><p:cSld><p:spTree>{GROUP_ROOT}{}{}{}</p:spTree><p:extLst><p:ext uri="{CREATION}"><p14:creationId val="1002"/></p:ext></p:extLst></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>"#,
        text_box(
            2,
            "Plain",
            &xfrm(1_000_000, 1_000_000, 4_000_000, 1_000_000),
            "<a:p><a:r><a:t>Second</a:t></a:r></a:p>"
        ),
        plain(3, "Twin", &xfrm(0, 0, 10, 10)),
        plain(3, "Twin", &xfrm(20, 0, 10, 10)),
    )
}

fn notes_placeholders(image: &str, body: &str, text: &str) -> String {
    format!(
        r#"<p:sp><p:nvSpPr><p:cNvPr id="2" name="{image}"/><p:cNvSpPr><a:spLocks noGrp="1" noRot="1" noChangeAspect="1"/></p:cNvSpPr><p:nvPr><p:ph type="sldImg" idx="2"/></p:nvPr></p:nvSpPr><p:spPr/></p:sp><p:sp><p:nvSpPr><p:cNvPr id="3" name="{body}"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr><p:nvPr><p:ph type="body" sz="quarter" idx="3"/></p:nvPr></p:nvSpPr><p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/>{text}</p:txBody></p:sp>"#
    )
}

fn parts() -> Vec<(&'static str, String)> {
    let types = [
        ("/ppt/presentation.xml", "presentation.main"),
        ("/ppt/slides/slide1.xml", "slide"),
        ("/ppt/slides/slide2.xml", "slide"),
        ("/ppt/slideLayouts/slideLayout1.xml", "slideLayout"),
        ("/ppt/slideMasters/slideMaster1.xml", "slideMaster"),
        ("/ppt/notesMasters/notesMaster1.xml", "notesMaster"),
        ("/ppt/notesSlides/notesSlide1.xml", "notesSlide"),
    ]
    .map(|(part, kind)| {
        format!(
            r#"<Override PartName="{part}" ContentType="application/vnd.openxmlformats-officedocument.presentationml.{kind}+xml"/>"#
        )
    })
    .concat();
    let title = placeholder(
        2,
        "Title 1",
        r#"<p:ph type="title"/>"#,
        &xfrm(838_200, 365_125, 10_515_600, 1_325_563),
        "",
    );
    let hyperlink = r#"<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.org/report" TargetMode="External"/></Relationships>"#;
    vec![
        (
            "[Content_Types].xml",
            format!(
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/>{types}<Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/></Types>"#
            ),
        ),
        (
            "_rels/.rels",
            rels(&[("rId1", "officeDocument", "ppt/presentation.xml")]),
        ),
        (
            "ppt/presentation.xml",
            format!(
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:presentation {NS}><p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst><p:notesMasterIdLst><p:notesMasterId r:id="rId4"/></p:notesMasterIdLst><p:sldIdLst><p:sldId id="256" r:id="rId2"/><p:sldId id="257" r:id="rId3"/></p:sldIdLst><p:sldSz cx="12192000" cy="6858000"/><p:notesSz cx="6858000" cy="9144000"/></p:presentation>"#
            ),
        ),
        (
            "ppt/_rels/presentation.xml.rels",
            rels(&[
                ("rId1", "slideMaster", "slideMasters/slideMaster1.xml"),
                ("rId2", "slide", "slides/slide1.xml"),
                ("rId3", "slide", "slides/slide2.xml"),
                ("rId4", "notesMaster", "notesMasters/notesMaster1.xml"),
                ("rId5", "theme", "theme/theme1.xml"),
            ]),
        ),
        (
            "ppt/slideMasters/slideMaster1.xml",
            format!(
                r#"<p:sldMaster {NS}><p:cSld><p:spTree>{GROUP_ROOT}{title}</p:spTree></p:cSld>{MASTER_CLR}<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst></p:sldMaster>"#
            ),
        ),
        (
            "ppt/slideMasters/_rels/slideMaster1.xml.rels",
            rels(&[
                ("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml"),
                ("rId2", "theme", "../theme/theme1.xml"),
            ]),
        ),
        (
            "ppt/slideLayouts/slideLayout1.xml",
            format!(
                r#"<p:sldLayout {NS}><p:cSld><p:spTree>{GROUP_ROOT}{title}</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>"#
            ),
        ),
        (
            "ppt/slideLayouts/_rels/slideLayout1.xml.rels",
            rels(&[("rId1", "slideMaster", "../slideMasters/slideMaster1.xml")]),
        ),
        ("ppt/theme/theme1.xml", theme()),
        (SLIDE, slide1()),
        (
            "ppt/slides/_rels/slide1.xml.rels",
            rels(&[
                ("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml"),
                ("rId2", "notesSlide", "../notesSlides/notesSlide1.xml"),
                ("rId3", "image", "../media/image1.png"),
            ])
            .replace("</Relationships>", hyperlink),
        ),
        (SECOND, slide2()),
        (
            "ppt/slides/_rels/slide2.xml.rels",
            rels(&[("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml")]),
        ),
        (
            "ppt/notesMasters/notesMaster1.xml",
            format!(
                r#"<p:notesMaster {NS}><p:cSld><p:spTree>{GROUP_ROOT}{}</p:spTree></p:cSld>{MASTER_CLR}</p:notesMaster>"#,
                notes_placeholders(
                    "Image de diapositive 1",
                    "Espace réservé des notes 2",
                    "<a:p><a:endParaRPr lang=\"fr-FR\"/></a:p>"
                )
            ),
        ),
        (
            "ppt/notesMasters/_rels/notesMaster1.xml.rels",
            rels(&[("rId1", "theme", "../theme/theme1.xml")]),
        ),
        (
            NOTES,
            format!(
                r#"<p:notes {NS}><p:cSld><p:spTree>{GROUP_ROOT}{}</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:notes>"#,
                notes_placeholders(
                    "Slide Image 1",
                    "Notes 2",
                    r#"<a:p><a:r><a:rPr lang="en-GB"/><a:t>Speak slowly</a:t></a:r></a:p>"#
                )
            ),
        ),
        (
            "ppt/notesSlides/_rels/notesSlide1.xml.rels",
            rels(&[
                ("rId1", "notesMaster", "../notesMasters/notesMaster1.xml"),
                ("rId2", "slide", "../slides/slide1.xml"),
            ]),
        ),
    ]
}

/// The fixture deck, with a real PNG as the existing picture's media.
pub(super) fn deck() -> Package {
    let mut package = Package::open(&archive(&parts()), limits()).unwrap();
    package
        .add_part(OLD_MEDIA, "image/png", png(4, 2, [10, 20, 30]))
        .unwrap();
    Package::open(&package.export().unwrap(), limits()).unwrap()
}

pub(super) fn target<'a>(package: &Package, slide: &'a str, shape: u32) -> Target<'a> {
    let view = DeckView::read(package).unwrap();
    let found = view
        .slides
        .iter()
        .find(|s| s.part == slide)
        .and_then(|s| s.shapes.iter().find(|s| s.id == Some(shape)))
        .unwrap();
    Target {
        slide,
        shape,
        expected: found.content_fingerprint,
    }
}

fn text(slide: &'static str, shape: u32, value: &'static str) -> ValueEdit<'static> {
    ValueEdit::SetText {
        target: target(&deck(), slide, shape),
        text: value,
    }
}

/// Apply to a fresh deck; returns the deck and the report.
fn apply(op: &ValueEdit<'_>) -> (Package, EditReport) {
    let mut package = deck();
    let report = edit(&mut package, op).unwrap();
    (package, report)
}

/// Refuse on a fresh deck, which must stay byte-identical.
fn refuse(op: &ValueEdit<'_>) -> EditRefusal {
    let mut package = deck();
    let before = package.export().unwrap();
    let refusal = edit(&mut package, op).unwrap_err();
    assert_eq!(
        package.export().unwrap(),
        before,
        "a refusal changed the deck"
    );
    refusal
}

pub(super) fn part(package: &Package, name: &str) -> String {
    String::from_utf8(package.part(name).unwrap().unwrap()).unwrap()
}

/// The shape's source XML.
pub(super) fn shape_xml(package: &Package, slide: &str, id: u32) -> String {
    let source = part(package, slide);
    let tree = XmlTree::parse(source.as_bytes(), limits().xml).unwrap();
    let at = find_shape(&tree, id).unwrap();
    source[tree.nodes[at].span.clone()].to_owned()
}

fn changed(report: &EditReport) -> Vec<&str> {
    let mut parts: Vec<&str> = report.changed_parts.iter().map(String::as_str).collect();
    parts.sort_unstable();
    parts
}

fn view_shape(package: &Package, slide: usize, id: u32) -> crate::deck::ShapeView {
    DeckView::read(package).unwrap().slides[slide]
        .shapes
        .iter()
        .find(|s| s.id == Some(id))
        .unwrap()
        .clone()
}

#[test]
fn set_text_keeps_every_run_outside_the_change() {
    let (deck, report) = apply(&text(
        SLIDE,
        3,
        "Revenue rose\nCosts fell\nSee reports\u{b}Page 1",
    ));
    assert_eq!(changed(&report), [SLIDE]);
    assert_eq!(
        report.fit,
        Err(FitUnverified {
            part: SLIDE.into(),
            shape: 3
        })
    );
    let body = shape_xml(&deck, SLIDE, 3);
    let expected = BODY
        .replace("<a:t>grew</a:t>", "<a:t>rose</a:t>")
        .replace("<a:t>report</a:t>", "<a:t>reports</a:t>");
    // The bold head, the linked run (now "reports"), the break, the field
    // and the autofit metrics keep their bytes; nothing else is written.
    assert!(body.contains(&expected), "{body}");
    assert!(body.contains(r#"<a:normAutofit fontScale="92500"/>"#));
    assert_eq!(
        part(&deck, SLIDE).replace(&expected, BODY),
        slide1(),
        "only the two changed runs differ"
    );
}

#[test]
fn set_text_adds_and_removes_paragraphs_like_their_neighbours() {
    let (deck, _) = apply(&text(
        SLIDE,
        3,
        "Revenue grew\nCosts fell\nMargins held\nSee report\u{b}Page 1",
    ));
    let added = r#"<a:p><a:pPr lvl="1"/><a:r><a:rPr lang="en-GB" sz="1800"/><a:t>Margins held</a:t></a:r><a:endParaRPr lang="en-GB" sz="1800"/></a:p>"#;
    assert!(shape_xml(&deck, SLIDE, 3).contains(&format!(
        "<a:endParaRPr lang=\"en-GB\" sz=\"1800\"/></a:p>{added}<a:p><a:r>"
    )));
    // Removing the break, "Page " and the field removes them whole and
    // keeps the linked run; clearing leaves one paragraph.
    let (deck, _) = apply(&text(SLIDE, 3, "Revenue grew\nCosts fell\nSee report"));
    let body = shape_xml(&deck, SLIDE, 3);
    assert!(
        body.contains(r#"<a:hlinkClick r:id="rId9"/></a:rPr><a:t>report</a:t></a:r></a:p>"#),
        "{body}"
    );
    assert!(!body.contains("a:fld") && !body.contains("a:br"));
    let (deck, _) = apply(&text(SLIDE, 3, ""));
    let view = view_shape(&deck, 0, 3);
    assert_eq!(view.text.unwrap().paragraphs.len(), 1);
    assert!(shape_xml(&deck, SLIDE, 3).contains("<a:lstStyle/><a:p></a:p></p:txBody>"));
    // Replacing a whole paragraph keeps the first replaced run's properties.
    let (deck, _) = apply(&text(
        SLIDE,
        3,
        "Profit doubled\nCosts fell\nSee report\u{b}Page 1",
    ));
    assert!(
        shape_xml(&deck, SLIDE, 3).contains(
            r#"<a:p><a:r><a:rPr lang="en-GB" b="1"/><a:t>Profit doubled</a:t></a:r></a:p>"#
        )
    );
}

#[test]
fn set_text_refuses_what_it_cannot_map() {
    // The body as it reads is a no-op: no part changes, no fit claim.
    let (unchanged, report) = apply(&text(SLIDE, 3, TEXT));
    assert!(report.changed_parts.is_empty() && report.fit.is_ok());
    assert_eq!(unchanged.export().unwrap(), deck().export().unwrap());
    for value in [
        "Revenue grew\nCosts fell\nSee report\u{b}Page 2",
        "Revenue\u{b}grew\nCosts fell\nSee report\u{b}Page 1",
    ] {
        assert!(
            matches!(refuse(&text(SLIDE, 3, value)), EditRefusal::TextMapping(_)),
            "{value:?}"
        );
    }
    assert!(matches!(
        refuse(&text(SLIDE, 3, "bad \u{1} char")),
        EditRefusal::Invalid(_)
    ));
    assert!(matches!(
        refuse(&text(SLIDE, 3, "carriage\r")),
        EditRefusal::Invalid(_)
    ));
    // Pictures and groups have no text body.
    assert_eq!(
        refuse(&text(SLIDE, 6, "x")),
        EditRefusal::Missing("text body")
    );
}

#[test]
fn set_text_writes_own_text_and_never_materialises_inherited_values() {
    let (deck, _) = apply(&text(SLIDE, 2, "Annual review & <outlook>"));
    let title = shape_xml(&deck, SLIDE, 2);
    assert!(title.contains(r#"<p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang="en-GB"/><a:t>Annual review &amp; &lt;outlook&gt;</a:t></a:r></a:p>"#), "{title}");
    let geometry = view_shape(&deck, 0, 2).geometry;
    assert!(geometry.offset.inherited && geometry.extent.inherited);
}

#[test]
fn text_edits_keep_animated_ranges_or_refuse() {
    // Paragraph 0 of shape 8 is built by paragraph: its text may change,
    // its paragraph structure may not.
    let (_, report) = apply(&text(SLIDE, 8, "Uno\nDos"));
    assert_eq!(changed(&report), [SLIDE]);
    for value in ["One\nTwo\nThree", "One"] {
        assert_eq!(
            refuse(&text(SLIDE, 8, value)),
            EditRefusal::AnimatedTextStructureChanged
        );
    }
    // Characters 0-3 of shape 9 hold while the length holds.
    apply(&text(SLIDE, 9, "Spilled"));
    assert_eq!(
        refuse(&text(SLIDE, 9, "Spelt")),
        EditRefusal::AnimatedTextStructureChanged
    );
    let run = |value| ValueEdit::ReplaceRunText {
        target: target(&deck(), SLIDE, 9),
        paragraph: 0,
        run: 0,
        expected: "Spelled",
        text: value,
    };
    assert_eq!(
        refuse(&run("Spell")),
        EditRefusal::AnimatedTextStructureChanged
    );
    let (deck, _) = apply(&run("Smelled"));
    let index = &DeckView::read(&deck).unwrap().slides[0].animation;
    assert_eq!(index.targets_of(9).count(), 1);
}

#[test]
fn replace_run_text_writes_that_run_alone() {
    let op = |run, expected, text| ValueEdit::ReplaceRunText {
        target: target(&deck(), SLIDE, 3),
        paragraph: 2,
        run,
        expected,
        text,
    };
    let (deck, report) = apply(&op(1, "report", "rapport"));
    assert_eq!(changed(&report), [SLIDE]);
    assert_eq!(
        part(&deck, SLIDE),
        slide1().replace("<a:t>report</a:t>", "<a:t>rapport</a:t>")
    );
    assert_eq!(refuse(&op(1, "rapport", "x")), EditRefusal::TargetChanged);
    assert!(matches!(
        refuse(&op(3, "1", "2")),
        EditRefusal::TextMapping(_)
    ));
    assert!(matches!(
        refuse(&op(1, "report", "two\nlines")),
        EditRefusal::Invalid(_)
    ));
    assert_eq!(refuse(&op(9, "report", "x")), EditRefusal::Missing("run"));
}

#[test]
fn edits_refuse_stale_missing_and_ambiguous_targets() {
    let mut stale = target(&deck(), SLIDE, 3);
    stale.expected[0] ^= 1;
    assert_eq!(
        refuse(&ValueEdit::SetText {
            target: stale,
            text: "x"
        }),
        EditRefusal::TargetChanged
    );
    let missing = Target { shape: 99, ..stale };
    assert_eq!(
        refuse(&ValueEdit::SetText {
            target: missing,
            text: "x"
        }),
        EditRefusal::Missing("shape")
    );
    let twin = Target {
        slide: SECOND,
        shape: 3,
        expected: [0; 32],
    };
    assert!(matches!(
        refuse(&ValueEdit::SetText {
            target: twin,
            text: "x"
        }),
        EditRefusal::AmbiguousAnchor(_)
    ));
}

#[test]
fn set_xfrm_writes_only_the_declared_properties() {
    let op = |xfrm| ValueEdit::SetXfrm {
        target: target(&deck(), SLIDE, 3),
        xfrm,
    };
    let (deck, report) = apply(&op(Xfrm {
        offset: Some((1_100_000, 2_000_000)),
        ..Xfrm::default()
    }));
    assert_eq!(changed(&report), [SLIDE]);
    assert_eq!(report.fit, Ok(()));
    assert_eq!(
        report.effects,
        [Effect::GluedConnector { connector: Some(7) }]
    );
    assert_eq!(
        part(&deck, SLIDE),
        slide1().replacen(
            r#"<a:off x="1000000" y="2000000"/>"#,
            r#"<a:off x="1100000" y="2000000"/>"#,
            1
        )
    );
    let (deck, report) = apply(&op(Xfrm {
        extent: Some((6_000_000, 2_500_000)),
        rotation: Some(600_000),
        flip_h: Some(true),
        flip_v: Some(false),
        ..Xfrm::default()
    }));
    assert!(shape_xml(&deck, SLIDE, 3).contains(r#"<a:xfrm rot="600000" flipH="1"><a:off x="1000000" y="2000000"/><a:ext cx="6000000" cy="2500000"/></a:xfrm>"#));
    assert_eq!(
        report.fit,
        Err(FitUnverified {
            part: SLIDE.into(),
            shape: 3
        })
    );
    let geometry = view_shape(&deck, 0, 3).geometry;
    assert_eq!(
        (
            geometry.rotation.value,
            geometry.flip_h.value,
            geometry.rotation.state
        ),
        (Some(600_000), Some(true), State::Explicit)
    );
    // A group's own offset moves it; its child space is not written.
    let (deck, _) = apply(&ValueEdit::SetXfrm {
        target: target(&self::deck(), SLIDE, 4),
        xfrm: Xfrm {
            offset: Some((0, 0)),
            ..Xfrm::default()
        },
    });
    assert!(shape_xml(&deck, SLIDE, 4).contains(r#"<a:off x="0" y="0"/><a:ext cx="2000000" cy="2000000"/><a:chOff x="0" y="0"/><a:chExt cx="1000000" cy="1000000"/>"#));
    for bad in [
        Xfrm {
            extent: Some((-1, 1)),
            ..Xfrm::default()
        },
        Xfrm {
            rotation: Some(21_600_000),
            ..Xfrm::default()
        },
        Xfrm {
            offset: Some((i64::MAX, 0)),
            ..Xfrm::default()
        },
    ] {
        assert!(matches!(
            refuse(&op(bad)),
            EditRefusal::UnrepresentableTransform(_)
        ));
    }
}

#[test]
fn an_inherited_transform_is_owned_only_when_declared_whole() {
    let op = |xfrm| ValueEdit::SetXfrm {
        target: target(&deck(), SLIDE, 2),
        xfrm,
    };
    let offset = Xfrm {
        offset: Some((0, 0)),
        ..Xfrm::default()
    };
    assert_eq!(refuse(&op(offset)), EditRefusal::InheritedTransform);
    let by = ValueEdit::MoveInSlideSpace {
        target: target(&deck(), SLIDE, 2),
        by: (10, 10),
    };
    assert_eq!(refuse(&by), EditRefusal::InheritedTransform);
    let (deck, report) = apply(&op(Xfrm {
        offset: Some((838_200, 365_125)),
        extent: Some((10_515_600, 1_000_000)),
        ..Xfrm::default()
    }));
    assert_eq!(changed(&report), [SLIDE]);
    let a = "http://schemas.openxmlformats.org/drawingml/2006/main";
    assert!(shape_xml(&deck, SLIDE, 2).contains(&format!(r#"<p:spPr><a:xfrm xmlns:a="{a}"><a:off x="838200" y="365125"/><a:ext cx="10515600" cy="1000000"/></a:xfrm></p:spPr>"#)));
    let geometry = view_shape(&deck, 0, 2).geometry;
    assert!(!geometry.offset.inherited && geometry.offset.state == State::Explicit);
}

#[test]
fn move_in_slide_space_inverts_the_parent_groups() {
    let moved = |id, by| {
        let (deck, _) = apply(&ValueEdit::MoveInSlideSpace {
            target: target(&deck(), SLIDE, id),
            by,
        });
        view_shape(&deck, 0, id).geometry.offset.value.unwrap()
    };
    // Twice-scaled group: 200,000 slide EMU is 100,000 local.
    assert_eq!(moved(5, (200_000, -50_000)), (200_000, 75_000));
    // A quarter turn: slide +x is local -y.
    assert_eq!(moved(11, (100_000, 0)), (0, -100_000));
    // Top level: the move is the offset change.
    assert_eq!(moved(3, (5, 7)), (1_000_005, 2_000_007));
    let flat = ValueEdit::MoveInSlideSpace {
        target: target(&deck(), SLIDE, 13),
        by: (1, 1),
    };
    assert_eq!(refuse(&flat), EditRefusal::NonInvertibleGroupTransform);
}

fn photo(bytes: &[u8], media: MediaType) -> AssetRecord {
    record("asset:photo", media, bytes, Origin::Held)
}

#[test]
fn set_picture_adds_media_and_keeps_the_old() {
    let bytes = png(8, 4, [200, 10, 10]);
    let record = photo(&bytes, MediaType::Png);
    let op = ValueEdit::SetPicture {
        target: target(&deck(), SLIDE, 6),
        picture: Picture {
            record: &record,
            bytes: &bytes,
            requested: AssetKind::Factual,
            limits: GraphicLimits::default(),
        },
    };
    let (deck, report) = apply(&op);
    let new_media = "ppt/media/image2.png";
    assert_eq!(
        changed(&report),
        [new_media, "ppt/slides/_rels/slide1.xml.rels", SLIDE]
    );
    assert_eq!(
        report.effects,
        [Effect::PreviousMedia {
            relationship: "rId3".into()
        }]
    );
    assert_eq!(deck.part(new_media).unwrap().unwrap(), bytes);
    assert_eq!(
        deck.part(OLD_MEDIA).unwrap(),
        self::deck().part(OLD_MEDIA).unwrap()
    );
    let picture = shape_xml(&deck, SLIDE, 6);
    assert!(
        picture.contains(r#"descr="Described asset:photo""#)
            && picture.contains(r#"<a:blip r:embed="rId10"/>"#),
        "{picture}"
    );
    // A JPEG has no default content type here: the override is the only
    // other write.
    let jpeg = [
        0xFF, 0xD8, 0xFF, 0xC0, 0, 11, 8, 0, 4, 0, 8, 1, 1, 0x11, 0, 0xFF, 0xD9,
    ];
    let record = photo(&jpeg, MediaType::Jpeg);
    let (deck, report) = apply(&ValueEdit::SetPicture {
        target: op_target(&op),
        picture: Picture {
            record: &record,
            bytes: &jpeg,
            requested: AssetKind::Factual,
            limits: GraphicLimits::default(),
        },
    });
    assert!(changed(&report).contains(&"[Content_Types].xml"));
    assert!(
        part(&deck, "[Content_Types].xml")
            .contains(r#"<Override PartName="/ppt/media/image2.jpeg" ContentType="image/jpeg"/>"#)
    );
}

fn op_target<'a>(op: &ValueEdit<'a>) -> Target<'a> {
    match *op {
        ValueEdit::SetPicture { target, .. } => target,
        _ => unreachable!(),
    }
}

#[test]
fn set_picture_refuses_other_shapes_and_unchecked_assets() {
    let bytes = png(8, 4, [200, 10, 10]);
    let good = photo(&bytes, MediaType::Png);
    let mut tampered = good.clone();
    tampered.content_hash[0] ^= 1;
    let svg = br##"<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 10 10"><rect width="10" height="10" fill="#000000"/></svg>"##;
    let figure = photo(svg, MediaType::Svg);
    let cases: [(u32, &AssetRecord, &[u8]); 3] = [
        (3, &good, &bytes),
        (6, &tampered, &bytes),
        (6, &figure, svg),
    ];
    let refusals: Vec<EditRefusal> = cases
        .iter()
        .map(|&(shape, record, bytes)| {
            refuse(&ValueEdit::SetPicture {
                target: target(&deck(), SLIDE, shape),
                picture: Picture {
                    record,
                    bytes,
                    requested: AssetKind::Factual,
                    limits: GraphicLimits::default(),
                },
            })
        })
        .collect();
    assert_eq!(
        refusals,
        [
            EditRefusal::Invalid("set_picture targets a picture"),
            EditRefusal::Picture(GraphicError::HashMismatch),
            EditRefusal::Invalid("set_picture takes a PNG or JPEG"),
        ]
    );
}

#[test]
fn set_notes_writes_the_notes_body() {
    let op = |expected, text| ValueEdit::SetNotes {
        slide: SLIDE,
        expected,
        text,
    };
    let (deck, report) = apply(&op(Some("Speak slowly"), "Speak slowly\nPause"));
    assert_eq!(changed(&report), [NOTES]);
    assert!(part(&deck, NOTES).contains(r#"<a:t>Speak slowly</a:t></a:r></a:p><a:p><a:r><a:rPr lang="en-GB"/><a:t>Pause</a:t></a:r></a:p>"#));
    assert_eq!(refuse(&op(Some("Speak"), "x")), EditRefusal::TargetChanged);
    assert_eq!(refuse(&op(None, "x")), EditRefusal::TargetChanged);
}

#[test]
fn set_notes_creates_a_notes_slide_over_the_master() {
    let (deck, report) = apply(&ValueEdit::SetNotes {
        slide: SECOND,
        expected: None,
        text: "Thank the team\u{b}by name",
    });
    let notes = "ppt/notesSlides/notesSlide2.xml";
    assert_eq!(
        changed(&report),
        [
            "[Content_Types].xml",
            "ppt/notesSlides/_rels/notesSlide2.xml.rels",
            notes,
            "ppt/slides/_rels/slide2.xml.rels"
        ]
    );
    assert_eq!(
        report.effects,
        [Effect::NotesCreated { part: notes.into() }]
    );
    let xml = part(&deck, notes);
    assert!(
        xml.contains(r#"name="Espace réservé des notes 2"/>"#)
            && xml.contains(r#"<p:ph type="body" idx="3"/>"#),
        "{xml}"
    );
    assert!(xml.contains(
        "<a:p><a:r><a:t>Thank the team</a:t></a:r><a:br/><a:r><a:t>by name</a:t></a:r></a:p>"
    ));
    let backlink = deck.relationships(notes).unwrap();
    assert!(
        backlink
            .iter()
            .any(|rel| rel.target == SECOND && rel.kind.ends_with("/slide"))
    );
    // Written again, the created notes are the existing ones.
    let mut deck = deck;
    let again = edit(
        &mut deck,
        &ValueEdit::SetNotes {
            slide: SECOND,
            expected: Some("Thank the team\u{b}by name"),
            text: "Thanks",
        },
    )
    .unwrap();
    assert_eq!(changed(&again), [notes]);
}

#[test]
fn the_check_refuses_a_write_outside_the_declared_elements() {
    let input = deck();
    let mut tampered = input.clone();
    let source = part(&input, SLIDE);
    // The declared text body changes, and so does the shape's name.
    let bad = source
        .replacen("<a:t>grew</a:t>", "<a:t>rose</a:t>", 1)
        .replacen(r#"name="Body""#, r#"name="Bodie""#, 1);
    tampered.replace_xml_part(SLIDE, bad.into_bytes()).unwrap();
    let declared = Declared::element(SLIDE, Some(3), &[(xml::P, "txBody")]);
    let written = Written {
        allowed: vec![SLIDE.into()],
        declared: vec![declared],
        relationships: Vec::new(),
        created: Vec::new(),
        effects: Vec::new(),
        fit: None,
    };
    let before = DeckView::read(&input).unwrap();
    let op = text(SLIDE, 3, "Revenue rose\nCosts fell\nSee report\u{b}Page 1");
    let refusal = check::verify(&input, &tampered, &before, &op, &written).unwrap_err();
    assert!(
        matches!(refusal, EditRefusal::WriteOutsideTarget { .. }),
        "{refusal:?}"
    );
    // A part outside the allowed set is refused by name.
    let mut other = input.clone();
    other
        .replace_xml_part(
            SECOND,
            part(&input, SECOND).replace("Second", "Deux").into_bytes(),
        )
        .unwrap();
    let refusal = check::verify(&input, &other, &before, &op, &written).unwrap_err();
    assert_eq!(
        refusal,
        EditRefusal::PartDiffOutsideTransaction(SECOND.into())
    );
}

/// A pinned PPTArena pair, acquired locally with `deck_oracle.py acquire`
/// (never committed): the original and its ground truth.
fn pptarena(case: &str) -> (Package, Package) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(case);
    let open =
        |name: &str| Package::open(&std::fs::read(dir.join(name)).unwrap(), limits()).unwrap();
    (open("original.pptx"), open("ground_truth.pptx"))
}

/// A shape's text body as `set_text` takes it.
fn body_text(package: &Package, part: &str, id: u32) -> Option<String> {
    let (_, tree) = xml::read(package, part).unwrap();
    let body = xml::child(&tree, find_shape(&tree, id)?, xml::P, "txBody")?;
    let lines: Vec<String> = text::paragraphs(&tree, body)
        .iter()
        .map(|p| p.text.iter().collect())
        .collect();
    Some(lines.join("\n"))
}

/// Lines between paragraph ends and `a:br`s, and the separators.
fn lines(text: &str) -> (Vec<&str>, Vec<char>) {
    let separators = text.chars().filter(|&c| matches!(c, '\n' | text::BREAK));
    (
        text.split(['\n', text::BREAK]).collect(),
        separators.collect(),
    )
}

fn joined(lines: &[&str], separators: &[char]) -> String {
    let mut text = lines[0].to_owned();
    for (line, separator) in lines[1..].iter().zip(separators) {
        text.push(*separator);
        text.push_str(line);
    }
    text
}

fn runs(package: &Package, part: &str, id: u32) -> Vec<Vec<String>> {
    let view = DeckView::read(package).unwrap();
    let slide = view.slides.iter().find(|s| s.part == part).unwrap();
    let shape = slide.shapes.iter().find(|s| s.id == Some(id)).unwrap();
    let paragraphs = &shape.text.as_ref().unwrap().paragraphs;
    paragraphs
        .iter()
        .map(|p| p.runs.iter().map(|r| r.text.clone()).collect())
        .collect()
}

/// Bring one shape to the ground truth with the narrowest verbs: one
/// `replace_run_text` per changed run where the runs align, else one
/// `set_text` per changed line. Returns the refusal for text it may not write.
fn translate(deck: &mut Package, part: &str, id: u32, truth: &Package) -> Option<EditRefusal> {
    let (old, new) = (runs(deck, part, id), runs(truth, part, id));
    let aligned = old.len() == new.len() && old.iter().zip(&new).all(|(o, n)| o.len() == n.len());
    if aligned {
        for (paragraph, (o, n)) in old.iter().zip(&new).enumerate() {
            for (run, (expected, text)) in o.iter().zip(n).enumerate().filter(|(_, (o, n))| o != n)
            {
                let target = target(deck, part, id);
                let op = ValueEdit::ReplaceRunText {
                    target,
                    paragraph,
                    run,
                    expected,
                    text,
                };
                assert_eq!(changed(&edit(deck, &op).unwrap()), [part]);
            }
        }
        return None;
    }
    let (old, new) = (
        body_text(deck, part, id).unwrap(),
        body_text(truth, part, id).unwrap(),
    );
    let ((mut current, separators), (want, more)) = (lines(&old), lines(&new));
    assert!(
        more.starts_with(&separators),
        "{part} #{id}: line structure differs"
    );
    for (k, line) in want.iter().enumerate().take(current.len()) {
        if current[k] != *line {
            current[k] = line;
            let text = joined(&current, &separators);
            let op = ValueEdit::SetText {
                target: target(deck, part, id),
                text: &text,
            };
            let report = edit(deck, &op).unwrap();
            assert_eq!(changed(&report), [part]);
            assert!(report.fit.is_err(), "changed text is never fit-proven");
        }
    }
    (more.len() > separators.len()).then(|| {
        let op = ValueEdit::SetText {
            target: target(deck, part, id),
            text: &new,
        };
        edit(deck, &op).unwrap_err()
    })
}

/// The `p:cNvPr` ids of shapes with a text body, per slide part.
fn text_shapes(package: &Package) -> Vec<(String, u32)> {
    let view = DeckView::read(package).unwrap();
    let mut shapes = Vec::new();
    for slide in &view.slides {
        for shape in slide.shapes.iter().filter(|s| s.text.is_some()) {
            shapes.extend(shape.id.map(|id| (slide.part.clone(), id)));
        }
    }
    shapes
}

/// Parts whose bytes differ between two packages with the same names.
fn diff(before: &Package, after: &Package) -> Vec<String> {
    assert!(before.names().eq(after.names()), "the part list changed");
    let differs = |name: &&str| before.part(name).unwrap() != after.part(name).unwrap();
    before.names().filter(differs).map(str::to_owned).collect()
}

#[test]
#[ignore = "requires locally acquired pinned PPTArena-001 pair"]
fn pptarena_001_translates_text_and_keeps_the_french() {
    let (input, truth) = pptarena("pptarena-001");
    let mut deck = input.clone();
    let mut edited = Vec::new();
    let mut refused = Vec::new();
    for (part, id) in text_shapes(&input) {
        if body_text(&input, &part, id) == body_text(&truth, &part, id) {
            continue;
        }
        if let Some(refusal) = translate(&mut deck, &part, id, &truth) {
            refused.push((part.clone(), id, refusal));
        }
        if !edited.contains(&part) {
            edited.push(part);
        }
    }
    // The ground truth ends slide 6's list with one more `a:br`; new line
    // breaks are refused by the text mapping, so that one stays unwritten.
    let slide6 = "ppt/slides/slide6.xml".to_owned();
    let refusal = EditRefusal::TextMapping("new text holds a line break");
    assert_eq!(refused, [(slide6.clone(), 2, refusal)]);
    for (part, id) in text_shapes(&input) {
        let mut got = body_text(&deck, &part, id).unwrap();
        if (part.as_str(), id) == (slide6.as_str(), 2) {
            got.push(text::BREAK);
        }
        assert_eq!(Some(got), body_text(&truth, &part, id), "{part} #{id}");
    }
    let mut changed = diff(&input, &deck);
    changed.sort_unstable();
    edited.sort_unstable();
    assert_eq!(changed, edited, "only the translated slides change");
    // Every French run on an edited slide keeps its bytes.
    let mut french = 0;
    for part in &edited {
        let (old, tree) = xml::read(&input, part).unwrap();
        let (new, _) = xml::read(&deck, part).unwrap();
        for (at, node) in tree
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.is(xml::A, "r"))
        {
            let lang =
                xml::child(&tree, at, xml::A, "rPr").and_then(|p| tree.nodes[p].attr("lang"));
            if lang.is_some_and(|lang| lang.starts_with("fr")) {
                let run = &old[node.span.clone()];
                assert!(
                    new.windows(run.len()).any(|w| w == run),
                    "{part}: French run changed"
                );
                french += 1;
            }
        }
    }
    assert!(french > 0, "the edited slides hold French runs");
}

/// The notes text of a slide, `None` when it has no notes slide.
fn notes_of(package: &Package, slide: &str) -> Option<String> {
    let part = media::related(package, slide, "notesSlide").unwrap()?;
    let (_, tree) = xml::read(package, &part).unwrap();
    let (_, body) = media::notes_body(&tree).unwrap();
    Some(media::notes_text(&tree, body))
}

#[test]
#[ignore = "requires locally acquired pinned PPTArena-036 pair"]
fn pptarena_036_writes_the_ground_truth_speaker_notes() {
    let (input, truth) = pptarena("pptarena-036");
    let (before, after) = (
        DeckView::read(&input).unwrap(),
        DeckView::read(&truth).unwrap(),
    );
    let mut deck = input.clone();
    let (mut notes, mut unmatched) = (Vec::new(), Vec::new());
    for slide in &before.slides {
        // Slides match by `p:sldId`: the ground truth renumbers the parts.
        let Some(other) = after.slides.iter().find(|s| s.sld_id == slide.sld_id) else {
            unmatched.push(slide.sld_id);
            continue;
        };
        let (old, new) = (notes_of(&input, &slide.part), notes_of(&truth, &other.part));
        let new = new.unwrap_or_default();
        if old.as_deref().unwrap_or_default() == new {
            continue;
        }
        let op = ValueEdit::SetNotes {
            slide: &slide.part,
            expected: old.as_deref(),
            text: &new,
        };
        let report = edit(&mut deck, &op).unwrap();
        let part = media::related(&deck, &slide.part, "notesSlide")
            .unwrap()
            .unwrap();
        assert_eq!(
            changed(&report),
            [part.as_str()],
            "existing notes change alone"
        );
        assert_eq!(notes_of(&deck, &slide.part), Some(new));
        notes.push(part);
    }
    assert_eq!(
        notes.len(),
        8,
        "the ground truth adds notes to eight slides"
    );
    // The ground truth also deletes the slide that held the notes as text
    // boxes; slide deletion is not a value or structure verb.
    assert_eq!(unmatched, [265]);
    let mut changed = diff(&input, &deck);
    changed.sort_unstable();
    notes.sort_unstable();
    assert_eq!(changed, notes, "only the notes parts change");
}

const NOTES_MASTER: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:notesMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:bg><p:bgRef idx="1001"><a:schemeClr val="bg1"/></p:bgRef></p:bg><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr><p:sp><p:nvSpPr><p:cNvPr id="2" name="Slide Image Placeholder 1"/><p:cNvSpPr><a:spLocks noGrp="1" noRot="1" noChangeAspect="1"/></p:cNvSpPr><p:nvPr><p:ph type="sldImg" idx="2"/></p:nvPr></p:nvSpPr><p:spPr><a:xfrm><a:off x="1143000" y="685800"/><a:ext cx="4572000" cy="3429000"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom><a:noFill/><a:ln w="12700"><a:solidFill><a:prstClr val="black"/></a:solidFill></a:ln></p:spPr></p:sp><p:sp><p:nvSpPr><p:cNvPr id="3" name="Notes Placeholder 2"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr><p:nvPr><p:ph type="body" sz="quarter" idx="3"/></p:nvPr></p:nvSpPr><p:spPr><a:xfrm><a:off x="685800" y="4400550"/><a:ext cx="5486400" cy="3600450"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr><p:txBody><a:bodyPr vert="horz" lIns="91440" tIns="45720" rIns="91440" bIns="45720" rtlCol="0"/><a:lstStyle/><a:p><a:pPr lvl="0"/><a:r><a:rPr lang="en-GB"/><a:t>Notes</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld><p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/><p:notesStyle><a:lvl1pPr marL="0" algn="l" defTabSz="914400" rtl="0" eaLnBrk="1" latinLnBrk="0" hangingPunct="1"><a:defRPr sz="1200" kern="1200"><a:solidFill><a:schemeClr val="tx1"/></a:solidFill><a:latin typeface="+mn-lt"/><a:ea typeface="+mn-ea"/><a:cs typeface="+mn-cs"/></a:defRPr></a:lvl1pPr></p:notesStyle></p:notesMaster>"#;

/// Give a deck without notes a notes master on its own copy of the theme,
/// as PowerPoint writes one.
fn with_notes_master(deck: &mut Package) {
    let (master, theme) = ("ppt/notesMasters/notesMaster1.xml", "ppt/theme/theme2.xml");
    let presentation = "ppt/presentation.xml";
    let kind = |name: &str| format!("{}/{name}", xml::R);
    let types = "application/vnd.openxmlformats-officedocument";
    let copy = deck.part("ppt/theme/theme1.xml").unwrap().unwrap();
    deck.add_part(theme, &format!("{types}.theme+xml"), copy)
        .unwrap();
    let master_type = format!("{types}.presentationml.notesMaster+xml");
    deck.add_part(master, &master_type, NOTES_MASTER.into())
        .unwrap();
    deck.relate(master, &kind("theme"), theme).unwrap();
    let id = deck
        .relate(presentation, &kind("notesMaster"), master)
        .unwrap();
    let list = format!(
        r#"</p:sldMasterIdLst><p:notesMasterIdLst><p:notesMasterId r:id="{id}"/></p:notesMasterIdLst>"#
    );
    let source = part(deck, presentation).replacen("</p:sldMasterIdLst>", &list, 1);
    deck.replace_xml_part(presentation, source.into_bytes())
        .unwrap();
}

/// The emitted oracle deck with a notes master, then each verb once.
#[test]
#[ignore = "writes the Office-oracle candidate to $ONEIRON_EDIT_CANDIDATE"]
fn office_oracle_candidate() {
    let base = crate::emit::tests::oracle_deck().bytes;
    let mut deck = Package::open(&base, limits()).unwrap();
    with_notes_master(&mut deck);
    let slide = |n: u32| format!("ppt/slides/slide{n}.xml");
    let (one, two, four, eight, nine) = (slide(1), slide(2), slide(4), slide(8), slide(9));
    let op = ValueEdit::SetText {
        target: target(&deck, &one, 2),
        text: "Revenue more than doubled",
    };
    edit(&mut deck, &op).unwrap();
    let op = ValueEdit::ReplaceRunText {
        target: target(&deck, &two, 3),
        paragraph: 0,
        run: 0,
        expected: "Margins held.",
        text: "Margins rose.",
    };
    edit(&mut deck, &op).unwrap();
    let xfrm = Xfrm {
        rotation: Some(600_000),
        ..Xfrm::default()
    };
    let op = ValueEdit::SetXfrm {
        target: target(&deck, &four, 4),
        xfrm,
    };
    edit(&mut deck, &op).unwrap();
    let op = ValueEdit::MoveInSlideSpace {
        target: target(&deck, &nine, 4),
        by: (457_200, 228_600),
    };
    edit(&mut deck, &op).unwrap();
    let bytes = png(64, 48, [0xC0, 0x50, 0x4D]);
    let record = photo(&bytes, MediaType::Png);
    let op = ValueEdit::SetPicture {
        target: target(&deck, &eight, 3),
        picture: Picture {
            record: &record,
            bytes: &bytes,
            requested: AssetKind::Factual,
            limits: GraphicLimits::default(),
        },
    };
    edit(&mut deck, &op).unwrap();
    let said = "Say the number slowly.";
    for (expected, text) in [
        (None, said),
        (Some(said), "Say the number slowly.\nThen pause."),
    ] {
        let op = ValueEdit::SetNotes {
            slide: &one,
            expected,
            text,
        };
        edit(&mut deck, &op).unwrap();
    }
    let path = std::env::var("ONEIRON_EDIT_CANDIDATE").unwrap();
    std::fs::write(format!("{path}.base"), &base).unwrap();
    std::fs::write(&path, deck.export().unwrap()).unwrap();
}

#[test]
fn an_empty_text_element_opens_with_its_own_bindings() {
    let mut package = deck();
    let bound = r#"<q:t xmlns:q="http://schemas.openxmlformats.org/drawingml/2006/main"/>"#;
    let slide = part(&package, SLIDE).replacen("<a:t>Two</a:t>", bound, 1);
    package.replace_xml_part(SLIDE, slide.into_bytes()).unwrap();
    let op = ValueEdit::ReplaceRunText {
        target: target(&package, SLIDE, 8),
        paragraph: 1,
        run: 0,
        expected: "",
        text: "Hello",
    };
    edit(&mut package, &op).unwrap();
    assert!(shape_xml(&package, SLIDE, 8).contains(
        r#"<q:t xmlns:q="http://schemas.openxmlformats.org/drawingml/2006/main">Hello</q:t>"#
    ));
}

#[test]
fn set_xfrm_owns_a_transform_where_there_was_none() {
    let mut package = deck();
    let frame = xfrm(5_000_000, 4_500_000, 3_000_000, 1_000_000);
    let slide = part(&package, SLIDE);
    assert_eq!(slide.matches(&frame).count(), 1);
    package
        .replace_xml_part(SLIDE, slide.replacen(&frame, "", 1).into_bytes())
        .unwrap();
    let op = ValueEdit::SetXfrm {
        target: target(&package, SLIDE, 9),
        xfrm: Xfrm {
            offset: Some((5_000_000, 4_500_000)),
            extent: Some((3_000_000, 1_000_000)),
            ..Xfrm::default()
        },
    };
    let report = edit(&mut package, &op).unwrap();
    assert_eq!(report.changed_parts, [SLIDE]);
    let geometry = view_shape(&package, 0, 9).geometry;
    assert_eq!(geometry.offset.value, Some((5_000_000, 4_500_000)));
    assert_eq!(geometry.rotation.value, Some(0));
}
