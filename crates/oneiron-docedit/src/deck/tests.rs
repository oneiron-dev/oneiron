//! ONE-2527 acceptance: the four resolvers in all four states; masters,
//! inheritance, `p:clrMapOvr`, groups and ambiguous ids; fingerprint
//! invalidation. The synthetic deck follows ECMA-376 part 1 (sections 19 and
//! 20); expected values come from the schema and from PowerPoint's palette,
//! not from this code.
use super::*;
use crate::retained_opc::{Limits, XmlLimits};
use std::io::Write;

const NS: &str = r#"xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:p14="http://schemas.microsoft.com/office/powerpoint/2010/main" xmlns:a16="http://schemas.microsoft.com/office/drawing/2014/main""#;
const GROUP_ROOT: &str =
    r#"<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>"#;
const MASTER: &str = "ppt/slideMasters/slideMaster1.xml";
const LAYOUT: &str = "ppt/slideLayouts/slideLayout1.xml";
const SLIDE1: &str = "ppt/slides/slide1.xml";
const SLIDE2: &str = "ppt/slides/slide2.xml";
const THEME: &str = "ppt/theme/theme1.xml";
const NOTES: &str = "ppt/notesSlides/notesSlide1.xml";
const IMAGE: &str = "ppt/media/image1.png";

fn limits() -> Limits {
    Limits {
        archive_bytes: 32 << 20,
        entries: 10_000,
        part_bytes: 16 << 20,
        expanded_bytes: 64 << 20,
        xml: XmlLimits {
            max_depth: 256,
            max_nodes: 1_000_000,
        },
    }
}

fn rels(entries: &[(&str, &str, &str)]) -> String {
    let mut out = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#,
    );
    for (id, kind, target) in entries {
        out.push_str(&format!(
            r#"<Relationship Id="{id}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/{kind}" Target="{target}"/>"#
        ));
    }
    out + "</Relationships>"
}

fn placeholder(id: u32, name: &str, ph: &str, sp_pr: &str, body: &str) -> String {
    format!(
        r#"<p:sp><p:nvSpPr><p:cNvPr id="{id}" name="{name}"/><p:cNvSpPr/><p:nvPr>{ph}</p:nvPr></p:nvSpPr><p:spPr>{sp_pr}</p:spPr>{body}</p:sp>"#
    )
}

fn xfrm(x: i64, y: i64, cx: i64, cy: i64) -> String {
    format!(r#"<a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>"#)
}

fn group(id: u32, name: &str, xfrm_attrs: &str, child: &str, inner: &str) -> String {
    format!(
        r#"<p:grpSp><p:nvGrpSpPr><p:cNvPr id="{id}" name="{name}"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm{xfrm_attrs}>{child}</a:xfrm></p:grpSpPr>{inner}</p:grpSp>"#
    )
}

fn master() -> String {
    let title = placeholder(
        2,
        "Title Placeholder 1",
        r#"<p:ph type="title"/>"#,
        &xfrm(100, 200, 3000, 400),
        "<p:txBody><a:bodyPr/><a:lstStyle/><a:p/></p:txBody>",
    );
    let body = placeholder(
        3,
        "Text Placeholder 2",
        r#"<p:ph type="body" idx="1"/>"#,
        &xfrm(100, 700, 3000, 2000),
        r#"<p:txBody><a:bodyPr lIns="12345"><a:normAutofit fontScale="92500" lnSpcReduction="10000"/></a:bodyPr><a:lstStyle/><a:p/></p:txBody>"#,
    );
    format!(
        r#"<p:sldMaster {NS}><p:cSld><p:spTree>{GROUP_ROOT}{title}{body}</p:spTree></p:cSld><p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/><p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst><p:txStyles><p:titleStyle><a:lvl1pPr algn="ctr"><a:defRPr sz="4400"><a:solidFill><a:schemeClr val="tx1"/></a:solidFill><a:latin typeface="+mj-lt"/></a:defRPr></a:lvl1pPr></p:titleStyle><p:bodyStyle><a:lvl1pPr><a:buChar char="•"/><a:defRPr sz="2800"><a:latin typeface="+mn-lt"/></a:defRPr></a:lvl1pPr><a:lvl2pPr algn="just"><a:buChar char="–"/><a:defRPr sz="2400"/></a:lvl2pPr></p:bodyStyle><p:otherStyle><a:lvl1pPr><a:defRPr/></a:lvl1pPr></p:otherStyle></p:txStyles></p:sldMaster>"#
    )
}

fn layout() -> String {
    let shapes = [
        placeholder(
            2,
            "Title 1",
            r#"<p:ph type="title"/>"#,
            "",
            "<p:txBody><a:bodyPr/><a:lstStyle/><a:p/></p:txBody>",
        ),
        placeholder(
            3,
            "Content 2",
            r#"<p:ph idx="1"/>"#,
            &xfrm(500, 900, 2000, 1500),
            "<p:txBody><a:bodyPr/><a:lstStyle/><a:p/></p:txBody>",
        ),
        placeholder(4, "Left", r#"<p:ph type="body" idx="2"/>"#, "", ""),
        placeholder(5, "Right", r#"<p:ph type="body" idx="2"/>"#, "", ""),
    ]
    .concat();
    format!(
        r#"<p:sldLayout {NS}><p:cSld><p:spTree>{GROUP_ROOT}{shapes}</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>"#
    )
}

fn theme() -> String {
    let slots = [
        ("dk1", r#"<a:sysClr val="windowText" lastClr="000000"/>"#),
        ("lt1", r#"<a:sysClr val="window" lastClr="FFFFFF"/>"#),
        ("dk2", r#"<a:srgbClr val="1F497D"/>"#),
        ("lt2", r#"<a:srgbClr val="EEECE1"/>"#),
        ("accent1", r#"<a:srgbClr val="4F81BD"/>"#),
        ("accent2", r#"<a:srgbClr val="C0504D"/>"#),
        ("accent3", r#"<a:srgbClr val="9BBB59"/>"#),
        ("accent4", r#"<a:srgbClr val="8064A2"/>"#),
        ("accent5", r#"<a:srgbClr val="4BACC6"/>"#),
        ("accent6", r#"<a:srgbClr val="F79646"/>"#),
        ("hlink", r#"<a:srgbClr val="0000FF"/>"#),
        ("folHlink", r#"<a:srgbClr val="800080"/>"#),
    ]
    .map(|(slot, colour)| format!("<a:{slot}>{colour}</a:{slot}>"))
    .concat();
    format!(
        r#"<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Office"><a:themeElements><a:clrScheme name="Office">{slots}</a:clrScheme><a:fontScheme name="Office"><a:majorFont><a:latin typeface="Calibri Light"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont><a:minorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont></a:fontScheme><a:fmtScheme name="Office"/></a:themeElements></a:theme>"#
    )
}

fn slide1() -> String {
    let title = r#"<p:sp><p:nvSpPr><p:cNvPr id="2" name="Title 1"><a:extLst><a:ext uri="{FF2B5EF4-FFF2-40B4-BE49-F238E27FC236}"><a16:creationId id="{5a1f0c2e-0000-4000-8000-000000000002}"/></a:ext></a:extLst></p:cNvPr><p:cNvSpPr/><p:nvPr><p:ph type="title"/></p:nvPr></p:nvSpPr><p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang="en-US" b="1"/><a:t>Quarterly results</a:t></a:r></a:p></p:txBody></p:sp>"#;
    let content = placeholder(
        3,
        "Content 2",
        r#"<p:ph idx="1"/>"#,
        &xfrm(600, 1000, 1800, 1200),
        r#"<p:txBody><a:bodyPr anchor="ctr"/><a:lstStyle/><a:p><a:pPr lvl="1"/><a:r><a:rPr lang="en-US" sz="2000"><a:solidFill><a:schemeClr val="accent1"><a:lumMod val="75000"/></a:schemeClr></a:solidFill></a:rPr><a:t>Revenue</a:t></a:r></a:p></p:txBody>"#,
    );
    let ambiguous = placeholder(
        4,
        "Ambiguous 3",
        r#"<p:ph type="body" idx="2"/>"#,
        "",
        r#"<p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang="en-US"/><a:t>Which side?</a:t></a:r></a:p></p:txBody>"#,
    );
    let text_box = r#"<p:sp><p:nvSpPr><p:cNvPr id="5" name="TextBox 4"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr><p:spPr/><p:txBody><a:bodyPr wrap="none"/><a:lstStyle/><a:p><a:r><a:rPr lang="ja-JP"><a:solidFill><a:schemeClr val="tx1"/></a:solidFill><a:latin typeface="+mj-ea"/></a:rPr><a:t>注記</a:t></a:r></a:p></p:txBody></p:sp>"#;
    let flat = group(
        8,
        "Flat group",
        "",
        r#"<a:off x="0" y="0"/><a:ext cx="100" cy="100"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="100"/>"#,
        &placeholder(11, "Lost", "", &xfrm(1, 1, 1, 1), ""),
    );
    let scaled = group(
        6,
        "Group 5",
        "",
        r#"<a:off x="1000" y="1000"/><a:ext cx="2000" cy="2000"/><a:chOff x="0" y="0"/><a:chExt cx="1000" cy="1000"/>"#,
        &[
            placeholder(7, "Inner 6", "", &xfrm(100, 100, 100, 100), ""),
            placeholder(3, "Duplicate id", "", "", ""),
            flat,
        ]
        .concat(),
    );
    let turned = group(
        12,
        "Turned",
        r#" rot="5400000""#,
        r#"<a:off x="0" y="0"/><a:ext cx="100" cy="100"/><a:chOff x="0" y="0"/><a:chExt cx="100" cy="100"/>"#,
        &placeholder(13, "Corner", "", &xfrm(0, 0, 10, 10), ""),
    );
    let connector = r#"<p:cxnSp><p:nvCxnSpPr><p:cNvPr id="9" name="Connector 8"/><p:cNvCxnSpPr><a:stCxn id="2" idx="2"/><a:endCxn id="3" idx="0"/></p:cNvCxnSpPr><p:nvPr/></p:nvCxnSpPr><p:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="10" cy="10"/></a:xfrm></p:spPr></p:cxnSp>"#;
    let morph = placeholder(10, "!!Hero", "", "", "");
    let timing = r#"<p:timing><p:tnLst><p:par><p:cTn id="1" dur="indefinite" restart="never" nodeType="tmRoot"><p:childTnLst><p:seq concurrent="1" nextAc="seek"><p:cTn id="2" dur="indefinite" nodeType="mainSeq"><p:childTnLst><p:par><p:cTn id="3" fill="hold"><p:stCondLst><p:cond delay="indefinite"><p:tgtEl><p:spTgt spid="2"/></p:tgtEl></p:cond></p:stCondLst><p:childTnLst><p:par><p:cTn id="4" presetID="10" presetClass="entr" grpId="0" nodeType="clickEffect"><p:childTnLst><p:animEffect transition="in" filter="fade"><p:cBhvr><p:cTn id="5" dur="500"/><p:tgtEl><p:spTgt spid="3"><p:txEl><p:pRg st="0" end="0"/></p:txEl></p:spTgt></p:tgtEl></p:cBhvr></p:animEffect></p:childTnLst></p:cTn></p:par></p:childTnLst></p:cTn></p:par></p:childTnLst></p:cTn></p:seq></p:childTnLst></p:cTn></p:par></p:tnLst><p:bldLst><p:bldP spid="3" grpId="0" build="p"/></p:bldLst></p:timing>"#;
    format!(
        r#"<p:sld {NS}><p:cSld><p:spTree>{GROUP_ROOT}{title}{content}{ambiguous}{text_box}{scaled}{turned}{connector}{morph}</p:spTree><p:extLst><p:ext uri="{SLIDE_CREATION_EXT}"><p14:creationId val="1001"/></p:ext></p:extLst></p:cSld><p:clrMapOvr><a:overrideClrMapping bg1="dk1" tx1="lt1" bg2="dk2" tx2="lt2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/></p:clrMapOvr>{timing}</p:sld>"#
    )
}

fn slide2() -> String {
    let title = placeholder(
        2,
        "Title 1",
        r#"<p:ph type="title"/>"#,
        "",
        r#"<p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang="en-US"/><a:t>Outlook</a:t></a:r></a:p></p:txBody>"#,
    );
    let note = placeholder(
        3,
        "Note",
        "",
        "",
        r#"<p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang="en-US"><a:solidFill><a:schemeClr val="accent2"><a:satMod val="120000"/></a:schemeClr></a:solidFill></a:rPr><a:t>Saturated</a:t></a:r></a:p></p:txBody>"#,
    );
    format!(
        r#"<p:sld {NS}><p:cSld><p:spTree>{GROUP_ROOT}{title}{note}</p:spTree><p:extLst><p:ext uri="{SLIDE_CREATION_EXT}"><p14:creationId val="1001"/></p:ext></p:extLst></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>"#
    )
}

fn parts() -> Vec<(&'static str, String)> {
    vec![
        (
            "[Content_Types].xml",
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/></Types>"#.to_owned(),
        ),
        ("_rels/.rels", rels(&[("rId1", "officeDocument", "ppt/presentation.xml")])),
        (
            "ppt/presentation.xml",
            format!(
                r#"<p:presentation {NS}><p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst><p:sldIdLst><p:sldId id="256" r:id="rId2"/><p:sldId id="257" r:id="rId3"/></p:sldIdLst><p:defaultTextStyle><a:lvl1pPr marL="0"><a:defRPr lang="en-US"/></a:lvl1pPr></p:defaultTextStyle></p:presentation>"#
            ),
        ),
        (
            "ppt/_rels/presentation.xml.rels",
            rels(&[
                ("rId1", "slideMaster", "slideMasters/slideMaster1.xml"),
                ("rId2", "slide", "slides/slide1.xml"),
                ("rId3", "slide", "slides/slide2.xml"),
                ("rId4", "theme", "theme/theme1.xml"),
            ]),
        ),
        (MASTER, master()),
        (
            "ppt/slideMasters/_rels/slideMaster1.xml.rels",
            rels(&[
                ("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml"),
                ("rId2", "theme", "../theme/theme1.xml"),
            ]),
        ),
        (LAYOUT, layout()),
        (
            "ppt/slideLayouts/_rels/slideLayout1.xml.rels",
            rels(&[("rId1", "slideMaster", "../slideMasters/slideMaster1.xml")]),
        ),
        (THEME, theme()),
        (SLIDE1, slide1()),
        (
            "ppt/slides/_rels/slide1.xml.rels",
            rels(&[
                ("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml"),
                ("rId2", "notesSlide", "../notesSlides/notesSlide1.xml"),
                ("rId3", "image", "../media/image1.png"),
            ]),
        ),
        (SLIDE2, slide2()),
        (
            "ppt/slides/_rels/slide2.xml.rels",
            rels(&[("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml")]),
        ),
        (
            NOTES,
            format!(r#"<p:notes {NS}><p:cSld><p:spTree>{GROUP_ROOT}</p:spTree></p:cSld></p:notes>"#),
        ),
        (IMAGE, "image-bytes-1".to_owned()),
    ]
}

fn archive(parts: &[(&str, String)]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, body) in parts {
        writer.start_file(*name, options).unwrap();
        writer.write_all(body.as_bytes()).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn read(parts: &[(&str, String)]) -> DeckView {
    DeckView::read(&Package::open(&archive(parts), limits()).unwrap()).unwrap()
}

/// The fixture with one part's text replaced.
fn with(name: &str, from: &str, to: &str) -> Vec<(&'static str, String)> {
    let mut parts = parts();
    let part = parts.iter_mut().find(|(part, _)| *part == name).unwrap();
    assert!(part.1.contains(from), "{name} lacks {from}");
    part.1 = part.1.replace(from, to);
    parts
}

fn shape<'a>(slide: &'a SlideView, name: &str) -> &'a ShapeView {
    slide
        .shapes
        .iter()
        .find(|shape| shape.name.as_deref() == Some(name))
        .unwrap()
}

fn text(shape: &ShapeView) -> &TextView {
    shape.text.as_ref().unwrap()
}

fn from_part<T>(value: &Value<T>) -> &str {
    value.source.as_ref().unwrap().node.part.as_str()
}

#[test]
fn four_resolvers_report_all_four_states_with_exact_sources() {
    let deck = read(&parts());
    let slide = &deck.slides[0];
    let (title, content) = (shape(slide, "Title 1"), shape(slide, "Content 2"));
    let (ambiguous, text_box) = (shape(slide, "Ambiguous 3"), shape(slide, "TextBox 4"));

    // Geometry: own a:xfrm, the master's through a layout placeholder without
    // one, the schema's rot="0", no transform at all, an ambiguous match.
    let own = &content.geometry.offset;
    assert_eq!(
        (own.value, own.state, own.inherited),
        (Some((600, 1000)), State::Explicit, false)
    );
    assert_eq!(own.source.as_ref().unwrap().element, "a:off");
    let master = &title.geometry.offset;
    assert_eq!(
        (master.value, master.state, master.inherited),
        (Some((100, 200)), State::Explicit, true)
    );
    assert_eq!(from_part(master), MASTER);
    assert_eq!(content.geometry.rotation.value, Some(0));
    assert_eq!(content.geometry.rotation.state, State::SchemaDefault);
    assert_eq!(text_box.geometry.offset.state, State::Absent);
    assert_eq!(
        ambiguous.geometry.offset.state,
        State::Unresolved(Refusal::AmbiguousPlaceholder)
    );

    // Text body: attributes resolve one by one, autofit separately.
    let body = &text(content).body;
    assert_eq!(
        (body.anchor.value.as_deref(), body.anchor.inherited),
        (Some("ctr"), false)
    );
    assert_eq!(
        (body.insets[0].value, body.insets[0].inherited),
        (Some(12_345), true)
    );
    assert_eq!(
        body.insets[0].source.as_ref().unwrap().attribute.as_deref(),
        Some("lIns")
    );
    assert_eq!(from_part(&body.insets[0]), MASTER);
    assert_eq!(
        (body.insets[1].value, body.insets[1].state),
        (Some(45_720), State::SchemaDefault)
    );
    assert_eq!(
        body.autofit.value,
        Some(Autofit::Normal {
            font_scale: Some(92_500),
            line_reduction: Some(10_000)
        })
    );
    assert_eq!(text(text_box).body.autofit.state, State::Absent);
    assert_eq!(
        text(ambiguous).body.autofit.state,
        State::Unresolved(Refusal::AmbiguousPlaceholder)
    );

    // Paragraph: own lvl, the master body style at that level, title style,
    // schema defaults, and a chain cut by the ambiguous placeholder.
    let paragraph = &text(content).paragraphs[0];
    assert_eq!(
        (paragraph.level.value, paragraph.level.state),
        (Some(1), State::Explicit)
    );
    assert_eq!(
        (paragraph.align.value.as_deref(), paragraph.align.inherited),
        (Some("just"), true)
    );
    assert_eq!(from_part(&paragraph.align), MASTER);
    assert_eq!(paragraph.bullet.value, Some(Bullet::Char("–".into())));
    assert_eq!(
        text(title).paragraphs[0].align.value.as_deref(),
        Some("ctr")
    );
    let plain = &text(text_box).paragraphs[0];
    assert_eq!(
        (plain.level.value, plain.level.state),
        (Some(0), State::SchemaDefault)
    );
    assert_eq!(
        (plain.align.value.as_deref(), plain.align.state),
        (Some("l"), State::SchemaDefault)
    );
    assert_eq!(plain.bullet.state, State::Absent);
    assert_eq!(
        text(ambiguous).paragraphs[0].align.state,
        State::Unresolved(Refusal::AmbiguousPlaceholder)
    );

    // Run: own b="1", the title style's size and theme major font, the
    // schema's b="0", no size anywhere, a theme reference that resolves to an
    // empty typeface.
    let run = &text(title).paragraphs[0].runs[0];
    assert_eq!(
        (run.bold.value, run.bold.state, run.bold.inherited),
        (Some(true), State::Explicit, false)
    );
    assert_eq!((run.size.value, run.size.inherited), (Some(4_400), true));
    let latin = run.latin.value.as_ref().unwrap();
    assert_eq!(
        (latin.typeface.as_str(), latin.resolved.as_str()),
        ("+mj-lt", "Calibri Light")
    );
    let run = &text(content).paragraphs[0].runs[0];
    assert_eq!((run.size.value, run.size.inherited), (Some(2_000), false));
    assert_eq!(
        (run.bold.value, run.bold.state),
        (Some(false), State::SchemaDefault)
    );
    let run = &text(text_box).paragraphs[0].runs[0];
    assert_eq!(run.size.state, State::Absent);
    assert_eq!(
        run.latin.state,
        State::Unresolved(Refusal::UnresolvedEffectiveStyle)
    );
    assert_eq!(
        run.latin.source.as_ref().unwrap().attribute.as_deref(),
        Some("typeface")
    );
    assert_eq!(
        text(ambiguous).paragraphs[0].runs[0].size.state,
        State::Unresolved(Refusal::AmbiguousPlaceholder)
    );
}

#[test]
fn colours_stay_symbolic_and_compute_through_the_slide_colour_map() {
    let deck = read(&parts());
    let first = &text(shape(&deck.slides[0], "Title 1")).paragraphs[0].runs[0].colour;
    let second = &text(shape(&deck.slides[1], "Title 1")).paragraphs[0].runs[0].colour;
    let tx1 = ColourSpec::Scheme {
        slot: "tx1".into(),
        transforms: Vec::new(),
    };
    // One master style, two colour maps: p:clrMapOvr sends tx1 to lt1 on the
    // first slide; the second keeps the master's tx1 -> dk1.
    for colour in [first, second] {
        assert_eq!(colour.value.as_ref().unwrap().spec, tx1);
        assert_eq!(from_part(colour), MASTER);
    }
    let rgb = |value: &Value<Colour>| value.value.as_ref().unwrap().computed.map(|c| c.rgb);
    assert_eq!(rgb(first), Ok([0xFF, 0xFF, 0xFF]));
    assert_eq!(rgb(second), Ok([0x00, 0x00, 0x00]));

    // PowerPoint's "Accent 1, Darker 25%" of the Office 2007 theme is #376092.
    let darker = &text(shape(&deck.slides[0], "Content 2")).paragraphs[0].runs[0].colour;
    assert_eq!(rgb(darker), Ok([0x37, 0x60, 0x92]));
    assert_eq!(
        darker.value.as_ref().unwrap().spec,
        ColourSpec::Scheme {
            slot: "accent1".into(),
            transforms: vec![ColourTransform {
                name: "lumMod".into(),
                value: Some(75_000)
            }],
        }
    );

    // An uncomputed transform keeps the symbolic colour and refuses the value.
    let saturated = &text(shape(&deck.slides[1], "Note")).paragraphs[0].runs[0].colour;
    assert_eq!(rgb(saturated), Err(Refusal::UnsupportedColourTransform));
    assert!(matches!(
        &saturated.value.as_ref().unwrap().spec,
        ColourSpec::Scheme { slot, transforms } if slot == "accent2" && transforms[0].name == "satMod"
    ));
}

#[test]
fn groups_compose_parent_transforms_and_refuse_degenerate_ones() {
    let deck = read(&parts());
    let slide = &deck.slides[0];
    // ECMA-376 20.1.7.6: child space (chOff, chExt) maps onto (off, ext).
    let inner = shape(slide, "Inner 6");
    let transform = inner.geometry.parent_transform.value.unwrap();
    assert_eq!(transform.apply(100.0, 100.0), (1_200.0, 1_200.0));
    assert_eq!(
        inner.geometry.offset.value,
        Some((100, 100)),
        "local values stay local"
    );
    let group = slide
        .shapes
        .iter()
        .position(|shape| shape.name.as_deref() == Some("Group 5"))
        .unwrap();
    assert_eq!(inner.group_path, vec![group]);
    // rot is clockwise: a 90° turn takes the group's top-left to its top-right.
    let corner = shape(slide, "Corner")
        .geometry
        .parent_transform
        .value
        .unwrap();
    let (x, y) = corner.apply(0.0, 0.0);
    assert!((x - 100.0).abs() < 1e-9 && y.abs() < 1e-9, "({x}, {y})");
    assert_eq!(
        shape(slide, "Lost").geometry.parent_transform.state,
        State::Unresolved(Refusal::NonInvertibleGroupTransform)
    );
    assert_eq!(
        shape(slide, "Title 1").geometry.parent_transform.value,
        Some(Affine::IDENTITY)
    );
}

#[test]
fn ambiguous_ids_are_reported_and_reading_mutates_nothing() {
    let bytes = archive(&parts());
    let package = Package::open(&bytes, limits()).unwrap();
    let deck = DeckView::read(&package).unwrap();
    assert_eq!(package.export().unwrap(), bytes);
    assert_eq!((deck.slides[0].sld_id, deck.slides[1].sld_id), (256, 257));
    assert_eq!(deck.slides[0].creation_id, Some(1001));
    assert_eq!(
        shape(&deck.slides[0], "Title 1").creation_id.as_deref(),
        Some("{5A1F0C2E-0000-4000-8000-000000000002}")
    );
    assert!(
        deck.ambiguities
            .contains(&Ambiguity::DuplicateSlideCreationId {
                creation_id: 1001,
                slides: vec![0, 1],
            })
    );
    let index = |name| {
        deck.slides[0]
            .shapes
            .iter()
            .position(|shape| shape.name.as_deref() == Some(name))
            .unwrap()
    };
    // Duplicate native ids are found across nested groups.
    assert!(deck.ambiguities.contains(&Ambiguity::DuplicateShapeId {
        slide: 0,
        id: 3,
        shapes: vec![index("Content 2"), index("Duplicate id")],
    }));
}

#[test]
fn animation_index_reports_dependencies_without_cascading() {
    let deck = read(&parts());
    let index = &deck.slides[0].animation;
    let effects: Vec<_> = index
        .targets_of(3)
        .map(|t| (t.role, t.text, t.timing_id))
        .collect();
    assert_eq!(
        effects,
        vec![
            (
                TargetRole::Effect,
                Some(TextRange::Paragraphs { start: 0, end: 0 }),
                Some(4)
            ),
            (TargetRole::Build, None, None),
        ]
    );
    let trigger: Vec<_> = index.targets_of(2).map(|t| (t.role, t.timing_id)).collect();
    assert_eq!(trigger, vec![(TargetRole::Condition, Some(3))]);
    assert_eq!(index.timing_ids, vec![1, 2, 3, 4, 5]);
    assert_eq!(index.morph_names, vec![(Some(10), "!!Hero".to_owned())]);
    let glued: Vec<_> = index.connections_to(2).collect();
    assert_eq!(
        glued,
        vec![&Connection {
            connector: Some(9),
            start: Some(2),
            end: Some(3)
        }]
    );
    assert!(deck.slides[1].animation.targets.is_empty());
}

#[test]
fn render_fingerprints_follow_dependencies_and_content_fingerprints_do_not() {
    let base = read(&parts());
    let fingerprints = |deck: &DeckView, slide: usize| {
        (
            deck.slides[slide].content_fingerprint,
            deck.slides[slide].render_fingerprint,
        )
    };
    let (content0, render0) = fingerprints(&base, 0);
    let (content1, render1) = fingerprints(&base, 1);

    // A theme edit changes what both slides show, not their own XML.
    let themed = read(&with(THEME, "F79646", "F79647"));
    assert_eq!(fingerprints(&themed, 0).0, content0);
    assert_ne!(fingerprints(&themed, 0).1, render0);
    assert_eq!(fingerprints(&themed, 1).0, content1);
    assert_ne!(fingerprints(&themed, 1).1, render1);

    // Notes are not a rendering dependency; media is, for its slide only.
    let noted = read(&with(NOTES, "<p:spTree>", "<p:spTree><!-- note -->"));
    assert_eq!(fingerprints(&noted, 0), (content0, render0));
    let pictured = read(&with(IMAGE, "image-bytes-1", "image-bytes-2"));
    assert_ne!(fingerprints(&pictured, 0).1, render0);
    assert_eq!(fingerprints(&pictured, 1), (content1, render1));

    // An edit to the second slide leaves the first untouched.
    let edited = read(&with(SLIDE2, "Outlook", "Forecast"));
    assert_eq!(fingerprints(&edited, 0), (content0, render0));
    assert_ne!(fingerprints(&edited, 1).0, content1);
    assert_ne!(fingerprints(&edited, 1).1, render1);
    assert_ne!(
        shape(&edited.slides[1], "Title 1").content_fingerprint,
        shape(&base.slides[1], "Title 1").content_fingerprint
    );
    assert_eq!(
        shape(&edited.slides[1], "Note").content_fingerprint,
        shape(&base.slides[1], "Note").content_fingerprint
    );

    assert_eq!(base.slides_depending_on(THEME), vec![0, 1]);
    assert_eq!(base.slides_depending_on(LAYOUT), vec![0, 1]);
    assert_eq!(base.slides_depending_on(IMAGE), vec![0]);
    assert!(base.slides_depending_on(NOTES).is_empty());
}

#[test]
#[ignore = "requires locally acquired pinned PPTArena-001 pair"]
fn pptarena_pair_reads_and_fingerprints_only_the_edited_slide() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pptarena-001");
    let original = std::fs::read(dir.join("original.pptx")).unwrap();
    let edited = std::fs::read(dir.join("ground_truth.pptx")).unwrap();
    let before_package = Package::open(&original, limits()).unwrap();
    let after_package = Package::open(&edited, limits()).unwrap();
    let before = DeckView::read(&before_package).unwrap();
    let after = DeckView::read(&after_package).unwrap();
    assert_eq!(before_package.export().unwrap(), original);
    assert_eq!(before.slides.len(), after.slides.len());
    let mut changed = 0;
    for (old, new) in before.slides.iter().zip(&after.slides) {
        assert_eq!((old.sld_id, old.creation_id), (new.sld_id, new.creation_id));
        if before_package.part(&old.part).unwrap() == after_package.part(&new.part).unwrap() {
            assert_eq!(old.content_fingerprint, new.content_fingerprint);
        } else if old.content_fingerprint != new.content_fingerprint {
            changed += 1;
        }
    }
    assert!(changed > 0, "the ground truth edits at least one slide");
}
