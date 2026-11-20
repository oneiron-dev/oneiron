#![cfg(oneiron_test_support)]
//! UC-07 PR 7, HEX-PR6-SIGN-SITES = B: a `+` hex digit is refused at the 10 decoders reachable
//! from this crate. Four are crate-private and reached through
//! `oneiron::test_doors::hex_sign_digit`; five are pub items of the leaf
//! crates, reached by their crate path; the docedit colour decoder is private
//! and reached through `DeckView::read`, the nearest pub fn above it (run
//! colour `a:srgbClr/@val` -> resolve -> `colour::read` -> `spec` -> `hex`).
//! Each test asserts the NEW behaviour: valid lowercase still decodes to the
//! same bytes (control), a `+` in the first pair is refused, and either-case
//! sites still decode uppercase (stored/wire sites refuse it). Every test
//! fails today (red) and passes after the bodies move onto `oneiron-hex`.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test hex_sign_digit`.

use oneiron::test_doors::hex_sign_digit as doors;

/// `chars` lowercase hex digits of neutral values (`chars` is a multiple of 16).
fn hex_pattern(chars: usize) -> String {
    "0123456789abcdef".repeat(chars / 16)
}

/// `valid` with `+a` in place of its first digit pair.
fn with_sign(valid: &str) -> String {
    format!("+a{}", &valid[2..])
}

#[test]
fn connector_call_digest_refuses_a_sign_and_uppercase() {
    let valid = hex_pattern(64);
    let expected = oneiron_hex::decode::<32>(&valid).unwrap();
    assert_eq!(
        doors::connector_call_digest_from_hex(&valid),
        Some(expected)
    );
    assert_eq!(
        doors::connector_call_digest_from_hex(&with_sign(&valid)),
        None
    );
    assert_eq!(
        doors::connector_call_digest_from_hex(&valid.to_uppercase()),
        None
    );
}

#[test]
fn weave_item_key_refuses_a_sign_and_uppercase() {
    let valid = format!("00{}", hex_pattern(32));
    let expected = oneiron_hex::decode::<17>(&valid).unwrap();
    assert_eq!(doors::weave_item_key_from_hex(&valid), Some(expected));
    // First pair `+0`: `u8::from_str_radix("+0", 16)` is 0, the Entity tag,
    // so the old body accepts it and this assert is red.
    assert_eq!(
        doors::weave_item_key_from_hex(&format!("+0{}", &valid[2..])),
        None
    );
    assert_eq!(doors::weave_item_key_from_hex(&valid.to_uppercase()), None);
}

#[test]
fn cooperative_parse_hex_refuses_a_sign_but_keeps_uppercase() {
    let valid = hex_pattern(32);
    let expected = oneiron_hex::decode_any_case::<16>(&valid).unwrap();
    assert_eq!(oneiron::deletion::parse_hex::<16>(&valid), Some(expected));
    assert_eq!(oneiron::deletion::parse_hex::<16>(&with_sign(&valid)), None);
    assert_eq!(
        oneiron::deletion::parse_hex::<16>(&valid.to_uppercase()),
        Some(expected)
    );
}

#[test]
fn evidence_pin_unhex_refuses_a_sign_but_keeps_uppercase() {
    let valid = hex_pattern(16);
    let expected = oneiron_hex::decode_vec_any_case(&valid).unwrap();
    assert_eq!(doors::evidence_pin_unhex(&valid), Some(expected.clone()));
    assert_eq!(doors::evidence_pin_unhex(&with_sign(&valid)), None);
    assert_eq!(
        doors::evidence_pin_unhex(&valid.to_uppercase()),
        Some(expected)
    );
}

#[cfg(feature = "sync")]
#[test]
fn federation_burst_hex_bytes_refuses_a_sign_and_uppercase() {
    let valid = hex_pattern(16);
    let expected = oneiron_hex::decode_vec(&valid).unwrap();
    assert_eq!(doors::federation_burst_hex_bytes(&valid), Some(expected));
    assert_eq!(doors::federation_burst_hex_bytes(&with_sign(&valid)), None);
    assert_eq!(
        doors::federation_burst_hex_bytes(&valid.to_uppercase()),
        None
    );
}

#[test]
fn brief_decode_hex_refuses_a_sign_but_keeps_uppercase() {
    let valid = hex_pattern(64);
    let expected = oneiron_hex::decode_any_case::<32>(&valid).unwrap();
    assert_eq!(
        oneiron_verb_wire::task_verb::brief::decode_hex::<32>(&valid),
        Some(expected)
    );
    assert_eq!(
        oneiron_verb_wire::task_verb::brief::decode_hex::<32>(&with_sign(&valid)),
        None
    );
    assert_eq!(
        oneiron_verb_wire::task_verb::brief::decode_hex::<32>(&valid.to_uppercase()),
        Some(expected)
    );
}

#[test]
fn revision_ref_from_hex_refuses_a_sign_but_keeps_uppercase() {
    use oneiron_store::vault::entity_revision::types::RevisionRef;
    let valid = hex_pattern(32);
    let expected = RevisionRef::from_hex(&valid).unwrap();
    assert_eq!(expected.to_hex(), valid);
    assert!(RevisionRef::from_hex(&with_sign(&valid)).is_err());
    assert_eq!(
        RevisionRef::from_hex(&valid.to_uppercase()).unwrap(),
        expected
    );
}

#[test]
fn docedit_digest_from_hex_refuses_a_sign_and_keeps_lowercase_only() {
    use oneiron_docedit::edit::transaction::Digest;
    let valid = hex_pattern(64);
    let expected = Digest::from_hex(&valid).unwrap();
    assert_eq!(expected.to_hex(), valid);
    assert_eq!(Digest::from_hex(&with_sign(&valid)), None);
    assert_eq!(Digest::from_hex(&valid.to_uppercase()), None);
}

#[test]
fn consent_hex_to_16_bytes_refuses_a_sign_and_uppercase() {
    use oneiron_consent_state::consent::support::hex_to_16_bytes;
    let valid = hex_pattern(32);
    let expected = oneiron_hex::decode::<16>(&valid).unwrap();
    assert_eq!(hex_to_16_bytes(&valid), Some(expected));
    assert_eq!(hex_to_16_bytes(&with_sign(&valid)), None);
    assert_eq!(hex_to_16_bytes(&valid.to_uppercase()), None);
}

// --- The colour site, through `DeckView::read` ---
//
// The builders below are the docedit deck fixture's (`deck/fixture.rs` and
// `deck/tests.rs`), copied so this crate's test builds its own package: the
// fixture is `pub(crate)` to docedit. Only the slide is this test's own: one
// shape with one run whose `a:srgbClr/@val` is the value under test.

const NS: &str = r#"xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:p14="http://schemas.microsoft.com/office/powerpoint/2010/main" xmlns:a16="http://schemas.microsoft.com/office/drawing/2014/main""#;

const GROUP_ROOT: &str =
    r#"<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>"#;

fn limits() -> oneiron_docedit::retained_opc::Limits {
    oneiron_docedit::retained_opc::Limits {
        archive_bytes: 32 << 20,
        part_bytes: 16 << 20,
        expanded_bytes: 64 << 20,
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

fn archive(parts: &[(&str, String)]) -> Vec<u8> {
    use std::io::Write as _;
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, body) in parts {
        writer.start_file(*name, options).unwrap();
        writer.write_all(body.as_bytes()).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn slide_with_colour(val: &str) -> String {
    let probe = format!(
        r#"<p:sp><p:nvSpPr><p:cNvPr id="2" name="Probe"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr><a:solidFill><a:srgbClr val="{val}"/></a:solidFill></a:rPr><a:t>probe</a:t></a:r></a:p></p:txBody></p:sp>"#
    );
    format!(r#"<p:sld {NS}><p:cSld><p:spTree>{GROUP_ROOT}{probe}</p:spTree></p:cSld></p:sld>"#)
}

fn deck_with_colour_val(val: &str) -> oneiron_docedit::deck::DeckView {
    use oneiron_docedit::resource::Resources;
    use oneiron_docedit::retained_opc::Package;
    let parts = vec![
        (
            "[Content_Types].xml",
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/></Types>"#.to_owned(),
        ),
        ("_rels/.rels", rels(&[("rId1", "officeDocument", "ppt/presentation.xml")])),
        (
            "ppt/presentation.xml",
            format!(
                r#"<p:presentation {NS}><p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst><p:sldIdLst><p:sldId id="256" r:id="rId2"/></p:sldIdLst><p:defaultTextStyle><a:lvl1pPr marL="0"><a:defRPr lang="en-US"/></a:lvl1pPr></p:defaultTextStyle></p:presentation>"#
            ),
        ),
        (
            "ppt/_rels/presentation.xml.rels",
            rels(&[
                ("rId1", "slideMaster", "slideMasters/slideMaster1.xml"),
                ("rId2", "slide", "slides/slide1.xml"),
                ("rId3", "theme", "theme/theme1.xml"),
            ]),
        ),
        ("ppt/slideMasters/slideMaster1.xml", master()),
        (
            "ppt/slideMasters/_rels/slideMaster1.xml.rels",
            rels(&[
                ("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml"),
                ("rId2", "theme", "../theme/theme1.xml"),
            ]),
        ),
        ("ppt/slideLayouts/slideLayout1.xml", layout()),
        (
            "ppt/slideLayouts/_rels/slideLayout1.xml.rels",
            rels(&[("rId1", "slideMaster", "../slideMasters/slideMaster1.xml")]),
        ),
        ("ppt/theme/theme1.xml", theme()),
        ("ppt/slides/slide1.xml", slide_with_colour(val)),
        (
            "ppt/slides/_rels/slide1.xml.rels",
            rels(&[("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml")]),
        ),
    ];
    let bytes = archive(&parts);
    let package = Package::open(&bytes, limits(), &Resources::measuring()).unwrap();
    oneiron_docedit::deck::DeckView::read(&package).unwrap()
}

#[test]
fn deck_colour_hex_refuses_a_sign_but_keeps_uppercase() {
    use oneiron_docedit::deck::ColourSpec;
    let spec_of = |val: &str| {
        let deck = deck_with_colour_val(val);
        let shape = deck.slides[0]
            .shapes
            .iter()
            .find(|shape| shape.name.as_deref() == Some("Probe"))
            .unwrap();
        shape.text.as_ref().unwrap().paragraphs[0].runs[0]
            .colour
            .value
            .clone()
            .map(|colour| colour.spec)
    };
    assert_eq!(
        spec_of("012345"),
        Some(ColourSpec::Srgb {
            rgb: [0x01, 0x23, 0x45],
            transforms: Vec::new()
        }),
    );
    assert_eq!(spec_of("+a2345"), None);
    assert_eq!(
        spec_of("ABCDEF"),
        Some(ColourSpec::Srgb {
            rgb: [0xab, 0xcd, 0xef],
            transforms: Vec::new()
        }),
    );
}
