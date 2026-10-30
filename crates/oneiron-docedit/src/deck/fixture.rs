//! A synthetic ECMA-376 deck builder shared by the deck, design-plan and
//! emission tests: the package plumbing, namespaces and theme every fixture
//! needs. Each test module keeps the parts it asserts on.
use crate::retained_opc::Limits;
use std::io::Write;

pub(crate) const NS: &str = r#"xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:p14="http://schemas.microsoft.com/office/powerpoint/2010/main" xmlns:a16="http://schemas.microsoft.com/office/drawing/2014/main""#;

pub(crate) const GROUP_ROOT: &str =
    r#"<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>"#;

pub(crate) fn limits() -> Limits {
    Limits {
        archive_bytes: 32 << 20,
        part_bytes: 16 << 20,
        expanded_bytes: 64 << 20,
    }
}

pub(crate) fn rels(entries: &[(&str, &str, &str)]) -> String {
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

pub(crate) fn placeholder(id: u32, name: &str, ph: &str, sp_pr: &str, body: &str) -> String {
    format!(
        r#"<p:sp><p:nvSpPr><p:cNvPr id="{id}" name="{name}"/><p:cNvSpPr/><p:nvPr>{ph}</p:nvPr></p:nvSpPr><p:spPr>{sp_pr}</p:spPr>{body}</p:sp>"#
    )
}

pub(crate) fn xfrm(x: i64, y: i64, cx: i64, cy: i64) -> String {
    format!(r#"<a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>"#)
}

pub(crate) fn theme() -> String {
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

pub(crate) fn archive(parts: &[(&str, String)]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, body) in parts {
        writer.start_file(*name, options).unwrap();
        writer.write_all(body.as_bytes()).unwrap();
    }
    writer.finish().unwrap().into_inner()
}
