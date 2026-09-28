//! Small OPC fixtures, not PowerPoint application-oracle evidence.
use super::super::package::{A, A16, CT, P, P14, R, REL, SLIDE_ID_EXT};
use crate::edit_roundtrip::opc::{self, OpcPackage, OpcPart};
use crate::edit_roundtrip::pptx::*;
use crate::entity_id::EntityId;
use std::collections::BTreeMap;

pub(crate) const SHAPE: &str = "{0980FF19-E7E7-493C-8D3E-15B2100EA940}";
pub(crate) const AUTHOR: &str = "{CD37207E-7903-4ED4-8AE8-017538D2DF7E}";
pub(crate) fn parts(missing: bool) -> BTreeMap<String, Vec<u8>> {
    let creation = if missing {
        String::new()
    } else {
        format!(
            "<p:ext uri=\"{SLIDE_ID_EXT}\"><p14:creationId xmlns:p14=\"{P14}\" val=\"41\"/></p:ext>"
        )
    };
    let slide = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><p:sld xmlns:p="{P}" xmlns:a="{A}" xmlns:v="urn:unknown" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" mc:Ignorable="v" v:keep="a &amp; b"><p:cSld name="Original"><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/><p:sp><p:nvSpPr><p:cNvPr id="2" name="!!MorphName"><a:extLst><a:ext uri="{{FF2B5EF4-FFF2-40B4-BE49-F238E27FC236}}"><a16:creationId xmlns:a16="{A16}" id="{SHAPE}"/></a:ext><a:ext uri="untouched"><v:opaque answer="42"/></a:ext></a:extLst></p:cNvPr><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x="123" y="456"/><a:ext cx="1000" cy="2000"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>Original text</a:t></a:r></a:p></p:txBody></p:sp><mc:AlternateContent><mc:Choice Requires="v"><v:keep><![CDATA[<opaque>]]></v:keep></mc:Choice><mc:Fallback/></mc:AlternateContent></p:spTree><p:extLst><!-- common-ext-sentinel -->{creation}<p:ext uri="opaque"><v:x/></p:ext></p:extLst></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr><p:extLst><p:ext uri="unrelated"><v:root keep="'&quot;"/></p:ext></p:extLst></p:sld>"#
    );
    BTreeMap::from([
        ("[Content_Types].xml".into(),format!("<Types xmlns=\"{CT}\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/ppt/presentation.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml\"/><Override PartName=\"/ppt/slides/slide9.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slide+xml\"/></Types>").into_bytes()),
        ("_rels/.rels".into(),format!("<Relationships xmlns=\"{REL}\"><Relationship Id=\"root\" Type=\"{R}/officeDocument\" Target=\"ppt/presentation.xml\"/></Relationships>").into_bytes()),
        ("ppt/presentation.xml".into(),format!("<p:presentation xmlns:p=\"{P}\" xmlns:r=\"{R}\"><p:sldIdLst><p:sldId id=\"256\" r:id=\"theSlide\"/></p:sldIdLst><p:sldSz cx=\"12192000\" cy=\"6858000\"/></p:presentation>").into_bytes()),
        ("ppt/_rels/presentation.xml.rels".into(),format!("<Relationships xmlns=\"{REL}\"><Relationship Id=\"theSlide\" Type=\"{R}/slide\" Target=\"slides/slide9.xml\"/></Relationships>").into_bytes()),
        ("ppt/slides/slide9.xml".into(),slide.into_bytes()),
        ("ppt/theme/theme1.xml".into(),b"<theme keep='untouched'/>".to_vec()),
        ("ppt/media/image1.bin".into(),vec![0,255,128,17,33]),
        ("customXml/unreachable.xml".into(),b"<unreachable keep='exact'/>".to_vec()),
    ])
}
pub(crate) fn bytes(parts: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    opc::write(&OpcPackage::from_parts(
        parts
            .iter()
            .map(|(name, data)| OpcPart {
                name: name.clone(),
                data: data.clone(),
            })
            .collect(),
    ))
}
pub(crate) fn unpack(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    opc::read(bytes)
        .unwrap()
        .parts()
        .iter()
        .map(|p| (p.name.clone(), p.data.clone()))
        .collect()
}
pub(crate) fn patch(shape: bool) -> PptxCommentPatch {
    let thread = EntityId::now();
    PptxCommentPatch {
        asked_by: EntityId::now(),
        answered_by: EntityId::now(),
        author: PptxAuthor {
            guid: AUTHOR.into(),
            name: "Selected Author".into(),
        },
        thread_id: thread,
        comment_id: thread,
        at: 1_700_000_000_123,
        action: PptxCommentAction::Add {
            target: PptxCommentTarget {
                slide: 1,
                slide_creation_id: Some(41),
                shape_creation_id: shape.then(|| SHAPE.into()),
                shape_fingerprint: None,
            },
            text: "High severity: cite A & B <sources>.".into(),
        },
    }
}
pub(crate) fn with_text(parts: &mut BTreeMap<String, Vec<u8>>, part: &str, from: &str, to: &str) {
    let value = String::from_utf8(parts[part].clone()).unwrap();
    assert!(value.contains(from));
    parts.insert(part.into(), value.replace(from, to).into_bytes());
}
