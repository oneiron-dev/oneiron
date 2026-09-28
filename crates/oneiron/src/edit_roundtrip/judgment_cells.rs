//! Independent OOXML reads for typed sheet answers. No session assertion is
//! trusted for either the source cells or the retained output cells.

use super::judgment::SheetAnswerBundle;
use super::opc::{self, OpcPackage};
use super::session_validate::resolve_part_path;
use super::xml;
use super::{CellRef, CellValue};
use crate::error::{ArtifactError, Error, Result};
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use std::collections::{BTreeMap, BTreeSet};

const SHEET_NS: &[u8] = b"http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const REL_NS: &[u8] = b"http://schemas.openxmlformats.org/package/2006/relationships";

/// Transient decoded cell while walking a worksheet's grid path.
type CellRead = (CellRef, Option<String>, String, Option<String>, bool);

fn invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidEditManifest(
        "typed sheet answers do not match the artifact bytes",
    ))
}

/// Validate before values if supplied, and every non-abstaining after value.
/// Called both before returning a proposal and at Keep on public proposal bytes.
pub(crate) fn verify_sheet_answer_bytes(
    bundle: &SheetAnswerBundle,
    source: Option<&[u8]>,
    output: Option<&[u8]>,
) -> Result<()> {
    bundle.ops()?;
    if let Some(source) = source {
        let actual = sheet_cells(source, bundle, true)?;
        for answer in &bundle.answers {
            if let Some(before) = &answer.before
                && actual
                    .get(&answer.cell)
                    .cloned()
                    .unwrap_or(CellValue::Blank)
                    != *before
            {
                return Err(invalid());
            }
        }
    }
    if let Some(output) = output {
        let actual = sheet_cells(output, bundle, false)?;
        for answer in &bundle.answers {
            if let Some(after) = &answer.value
                && actual
                    .get(&answer.cell)
                    .cloned()
                    .unwrap_or(CellValue::Blank)
                    != *after
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

fn sheet_cells(
    bytes: &[u8],
    bundle: &SheetAnswerBundle,
    source: bool,
) -> Result<BTreeMap<CellRef, CellValue>> {
    let pkg = opc::read(bytes)?;
    let part = named_sheet_part(&pkg, &bundle.sheet)?;
    let sheet = pkg.part(&part).ok_or_else(invalid)?;
    // Only cells whose value is needed are parsed. In particular, a formula
    // on an abstaining cell or an unchecked source is not an error.
    let targets: BTreeSet<CellRef> = bundle
        .answers
        .iter()
        .filter(|a| {
            if source {
                a.before.is_some()
            } else {
                a.value.is_some()
            }
        })
        .map(|a| a.cell)
        .collect();
    let mut cells = BTreeMap::new();
    let mut reader = NsReader::from_reader(sheet);
    let mut current: Option<CellRead> = None;
    let mut capture: Option<&'static str> = None;
    let mut inline_string = false;
    let mut inline_run = false;
    let mut in_sheet_data = false;
    let mut row: Option<u32> = None;
    let mut depth = 0usize;
    let mut root_seen = false;
    loop {
        let event = reader.read_event().map_err(|_| invalid())?;
        if let Event::Start(tag) = &event {
            depth += 1;
            if depth == 1 {
                if root_seen || !sheet_tag(&reader, tag, "worksheet") {
                    return Err(invalid());
                }
                root_seen = true;
            }
        }
        let ended = matches!(&event, Event::End(_));
        match event {
            Event::Start(tag) if depth == 2 && sheet_tag(&reader, &tag, "sheetData") => {
                if in_sheet_data {
                    return Err(invalid());
                }
                in_sheet_data = true;
            }
            Event::Start(tag) if depth == 3 && sheet_tag(&reader, &tag, "row") && in_sheet_data => {
                if row.is_some() {
                    return Err(invalid());
                }
                row = Some(
                    attributes(&tag)?
                        .get("r")
                        .ok_or_else(invalid)?
                        .parse::<u32>()
                        .map_err(|_| invalid())?,
                );
            }
            Event::Start(tag) if depth == 4 && sheet_tag(&reader, &tag, "c") && row.is_some() => {
                if current.is_some() {
                    return Err(invalid());
                }
                let attrs = attributes(&tag)?;
                let cell =
                    CellRef::parse(attrs.get("r").ok_or_else(invalid)?).map_err(|_| invalid())?;
                if Some(cell.row) != row {
                    return Err(invalid());
                }
                current = Some((cell, attrs.get("t").cloned(), String::new(), None, false));
            }
            Event::Empty(tag) if depth == 3 && sheet_tag(&reader, &tag, "c") && row.is_some() => {
                if current.is_some() {
                    return Err(invalid());
                }
                let attrs = attributes(&tag)?;
                let cell =
                    CellRef::parse(attrs.get("r").ok_or_else(invalid)?).map_err(|_| invalid())?;
                if Some(cell.row) != row {
                    return Err(invalid());
                }
                current = Some((cell, attrs.get("t").cloned(), String::new(), None, false));
                finish_cell(&mut current, &targets, &mut cells, &pkg)?;
            }
            Event::Start(tag)
                if current.is_some() && depth == 5 && sheet_tag(&reader, &tag, "is") =>
            {
                inline_string = true;
            }
            Event::Start(tag)
                if current.is_some()
                    && inline_string
                    && depth == 6
                    && sheet_tag(&reader, &tag, "r") =>
            {
                inline_run = true;
            }
            Event::Start(tag)
                if current.is_some() && depth == 5 && sheet_tag(&reader, &tag, "f") =>
            {
                current.as_mut().ok_or_else(invalid)?.3 = Some(String::new());
                capture = Some("formula");
            }
            Event::Empty(tag)
                if current.is_some() && depth == 5 && sheet_tag(&reader, &tag, "f") =>
            {
                current.as_mut().ok_or_else(invalid)?.3 = Some(String::new());
            }
            Event::Start(tag)
                if current.is_some()
                    && ((depth == 5 && sheet_tag(&reader, &tag, "v"))
                        || (depth == 6
                            && inline_string
                            && !inline_run
                            && sheet_tag(&reader, &tag, "t"))
                        || (depth == 7
                            && inline_string
                            && inline_run
                            && sheet_tag(&reader, &tag, "t"))) =>
            {
                capture = Some("value");
                current.as_mut().ok_or_else(invalid)?.4 = true;
            }
            Event::Empty(tag)
                if current.is_some() && depth == 5 && sheet_tag(&reader, &tag, "v") =>
            {
                current.as_mut().ok_or_else(invalid)?.4 = true;
            }
            Event::Text(text)
                if capture.is_some()
                    && (depth == 5
                        || (depth == 6 && inline_string && !inline_run)
                        || (depth == 7 && inline_run)) =>
            {
                let v = quick_xml::escape::unescape(text.as_ref()).map_err(|_| invalid())?;
                push_captured(&mut current, capture, &v)?;
            }
            Event::CData(text)
                if capture.is_some()
                    && (depth == 5
                        || (depth == 6 && inline_string && !inline_run)
                        || (depth == 7 && inline_run)) =>
            {
                push_captured(&mut current, capture, text.as_ref())?;
            }
            Event::GeneralRef(reference)
                if capture.is_some()
                    && (depth == 5
                        || (depth == 6 && inline_string && !inline_run)
                        || (depth == 7 && inline_run)) =>
            {
                let value = reference
                    .resolve_char_ref()
                    .map_err(|_| invalid())?
                    .map(|ch| ch.to_string())
                    .or_else(|| {
                        quick_xml::escape::resolve_predefined_entity(reference.as_ref())
                            .map(str::to_owned)
                    })
                    .ok_or_else(invalid)?;
                push_captured(&mut current, capture, &value)?;
            }
            Event::End(tag) if depth == 4 && sheet_end(&reader, &tag, "c") && current.is_some() => {
                finish_cell(&mut current, &targets, &mut cells, &pkg)?;
                capture = None;
                inline_string = false;
                inline_run = false;
            }
            Event::End(tag)
                if (depth == 5
                    && (sheet_end(&reader, &tag, "v") || sheet_end(&reader, &tag, "f")))
                    || (depth == 6
                        && inline_string
                        && !inline_run
                        && sheet_end(&reader, &tag, "t"))
                    || (depth == 7 && inline_run && sheet_end(&reader, &tag, "t")) =>
            {
                capture = None;
            }
            Event::End(tag) if depth == 6 && inline_run && sheet_end(&reader, &tag, "r") => {
                inline_run = false;
            }
            Event::End(tag) if depth == 5 && inline_string && sheet_end(&reader, &tag, "is") => {
                inline_string = false;
            }
            Event::End(tag)
                if depth == 3 && tag.local_name().as_ref() == "row" && row.is_some() =>
            {
                if current.is_some() {
                    return Err(invalid());
                }
                row = None;
            }
            Event::End(tag)
                if depth == 2 && tag.local_name().as_ref() == "sheetData" && in_sheet_data =>
            {
                if row.is_some() {
                    return Err(invalid());
                }
                in_sheet_data = false;
            }
            Event::DocType(_) => return Err(invalid()),
            Event::Eof => break,
            _ => {}
        }
        if ended {
            depth = depth.checked_sub(1).ok_or_else(invalid)?;
        }
    }
    if current.is_some() || row.is_some() || in_sheet_data || depth != 0 || !root_seen {
        return Err(invalid());
    }
    Ok(cells)
}

fn push_captured(current: &mut Option<CellRead>, capture: Option<&str>, text: &str) -> Result<()> {
    let cell = current.as_mut().ok_or_else(invalid)?;
    if capture == Some("formula") {
        cell.3.as_mut().ok_or_else(invalid)?.push_str(text);
    } else {
        cell.2.push_str(text);
    }
    Ok(())
}

fn sheet_end(reader: &NsReader<&[u8]>, tag: &quick_xml::events::BytesEnd<'_>, name: &str) -> bool {
    let (ns, local) = reader.resolver().resolve_element(tag.name());
    local.as_ref() == name
        && match ns {
            ResolveResult::Bound(uri) => uri.as_ref().as_bytes() == SHEET_NS,
            ResolveResult::Unbound => true,
            ResolveResult::Unknown(_) => false,
        }
}

/// Only worksheet-namespace cells under sheetData/row represent grid values.
fn sheet_tag(reader: &NsReader<&[u8]>, tag: &BytesStart<'_>, name: &str) -> bool {
    let (ns, local) = reader.resolver().resolve_element(tag.name());
    local.as_ref() == name
        && match ns {
            ResolveResult::Bound(uri) => uri.as_ref().as_bytes() == SHEET_NS,
            ResolveResult::Unbound => true, // minimal valid no-namespace fixtures
            ResolveResult::Unknown(_) => false,
        }
}

fn finish_cell(
    current: &mut Option<CellRead>,
    targets: &BTreeSet<CellRef>,
    cells: &mut BTreeMap<CellRef, CellValue>,
    pkg: &OpcPackage,
) -> Result<()> {
    let (cell, kind, value, formula, value_seen) = current.take().ok_or_else(invalid)?;
    if !targets.contains(&cell) {
        return Ok(());
    }
    let parsed = match kind.as_deref() {
        Some("inlineStr" | "str") => CellValue::Text(value),
        Some("s") => {
            let index = value.parse::<usize>().map_err(|_| invalid())?;
            CellValue::Text(shared_string(pkg, index)?)
        }
        Some("b") => CellValue::Bool(match value.as_str() {
            "0" => false,
            "1" => true,
            _ => return Err(invalid()),
        }),
        Some("e") => CellValue::Error(value),
        Some("n") | None if value.is_empty() => CellValue::Blank,
        Some("n") | None => {
            let number = value.parse::<f64>().map_err(|_| invalid())?;
            if !number.is_finite() {
                return Err(invalid());
            }
            CellValue::Number(number)
        }
        _ => return Err(invalid()),
    };
    let parsed = if let Some(expr) = formula {
        CellValue::Formula {
            expr,
            cached: value_seen.then(|| Box::new(parsed)),
        }
    } else {
        parsed
    };
    if cells.insert(cell, parsed).is_some() {
        return Err(invalid());
    }
    Ok(())
}

fn shared_string(pkg: &OpcPackage, index: usize) -> Result<String> {
    let xml = pkg.part("xl/sharedStrings.xml").ok_or_else(invalid)?;
    let mut reader = NsReader::from_reader(xml);
    let (mut ordinal, mut content, mut depth) = (0usize, String::new(), 0usize);
    let (mut in_item, mut in_run, mut text) = (false, false, false);
    loop {
        let event = reader.read_event().map_err(|_| invalid())?;
        if let Event::Start(tag) = &event {
            depth += 1;
            if depth == 1 && !sheet_tag(&reader, tag, "sst") {
                return Err(invalid());
            }
        }
        let ended = matches!(&event, Event::End(_));
        match event {
            Event::Empty(tag) if depth == 1 && sheet_tag(&reader, &tag, "si") => {
                if ordinal == index {
                    return Ok(String::new());
                }
                ordinal += 1;
            }
            Event::Start(tag) if depth == 2 && sheet_tag(&reader, &tag, "si") => {
                if in_item {
                    return Err(invalid());
                }
                in_item = true;
                content.clear();
            }
            Event::Start(tag) if depth == 3 && in_item && sheet_tag(&reader, &tag, "r") => {
                in_run = true;
            }
            Event::Start(tag)
                if in_item
                    && sheet_tag(&reader, &tag, "t")
                    && ((depth == 3 && !in_run) || (depth == 4 && in_run)) =>
            {
                text = true;
            }
            Event::Text(v) if text && ((depth == 3 && !in_run) || (depth == 4 && in_run)) => {
                content.push_str(&quick_xml::escape::unescape(v.as_ref()).map_err(|_| invalid())?);
            }
            Event::CData(v) if text && ((depth == 3 && !in_run) || (depth == 4 && in_run)) => {
                content.push_str(v.as_ref());
            }
            Event::GeneralRef(reference)
                if text && ((depth == 3 && !in_run) || (depth == 4 && in_run)) =>
            {
                let value = reference
                    .resolve_char_ref()
                    .map_err(|_| invalid())?
                    .map(|ch| ch.to_string())
                    .or_else(|| {
                        quick_xml::escape::resolve_predefined_entity(reference.as_ref())
                            .map(str::to_owned)
                    })
                    .ok_or_else(invalid)?;
                content.push_str(&value);
            }
            Event::End(tag)
                if text
                    && ((depth == 3 && !in_run) || (depth == 4 && in_run))
                    && sheet_end(&reader, &tag, "t") =>
            {
                text = false;
            }
            Event::End(tag) if depth == 3 && in_run && sheet_end(&reader, &tag, "r") => {
                in_run = false;
            }
            Event::End(tag) if depth == 2 && in_item && sheet_end(&reader, &tag, "si") => {
                if ordinal == index {
                    return Ok(content);
                }
                ordinal += 1;
                in_item = false;
            }
            Event::DocType(_) => return Err(invalid()),
            Event::Eof => return Err(invalid()),
            _ => {}
        }
        if ended {
            depth = depth.checked_sub(1).ok_or_else(invalid)?;
        }
    }
}

fn attributes(tag: &quick_xml::events::BytesStart<'_>) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for a in tag.attributes() {
        let a = a.map_err(|_| invalid())?;
        let name = a.key.local_name().as_ref().to_owned();
        let value = a
            .normalized_value(quick_xml::XmlVersion::default())
            .map_err(|_| invalid())?
            .into_owned();
        if out.insert(name, value).is_some() {
            return Err(invalid());
        }
    }
    Ok(out)
}

fn named_sheet_part(pkg: &OpcPackage, name: &str) -> Result<String> {
    let workbook = pkg.part("xl/workbook.xml").ok_or_else(invalid)?;
    let sheets = xml::elements(workbook).map_err(|_| invalid())?;
    let mut matched = sheets
        .iter()
        .filter(|e| e.is("sheet", SHEET_NS) && e.attribute("name") == Some(name));
    let sheet = matched.next().ok_or_else(invalid)?;
    if matched.next().is_some() {
        return Err(invalid());
    }
    let part = if let Some(rels) = pkg.part("xl/_rels/workbook.xml.rels") {
        let id = sheet.relationship_id().ok_or_else(invalid)?;
        let relationships = xml::elements(rels).map_err(|_| invalid())?;
        let mut matches = relationships
            .iter()
            .filter(|e| e.is("Relationship", REL_NS) && e.attribute("Id") == Some(id));
        let rel = matches.next().ok_or_else(invalid)?;
        if matches.next().is_some()
            || !rel
                .attribute("Type")
                .is_some_and(|t| t.ends_with("/worksheet"))
            || rel.attribute("TargetMode") == Some("External")
        {
            return Err(invalid());
        }
        resolve_part_path("xl/", rel.attribute("Target").ok_or_else(invalid)?)
            .ok_or_else(invalid)?
    } else {
        // A small fixture can omit workbook relationships. Never guess by
        // workbook position: the named sheet's explicit sheetId must match.
        let index = sheet
            .attribute("sheetId")
            .ok_or_else(invalid)?
            .parse::<u32>()
            .map_err(|_| invalid())?;
        if index == 0 {
            return Err(invalid());
        }
        format!("xl/worksheets/sheet{index}.xml")
    };
    if !part.starts_with("xl/worksheets/") || !part.ends_with(".xml") || !pkg.contains(&part) {
        return Err(invalid());
    }
    Ok(part)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edit_roundtrip::{RangeRef, SheetCellAnswer};

    fn bundle(sheet: &str, before: Option<CellValue>, value: CellValue) -> SheetAnswerBundle {
        SheetAnswerBundle {
            question: "fit".into(),
            question_version: "q1".into(),
            principal: "owner".into(),
            sheet: sheet.into(),
            range: RangeRef::parse("B2:B2").unwrap(),
            max_count_override: None,
            answers: vec![SheetCellAnswer {
                cell: CellRef::parse("B2").unwrap(),
                before,
                value: Some(value),
                probability: 0.8,
                confidence: 0.9,
                rung: "rule".into(),
                model: "local".into(),
                revision: "r1".into(),
                cost_per_thousand: 0.0,
                evidence_versions: vec![],
            }],
        }
    }

    fn package(target: &str, shared: bool) -> Vec<u8> {
        let mut parts = vec![
            opc::OpcPart { name: "[Content_Types].xml".into(), data: b"<Types/>".to_vec() },
            opc::OpcPart { name: "xl/workbook.xml".into(), data: br#"<workbook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Other" sheetId="1" r:id="rId1"/><sheet name="Data &amp; Co" sheetId="2" r:id="rId2"/></sheets></workbook>"#.to_vec() },
            opc::OpcPart { name: "xl/_rels/workbook.xml.rels".into(), data: br#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>"#.to_vec() },
            opc::OpcPart { name: "xl/worksheets/sheet2.xml".into(), data: br#"<worksheet><sheetData><row r="2"><c r="B2"><v>999</v></c></row></sheetData></worksheet>"#.to_vec() },
            opc::OpcPart { name: "xl/worksheets/sheet1.xml".into(), data: target.as_bytes().to_vec() },
        ];
        if shared {
            parts.push(opc::OpcPart {
                name: "xl/sharedStrings.xml".into(),
                data: b"<sst><si><t>Other</t></si><si><t>Yes &amp; No</t></si></sst>".to_vec(),
            });
        }
        opc::write(&OpcPackage::from_parts(parts))
    }

    #[test]
    fn rich_inline_and_empty_shared_items_have_their_actual_text() -> Result<()> {
        let rich = package(
            r#"<worksheet><sheetData><row r="2"><c r="B2" t="inlineStr"><is><r><t>Actual</t></r></is></c></row></sheetData></worksheet>"#,
            false,
        );
        let mut ask = bundle(
            "Data & Co",
            Some(CellValue::Text("Actual".into())),
            CellValue::Text("Actual".into()),
        );
        verify_sheet_answer_bytes(&ask, Some(&rich), Some(&rich))?;
        ask.answers[0].before = Some(CellValue::Text(String::new()));
        assert!(verify_sheet_answer_bytes(&ask, Some(&rich), Some(&rich)).is_err());
        let mut pkg = opc::read(&package(
            r#"<worksheet><sheetData><row r="2"><c r="B2" t="s"><v>0</v></c></row></sheetData></worksheet>"#,
            true,
        ))?;
        pkg.upsert(
            "xl/sharedStrings.xml",
            br#"<sst><si/><si><t>Wrong</t></si></sst>"#.to_vec(),
        );
        let shared = opc::write(&pkg);
        ask.answers[0].before = Some(CellValue::Text(String::new()));
        ask.answers[0].value = Some(CellValue::Text(String::new()));
        verify_sheet_answer_bytes(&ask, Some(&shared), Some(&shared))?;
        ask.answers[0].value = Some(CellValue::Text("Wrong".into()));
        assert!(verify_sheet_answer_bytes(&ask, Some(&shared), Some(&shared)).is_err());
        Ok(())
    }

    #[test]
    fn source_formula_and_abstention_are_not_literal_answer_refusals() -> Result<()> {
        let source = package(
            r#"<worksheet><sheetData><row r="2"><c r="B2"><f>1+1</f><v>2</v></c></row><row r="3"><c r="B3"><f>3+3</f><v>6</v></c></row></sheetData></worksheet>"#,
            false,
        );
        let output = package(
            r#"<worksheet><sheetData><row r="2"><c r="B2"><v>7</v></c></row><row r="3"><c r="B3"><f>3+3</f><v>6</v></c></row></sheetData></worksheet>"#,
            false,
        );
        let mut ask = bundle("Data & Co", None, CellValue::Number(7.0));
        ask.answers.push(SheetCellAnswer {
            cell: CellRef::parse("B3")?,
            before: None,
            value: None,
            ..ask.answers[0].clone()
        });
        ask.range = RangeRef::parse("B2:B3")?;
        verify_sheet_answer_bytes(&ask, Some(&source), Some(&output))?;
        ask.answers[0].before = Some(CellValue::Formula {
            expr: "1+1".into(),
            cached: Some(Box::new(CellValue::Number(2.0))),
        });
        verify_sheet_answer_bytes(&ask, Some(&source), Some(&output))?;
        let no_cache = package(
            r#"<worksheet><sheetData><row r="2"><c r="B2"><f>1+1</f></c></row></sheetData></worksheet>"#,
            false,
        );
        ask.answers[0].before = Some(CellValue::Formula {
            expr: "1+1".into(),
            cached: None,
        });
        verify_sheet_answer_bytes(&ask, Some(&no_cache), Some(&output))?;
        ask.answers[0].before = Some(CellValue::Formula {
            expr: "9+9".into(),
            cached: Some(Box::new(CellValue::Number(2.0))),
        });
        assert!(verify_sheet_answer_bytes(&ask, Some(&source), Some(&output)).is_err());
        Ok(())
    }

    #[test]
    fn extension_and_phonetic_descendants_are_not_cell_values() -> Result<()> {
        let mut ask = bundle("Data & Co", None, CellValue::Number(6.0));
        let blank = package("<worksheet><sheetData/></worksheet>", false);
        for fake in [
            r#"<worksheet><sheetData><row r="2"><c r="B2"><extLst><ext uri="urn:example"><x:v xmlns:x="urn:example">6</x:v></ext></extLst></c></row></sheetData></worksheet>"#,
            r#"<worksheet><sheetData><row r="2"><c r="B2"><extLst><ext><v>6</v></ext></extLst></c></row></sheetData></worksheet>"#,
        ] {
            let output = package(fake, false);
            assert!(verify_sheet_answer_bytes(&ask, Some(&blank), Some(&output)).is_err());
        }
        ask.answers[0].value = Some(CellValue::Text("False".into()));
        let fake_inline = package(
            r#"<worksheet><sheetData><row r="2"><c r="B2" t="inlineStr"><is><ext><t>False</t></ext></is></c></row></sheetData></worksheet>"#,
            false,
        );
        assert!(verify_sheet_answer_bytes(&ask, Some(&blank), Some(&fake_inline)).is_err());
        let shared_cell = package(
            r#"<worksheet><sheetData><row r="2"><c r="B2" t="s"><v>0</v></c></row></sheetData></worksheet>"#,
            true,
        );
        let mut pkg = opc::read(&shared_cell)?;
        pkg.upsert(
            "xl/sharedStrings.xml",
            br#"<sst><si><rPh><t>False</t></rPh></si></sst>"#.to_vec(),
        );
        assert!(verify_sheet_answer_bytes(&ask, Some(&blank), Some(&opc::write(&pkg))).is_err());
        pkg.upsert(
            "xl/sharedStrings.xml",
            br#"<sst><si><r><t>True</t></r><rPh><t>False</t></rPh></si></sst>"#.to_vec(),
        );
        assert!(verify_sheet_answer_bytes(&ask, Some(&blank), Some(&opc::write(&pkg))).is_err());
        Ok(())
    }

    #[test]
    fn joins_named_sheet_relationship_and_shared_string_not_sheet_position() -> Result<()> {
        let source = package(
            r#"<worksheet><sheetData><row r="2"><c r="B2" t="s"><v>1</v></c></row></sheetData></worksheet>"#,
            true,
        );
        let output = package(
            r#"<worksheet><sheetData><row r="2"><c r="B2" t="inlineStr"><is><t>Ready &amp; Yes</t></is></c></row></sheetData></worksheet>"#,
            true,
        );
        let bundle = bundle(
            "Data & Co",
            Some(CellValue::Text("Yes & No".into())),
            CellValue::Text("Ready & Yes".into()),
        );
        verify_sheet_answer_bytes(&bundle, Some(&source), Some(&output))?;
        assert!(
            verify_sheet_answer_bytes(
                &bundle,
                Some(&package("<worksheet><sheetData/></worksheet>", true)),
                Some(&output)
            )
            .is_err()
        );
        assert!(
            verify_sheet_answer_bytes(
                &bundle,
                Some(&source),
                Some(&package("<worksheet><sheetData/></worksheet>", true))
            )
            .is_err()
        );
        // A matching XML tag outside sheetData/row, or in another namespace,
        // does not create an Excel grid cell and must not ground a receipt.
        for fake in [
            r#"<worksheet><sheetData/><extLst><c r="B2" t="inlineStr"><is><t>Ready &amp; Yes</t></is></c></extLst></worksheet>"#,
            r#"<worksheet><sheetData><row r="2"><x:c xmlns:x="urn:other" r="B2" t="inlineStr"><x:is><x:t>Ready &amp; Yes</x:t></x:is></x:c></row></sheetData></worksheet>"#,
            r#"<worksheet><sheetData><row r="3"><c r="B2" t="inlineStr"><is><t>Ready &amp; Yes</t></is></c></row></sheetData></worksheet>"#,
            r#"<worksheet><sheetData/><extLst><sheetData><row r="2"><c r="B2" t="inlineStr"><is><t>Ready &amp; Yes</t></is></c></row></sheetData></extLst></worksheet>"#,
        ] {
            assert!(
                verify_sheet_answer_bytes(&bundle, Some(&source), Some(&package(fake, true)))
                    .is_err()
            );
        }
        Ok(())
    }
}
