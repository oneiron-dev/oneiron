//! Independent named-sheet cell reads from OOXML.
//! Entry: `named_sheet_cells`.
//! Definitions live here; judgment_cells forwards its crate-visible entry.

use super::*;

/// The saved values of the cells `wanted` selects on one named sheet: the
/// stored value, or a formula with its saved cache. Nothing is recalculated.
pub(crate) fn named_sheet_cells(
    bytes: &[u8],
    sheet_name: &str,
    wanted: &dyn Fn(&CellRef) -> bool,
) -> Result<BTreeMap<CellRef, CellValue>> {
    let pkg = opc::read(bytes)?;
    let part = named_sheet_part(&pkg, sheet_name)?;
    let sheet = pkg.part(&part).ok_or_else(invalid)?;
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
                finish_cell(&mut current, wanted, &mut cells, &pkg)?;
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
                finish_cell(&mut current, wanted, &mut cells, &pkg)?;
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

pub(super) fn push_captured(
    current: &mut Option<CellRead>,
    capture: Option<&str>,
    text: &str,
) -> Result<()> {
    let cell = current.as_mut().ok_or_else(invalid)?;
    if capture == Some("formula") {
        cell.3.as_mut().ok_or_else(invalid)?.push_str(text);
    } else {
        cell.2.push_str(text);
    }
    Ok(())
}

pub(super) fn sheet_end(
    reader: &NsReader<&[u8]>,
    tag: &quick_xml::events::BytesEnd<'_>,
    name: &str,
) -> bool {
    let (ns, local) = reader.resolver().resolve_element(tag.name());
    local.as_ref() == name
        && match ns {
            ResolveResult::Bound(uri) => uri.as_ref().as_bytes() == SHEET_NS,
            ResolveResult::Unbound => true,
            ResolveResult::Unknown(_) => false,
        }
}

/// Only worksheet-namespace cells under sheetData/row represent grid values.
pub(super) fn sheet_tag(reader: &NsReader<&[u8]>, tag: &BytesStart<'_>, name: &str) -> bool {
    let (ns, local) = reader.resolver().resolve_element(tag.name());
    local.as_ref() == name
        && match ns {
            ResolveResult::Bound(uri) => uri.as_ref().as_bytes() == SHEET_NS,
            ResolveResult::Unbound => true, // minimal valid no-namespace fixtures
            ResolveResult::Unknown(_) => false,
        }
}

pub(super) fn finish_cell(
    current: &mut Option<CellRead>,
    wanted: &dyn Fn(&CellRef) -> bool,
    cells: &mut BTreeMap<CellRef, CellValue>,
    pkg: &OpcPackage,
) -> Result<()> {
    let (cell, kind, value, formula, value_seen) = current.take().ok_or_else(invalid)?;
    if !wanted(&cell) {
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

pub(super) fn shared_string(pkg: &OpcPackage, index: usize) -> Result<String> {
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

pub(super) fn attributes(
    tag: &quick_xml::events::BytesStart<'_>,
) -> Result<BTreeMap<String, String>> {
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

pub(super) fn named_sheet_part(pkg: &OpcPackage, name: &str) -> Result<String> {
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
