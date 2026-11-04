//! Independent named-sheet cell reads from OOXML.
//! Entry: `named_sheet_cells`.
//! Definitions live here; judgment_cells forwards its crate-visible entry.

mod bounded;

use super::*;
use bounded::{
    Bounds, checkpoint, cover_scratch, cover_scratch_estimate, hand_retained,
    named_sheet_part_retained, reserve_retained, reserve_retained_estimate, retained_invalid,
};
use oneiron_docedit::resource::{Resources, bytes_of, wide};
use oneiron_docedit::retained_opc::{Limits, Package as RetainedPackage};
use std::time::Instant;

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
    let shared_xml = pkg.part("xl/sharedStrings.xml");
    let mut shared_cache = BTreeMap::new();
    let mut bounds: Option<Bounds<'_>> = None;
    parse_sheet(sheet, wanted, shared_xml, &mut shared_cache, &mut bounds)
}

/// Deadline-checked sparse read of one named sheet (FIX 9817, source-only).
/// Same grid semantics as [`named_sheet_cells`], but the package opens under
/// `limits`/`resources` and every long loop, relationship resolution,
/// shared-string scan and growing allocation checkpoints `deadline` and the
/// port, reserving before it allocates. A typed machine floor is a real
/// failure; an expired `deadline` is the existing timed-out read
/// (`Error::Io` with `TimedOut`) for the caller to turn into an explicit
/// partial. Never reads the whole book.
pub(crate) fn named_sheet_cells_until(
    bytes: &[u8],
    sheet_name: &str,
    wanted: &dyn Fn(&CellRef) -> bool,
    limits: Limits,
    resources: &Resources,
    deadline: Instant,
) -> Result<BTreeMap<CellRef, CellValue>> {
    let mut bounds: Option<Bounds<'_>> = Some(Bounds::new(resources, deadline));
    // Explicit clock before admission: `MeasuringPort` ignores deadlines.
    checkpoint(&bounds)?;
    let pkg = RetainedPackage::open(bytes, limits, resources).map_err(retained_invalid)?;
    checkpoint(&bounds)?;
    let part = named_sheet_part_retained(&pkg, sheet_name, &mut bounds)?;
    checkpoint(&bounds)?;
    let sheet = pkg
        .part(part.as_str())
        .map_err(retained_invalid)?
        .ok_or_else(invalid)?;
    checkpoint(&bounds)?;
    // Shared strings once, decoded on demand and cached by index.
    let shared_bytes = pkg.part("xl/sharedStrings.xml").map_err(retained_invalid)?;
    checkpoint(&bounds)?;
    let mut shared_cache = BTreeMap::new();
    parse_sheet(
        sheet.as_slice(),
        wanted,
        shared_bytes.as_deref(),
        &mut shared_cache,
        &mut bounds,
    )
}

/// Shared worksheet grid parser for both readers: only worksheet-namespace
/// cells under `sheetData`/`row` become grid values. `bounds=None` is the
/// legacy path (no checkpoints, no reservations); `Some` checkpoints the
/// explicit deadline and the port on every event and reserves before every
/// growing allocation.
fn parse_sheet(
    sheet: &[u8],
    wanted: &dyn Fn(&CellRef) -> bool,
    shared_xml: Option<&[u8]>,
    shared_cache: &mut BTreeMap<usize, String>,
    bounds: &mut Option<Bounds<'_>>,
) -> Result<BTreeMap<CellRef, CellValue>> {
    checkpoint(bounds)?;
    cover_scratch(bounds, wide(sheet.len().min(1024)))?;
    let mut cells = BTreeMap::new();
    let mut reader = NsReader::from_reader(sheet);
    let mut current: Option<CellRead> = None;
    let mut in_cell = false;
    let mut capture: Option<&'static str> = None;
    let mut inline_string = false;
    let mut inline_run = false;
    let mut in_sheet_data = false;
    let mut row: Option<u32> = None;
    let mut depth = 0usize;
    let mut root_seen = false;
    loop {
        checkpoint(bounds)?;
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
                    attributes(&tag, bounds)?
                        .get("r")
                        .ok_or_else(invalid)?
                        .parse::<u32>()
                        .map_err(|_| invalid())?,
                );
            }
            Event::Start(tag) if depth == 4 && sheet_tag(&reader, &tag, "c") && row.is_some() => {
                if in_cell {
                    return Err(invalid());
                }
                let attrs = attributes(&tag, bounds)?;
                let cell =
                    CellRef::parse(attrs.get("r").ok_or_else(invalid)?).map_err(|_| invalid())?;
                if Some(cell.row) != row {
                    return Err(invalid());
                }
                // `wanted` once per cell, at its start tag, in document order.
                // Unwanted cells skip `t`/value/formula capture entirely (no
                // transient strings); `in_cell` still guards structure.
                in_cell = true;
                if wanted(&cell) {
                    if let Some(t) = attrs.get("t") {
                        cover_scratch(bounds, wide(t.len()))?;
                    }
                    current = Some((cell, attrs.get("t").cloned(), String::new(), None, false));
                }
            }
            Event::Empty(tag) if depth == 3 && sheet_tag(&reader, &tag, "c") && row.is_some() => {
                if in_cell {
                    return Err(invalid());
                }
                let attrs = attributes(&tag, bounds)?;
                let cell =
                    CellRef::parse(attrs.get("r").ok_or_else(invalid)?).map_err(|_| invalid())?;
                if Some(cell.row) != row {
                    return Err(invalid());
                }
                if wanted(&cell) {
                    if let Some(t) = attrs.get("t") {
                        cover_scratch(bounds, wide(t.len()))?;
                    }
                    current = Some((cell, attrs.get("t").cloned(), String::new(), None, false));
                    finish_cell(&mut current, &mut cells, shared_xml, shared_cache, bounds)?;
                } else {
                    checkpoint(bounds)?;
                }
            }
            Event::Start(tag) if in_cell && depth == 5 && sheet_tag(&reader, &tag, "is") => {
                inline_string = true;
            }
            Event::Start(tag)
                if in_cell && inline_string && depth == 6 && sheet_tag(&reader, &tag, "r") =>
            {
                inline_run = true;
            }
            Event::Start(tag) if in_cell && depth == 5 && sheet_tag(&reader, &tag, "f") => {
                // Unwanted cells validate formula text but keep no buffer.
                if let Some(cell) = current.as_mut() {
                    cell.3 = Some(String::new());
                }
                capture = Some("formula");
            }
            Event::Empty(tag)
                if current.is_some() && depth == 5 && sheet_tag(&reader, &tag, "f") =>
            {
                current.as_mut().ok_or_else(invalid)?.3 = Some(String::new());
            }
            Event::Start(tag)
                if in_cell
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
                // Unwanted cells validate value text but keep no flag.
                if let Some(cell) = current.as_mut() {
                    cell.4 = true;
                }
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
                cover_scratch(bounds, wide(text.as_ref().len()))?;
                let v = quick_xml::escape::unescape(text.as_ref()).map_err(|_| invalid())?;
                // Unwanted cells validated above; only wanted cells retain.
                if current.is_some() {
                    push_captured(&mut current, capture, &v, bounds)?;
                }
            }
            Event::CData(text)
                if capture.is_some()
                    && (depth == 5
                        || (depth == 6 && inline_string && !inline_run)
                        || (depth == 7 && inline_run)) =>
            {
                if current.is_some() {
                    push_captured(&mut current, capture, text.as_ref(), bounds)?;
                }
            }
            Event::GeneralRef(reference)
                if capture.is_some()
                    && (depth == 5
                        || (depth == 6 && inline_string && !inline_run)
                        || (depth == 7 && inline_run)) =>
            {
                cover_scratch(bounds, wide(8))?;
                let value = reference
                    .resolve_char_ref()
                    .map_err(|_| invalid())?
                    .map(|ch| ch.to_string())
                    .or_else(|| {
                        quick_xml::escape::resolve_predefined_entity(reference.as_ref())
                            .map(str::to_owned)
                    })
                    .ok_or_else(invalid)?;
                if current.is_some() {
                    push_captured(&mut current, capture, &value, bounds)?;
                }
            }
            Event::End(tag) if depth == 4 && sheet_end(&reader, &tag, "c") && in_cell => {
                if current.is_some() {
                    finish_cell(&mut current, &mut cells, shared_xml, shared_cache, bounds)?;
                } else {
                    checkpoint(bounds)?;
                }
                capture = None;
                inline_string = false;
                inline_run = false;
                in_cell = false;
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
                if in_cell {
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
    if current.is_some() || in_cell || row.is_some() || in_sheet_data || depth != 0 || !root_seen {
        return Err(invalid());
    }
    Ok(cells)
}

pub(super) fn push_captured(
    current: &mut Option<CellRead>,
    capture: Option<&str>,
    text: &str,
    bounds: &mut Option<Bounds<'_>>,
) -> Result<()> {
    reserve_retained(bounds, wide(text.len()))?;
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
    cells: &mut BTreeMap<CellRef, CellValue>,
    shared_xml: Option<&[u8]>,
    shared_cache: &mut BTreeMap<usize, String>,
    bounds: &mut Option<Bounds<'_>>,
) -> Result<()> {
    checkpoint(bounds)?;
    let (cell, kind, value, formula, value_seen) = current.take().ok_or_else(invalid)?;
    // Caller checked `wanted` at `<c>`; this finishes wanted cells only.
    let parsed = match kind.as_deref() {
        Some("inlineStr" | "str") => CellValue::Text(value),
        Some("s") => {
            let index = value.parse::<usize>().map_err(|_| invalid())?;
            checkpoint(bounds)?;
            let text = shared_string_cached(index, shared_xml, shared_cache, bounds)?;
            CellValue::Text(text)
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
        reserve_retained_estimate(bounds, bytes_of::<CellValue>(1), 0)?;
        CellValue::Formula {
            expr,
            cached: if value_seen {
                reserve_retained_estimate(bounds, bytes_of::<CellValue>(1), 0)?;
                Some(Box::new(parsed))
            } else {
                None
            },
        }
    } else {
        parsed
    };
    reserve_retained_estimate(bounds, bytes_of::<(CellRef, CellValue)>(1), 0)?;
    if cells.insert(cell, parsed).is_some() {
        return Err(invalid());
    }
    // Hand this cell's retained bytes to the live reading; later cells must
    // not double-count history (resource.rs "lasts until they are").
    hand_retained(bounds);
    Ok(())
}

/// Shared-string `index` via the cached bytes: decoded once per index,
/// scanned with the same checks as the legacy path.
fn shared_string_cached(
    index: usize,
    shared_xml: Option<&[u8]>,
    cache: &mut BTreeMap<usize, String>,
    bounds: &mut Option<Bounds<'_>>,
) -> Result<String> {
    if let Some(hit) = cache.get(&index) {
        reserve_retained(bounds, wide(hit.len()))?;
        return Ok(hit.clone());
    }
    let xml = shared_xml.ok_or_else(invalid)?;
    let text = shared_string(xml, index, bounds)?;
    reserve_retained(bounds, wide(text.len()))?;
    reserve_retained_estimate(bounds, bytes_of::<(usize, String)>(1), 0)?;
    let out = text.clone();
    cache.insert(index, text);
    Ok(out)
}

pub(super) fn shared_string(
    xml: &[u8],
    index: usize,
    bounds: &mut Option<Bounds<'_>>,
) -> Result<String> {
    checkpoint(bounds)?;
    cover_scratch(bounds, wide(xml.len().min(1024)))?;
    let mut reader = NsReader::from_reader(xml);
    let (mut ordinal, mut content, mut depth) = (0usize, String::new(), 0usize);
    let (mut in_item, mut in_run, mut text) = (false, false, false);
    loop {
        checkpoint(bounds)?;
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
                cover_scratch(bounds, wide(v.as_ref().len()))?;
                let decoded = quick_xml::escape::unescape(v.as_ref()).map_err(|_| invalid())?;
                cover_scratch(bounds, wide(content.len().saturating_add(decoded.len())))?;
                content.push_str(&decoded);
            }
            Event::CData(v) if text && ((depth == 3 && !in_run) || (depth == 4 && in_run)) => {
                cover_scratch(bounds, wide(content.len().saturating_add(v.as_ref().len())))?;
                content.push_str(v.as_ref());
            }
            Event::GeneralRef(reference)
                if text && ((depth == 3 && !in_run) || (depth == 4 && in_run)) =>
            {
                cover_scratch(bounds, wide(8))?;
                let value = reference
                    .resolve_char_ref()
                    .map_err(|_| invalid())?
                    .map(|ch| ch.to_string())
                    .or_else(|| {
                        quick_xml::escape::resolve_predefined_entity(reference.as_ref())
                            .map(str::to_owned)
                    })
                    .ok_or_else(invalid)?;
                cover_scratch(bounds, wide(content.len().saturating_add(value.len())))?;
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
    bounds: &mut Option<Bounds<'_>>,
) -> Result<BTreeMap<String, String>> {
    checkpoint(bounds)?;
    let mut out = BTreeMap::new();
    // Scratch peak for one tag's map (dropped after `r`/`t`): running raw
    // total plus node count, never volume across tags.
    let mut total: u64 = 0;
    for a in tag.attributes() {
        checkpoint(bounds)?;
        let a = a.map_err(|_| invalid())?;
        let raw = wide(a.key.as_ref().len().saturating_add(a.value.len()));
        cover_scratch(bounds, total.saturating_add(raw))?;
        total = total.saturating_add(raw);
        let name = a.key.local_name().as_ref().to_owned();
        let value = a
            .normalized_value(quick_xml::XmlVersion::default())
            .map_err(|_| invalid())?
            .into_owned();
        cover_scratch_estimate(
            bounds,
            bytes_of::<(String, String)>(out.len().saturating_add(1)),
            0,
        )?;
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
