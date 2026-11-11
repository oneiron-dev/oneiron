//! Independent named-sheet cell reads from OOXML.
//! Entry: `named_sheet_cells`.
//! Definitions live here; judgment_cells forwards its crate-visible entry.

mod bounded;

use super::*;
use bounded::{
    BoundedSheetCells, Bounds, Scoped, ack_temp, append_temp, checkpoint, grow_temp, live_cache,
    live_cells, mark_cache, mark_cells, named_sheet_part_retained, release_cache, retained_invalid,
    take_cache, take_cells, temp_scope,
};
use oneiron_docedit::resource::{ResourceAllocation, Resources, bytes_of, wide};
use oneiron_docedit::retained_opc::{Limits, Package as RetainedPackage};
use std::borrow::Cow;
use std::time::Instant;

/// A wanted cell's transient buffers with their allocation scope (FIX 13218):
/// created at `<c>`, grown by captured text/formula, moved into the cells
/// map (or freed with the `t` marker) at `finish_cell`. Field order frees
/// the buffers before the scope releases their charge.
pub(super) struct CurrentCell {
    read: CellRead,
    scope: Option<Box<dyn ResourceAllocation>>,
    live: u64,
}

impl CurrentCell {
    fn live_bytes(&self) -> u64 {
        self.read
            .1
            .as_ref()
            .map_or(0, |s| wide(s.capacity()))
            .saturating_add(wide(self.read.2.capacity()))
            .saturating_add(self.read.3.as_ref().map_or(0, |s| wide(s.capacity())))
    }

    fn reset_formula(&mut self) {
        self.read.3 = Some(String::new());
        self.live = self.live_bytes();
        ack_temp(&mut self.scope, self.live);
    }
}

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

/// Deadline-checked sparse read of one named sheet (FIX 9817, 13218, source-only).
/// Same grid semantics as [`named_sheet_cells`], but the package opens under
/// `limits`/`resources` and every long loop, relationship resolution,
/// shared-string scan and growing allocation checkpoints `deadline` and the
/// port, reserving before it allocates. The returned [`BoundedSheetCells`]
/// carries the map's allocation scope with it, so the map's bytes stay
/// charged until the caller frees them. A typed machine floor is a real
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
) -> Result<BoundedSheetCells> {
    let mut bounds: Option<Bounds<'_>> = Some(Bounds::new(resources, deadline));
    // Explicit clock before admission: `MeasuringPort` ignores deadlines.
    checkpoint(&bounds)?;
    let pkg = RetainedPackage::open(bytes, limits, resources).map_err(retained_invalid)?;
    checkpoint(&bounds)?;
    let part = named_sheet_part_retained(&pkg, sheet_name, &mut bounds)?;
    checkpoint(&bounds)?;
    let sheet = pkg
        .part(part.value.as_str())
        .map_err(retained_invalid)?
        .ok_or_else(invalid)?;
    // The part name is a temporary: free it before the grid scan admits.
    drop(part);
    checkpoint(&bounds)?;
    // Shared strings once, decoded on demand and cached by index.
    let shared_bytes = pkg.part("xl/sharedStrings.xml").map_err(retained_invalid)?;
    checkpoint(&bounds)?;
    let mut shared_cache = BTreeMap::new();
    let cells = parse_sheet(
        sheet.as_slice(),
        wanted,
        shared_bytes.as_deref(),
        &mut shared_cache,
        &mut bounds,
    )?;
    // The cache frees with the read; release its charge beside it, then
    // return the map with its own scope.
    drop(shared_cache);
    release_cache(&mut bounds);
    let bounds = bounds.take().ok_or_else(invalid)?;
    Ok(BoundedSheetCells::new(cells, bounds.into_cells_scope()))
}

/// A wanted cell's transient buffers with their scope, admitted for the `t`
/// marker clone. Unwanted cells never reach here (no transient strings).
fn begin_cell(
    cell: CellRef,
    kind: Option<&String>,
    bounds: &Option<Bounds<'_>>,
) -> Result<CurrentCell> {
    let mut scope = temp_scope(bounds);
    if let Some(t) = kind {
        grow_temp(&mut scope, bounds, wide(t.len()), wide(t.len()))?;
    }
    let kind = kind.cloned();
    let live = kind.as_ref().map_or(0, |t| wide(t.capacity()));
    ack_temp(&mut scope, live);
    Ok(CurrentCell {
        read: (cell, kind, String::new(), None, false),
        scope,
        live,
    })
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
    let mut cells = BTreeMap::new();
    let mut reader = NsReader::from_reader(sheet);
    let mut current: Option<CurrentCell> = None;
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
                        .value
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
                let cell = CellRef::parse(attrs.value.get("r").ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
                if Some(cell.row) != row {
                    return Err(invalid());
                }
                // `wanted` once per cell, at its start tag, in document order.
                // Unwanted cells skip `t`/value/formula capture entirely (no
                // transient strings); `in_cell` still guards structure.
                in_cell = true;
                if wanted(&cell) {
                    current = Some(begin_cell(cell, attrs.value.get("t"), bounds)?);
                }
            }
            Event::Empty(tag) if depth == 3 && sheet_tag(&reader, &tag, "c") && row.is_some() => {
                if in_cell {
                    return Err(invalid());
                }
                let attrs = attributes(&tag, bounds)?;
                let cell = CellRef::parse(attrs.value.get("r").ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
                if Some(cell.row) != row {
                    return Err(invalid());
                }
                if wanted(&cell) {
                    current = Some(begin_cell(cell, attrs.value.get("t"), bounds)?);
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
                    cell.reset_formula();
                }
                capture = Some("formula");
            }
            Event::Empty(tag)
                if current.is_some() && depth == 5 && sheet_tag(&reader, &tag, "f") =>
            {
                current.as_mut().ok_or_else(invalid)?.reset_formula();
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
                    cell.read.4 = true;
                }
            }
            Event::Empty(tag)
                if current.is_some() && depth == 5 && sheet_tag(&reader, &tag, "v") =>
            {
                current.as_mut().ok_or_else(invalid)?.read.4 = true;
            }
            Event::Text(text)
                if capture.is_some()
                    && (depth == 5
                        || (depth == 6 && inline_string && !inline_run)
                        || (depth == 7 && inline_run)) =>
            {
                let mut decode = temp_scope(bounds);
                if text.as_ref().contains('&') {
                    let bytes = wide(text.as_ref().len());
                    grow_temp(&mut decode, bounds, bytes, bytes)?;
                }
                let v = quick_xml::escape::unescape(text.as_ref()).map_err(|_| invalid())?;
                ack_temp(
                    &mut decode,
                    match &v {
                        Cow::Borrowed(_) => 0,
                        Cow::Owned(owned) => wide(owned.capacity()),
                    },
                );
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
                let mut decode = temp_scope(bounds);
                let mut encoded = [0; 4];
                let resolved = reference.resolve_char_ref().map_err(|_| invalid())?;
                let text = match resolved {
                    Some(ch) => ch.encode_utf8(&mut encoded),
                    None => quick_xml::escape::resolve_predefined_entity(reference.as_ref())
                        .ok_or_else(invalid)?,
                };
                let bytes = wide(text.len());
                grow_temp(&mut decode, bounds, bytes, bytes)?;
                let value = text.to_owned();
                ack_temp(&mut decode, wide(value.capacity()));
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
    current: &mut Option<CurrentCell>,
    capture: Option<&str>,
    text: &str,
    bounds: &mut Option<Bounds<'_>>,
) -> Result<()> {
    let cell = current.as_mut().ok_or_else(invalid)?;
    cell.live = cell.live_bytes();
    if capture == Some("formula") {
        let value = cell.read.3.as_mut().ok_or_else(invalid)?;
        let other = cell.live.saturating_sub(wide(value.capacity()));
        append_temp(&mut cell.scope, bounds, value, text, other)?;
    } else {
        let other = cell.live.saturating_sub(wide(cell.read.2.capacity()));
        append_temp(&mut cell.scope, bounds, &mut cell.read.2, text, other)?;
    }
    cell.live = cell.live_bytes();
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
    current: &mut Option<CurrentCell>,
    cells: &mut BTreeMap<CellRef, CellValue>,
    shared_xml: Option<&[u8]>,
    shared_cache: &mut BTreeMap<usize, String>,
    bounds: &mut Option<Bounds<'_>>,
) -> Result<()> {
    checkpoint(bounds)?;
    let current = current.take().ok_or_else(invalid)?;
    let mut cell_scope = current.scope;
    let (cell, kind, value, formula, value_seen) = current.read;
    let expr_bytes = formula.as_ref().map_or(0, |s| wide(s.capacity()));
    let mut moved: u64 = 0;
    let mut shared_scope = None;
    let parsed = match kind.as_deref() {
        Some("inlineStr" | "str") => {
            moved = wide(value.capacity());
            CellValue::Text(value)
        }
        Some("s") => {
            let index = value.parse::<usize>().map_err(|_| invalid())?;
            drop(value);
            // The index buffer is gone before the shared-string admission.
            ack_temp(
                &mut cell_scope,
                expr_bytes.saturating_add(kind.as_ref().map_or(0, |s| wide(s.capacity()))),
            );
            let shared = shared_string_cached(index, shared_xml, shared_cache, bounds)?;
            moved = wide(shared.value.capacity());
            shared_scope = shared.scope;
            CellValue::Text(shared.value)
        }
        Some("b") => {
            let parsed = match value.as_str() {
                "0" => false,
                "1" => true,
                _ => return Err(invalid()),
            };
            drop(value);
            CellValue::Bool(parsed)
        }
        Some("e") => {
            moved = wide(value.capacity());
            CellValue::Error(value)
        }
        Some("n") | None if value.is_empty() => {
            drop(value);
            CellValue::Blank
        }
        Some("n") | None => {
            let number = value.parse::<f64>().map_err(|_| invalid())?;
            if !number.is_finite() {
                return Err(invalid());
            }
            drop(value);
            CellValue::Number(number)
        }
        _ => return Err(invalid()),
    };
    drop(kind);
    let cell_value_bytes = if shared_scope.is_some() { 0 } else { moved };
    ack_temp(&mut cell_scope, expr_bytes.saturating_add(cell_value_bytes));
    let parsed = if let Some(expr) = formula {
        let cached = if value_seen {
            take_cells(bounds, bytes_of::<CellValue>(1), 0)?;
            let cached = Box::new(parsed);
            let total = live_cells(bounds).saturating_add(bytes_of::<CellValue>(1));
            mark_cells(bounds, total);
            Some(cached)
        } else {
            drop(parsed);
            moved = 0;
            ack_temp(&mut cell_scope, expr_bytes);
            ack_temp(&mut shared_scope, 0);
            None
        };
        moved = moved.saturating_add(wide(expr.capacity()));
        CellValue::Formula { expr, cached }
    } else {
        parsed
    };
    take_cells(bounds, bytes_of::<(CellRef, CellValue)>(1), 0)?;
    if cells.insert(cell, parsed).is_some() {
        return Err(invalid());
    }
    let total = live_cells(bounds)
        .saturating_add(moved)
        .saturating_add(bytes_of::<(CellRef, CellValue)>(1));
    // Mark before releasing moved-buffer scopes: other threads may admit
    // between memory-line operations, even without a local checkpoint.
    mark_cells(bounds, total);
    drop(cell_scope);
    drop(shared_scope);
    Ok(())
}

/// Shared-string `index` via the cached bytes: decoded once per index,
/// scanned with the same checks as the legacy path.
fn shared_string_cached(
    index: usize,
    shared_xml: Option<&[u8]>,
    cache: &mut BTreeMap<usize, String>,
    bounds: &mut Option<Bounds<'_>>,
) -> Result<Scoped<String>> {
    if let Some(hit) = cache.get(&index) {
        let mut scope = temp_scope(bounds);
        grow_temp(&mut scope, bounds, wide(hit.len()), wide(hit.len()))?;
        let out = hit.clone();
        ack_temp(&mut scope, wide(out.capacity()));
        return Ok(Scoped { value: out, scope });
    }
    let xml = shared_xml.ok_or_else(invalid)?;
    let scanned = shared_string(xml, index, bounds)?;
    // The cell's own clone first, on its own scope ...
    let mut out_scope = temp_scope(bounds);
    grow_temp(
        &mut out_scope,
        bounds,
        wide(scanned.value.len()),
        wide(scanned.value.len()),
    )?;
    let out = scanned.value.clone();
    ack_temp(&mut out_scope, wide(out.capacity()));
    // The scanned text moves; only the cache node is a new allocation.
    take_cache(bounds, bytes_of::<(usize, String)>(1), 0)?;
    let Scoped { value: text, scope } = scanned;
    let total = live_cache(bounds)
        .saturating_add(wide(text.capacity()))
        .saturating_add(bytes_of::<(usize, String)>(1));
    cache.insert(index, text);
    mark_cache(bounds, total);
    drop(scope);
    Ok(Scoped {
        value: out,
        scope: out_scope,
    })
}

pub(super) fn shared_string(
    xml: &[u8],
    index: usize,
    bounds: &mut Option<Bounds<'_>>,
) -> Result<Scoped<String>> {
    checkpoint(bounds)?;
    let mut reader = NsReader::from_reader(xml);
    // The scanned item text with its scope: acked to the content's actual
    // capacity after every append, transferred to the cache on return.
    let mut out_scope = temp_scope(bounds);
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
                    drop(content);
                    ack_temp(&mut out_scope, 0);
                    return Ok(Scoped {
                        value: String::new(),
                        scope: out_scope,
                    });
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
                let mut decode = temp_scope(bounds);
                if v.as_ref().contains('&') {
                    let bytes = wide(v.as_ref().len());
                    grow_temp(&mut decode, bounds, bytes, bytes)?;
                }
                let decoded = quick_xml::escape::unescape(v.as_ref()).map_err(|_| invalid())?;
                ack_temp(
                    &mut decode,
                    match &decoded {
                        Cow::Borrowed(_) => 0,
                        Cow::Owned(owned) => wide(owned.capacity()),
                    },
                );
                append_temp(&mut out_scope, bounds, &mut content, &decoded, 0)?;
            }
            Event::CData(v) if text && ((depth == 3 && !in_run) || (depth == 4 && in_run)) => {
                append_temp(&mut out_scope, bounds, &mut content, v.as_ref(), 0)?;
            }
            Event::GeneralRef(reference)
                if text && ((depth == 3 && !in_run) || (depth == 4 && in_run)) =>
            {
                let mut decode = temp_scope(bounds);
                let mut encoded = [0; 4];
                let resolved = reference.resolve_char_ref().map_err(|_| invalid())?;
                let text = match resolved {
                    Some(ch) => ch.encode_utf8(&mut encoded),
                    None => quick_xml::escape::resolve_predefined_entity(reference.as_ref())
                        .ok_or_else(invalid)?,
                };
                let bytes = wide(text.len());
                grow_temp(&mut decode, bounds, bytes, bytes)?;
                let value = text.to_owned();
                ack_temp(&mut decode, wide(value.capacity()));
                append_temp(&mut out_scope, bounds, &mut content, &value, 0)?;
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
                    ack_temp(&mut out_scope, wide(content.capacity()));
                    return Ok(Scoped {
                        value: content,
                        scope: out_scope,
                    });
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
) -> Result<Scoped<BTreeMap<String, String>>> {
    checkpoint(bounds)?;
    let mut scope = temp_scope(bounds);
    let mut out = BTreeMap::new();
    // One tag's map with its scope, dropped after `r`/`t` are read: each
    // attribute grows by its measured bytes plus one node estimate, acked
    // to actual capacities, never volume across tags.
    let mut live: u64 = 0;
    for a in tag.attributes() {
        checkpoint(bounds)?;
        let a = a.map_err(|_| invalid())?;
        let raw = wide(a.key.as_ref().len().saturating_add(a.value.len()));
        grow_temp(
            &mut scope,
            bounds,
            raw.saturating_add(bytes_of::<(String, String)>(1)),
            raw,
        )?;
        let name = a.key.local_name().as_ref().to_owned();
        let value = a
            .normalized_value(quick_xml::XmlVersion::default())
            .map_err(|_| invalid())?
            .into_owned();
        let entry = wide(name.capacity()).saturating_add(wide(value.capacity()));
        if out.insert(name, value).is_some() {
            return Err(invalid());
        }
        live = live
            .saturating_add(entry)
            .saturating_add(bytes_of::<(String, String)>(1));
        ack_temp(&mut scope, live);
    }
    Ok(Scoped { value: out, scope })
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
