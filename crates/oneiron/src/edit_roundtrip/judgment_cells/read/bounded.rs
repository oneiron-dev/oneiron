//! Bounded sparse-read admission for named-sheet cells (FIX 9817, 13218, 13219).
//! `Bounds` splits the read's live bytes by owner lifetime: the returned
//! cells map, the shared-string cache, and one scope per temporary. Each
//! scope reserves before its bytes allocate, names its actual live bytes
//! after, and releases them when they free, in both live and None-live
//! reads; freed temporaries never linger in the operation's charge.
//! Parent `read` owns grid parsing; this module owns admission only.

use super::super::{REL_NS, SHEET_NS, invalid};
use crate::edit_roundtrip::session_validate::resolve_part_path;
use crate::edit_roundtrip::{CellRef, CellValue};
use crate::error::{Error, Result};
use crate::office_body::{document_refused, machine_memory_refused};
use oneiron_docedit::resource::{ResourceAllocation, ResourceRefusal, Resources, wide};
use oneiron_docedit::retained_opc::Package as RetainedPackage;
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::time::Instant;

/// Relationship-attribute namespace for `r:id` (sheet to worksheet rel).
const REL_ATTR_NS: &[u8] = b"http://schemas.openxmlformats.org/officeDocument/2006/relationships";

/// The bounded read's cells with their allocation scope (FIX 13218): the
/// scope holds the map's live bytes and releases them when the map frees,
/// in both live and None-live reads. Field order frees the map before the
/// scope. Callers name only `cells`.
pub(crate) struct BoundedSheetCells {
    pub(crate) cells: BTreeMap<CellRef, CellValue>,
    _memory: Box<dyn ResourceAllocation>,
}

impl BoundedSheetCells {
    pub(super) fn new(
        cells: BTreeMap<CellRef, CellValue>,
        memory: Box<dyn ResourceAllocation>,
    ) -> Self {
        Self {
            cells,
            _memory: memory,
        }
    }
}

/// An owned temporary with its allocation scope (FIX 13218): the scope
/// holds the value's actual live bytes and releases them when the value
/// frees. Field order frees the value before the scope. `scope` is `None`
/// on the legacy path. A consumer either drops the whole value (release)
/// or moves the value on and drops the scope after marking the target
/// (transfer: target marked before source release).
pub(super) struct Scoped<T> {
    pub(super) value: T,
    pub(super) scope: Option<Box<dyn ResourceAllocation>>,
}

/// Explicit deadline plus port for the bounded sparse read (FIX 9817, 13218).
/// `MeasuringPort` never stops at a deadline, so the clock is checked
/// alongside every port checkpoint. The cells scope holds the returned
/// map's cumulative live bytes and travels with it; the cache scope holds
/// the shared-string cache's and releases when the cache frees. Every
/// other allocation takes a fresh temp scope via [`Bounds::temp`], grown
/// before it allocates and acked to its actual live bytes after, so freed
/// temporaries release on drop instead of lingering in the charge.
pub(super) struct Bounds<'a> {
    resources: &'a Resources,
    deadline: Instant,
    cells: Box<dyn ResourceAllocation>,
    cells_live: u64,
    cache: Box<dyn ResourceAllocation>,
    cache_live: u64,
}

impl<'a> Bounds<'a> {
    pub(super) fn new(resources: &'a Resources, deadline: Instant) -> Self {
        Self {
            resources,
            deadline,
            cells: resources.allocation(),
            cells_live: 0,
            cache: resources.allocation(),
            cache_live: 0,
        }
    }

    /// Checkpoint the explicit clock and the port.
    pub(super) fn checkpoint(&self) -> Result<()> {
        if Instant::now() >= self.deadline {
            return Err(document_refused(ResourceRefusal::Deadline));
        }
        self.resources
            .checkpoint()
            .map_err(machine_memory_refused)?;
        if Instant::now() >= self.deadline {
            return Err(document_refused(ResourceRefusal::Deadline));
        }
        Ok(())
    }

    /// Checkpoint, then reserve before a cells-map allocation. The caller
    /// allocates, then names the new total via [`Self::mark_cells`] before
    /// the next take on this scope: `materialized` consumes all pending.
    pub(super) fn take_cells(&mut self, bytes: u64, measured: u64) -> Result<()> {
        self.checkpoint()?;
        self.cells
            .grow(bytes, measured)
            .map_err(machine_memory_refused)?;
        if Instant::now() >= self.deadline {
            return Err(document_refused(ResourceRefusal::Deadline));
        }
        Ok(())
    }

    /// Name the cells map's TOTAL live bytes after an allocation, release
    /// or ownership transfer. Never waits or refuses.
    pub(super) fn mark_cells(&mut self, total: u64) {
        self.cells_live = total;
        self.cells.materialized(total);
    }

    /// The cells map's live bytes named so far.
    pub(super) fn live_cells(&self) -> u64 {
        self.cells_live
    }

    /// Checkpoint, then reserve before a shared-cache allocation; see
    /// [`Self::take_cells`] for the take/allocate/mark cycle.
    pub(super) fn take_cache(&mut self, bytes: u64, measured: u64) -> Result<()> {
        self.checkpoint()?;
        self.cache
            .grow(bytes, measured)
            .map_err(machine_memory_refused)?;
        if Instant::now() >= self.deadline {
            return Err(document_refused(ResourceRefusal::Deadline));
        }
        Ok(())
    }

    /// Name the shared cache's TOTAL live bytes. Never waits or refuses.
    pub(super) fn mark_cache(&mut self, total: u64) {
        self.cache_live = total;
        self.cache.materialized(total);
    }

    /// The shared cache's live bytes named so far.
    pub(super) fn live_cache(&self) -> u64 {
        self.cache_live
    }

    /// Release the shared cache's charge once the cache itself is freed.
    pub(super) fn release_cache(&mut self) {
        self.mark_cache(0);
    }

    /// A fresh scope for one temporary: grow it before the temporary
    /// allocates, ack its actual live bytes after, drop it with the
    /// temporary.
    pub(super) fn temp(&self) -> Box<dyn ResourceAllocation> {
        self.resources.allocation()
    }

    /// The cells scope, returned with the map; the cache scope drops here,
    /// already released beside the freed cache.
    pub(super) fn into_cells_scope(self) -> Box<dyn ResourceAllocation> {
        self.cells
    }
}

/// Checkpoint when bounded; no-op for the legacy path.
pub(super) fn checkpoint(bounds: &Option<Bounds<'_>>) -> Result<()> {
    if let Some(b) = bounds {
        b.checkpoint()?;
    }
    Ok(())
}

/// A fresh temp scope when bounded; `None` for the legacy path.
pub(super) fn temp_scope(bounds: &Option<Bounds<'_>>) -> Option<Box<dyn ResourceAllocation>> {
    bounds.as_ref().map(Bounds::temp)
}

/// Checkpoint, then grow a temp scope before its allocation; no-op for the
/// legacy path.
pub(super) fn grow_temp(
    scope: &mut Option<Box<dyn ResourceAllocation>>,
    bounds: &Option<Bounds<'_>>,
    bytes: u64,
    measured: u64,
) -> Result<()> {
    if let (Some(scope), Some(bounds)) = (scope.as_mut(), bounds.as_ref()) {
        bounds.checkpoint()?;
        scope
            .grow(bytes, measured)
            .map_err(machine_memory_refused)?;
        if Instant::now() >= bounds.deadline {
            return Err(document_refused(ResourceRefusal::Deadline));
        }
    }
    Ok(())
}

/// Name a temp scope's TOTAL live bytes after its allocation; no-op for the
/// legacy path. Never waits or refuses.
pub(super) fn ack_temp(scope: &mut Option<Box<dyn ResourceAllocation>>, live: u64) {
    if let Some(scope) = scope.as_mut() {
        scope.materialized(live);
    }
}

/// Checkpoint, then reserve before a cells-map allocation; no-op for the
/// legacy path.
pub(super) fn take_cells(bounds: &mut Option<Bounds<'_>>, bytes: u64, measured: u64) -> Result<()> {
    if let Some(b) = bounds {
        b.take_cells(bytes, measured)?;
    }
    Ok(())
}

/// Name the cells map's TOTAL live bytes; no-op for the legacy path.
pub(super) fn mark_cells(bounds: &mut Option<Bounds<'_>>, total: u64) {
    if let Some(b) = bounds {
        b.mark_cells(total);
    }
}

/// The cells map's live bytes named so far; zero for the legacy path.
pub(super) fn live_cells(bounds: &Option<Bounds<'_>>) -> u64 {
    bounds.as_ref().map_or(0, Bounds::live_cells)
}

/// Checkpoint, then reserve before a shared-cache allocation; no-op for the
/// legacy path.
pub(super) fn take_cache(bounds: &mut Option<Bounds<'_>>, bytes: u64, measured: u64) -> Result<()> {
    if let Some(b) = bounds {
        b.take_cache(bytes, measured)?;
    }
    Ok(())
}

/// Name the shared cache's TOTAL live bytes; no-op for the legacy path.
pub(super) fn mark_cache(bounds: &mut Option<Bounds<'_>>, total: u64) {
    if let Some(b) = bounds {
        b.mark_cache(total);
    }
}

/// The shared cache's live bytes named so far; zero for the legacy path.
pub(super) fn live_cache(bounds: &Option<Bounds<'_>>) -> u64 {
    bounds.as_ref().map_or(0, Bounds::live_cache)
}

/// Release the shared cache's charge; no-op for the legacy path.
pub(super) fn release_cache(bounds: &mut Option<Bounds<'_>>) {
    if let Some(b) = bounds {
        b.release_cache();
    }
}

/// A retained-package failure as the engine error: a resource refusal as
/// itself (typed floor / timed-out wait), a ceiling the package passed as
/// a refusal naming its dimension, anything else invalid under the
/// existing typed-answer message.
pub(super) fn retained_invalid(error: oneiron_docedit::retained_opc::Error) -> Error {
    if let Some(refusal) = error.resource() {
        return machine_memory_refused(refusal);
    }
    if let Some(hit) = error.capacity() {
        return Error::Refused(hit.to_string());
    }
    invalid()
}

/// Move an owned normalized attribute without reserving a clone that is
/// not made. Borrowed input needs one real clone; both paths name the
/// destination before releasing the source charge.
fn own_attribute(
    decoded: Cow<'_, str>,
    source: &mut Option<Box<dyn ResourceAllocation>>,
    target: &mut Option<Box<dyn ResourceAllocation>>,
    target_live: &mut u64,
    bounds: &Option<Bounds<'_>>,
) -> Result<String> {
    let owned = match decoded {
        Cow::Borrowed(value) => {
            let bytes = wide(value.len());
            grow_temp(target, bounds, bytes, bytes)?;
            value.to_owned()
        }
        Cow::Owned(value) => value,
    };
    *target_live = target_live.saturating_add(wide(owned.capacity()));
    ack_temp(target, *target_live);
    ack_temp(source, 0);
    Ok(owned)
}

/// Grow a String only when its current capacity cannot hold the append.
/// Reserve the additional capacity, not the already-live prefix. The same
/// scope can include `other_live` bytes belonging to sibling buffers.
pub(super) fn append_temp(
    scope: &mut Option<Box<dyn ResourceAllocation>>,
    bounds: &Option<Bounds<'_>>,
    value: &mut String,
    text: &str,
    other_live: u64,
) -> Result<()> {
    let needed = value.len().saturating_add(text.len());
    if needed > value.capacity() {
        let bytes = wide(needed - value.capacity());
        grow_temp(scope, bounds, bytes, bytes)?;
        value.reserve_exact(needed - value.len());
        ack_temp(scope, other_live.saturating_add(wide(value.capacity())));
    }
    value.push_str(text);
    Ok(())
}

/// Bounded workbook to worksheet-part resolution for the retained path.
/// Same join as `named_sheet_part` (exact sheet name, exactly one match,
/// `r:id` to relationship to worksheet target, or `sheetId` fallback when
/// the workbook has no relationships part), but streamed with per-event
/// checkpoints and one scope per decoded temporary, never via an unbounded
/// element tree. Borrowed quick-xml events allocate nothing per event, so
/// no per-event charge; only decoded/stored temporaries take scopes.
/// Package parts stay borrowed and uncounted.
pub(super) fn named_sheet_part_retained(
    pkg: &RetainedPackage,
    name: &str,
    bounds: &mut Option<Bounds<'_>>,
) -> Result<Scoped<String>> {
    checkpoint(bounds)?;
    let workbook = pkg
        .part("xl/workbook.xml")
        .map_err(retained_invalid)?
        .ok_or_else(invalid)?;
    checkpoint(bounds)?;
    let rels = pkg
        .part("xl/_rels/workbook.xml.rels")
        .map_err(retained_invalid)?;
    checkpoint(bounds)?;
    let target = workbook_sheet_target(workbook.as_slice(), name, rels.as_deref(), bounds)?;
    if !target.value.starts_with("xl/worksheets/") || !target.value.ends_with(".xml") {
        return Err(invalid());
    }
    checkpoint(bounds)?;
    let exists = pkg
        .names()
        .any(|candidate| candidate == target.value.as_str());
    if !exists {
        return Err(invalid());
    }
    Ok(target)
}

/// The worksheet part a workbook names for `name`: exactly one `sheet`
/// with that unqualified `name`, joined via its `r:id` to exactly one
/// worksheet relationship, or via `sheetId` when `rels` is `None`.
fn workbook_sheet_target(
    workbook: &[u8],
    name: &str,
    rels: Option<&[u8]>,
    bounds: &mut Option<Bounds<'_>>,
) -> Result<Scoped<String>> {
    checkpoint(bounds)?;
    std::str::from_utf8(workbook).map_err(|_| invalid())?;
    let mut reader = NsReader::from_reader(workbook);
    // The matched sheet's `r:id` / `sheetId` with their scope: named once a
    // sheet called `name` matches; freed before the target is built.
    let mut matched_scope = temp_scope(bounds);
    let mut matched_live: u64 = 0;
    let mut matched_id: Option<Option<String>> = None;
    let mut matched_sheet_id: Option<Option<String>> = None;
    loop {
        checkpoint(bounds)?;
        // Borrowed events: no per-event allocation, checkpoint only.
        let event = reader.read_event().map_err(|_| invalid())?;
        match event {
            Event::Start(tag) | Event::Empty(tag) => {
                // Strictness matches `opc_xml::elements`: any unknown prefix
                // or bad attribute value anywhere is invalid, even outside
                // the sheet join.
                let (ns, local) = reader.resolver().resolve_element(tag.name());
                let is_sheet = match ns {
                    ResolveResult::Bound(uri) => {
                        local.as_ref() == "sheet" && uri.as_ref().as_bytes() == SHEET_NS
                    }
                    ResolveResult::Unbound => local.as_ref() == "sheet",
                    ResolveResult::Unknown(_) => return Err(invalid()),
                };
                // One element's candidate strings with their scope: freed at
                // the element's end unless this sheet matches `name`.
                let mut elem_scope = temp_scope(bounds);
                let mut elem_live: u64 = 0;
                let mut sheet_name: Option<String> = None;
                let mut rel_id: Option<String> = None;
                let mut sheet_id: Option<String> = None;
                for attr in tag.attributes() {
                    checkpoint(bounds)?;
                    let attr = attr.map_err(|_| invalid())?;
                    let mut decode = temp_scope(bounds);
                    if attr.value.contains(['&', '\t', '\r', '\n']) {
                        let bytes = wide(attr.value.len());
                        grow_temp(&mut decode, bounds, bytes, bytes)?;
                    }
                    let key_bytes = attr.key.as_ref();
                    let is_xmlns = key_bytes == "xmlns" || key_bytes.starts_with("xmlns:");
                    let (ans, alocal) = reader.resolver().resolve_attribute(attr.key);
                    if !is_xmlns {
                        match ans {
                            ResolveResult::Bound(_) | ResolveResult::Unbound => {}
                            ResolveResult::Unknown(_) => return Err(invalid()),
                        }
                    }
                    let decoded = attr
                        .normalized_value(quick_xml::XmlVersion::default())
                        .map_err(|_| invalid())?;
                    ack_temp(
                        &mut decode,
                        match &decoded {
                            Cow::Borrowed(_) => 0,
                            Cow::Owned(owned) => wide(owned.capacity()),
                        },
                    );
                    if !is_sheet || is_xmlns {
                        continue;
                    }
                    let key = alocal.as_ref();
                    match ans {
                        ResolveResult::Unbound if key == "name" && sheet_name.is_none() => {
                            let owned = own_attribute(
                                decoded,
                                &mut decode,
                                &mut elem_scope,
                                &mut elem_live,
                                bounds,
                            )?;
                            sheet_name = Some(owned);
                        }
                        ResolveResult::Unbound if key == "sheetId" && sheet_id.is_none() => {
                            let owned = own_attribute(
                                decoded,
                                &mut decode,
                                &mut elem_scope,
                                &mut elem_live,
                                bounds,
                            )?;
                            sheet_id = Some(owned);
                        }
                        ResolveResult::Bound(uri)
                            if key == "id"
                                && uri.as_ref().as_bytes() == REL_ATTR_NS
                                && rel_id.is_none() =>
                        {
                            let owned = own_attribute(
                                decoded,
                                &mut decode,
                                &mut elem_scope,
                                &mut elem_live,
                                bounds,
                            )?;
                            rel_id = Some(owned);
                        }
                        _ => {}
                    }
                }
                if !is_sheet {
                    continue;
                }
                if sheet_name.as_deref() != Some(name) {
                    continue;
                }
                if matched_id.is_some() {
                    return Err(invalid());
                }
                // Transfer the matched element's `r:id` / `sheetId` (no new
                // reserve): the compared name frees here; release the
                // element scope only after marking the matched scope. A
                // concurrent admission never sees these live bytes released.
                drop(sheet_name);
                let transfer = rel_id
                    .as_ref()
                    .map_or(0, |s| wide(s.capacity()))
                    .saturating_add(sheet_id.as_ref().map_or(0, |s| wide(s.capacity())));
                matched_live = matched_live.saturating_add(transfer);
                ack_temp(&mut matched_scope, matched_live);
                drop(elem_scope);
                matched_id = Some(rel_id);
                matched_sheet_id = Some(sheet_id);
            }
            Event::DocType(_) => return Err(invalid()),
            Event::Eof => break,
            _ => {}
        }
    }
    let (rel_id, sheet_id) = match (matched_id, matched_sheet_id) {
        (Some(rel_id), Some(sheet_id)) => (rel_id, sheet_id),
        _ => return Err(invalid()),
    };
    if let Some(rels) = rels {
        let id = rel_id.ok_or_else(invalid)?;
        let rel = workbook_relationship_target(rels, id.as_str(), bounds)?;
        drop(id);
        drop(sheet_id);
        ack_temp(&mut matched_scope, 0);
        if !rel.value.0.ends_with("/worksheet") || rel.value.2.as_deref() == Some("External") {
            return Err(invalid());
        }
        let mut scope = temp_scope(bounds);
        let target_est = wide(rel.value.1.len().saturating_add(3));
        grow_temp(&mut scope, bounds, target_est, target_est)?;
        let resolved = resolve_part_path("xl/", rel.value.1.as_str()).ok_or_else(invalid)?;
        ack_temp(&mut scope, wide(resolved.capacity()));
        drop(rel);
        Ok(Scoped {
            value: resolved,
            scope,
        })
    } else {
        let index = sheet_id
            .ok_or_else(invalid)?
            .parse::<u32>()
            .map_err(|_| invalid())?;
        if index == 0 {
            return Err(invalid());
        }
        drop(rel_id);
        ack_temp(&mut matched_scope, 0);
        let mut scope = temp_scope(bounds);
        grow_temp(&mut scope, bounds, wide(64), wide(64))?;
        let resolved = format!("xl/worksheets/sheet{index}.xml");
        ack_temp(&mut scope, wide(resolved.capacity()));
        Ok(Scoped {
            value: resolved,
            scope,
        })
    }
}

/// Exactly one `Relationship` with unqualified `Id == id` in a workbook
/// relationships part: its unqualified `Type`, `Target` and `TargetMode`.
fn workbook_relationship_target(
    rels: &[u8],
    id: &str,
    bounds: &mut Option<Bounds<'_>>,
) -> Result<Scoped<(String, String, Option<String>)>> {
    checkpoint(bounds)?;
    std::str::from_utf8(rels).map_err(|_| invalid())?;
    let mut reader = NsReader::from_reader(rels);
    // The matched relationship with its scope.
    let mut matched_scope = temp_scope(bounds);
    let mut matched: Option<(String, String, Option<String>)> = None;
    let mut matched_live: u64 = 0;
    loop {
        checkpoint(bounds)?;
        let event = reader.read_event().map_err(|_| invalid())?;
        match event {
            Event::Start(tag) | Event::Empty(tag) => {
                let (ns, local) = reader.resolver().resolve_element(tag.name());
                let is_rel = match ns {
                    ResolveResult::Bound(uri) => {
                        local.as_ref() == "Relationship" && uri.as_ref().as_bytes() == REL_NS
                    }
                    ResolveResult::Unbound => local.as_ref() == "Relationship",
                    ResolveResult::Unknown(_) => return Err(invalid()),
                };
                let mut elem_scope = temp_scope(bounds);
                let mut elem_live: u64 = 0;
                let mut rel_id: Option<String> = None;
                let mut rel_type: Option<String> = None;
                let mut target: Option<String> = None;
                let mut mode: Option<String> = None;
                for attr in tag.attributes() {
                    checkpoint(bounds)?;
                    let attr = attr.map_err(|_| invalid())?;
                    let mut decode = temp_scope(bounds);
                    if attr.value.contains(['&', '\t', '\r', '\n']) {
                        let bytes = wide(attr.value.len());
                        grow_temp(&mut decode, bounds, bytes, bytes)?;
                    }
                    let key_bytes = attr.key.as_ref();
                    let is_xmlns = key_bytes == "xmlns" || key_bytes.starts_with("xmlns:");
                    let (ans, alocal) = reader.resolver().resolve_attribute(attr.key);
                    if !is_xmlns {
                        match ans {
                            ResolveResult::Bound(_) | ResolveResult::Unbound => {}
                            ResolveResult::Unknown(_) => return Err(invalid()),
                        }
                    }
                    let decoded = attr
                        .normalized_value(quick_xml::XmlVersion::default())
                        .map_err(|_| invalid())?;
                    ack_temp(
                        &mut decode,
                        match &decoded {
                            Cow::Borrowed(_) => 0,
                            Cow::Owned(owned) => wide(owned.capacity()),
                        },
                    );
                    if !is_rel || is_xmlns {
                        continue;
                    }
                    if !matches!(ans, ResolveResult::Unbound) {
                        continue;
                    }
                    let key = alocal.as_ref();
                    if key == "Id" && rel_id.is_none() {
                        let owned = own_attribute(
                            decoded,
                            &mut decode,
                            &mut elem_scope,
                            &mut elem_live,
                            bounds,
                        )?;
                        rel_id = Some(owned);
                    } else if key == "Type" && rel_type.is_none() {
                        let owned = own_attribute(
                            decoded,
                            &mut decode,
                            &mut elem_scope,
                            &mut elem_live,
                            bounds,
                        )?;
                        rel_type = Some(owned);
                    } else if key == "Target" && target.is_none() {
                        let owned = own_attribute(
                            decoded,
                            &mut decode,
                            &mut elem_scope,
                            &mut elem_live,
                            bounds,
                        )?;
                        target = Some(owned);
                    } else if key == "TargetMode" && mode.is_none() {
                        let owned = own_attribute(
                            decoded,
                            &mut decode,
                            &mut elem_scope,
                            &mut elem_live,
                            bounds,
                        )?;
                        mode = Some(owned);
                    }
                }
                if !is_rel {
                    continue;
                }
                if rel_id.as_deref() != Some(id) {
                    continue;
                }
                if matched.is_some() {
                    return Err(invalid());
                }
                // Transfer the matched relationship (no new reserve): the
                // compared `Id` frees here; mark the matched scope before
                // releasing the element scope, also for concurrent callers.
                drop(rel_id);
                let transfer = rel_type
                    .as_ref()
                    .map_or(0, |s| wide(s.capacity()))
                    .saturating_add(target.as_ref().map_or(0, |s| wide(s.capacity())))
                    .saturating_add(mode.as_ref().map_or(0, |s| wide(s.capacity())));
                matched_live = matched_live.saturating_add(transfer);
                ack_temp(&mut matched_scope, matched_live);
                drop(elem_scope);
                matched = Some((
                    rel_type.ok_or_else(invalid)?,
                    target.ok_or_else(invalid)?,
                    mode,
                ));
            }
            Event::DocType(_) => return Err(invalid()),
            Event::Eof => break,
            _ => {}
        }
    }
    let found = matched.ok_or_else(invalid)?;
    Ok(Scoped {
        value: found,
        scope: matched_scope,
    })
}
