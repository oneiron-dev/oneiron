//! Bounded sparse-read admission for named-sheet cells (FIX 9817).
//! `Bounds` splits retained (cumulative live-until-end) from scratch (peak
//! temporaries); workbook/rels resolution streams under it. Parent `read`
//! owns grid parsing; this module owns admission only.

use super::super::{REL_NS, SHEET_NS, invalid};
use crate::edit_roundtrip::session_validate::resolve_part_path;
use crate::error::{Error, Result};
use crate::office_body::{document_refused, machine_memory_refused};
use oneiron_docedit::resource::{Hold, ResourceRefusal, Resources, wide};
use oneiron_docedit::retained_opc::Package as RetainedPackage;
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use std::time::Instant;

/// Relationship-attribute namespace for `r:id` (sheet to worksheet rel).
const REL_ATTR_NS: &[u8] = b"http://schemas.openxmlformats.org/officeDocument/2006/relationships";

/// Explicit deadline plus port for the bounded sparse read (FIX 9817).
/// `MeasuringPort` never stops at a deadline, so the clock is checked
/// alongside every port checkpoint. Retained holds cumulative live-until-end
/// (wanted values, cells/cache nodes); scratch holds peak temporaries
/// (attrmaps, decoded Cows, discarded shared prefix, workbook temps) via
/// `covered`, never cumulative volume. Both drop with the read; the live
/// reading carries the returned map after that.
pub(super) struct Bounds<'a> {
    resources: &'a Resources,
    deadline: Instant,
    retained: Hold,
    scratch: Hold,
    covered: u64,
}

impl<'a> Bounds<'a> {
    pub(super) fn new(resources: &'a Resources, deadline: Instant) -> Self {
        Self {
            resources,
            deadline,
            retained: resources.hold(),
            scratch: resources.hold(),
            covered: 0,
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

    /// Reserve `bytes` (all measured) for retained live-until-end.
    pub(super) fn take_retained(&mut self, bytes: u64) -> Result<()> {
        self.checkpoint()?;
        self.retained.take(bytes).map_err(machine_memory_refused)?;
        if Instant::now() >= self.deadline {
            return Err(document_refused(ResourceRefusal::Deadline));
        }
        Ok(())
    }

    /// Reserve `bytes` of which only `measured` were measured, for retained.
    pub(super) fn take_retained_estimate(&mut self, bytes: u64, measured: u64) -> Result<()> {
        self.checkpoint()?;
        self.retained
            .take_estimate(bytes, measured)
            .map_err(machine_memory_refused)?;
        if Instant::now() >= self.deadline {
            return Err(document_refused(ResourceRefusal::Deadline));
        }
        Ok(())
    }

    /// Hand retained bytes allocated so far to the live reading (resource.rs
    /// "lasts until they are"): drop the retained hold (returning its pending
    /// where live carries, absorbing its total where it cannot, FIX 10589)
    /// and start fresh, so later takes do not double-count history. Scratch
    /// peak is untouched.
    pub(super) fn hand_retained(&mut self) {
        self.retained = self.resources.hold();
    }

    /// Cover `bytes` of scratch live (peak, not volume): only growth past
    /// `covered` reaches the port. For temporaries dropped before the read
    /// ends (attrmaps, decoded Cows, discarded prefix, workbook temps).
    pub(super) fn cover(&mut self, bytes: u64) -> Result<()> {
        self.cover_estimate(bytes, bytes)
    }

    /// `cover` for `bytes` of which only `measured` were measured.
    pub(super) fn cover_estimate(&mut self, bytes: u64, measured: u64) -> Result<()> {
        self.checkpoint()?;
        if bytes > self.covered {
            let more = bytes - self.covered;
            // Only the uncovered growth is new; measured past covered is at
            // most the growth (estimates never hit the floor at once).
            let measured_more = measured.saturating_sub(self.covered).min(more);
            self.scratch
                .take_estimate(more, measured_more)
                .map_err(machine_memory_refused)?;
            self.covered = bytes;
        }
        if Instant::now() >= self.deadline {
            return Err(document_refused(ResourceRefusal::Deadline));
        }
        Ok(())
    }
}

/// Checkpoint when bounded; no-op for the legacy path.
pub(super) fn checkpoint(bounds: &Option<Bounds<'_>>) -> Result<()> {
    if let Some(b) = bounds {
        b.checkpoint()?;
    }
    Ok(())
}

/// Reserve retained when bounded; no-op for the legacy path.
pub(super) fn reserve_retained(bounds: &mut Option<Bounds<'_>>, bytes: u64) -> Result<()> {
    if let Some(b) = bounds {
        b.take_retained(bytes)?;
    }
    Ok(())
}

/// Reserve a retained estimate when bounded; no-op for the legacy path.
pub(super) fn reserve_retained_estimate(
    bounds: &mut Option<Bounds<'_>>,
    bytes: u64,
    measured: u64,
) -> Result<()> {
    if let Some(b) = bounds {
        b.take_retained_estimate(bytes, measured)?;
    }
    Ok(())
}

/// Hand retained to live when bounded; no-op for the legacy path.
pub(super) fn hand_retained(bounds: &mut Option<Bounds<'_>>) {
    if let Some(b) = bounds {
        b.hand_retained();
    }
}

/// Cover scratch peak when bounded; no-op for the legacy path.
pub(super) fn cover_scratch(bounds: &mut Option<Bounds<'_>>, bytes: u64) -> Result<()> {
    if let Some(b) = bounds {
        b.cover(bytes)?;
    }
    Ok(())
}

/// Cover a scratch estimate when bounded; no-op for the legacy path.
pub(super) fn cover_scratch_estimate(
    bounds: &mut Option<Bounds<'_>>,
    bytes: u64,
    measured: u64,
) -> Result<()> {
    if let Some(b) = bounds {
        b.cover_estimate(bytes, measured)?;
    }
    Ok(())
}

/// A retained-package failure as the engine error: a resource refusal as
/// itself (typed floor / timed-out wait), anything else invalid under the
/// existing typed-answer message. Capacity past the caller limits stays
/// invalid here (no new cap surface for this slice).
pub(super) fn retained_invalid(error: oneiron_docedit::retained_opc::Error) -> Error {
    error
        .resource()
        .map_or_else(invalid, machine_memory_refused)
}

/// Bounded workbook to worksheet-part resolution for the retained path.
/// Same join as `named_sheet_part` (exact sheet name, exactly one match,
/// `r:id` to relationship to worksheet target, or `sheetId` fallback when
/// the workbook has no relationships part), but streamed with per-event
/// checkpoints and scratch-peak (not volume) cover, never via an unbounded
/// element tree. Borrowed quick-xml events allocate nothing per event, so
/// no per-event charge; only decoded/stored temporaries cover peak.
pub(super) fn named_sheet_part_retained(
    pkg: &RetainedPackage,
    name: &str,
    bounds: &mut Option<Bounds<'_>>,
) -> Result<String> {
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
    if !target.starts_with("xl/worksheets/") || !target.ends_with(".xml") {
        return Err(invalid());
    }
    checkpoint(bounds)?;
    let exists = pkg.names().any(|candidate| candidate == target.as_str());
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
) -> Result<String> {
    checkpoint(bounds)?;
    std::str::from_utf8(workbook).map_err(|_| invalid())?;
    cover_scratch(bounds, wide(workbook.len().min(1024)))?;
    let mut reader = NsReader::from_reader(workbook);
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
                let mut sheet_name: Option<String> = None;
                let mut rel_id: Option<String> = None;
                let mut sheet_id: Option<String> = None;
                let mut elem_total: u64 = 0;
                for attr in tag.attributes() {
                    checkpoint(bounds)?;
                    let attr = attr.map_err(|_| invalid())?;
                    cover_scratch(bounds, wide(attr.value.len().saturating_add(64)))?;
                    let key_bytes = attr.key.as_ref();
                    let is_xmlns = key_bytes == b"xmlns" || key_bytes.starts_with(b"xmlns:");
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
                    if !is_sheet || is_xmlns {
                        continue;
                    }
                    let key = alocal.as_ref();
                    match ans {
                        ResolveResult::Unbound if key == "name" && sheet_name.is_none() => {
                            cover_scratch(bounds, elem_total.saturating_add(wide(decoded.len())))?;
                            elem_total = elem_total.saturating_add(wide(decoded.len()));
                            sheet_name = Some(decoded.into_owned());
                        }
                        ResolveResult::Unbound if key == "sheetId" && sheet_id.is_none() => {
                            cover_scratch(bounds, elem_total.saturating_add(wide(decoded.len())))?;
                            elem_total = elem_total.saturating_add(wide(decoded.len()));
                            sheet_id = Some(decoded.into_owned());
                        }
                        ResolveResult::Bound(uri)
                            if key == "id"
                                && uri.as_ref().as_bytes() == REL_ATTR_NS
                                && rel_id.is_none() =>
                        {
                            cover_scratch(bounds, elem_total.saturating_add(wide(decoded.len())))?;
                            elem_total = elem_total.saturating_add(wide(decoded.len()));
                            rel_id = Some(decoded.into_owned());
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
        let (rel_type, target, mode) = workbook_relationship_target(rels, id.as_str(), bounds)?;
        if !rel_type.ends_with("/worksheet") || mode.as_deref() == Some("External") {
            return Err(invalid());
        }
        reserve_retained(bounds, wide(target.len().saturating_add(3)))?;
        resolve_part_path("xl/", target.as_str()).ok_or_else(invalid)
    } else {
        let index = sheet_id
            .ok_or_else(invalid)?
            .parse::<u32>()
            .map_err(|_| invalid())?;
        if index == 0 {
            return Err(invalid());
        }
        reserve_retained(bounds, wide(64))?;
        Ok(format!("xl/worksheets/sheet{index}.xml"))
    }
}

/// Exactly one `Relationship` with unqualified `Id == id` in a workbook
/// relationships part: its unqualified `Type`, `Target` and `TargetMode`.
fn workbook_relationship_target(
    rels: &[u8],
    id: &str,
    bounds: &mut Option<Bounds<'_>>,
) -> Result<(String, String, Option<String>)> {
    checkpoint(bounds)?;
    std::str::from_utf8(rels).map_err(|_| invalid())?;
    cover_scratch(bounds, wide(rels.len().min(1024)))?;
    let mut reader = NsReader::from_reader(rels);
    let mut matched: Option<(String, String, Option<String>)> = None;
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
                let mut rel_id: Option<String> = None;
                let mut rel_type: Option<String> = None;
                let mut target: Option<String> = None;
                let mut mode: Option<String> = None;
                let mut elem_total: u64 = 0;
                for attr in tag.attributes() {
                    checkpoint(bounds)?;
                    let attr = attr.map_err(|_| invalid())?;
                    cover_scratch(bounds, wide(attr.value.len().saturating_add(64)))?;
                    let key_bytes = attr.key.as_ref();
                    let is_xmlns = key_bytes == b"xmlns" || key_bytes.starts_with(b"xmlns:");
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
                    if !is_rel || is_xmlns {
                        continue;
                    }
                    if !matches!(ans, ResolveResult::Unbound) {
                        continue;
                    }
                    let key = alocal.as_ref();
                    if key == "Id" && rel_id.is_none() {
                        cover_scratch(bounds, elem_total.saturating_add(wide(decoded.len())))?;
                        elem_total = elem_total.saturating_add(wide(decoded.len()));
                        rel_id = Some(decoded.into_owned());
                    } else if key == "Type" && rel_type.is_none() {
                        cover_scratch(bounds, elem_total.saturating_add(wide(decoded.len())))?;
                        elem_total = elem_total.saturating_add(wide(decoded.len()));
                        rel_type = Some(decoded.into_owned());
                    } else if key == "Target" && target.is_none() {
                        cover_scratch(bounds, elem_total.saturating_add(wide(decoded.len())))?;
                        elem_total = elem_total.saturating_add(wide(decoded.len()));
                        target = Some(decoded.into_owned());
                    } else if key == "TargetMode" && mode.is_none() {
                        cover_scratch(bounds, elem_total.saturating_add(wide(decoded.len())))?;
                        elem_total = elem_total.saturating_add(wide(decoded.len()));
                        mode = Some(decoded.into_owned());
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
    matched.ok_or_else(invalid)
}
