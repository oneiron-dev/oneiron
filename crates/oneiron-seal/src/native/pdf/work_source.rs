//! Ported static page-tree and resource-graph admission and copying (FIX 7980/8157).
//!
//! Ports the engine's `render/source` only: page-tree walk ([`pages`]),
//! signature rejection ([`reject_signatures`]), the static visual copy
//! ([`VisualCopy`]), glyph and page-content admission ([`glyph_content`],
//! [`PageContents`]), content balance ([`check_content`],
//! [`reject_inline_images`]), and box geometry ([`pdf_box`],
//! [`page_geometry`]).
//!
//! Behavior-identical to the engine except admission and bounds: every
//! decode runs through [`decoded`] against the call's operation ledger with
//! no per-stream codec bound (growth admitted, never refused past a row),
//! every buffer and map insertion is admitted first by `limits`, and the
//! recursion guards (page-tree and copy depth 64, glyph depth 32, content
//! nesting 64) refuse as [`InputInvalidCode::MalformedPdf`]. The engine's
//! `Limit`/`StreamBound` never arise here; `AlreadySigned` reads as
//! [`InputInvalidCode::ExistingSignature`].

use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;

use lopdf::content::Content;
use lopdf::{Dictionary, Document, Object, ObjectId, Stream};

use super::work::{WorkError, WorkLimits};
use super::work_present::{FieldGeometry, PageGeometry, render_field_geometry};
use super::work_streams::decoded;
use crate::error::InputInvalidCode;
use crate::memory::{MemoryLedger, SealMemoryRefusal};

type Result<T> = std::result::Result<T, WorkError>;

pub(super) fn resolved<'a>(
    doc: &'a Document,
    object: &'a Object,
    limits: &WorkLimits,
) -> Result<&'a Object> {
    doc.dereference(object)
        .map(|(_, object)| object)
        .map_err(|err| lopdf_error(limits, err))
}

fn name<'a>(
    doc: &'a Document,
    dict: &'a Dictionary,
    key: &[u8],
    limits: &WorkLimits,
) -> Result<Option<&'a [u8]>> {
    dict.get(key)
        .ok()
        .map(|value| {
            let object = resolved(doc, value, limits)?;
            object.as_name().map_err(|err| lopdf_error(limits, err))
        })
        .transpose()
}

pub(super) fn number(doc: &Document, value: &Object, limits: &WorkLimits) -> Result<f64> {
    match resolved(doc, value, limits)? {
        Object::Integer(value) => Ok(*value as f64),
        Object::Real(value) if value.is_finite() => Ok(f64::from(*value)),
        _ => Err(WorkError::Invalid(InputInvalidCode::MalformedPdf)),
    }
}

pub(super) fn pdf_box(doc: &Document, value: &Object, limits: &WorkLimits) -> Result<[f64; 4]> {
    let values = resolved(doc, value, limits)?
        .as_array()
        .map_err(|err| lopdf_error(limits, err))?;
    if values.len() != 4 {
        return Err(WorkError::Invalid(InputInvalidCode::InvalidGeometry));
    }
    let result = [
        number(doc, &values[0], limits)?,
        number(doc, &values[1], limits)?,
        number(doc, &values[2], limits)?,
        number(doc, &values[3], limits)?,
    ];
    render_field_geometry(
        &FieldGeometry {
            page: 1,
            x_percent: 0.0,
            y_percent: 0.0,
            width_percent: 100.0,
            height_percent: 100.0,
        },
        result,
    )?;
    Ok(result)
}

// Scan even unreachable and nested dictionaries before discarding anything.
// The walk keeps its own stack, so every object the file holds is scanned,
// however many and however deep lopdf's parser let them nest.
pub(super) fn reject_signatures(doc: &Document, limits: &WorkLimits) -> Result<()> {
    let mut stack: Vec<&Object> = Vec::new();
    reserve(limits.ledger, &mut stack, doc.objects.len())?;
    stack.extend(doc.objects.values());
    while let Some(value) = stack.pop() {
        let dict = match value {
            Object::Dictionary(dict) => dict,
            Object::Stream(stream) => &stream.dict,
            Object::Array(values) => {
                reserve(limits.ledger, &mut stack, values.len())?;
                stack.extend(values.iter());
                continue;
            }
            _ => continue,
        };
        if matches!(
            name(doc, dict, b"Type", limits)?,
            Some(b"Sig" | b"DocTimeStamp")
        ) || name(doc, dict, b"FT", limits)? == Some(b"Sig")
            || [
                b"ByteRange".as_slice(),
                b"Lock",
                b"DocMDP",
                b"FieldMDP",
                b"UR3",
            ]
            .iter()
            .any(|key| dict.has(key))
        {
            return Err(WorkError::Invalid(InputInvalidCode::ExistingSignature));
        }
        reserve(limits.ledger, &mut stack, dict.len())?;
        stack.extend(dict.iter().map(|(_, value)| value));
    }
    Ok(())
}

pub(super) fn pages<'a>(
    doc: &'a Document,
    id: ObjectId,
    mut inherited: BTreeMap<&'static [u8], &'a Object>,
    seen: &mut BTreeSet<ObjectId>,
    out: &mut Vec<BTreeMap<&'static [u8], &'a Object>>,
    depth: usize,
    limits: &WorkLimits,
) -> Result<()> {
    // A node met twice is a cycle. The depth guard bounds this recursion,
    // not the pages: a page tree of fanout two holds 2^64 pages at it.
    if depth > 64 {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
    }
    btree::<ObjectId, ()>(limits.ledger, 1)?;
    if !seen.insert(id) {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
    }
    let node = doc
        .get_dictionary(id)
        .map_err(|err| lopdf_error(limits, err))?;
    for key in [b"MediaBox".as_slice(), b"CropBox", b"Resources", b"Rotate"] {
        if let Ok(value) = node.get(key) {
            btree::<&[u8], &Object>(limits.ledger, 1)?;
            inherited.insert(key, value);
        }
    }
    match name(doc, node, b"Type", limits)? {
        Some(b"Pages") => {
            let before = out.len();
            let kids = resolved(
                doc,
                node.get(b"Kids").map_err(|err| lopdf_error(limits, err))?,
                limits,
            )?
            .as_array()
            .map_err(|err| lopdf_error(limits, err))?;
            for child in kids {
                let child_id = child
                    .as_reference()
                    .map_err(|err| lopdf_error(limits, err))?;
                btree::<&[u8], &Object>(limits.ledger, inherited.len())?;
                pages(
                    doc,
                    child_id,
                    inherited.clone(),
                    seen,
                    out,
                    depth + 1,
                    limits,
                )?;
            }
            let count = node
                .get(b"Count")
                .map_err(|err| lopdf_error(limits, err))?
                .as_i64()
                .map_err(|err| lopdf_error(limits, err))?;
            if count != (out.len() - before) as i64 {
                return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
            }
        }
        Some(b"Page") => {
            for key in [
                b"Contents".as_slice(),
                b"Annots",
                b"UserUnit",
                b"Group",
                b"TrimBox",
                b"BleedBox",
                b"ArtBox",
            ] {
                if let Ok(value) = node.get(key) {
                    btree::<&[u8], &Object>(limits.ledger, 1)?;
                    inherited.insert(key, value);
                }
            }
            push(limits.ledger, out, inherited)?;
        }
        _ => return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf)),
    }
    Ok(())
}

// Copy only the static visual graph into a fresh document, never catalog,
// annotation, form, metadata, action or attachment graphs. Cycles fail closed.
// Each indirect object is copied once, however many pages share it, so the
// copy grows with the source and every insertion is admitted (Rule 5).
pub(super) struct VisualCopy<'a> {
    pub(super) source: &'a Document,
    pub(super) ids: BTreeMap<ObjectId, ObjectId>,
    pub(super) active: BTreeSet<ObjectId>,
}

impl VisualCopy<'_> {
    pub(super) fn copy(
        &mut self,
        out: &mut Document,
        value: &Object,
        depth: usize,
        limits: &WorkLimits,
    ) -> Result<Object> {
        // Bounds this recursion's stack, not the graph's size.
        if depth > 64 {
            return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
        }
        Ok(match value {
            Object::Reference(id) => {
                if let Some(mapped) = self.ids.get(id) {
                    return Ok((*mapped).into());
                }
                btree::<ObjectId, ()>(limits.ledger, 1)?;
                if !self.active.insert(*id) {
                    return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf));
                }
                let object = self
                    .source
                    .objects
                    .get(id)
                    .ok_or(WorkError::Invalid(InputInvalidCode::MalformedPdf))?;
                let copied = self.copy(out, object, depth + 1, limits)?;
                btree::<ObjectId, Object>(limits.ledger, 1)?;
                let mapped = out.add_object(copied);
                self.active.remove(id);
                btree::<ObjectId, ObjectId>(limits.ledger, 1)?;
                self.ids.insert(*id, mapped);
                mapped.into()
            }
            Object::Array(values) => {
                let mut copied: Vec<Object> = Vec::new();
                reserve(limits.ledger, &mut copied, values.len())?;
                for value in values {
                    let object = self.copy(out, value, depth + 1, limits)?;
                    push(limits.ledger, &mut copied, object)?;
                }
                Object::Array(copied)
            }
            Object::Dictionary(dict) => self.dictionary(out, dict, depth, limits)?.into(),
            Object::Stream(stream) => {
                if stream.dict.has(b"F") {
                    return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf));
                }
                // Form and tiling-pattern streams are executable page content,
                // not opaque bytes. Apply the same static-content admission.
                if name(self.source, &stream.dict, b"Subtype", limits)? == Some(b"Form")
                    || stream.dict.has(b"PatternType")
                {
                    // organ: admitted, not refused (FIX 7980)
                    let mut content = decoded(stream, limits)?;
                    reserve(limits.ledger, &mut content, 1)?;
                    content.push(b'\n');
                    check_content(&content, limits)?;
                }
                limits
                    .ledger
                    .admit_len::<u8>(stream.content.len())
                    .map_err(WorkError::Memory)?;
                Object::Stream(Stream::new(
                    self.dictionary(out, &stream.dict, depth, limits)?,
                    stream.content.clone(),
                ))
            }
            Object::Name(bytes) | Object::String(bytes, _) => {
                limits
                    .ledger
                    .admit_len::<u8>(bytes.len())
                    .map_err(WorkError::Memory)?;
                value.clone()
            }
            _ => value.clone(),
        })
    }

    pub(super) fn resources(
        &mut self,
        out: &mut Document,
        value: &Object,
        depth: usize,
        limits: &WorkLimits,
    ) -> Result<Dictionary> {
        if depth > 64 {
            return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
        }
        let resources = resolved(self.source, value, limits)?
            .as_dict()
            .map_err(|err| lopdf_error(limits, err))?;
        let mut copied = Dictionary::new();
        for (kind, members) in resources {
            if kind == b"ProcSet" {
                let object = self.copy(out, members, depth + 1, limits)?;
                limits
                    .ledger
                    .admit_len::<u8>(kind.len())
                    .map_err(WorkError::Memory)?;
                btree::<Vec<u8>, Object>(limits.ledger, 1)?;
                copied.set(kind.clone(), object);
                continue;
            }
            if !matches!(
                kind.as_slice(),
                b"Font"
                    | b"XObject"
                    | b"ExtGState"
                    | b"ColorSpace"
                    | b"Pattern"
                    | b"Shading"
                    | b"Properties"
            ) {
                return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf));
            }
            let mut map = Dictionary::new();
            for (key, object) in resolved(self.source, members, limits)?
                .as_dict()
                .map_err(|err| lopdf_error(limits, err))?
            {
                if kind == b"XObject" {
                    let stream = resolved(self.source, object, limits)?
                        .as_stream()
                        .map_err(|err| lopdf_error(limits, err))?;
                    if !matches!(
                        name(self.source, &stream.dict, b"Subtype", limits)?,
                        Some(b"Form" | b"Image")
                    ) {
                        return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf));
                    }
                }
                let object = self.copy(out, object, depth + 1, limits)?;
                limits
                    .ledger
                    .admit_len::<u8>(key.len())
                    .map_err(WorkError::Memory)?;
                btree::<Vec<u8>, Object>(limits.ledger, 1)?;
                map.set(key.clone(), object);
            }
            limits
                .ledger
                .admit_len::<u8>(kind.len())
                .map_err(WorkError::Memory)?;
            btree::<Vec<u8>, Object>(limits.ledger, 1)?;
            copied.set(kind.clone(), map);
        }
        Ok(copied)
    }

    fn dictionary(
        &mut self,
        out: &mut Document,
        dict: &Dictionary,
        depth: usize,
        limits: &WorkLimits,
    ) -> Result<Dictionary> {
        if [
            b"AA".as_slice(),
            b"A",
            b"OpenAction",
            b"JS",
            b"JavaScript",
            b"EF",
            b"AF",
            b"EmbeddedFiles",
            b"XFA",
            b"AcroForm",
            b"Annots",
            b"OC",
            b"OCProperties",
            b"Ref",
            b"Alternates",
            b"OPI",
        ]
        .iter()
        .any(|key| dict.has(key))
            || matches!(
                name(self.source, dict, b"Type", limits)?,
                Some(
                    b"Filespec"
                        | b"EmbeddedFile"
                        | b"Annot"
                        | b"Action"
                        | b"OCG"
                        | b"OCMD"
                        | b"Catalog"
                        | b"Page"
                        | b"Pages"
                        | b"ObjStm"
                        | b"XRef"
                )
            )
            || matches!(
                name(self.source, dict, b"Subtype", limits)?,
                Some(b"PS" | b"RichMedia" | b"Movie" | b"Sound" | b"Screen" | b"3D")
            )
            || name(self.source, dict, b"S", limits)?.is_some_and(|s| {
                !(matches!(s, b"Transparency" | b"Alpha" | b"Luminosity")
                    || dict.has_type(b"OutputIntent")
                        && matches!(s, b"GTS_PDFX" | b"GTS_PDFA1" | b"ISO_PDFE1"))
            })
        {
            return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf));
        }
        let mut copied = Dictionary::new();
        for (key, value) in dict {
            if !matches!(key.as_slice(), b"Length" | b"Metadata" | b"PieceInfo") {
                let object = if key == b"Resources" {
                    self.resources(out, value, depth + 1, limits)?.into()
                } else if key == b"CharProcs" {
                    let mut glyphs = Dictionary::new();
                    for (glyph_name, glyph) in resolved(self.source, value, limits)?
                        .as_dict()
                        .map_err(|err| lopdf_error(limits, err))?
                    {
                        let mut content = Vec::new();
                        glyph_content(self.source, glyph, &mut content, 0, limits)?;
                        check_content(&content, limits)?;
                        let object = self.copy(out, glyph, depth + 1, limits)?;
                        limits
                            .ledger
                            .admit_len::<u8>(glyph_name.len())
                            .map_err(WorkError::Memory)?;
                        btree::<Vec<u8>, Object>(limits.ledger, 1)?;
                        glyphs.set(glyph_name.clone(), object);
                    }
                    glyphs.into()
                } else {
                    self.copy(out, value, depth + 1, limits)?
                };
                limits
                    .ledger
                    .admit_len::<u8>(key.len())
                    .map_err(WorkError::Memory)?;
                btree::<Vec<u8>, Object>(limits.ledger, 1)?;
                copied.set(key.clone(), object);
            }
        }
        Ok(copied)
    }
}

/// A Type 3 glyph's content: its stream, or the streams an array of them
/// names, each decoded admitted, never refused past a codec bound.
fn glyph_content(
    doc: &Document,
    value: &Object,
    bytes: &mut Vec<u8>,
    depth: usize,
    limits: &WorkLimits,
) -> Result<()> {
    // Bounds this recursion's stack, not the content's size.
    if depth > 32 {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
    }
    match resolved(doc, value, limits)? {
        Object::Array(values) => {
            for value in values {
                glyph_content(doc, value, bytes, depth + 1, limits)?;
            }
        }
        Object::Stream(stream) => {
            if stream.dict.has(b"F") {
                return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf));
            }
            // organ: admitted, not refused (FIX 7980)
            let decoded_bytes = decoded(stream, limits)?;
            reserve(limits.ledger, bytes, decoded_bytes.len().saturating_add(1))?;
            bytes.extend_from_slice(&decoded_bytes);
            bytes.push(b'\n');
        }
        _ => return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf)),
    }
    Ok(())
}

/// The page contents admitted so far, each by the streams it names in order,
/// and every content stream decoded so far, by its id: content that many
/// pages share is checked once, and a stream named many times, on one page or
/// across pages, decodes once for the whole preparation.
#[derive(Default)]
pub(super) struct PageContents {
    checked: BTreeSet<Vec<ObjectId>>,
    decoded: BTreeMap<ObjectId, Vec<u8>>,
}

impl PageContents {
    /// Admits a page's `/Contents` (a stream or an array of streams, ISO
    /// 32000-1 section 7.7.3.3, Table 30) and returns its streams, in order,
    /// a stream the page names twice included twice. Each distinct stream
    /// decodes once admitted, and the page's streams are checked as the one
    /// program a reader concatenates them into, in naming order, repeats
    /// included: a fragment is never checked for balance alone.
    pub(super) fn admit(
        &mut self,
        doc: &Document,
        value: &Object,
        limits: &WorkLimits,
    ) -> Result<Vec<ObjectId>> {
        let stream = |value: &Object| -> Result<ObjectId> {
            match doc
                .dereference(value)
                .map_err(|err| lopdf_error(limits, err))?
            {
                (Some(id), Object::Stream(stream)) if !stream.dict.has(b"F") => Ok(id),
                (Some(_), Object::Stream(_)) => {
                    Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf))
                }
                _ => Err(WorkError::Invalid(InputInvalidCode::MalformedPdf)),
            }
        };
        let streams = match doc
            .dereference(value)
            .map_err(|err| lopdf_error(limits, err))?
        {
            (_, Object::Array(values)) => {
                let mut ids: Vec<ObjectId> = Vec::new();
                reserve(limits.ledger, &mut ids, values.len())?;
                for value in values {
                    push(limits.ledger, &mut ids, stream(value)?)?;
                }
                ids
            }
            _ => {
                let mut ids: Vec<ObjectId> = Vec::new();
                reserve(limits.ledger, &mut ids, 1)?;
                push(limits.ledger, &mut ids, stream(value)?)?;
                ids
            }
        };
        if self.checked.contains(&streams) {
            return Ok(streams);
        }
        let mut content: Vec<u8> = Vec::new();
        for id in &streams {
            let bytes = match self.decoded.entry(*id) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    // organ: admitted, not refused (FIX 7980)
                    let bytes = decoded(
                        doc.get_object(*id)
                            .map_err(|err| lopdf_error(limits, err))?
                            .as_stream()
                            .map_err(|err| lopdf_error(limits, err))?,
                        limits,
                    )?;
                    btree::<ObjectId, Vec<u8>>(limits.ledger, 1)?;
                    entry.insert(bytes)
                }
            };
            reserve(limits.ledger, &mut content, bytes.len().saturating_add(1))?;
            content.extend_from_slice(bytes);
            content.push(b'\n');
        }
        check_content(&content, limits)?;
        limits
            .ledger
            .admit_len::<ObjectId>(streams.len())
            .map_err(WorkError::Memory)?;
        btree::<Vec<ObjectId>, ()>(limits.ledger, 1)?;
        self.checked.insert(streams.clone());
        Ok(streams)
    }
}

fn check_content(bytes: &[u8], limits: &WorkLimits) -> Result<()> {
    reject_inline_images(bytes)?;
    let content = Content::decode_strict(bytes).map_err(|err| lopdf_error(limits, err))?;
    let (mut graphics, mut marked, mut text) = (0i32, 0i32, false);
    for op in content.operations {
        match op.operator.as_str() {
            "q" => graphics += 1,
            "Q" => graphics -= 1,
            "BT" if !text => text = true,
            "ET" if text => text = false,
            "BT" | "ET" => return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf)),
            "BMC" | "BDC" => {
                if op.operands.first().and_then(|v| v.as_name().ok()) == Some(b"OC") {
                    return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf));
                }
                marked += 1;
            }
            "EMC" => marked -= 1,
            "BI" | "BX" | "EX" | "PS" => {
                return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf));
            }
            "cm" | "w" | "J" | "j" | "M" | "d" | "ri" | "i" | "gs" | "m" | "l" | "c" | "v"
            | "y" | "h" | "re" | "S" | "s" | "f" | "F" | "f*" | "B" | "B*" | "b" | "b*" | "n"
            | "W" | "W*" | "Tc" | "Tw" | "Tz" | "TL" | "Tf" | "Tr" | "Ts" | "Td" | "TD" | "Tm"
            | "T*" | "Tj" | "TJ" | "'" | "\"" | "d0" | "d1" | "CS" | "cs" | "SC" | "SCN" | "sc"
            | "scn" | "G" | "g" | "RG" | "rg" | "K" | "k" | "sh" | "Do" | "MP" | "DP" => {}
            _ => return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf)),
        }
        if !(0..=64).contains(&graphics) || !(0..=64).contains(&marked) {
            return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
        }
    }
    if graphics != 0 || marked != 0 || text {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
    }
    Ok(())
}

// lopdf's inline-image parser can recover by skipping bytes and assumes some
// dimensions/colorspaces. Refuse that grammar before invoking it, not after.
pub(super) fn reject_inline_images(bytes: &[u8]) -> Result<()> {
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                while i < bytes.len() && !matches!(bytes[i], b'\r' | b'\n') {
                    i += 1;
                }
            }
            b'(' => {
                i += 1;
                let mut depth = 1;
                while i < bytes.len() && depth > 0 {
                    match bytes[i] {
                        b'\\' => {
                            i += 1;
                        }
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                    i += 1;
                }
            }
            b'<' if bytes.get(i + 1) != Some(&b'<') => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'>' {
                    i += 1;
                }
                i += 1;
            }
            b'/' => {
                i += 1;
                while i < bytes.len()
                    && !bytes[i].is_ascii_whitespace()
                    && !b"()<>[]{}/%".contains(&bytes[i])
                {
                    i += 1;
                }
            }
            b if b.is_ascii_whitespace() || b"<>[]{}".contains(&b) => {
                i += 1;
            }
            _ => {
                let start = i;
                i += 1;
                while i < bytes.len()
                    && !bytes[i].is_ascii_whitespace()
                    && !b"()<>[]{}/%".contains(&bytes[i])
                {
                    i += 1;
                }
                if &bytes[start..i] == b"BI" {
                    return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf));
                }
            }
        }
    }
    Ok(())
}

/// Visible boxes are the CropBox/MediaBox intersection (PDF 32000-1 14.11.2).
pub(super) fn page_geometry(
    doc: &Document,
    page: &BTreeMap<&[u8], &Object>,
    limits: &WorkLimits,
) -> Result<PageGeometry> {
    let media = pdf_box(
        doc,
        page.get(b"MediaBox".as_slice())
            .ok_or(WorkError::Invalid(InputInvalidCode::MalformedPdf))?,
        limits,
    )?;
    let mut crop = page
        .get(b"CropBox".as_slice())
        .map(|value| pdf_box(doc, value, limits))
        .transpose()?
        .unwrap_or(media);
    crop = [
        crop[0].max(media[0]),
        crop[1].max(media[1]),
        crop[2].min(media[2]),
        crop[3].min(media[3]),
    ];
    let rotation = page
        .get(b"Rotate".as_slice())
        .map(|value| number(doc, value, limits))
        .transpose()?
        .unwrap_or(0.);
    if rotation.fract() != 0. || rotation % 90. != 0. {
        return Err(WorkError::Invalid(InputInvalidCode::InvalidGeometry));
    }
    let geometry = PageGeometry {
        crop,
        rotation: rotation.rem_euclid(360.) as u16,
        user_unit: page
            .get(b"UserUnit".as_slice())
            .map(|value| number(doc, value, limits))
            .transpose()?
            .unwrap_or(1.),
    };
    geometry.display_box()?;
    Ok(geometry)
}

/// A lopdf read failure as the organ reads it: a kept memory refusal as
/// itself, anything else as a malformed PDF, never the reverse.
fn lopdf_error(limits: &WorkLimits, err: lopdf::Error) -> WorkError {
    limits.ledger.refusal_of(&err).map_or(
        WorkError::Invalid(InputInvalidCode::MalformedPdf),
        WorkError::Memory,
    )
}

fn floor(bytes: usize) -> SealMemoryRefusal {
    SealMemoryRefusal::Floor {
        needed: u64::try_from(bytes).unwrap_or(u64::MAX),
        available: 0,
    }
}

fn layout_bytes<T>(len: usize) -> Option<usize> {
    len.checked_mul(size_of::<T>())
        .filter(|bytes| *bytes <= isize::MAX as usize)
}

/// Fallibly grow one vector under the call's operation ledger, with the
/// same double-capacity growth and old-buffer release as `admitted`.
fn reserve<T>(ledger: &MemoryLedger, output: &mut Vec<T>, additional: usize) -> Result<()> {
    let needed = output
        .len()
        .checked_add(additional)
        .ok_or_else(|| WorkError::Memory(floor(usize::MAX)))?;
    if needed <= output.capacity() {
        return Ok(());
    }
    let old_capacity = output.capacity();
    let target = old_capacity.saturating_mul(2).max(needed);
    let bytes = layout_bytes::<T>(target).ok_or_else(|| WorkError::Memory(floor(usize::MAX)))?;
    ledger.admit_len::<T>(target).map_err(WorkError::Memory)?;
    output
        .try_reserve_exact(target - output.len())
        .map_err(|_| WorkError::Memory(floor(bytes)))?;
    let old_bytes = layout_bytes::<T>(old_capacity).unwrap_or(0);
    ledger.release_admitted(u64::try_from(old_bytes).unwrap_or(u64::MAX));
    Ok(())
}

fn push<T>(ledger: &MemoryLedger, output: &mut Vec<T>, value: T) -> Result<()> {
    reserve(ledger, output, 1)?;
    output.push(value);
    Ok(())
}

const fn btree_node_bytes<K, V>() -> usize {
    11 * (size_of::<K>() + size_of::<V>()) + 12 * size_of::<usize>() + 64
}

const fn btree_entry_bytes<K, V>() -> usize {
    btree_node_bytes::<K, V>().div_ceil(5)
}

/// Admit the nodes of a BTreeMap/BTreeSet before insertion.
fn btree<K, V>(ledger: &MemoryLedger, entries: usize) -> Result<()> {
    let bytes = btree_entry_bytes::<K, V>()
        .checked_mul(entries)
        .and_then(|shares| shares.checked_add(btree_node_bytes::<K, V>()))
        .ok_or_else(|| WorkError::Memory(floor(usize::MAX)))?;
    ledger.admit_len::<u8>(bytes).map_err(WorkError::Memory)
}
