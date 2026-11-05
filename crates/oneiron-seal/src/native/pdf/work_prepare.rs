//! Ported esign PDF preparation orchestration (FIX 7980/8157).
//!
//! Ports the engine's `render` orchestration (`prepare_esign_pdf_within`/
//! `inspect_in`/`page_tree`/`BoundedOutput`, `E/render.rs`) into the organ
//! admission model, calling the six ports above. The audit-chain replay
//! (`evidence()`) stays engine-side: the host runs it there and lents its
//! checked output (`chain`/`trail`/`audit_rows`), so this file takes lent
//! scalars, never the engine model (F4).
//!
//! Behavior-identical except admission and bounds: every buffer, dictionary
//! entry, and fresh-document object is admitted against the call's operation
//! ledger first (via [`WorkLimits`]), never the engine `Stage`; growth is
//! admitted, never refused past a per-stream codec bound; the format bounds
//! are [`PDF_FORMAT_BYTES`]/[`PDF_FORMAT_OBJECTS`]. Value-shape refusals
//! stay engine-side and their checked scalars are lent in, marked below.
//!
//! Reuses [`super::work_preflight`] for loading, [`super::work_source`] for
//! the page walk and visual copy, [`super::work_burn`] for field burn-in and
//! annotation flattening, [`super::work_present`] for geometry, and
//! [`super::work_evidence`] for the certificate. The visual copy crosses to
//! `flatten` as a caller-supplied `copy` closure wired here to
//! `work_source`'s copier.

use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;

use lopdf::content::Content;
use lopdf::{Dictionary, Document, Object, ObjectId, Stream, dictionary};
use sha2::{Digest, Sha256};

use super::work::{WorkError, WorkLimits};
use super::work_burn::{BurnField, BurnImages, BurnValue, WorkRaster, burn_fields, flatten, op};
use super::work_evidence::{CertificateRequest, WorkRecipient, WorkSignature, certificate};
use super::work_preflight::load;
use super::work_present::PageGeometry;
use super::work_source::{
    PageContents, VisualCopy, page_geometry, pages, pdf_box, reject_signatures, resolved,
};
use crate::api::{PDF_FORMAT_BYTES, PDF_FORMAT_OBJECTS};
use crate::error::InputInvalidCode;
use crate::memory::{MemoryLedger, SealMemoryRefusal};

/// The preparation's lent scalars, replacing the engine's `PdfPreparation`
/// (`E/render.rs:143-151`) plus the replay-bound item row and raster map.
/// The host projects every field engine-side; the organ never indexes state
/// (F4). Every field is lent by the host, checked engine-side, except
/// `canonical_url`, whose narrow HTTPS grammar the organ verifies verbatim
/// in [`certificate`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct WorkPrepareRequest<'a> {
    /// `PdfPreparation.document_ref` (`E/render.rs:145`).
    pub document_ref: &'a str,
    /// `PdfPreparation.item` (`E/render.rs:146`).
    pub item: u32,
    /// NOT pre-checked; organ verifies narrow HTTPS grammar verbatim.
    pub canonical_url: &'a str,
    /// `state.document.items[item].artifact_ref` — host indexes.
    pub artifact_ref: &'a str,
    /// `state.document.items[item].original_version` — host indexes.
    pub original_version: u64,
    /// `state.document.title`.
    pub title: &'a str,
    /// `request.audit.len()`.
    pub audit_rows: usize,
    /// `state.rejection`.
    pub rejection: Option<&'a str>,
    /// `state.document.recipients`.
    pub recipients: &'a [WorkRecipient<'a>],
    /// `state.signatures.values()` in field-id order.
    pub signatures: &'a [WorkSignature<'a>],
    /// `state.document.fields` filtered `f.item == item`.
    pub fields: &'a [BurnField],
    /// `state.signatures: field.id -> value`.
    pub values: &'a BTreeMap<String, BurnValue>,
    /// `signature_images`.
    pub rasters: &'a BTreeMap<String, WorkRaster<'a>>,
    /// Audit-chain head from engine `evidence()` — replay stays engine-side.
    pub chain: [u8; 32],
    /// Full-trail lines from engine `evidence()`.
    pub trail: &'a [String],
}

/// The prepared PDF, as the engine's `PreparedEsignPdf`
/// (`E/render.rs:152-160`): same field names.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WorkPrepared {
    pub bytes: Vec<u8>,
    pub original_sha256: [u8; 32],
    pub audit_chain_sha256: [u8; 32],
    pub original_pages: u32,
    pub appendix_pages: u32,
}

/// Rewrite immutable original bytes and flatten all recorded fields, as the
/// engine's `prepare_esign_pdf_within` (`E/render.rs:208-364`): the same
/// gates, page walk, per-page rebuild, certificate, page tree, and bounded
/// write, with the audit replay lent in (`chain`/`trail`/`audit_rows`).
pub(crate) fn prepare_in(
    original: &[u8],
    request: &WorkPrepareRequest<'_>,
    limits: &WorkLimits<'_>,
) -> Result<WorkPrepared, WorkError> {
    if !original.starts_with(b"%PDF-") {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
    }
    let source = load(original, limits)?;
    reject_signatures(&source, limits)?;
    let catalog = source.catalog().map_err(|err| lopdf_error(limits, err))?;
    if [b"OCProperties".as_slice(), b"AlternatePresentations"]
        .iter()
        .any(|key| catalog.has(key))
    {
        return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf));
    }
    if let Ok(form) = catalog.get(b"AcroForm") {
        let form = resolved(&source, form, limits)?
            .as_dict()
            .map_err(|err| lopdf_error(limits, err))?;
        if form.has(b"XFA")
            || form
                .get(b"NeedAppearances")
                .ok()
                .is_some_and(|v| v.as_bool().ok() != Some(false))
        {
            return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf));
        }
    }
    let mut input_pages = Vec::new();
    let mut seen = BTreeSet::new();
    let pages_id = catalog
        .get(b"Pages")
        .map_err(|err| lopdf_error(limits, err))?
        .as_reference()
        .map_err(|err| lopdf_error(limits, err))?;
    pages(
        &source,
        pages_id,
        BTreeMap::new(),
        &mut seen,
        &mut input_pages,
        0,
        limits,
    )?;
    if input_pages.is_empty() {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
    }
    // organ: lent by the host, checked engine-side (`fields` already filtered `f.item == item`).
    if request
        .fields
        .iter()
        .any(|f| f.geometry.page as usize > input_pages.len())
    {
        return Err(WorkError::Invalid(InputInvalidCode::InvalidGeometry));
    }
    let original_sha256: [u8; 32] = Sha256::digest(original).into();
    let mut out = Document::with_version("1.7");
    out.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceTable;
    let parent = out.new_object_id();
    dictionary_built(limits.ledger, 4, 27, 30)?;
    object_insert(limits.ledger)?;
    let font = out.add_object(dictionary! { "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Courier", "Encoding" => "WinAnsiEncoding" });
    let mut copier = VisualCopy {
        source: &source,
        ids: BTreeMap::new(),
        active: BTreeSet::new(),
    };
    let mut kids: Vec<Object> = Vec::new();
    let mut images = BurnImages::default();
    let mut contents = PageContents::default();
    // Every page's content opens inside this one shared stream; the page's
    // own streams follow it by reference, and its closing stream ends it.
    limits
        .ledger
        .admit_len::<u8>(2)
        .map_err(WorkError::Memory)?;
    object_insert(limits.ledger)?;
    let open = out.add_object(Stream::new(Dictionary::new(), b"q\n".to_vec()));
    for (index, page) in input_pages.iter().enumerate() {
        let media = pdf_box(
            &source,
            page.get(b"MediaBox".as_slice())
                .ok_or(WorkError::Invalid(InputInvalidCode::MalformedPdf))?,
            limits,
        )?;
        let geometry = page_geometry(&source, page, limits)?;
        let crop = geometry.crop;
        let streams = match page.get(b"Contents".as_slice()) {
            Some(value) => contents.admit(&source, value, limits)?,
            None => Vec::new(),
        };
        let mut resources = match page.get(b"Resources".as_slice()) {
            Some(v) => copier.resources(&mut out, v, 0, limits)?,
            None => Dictionary::new(),
        };
        let mut ops = flatten(
            &source,
            page.get(b"Annots".as_slice()),
            &mut |out: &mut Document, value: &Object, depth: usize| {
                copier.copy(out, value, depth, limits)
            },
            &mut out,
            &mut resources,
            limits,
        )?;
        op(&mut ops, "q", &[], limits)?;
        op(&mut ops, "cm", &geometry.to_pdf()?, limits)?;
        // organ: lent by the host, checked engine-side.
        let burned = burn_fields(
            &mut out,
            &mut resources,
            geometry.display_box()?,
            index as u32 + 1,
            request.fields,
            request.values,
            request.rasters,
            request.rejection.is_some(),
            font,
            &mut images,
            limits,
        )?;
        reserve(limits.ledger, &mut ops, burned.len())?;
        ops.extend(burned);
        op(&mut ops, "Q", &[], limits)?;
        // The page's own streams are copied as they are, compression kept, and
        // named in order: content shared by many pages is written once
        // (ISO 32000-1 section 7.8.2 reads the array as one stream).
        let mut page_streams: Vec<Object> = Vec::new();
        push(limits.ledger, &mut page_streams, Object::Reference(open))?;
        for id in streams {
            let copied = copier.copy(&mut out, &Object::Reference(id), 0, limits)?;
            push(limits.ledger, &mut page_streams, copied)?;
        }
        let encoded = Content { operations: ops }
            .encode()
            .map_err(|err| lopdf_error(limits, err))?;
        limits
            .ledger
            .admit_len::<u8>(encoded.len())
            .map_err(WorkError::Memory)?;
        let mut close: Vec<u8> = Vec::new();
        reserve(limits.ledger, &mut close, b"\nQ\nn\n".len() + encoded.len())?;
        close.extend_from_slice(b"\nQ\nn\n");
        close.extend_from_slice(&encoded);
        let encoded_len = encoded.len();
        drop(encoded);
        limits.ledger.release_admitted(wide(encoded_len));
        object_insert(limits.ledger)?;
        let close_id = out.add_object(Stream::new(Dictionary::new(), close));
        push(
            limits.ledger,
            &mut page_streams,
            Object::Reference(close_id),
        )?;
        limits
            .ledger
            .admit_len::<Object>(4)
            .map_err(WorkError::Memory)?;
        let media_array: Vec<Object> = media.iter().map(|v| Object::Real(*v as f32)).collect();
        limits
            .ledger
            .admit_len::<Object>(4)
            .map_err(WorkError::Memory)?;
        let crop_array: Vec<Object> = crop.iter().map(|v| Object::Real(*v as f32)).collect();
        dictionary_built(limits.ledger, 6, 42, 4)?;
        let mut new_page = dictionary! { "Type" => "Page", "Parent" => parent,
        "MediaBox" => media_array, "CropBox" => crop_array, "Resources" => resources, "Contents" => page_streams };
        dictionary_insert(limits.ledger, 6)?;
        new_page.set("Rotate", i64::from(geometry.rotation));
        dictionary_insert(limits.ledger, 8)?;
        new_page.set("UserUnit", Object::Real(geometry.user_unit as f32));
        for key in [b"Group".as_slice(), b"TrimBox", b"BleedBox", b"ArtBox"] {
            if let Some(value) = page.get(key) {
                let copied = copier.copy(&mut out, value, 0, limits)?;
                dictionary_insert(limits.ledger, key.len())?;
                new_page.set(key, copied);
            }
        }
        object_insert(limits.ledger)?;
        let kid = out.add_object(new_page);
        push(limits.ledger, &mut kids, Object::Reference(kid))?;
    }
    let original_pages = kids.len() as u32;
    certificate(
        &mut out,
        parent,
        font,
        &CertificateRequest {
            document_ref: request.document_ref,
            item: request.item,
            canonical_url: request.canonical_url,
            artifact_ref: request.artifact_ref,
            original_version: request.original_version,
            title: request.title,
            audit_rows: request.audit_rows,
            rejection: request.rejection,
            recipients: request.recipients,
            signatures: request.signatures,
        },
        (original_sha256, request.chain, request.trail),
        &mut kids,
        limits,
    )?;
    let appendix_pages = kids.len() as u32 - original_pages;
    page_tree(&mut out, parent, kids, limits)?;
    dictionary_built(limits.ledger, 2, 9, 7)?;
    let mut catalog_out = dictionary! { "Type" => "Catalog", "Pages" => parent };
    if let Ok(intents) = catalog.get(b"OutputIntents") {
        let copied = copier.copy(&mut out, intents, 0, limits)?;
        dictionary_insert(limits.ledger, 13)?;
        catalog_out.set("OutputIntents", copied);
    }
    object_insert(limits.ledger)?;
    let root = out.add_object(catalog_out);
    dictionary_insert(limits.ledger, 4)?;
    out.trailer.set("Root", root);
    if out.objects.len() > PDF_FORMAT_OBJECTS {
        return Err(WorkError::Invalid(InputInvalidCode::ObjectLimitExceeded));
    }
    let mut writer = BoundedOutput::new(limits);
    if out.save_to(&mut writer).is_err() {
        return Err(writer
            .failure()
            .unwrap_or(WorkError::Invalid(InputInvalidCode::TooLarge)));
    }
    Ok(WorkPrepared {
        bytes: writer.into_bytes(),
        original_sha256,
        audit_chain_sha256: request.chain,
        original_pages,
        appendix_pages,
    })
}

/// Read actual inherited page boxes/rotation for editor and signing overlays,
/// as the engine's `inspect_in` (`E/render.rs:392-417`): the strict load, the
/// signature gate, the page walk, and one geometry per page.
pub(crate) fn inspect_in(
    bytes: &[u8],
    limits: &WorkLimits<'_>,
) -> Result<Vec<PageGeometry>, WorkError> {
    let source = load(bytes, limits)?;
    reject_signatures(&source, limits)?;
    let mut input = Vec::new();
    let mut seen = BTreeSet::new();
    let pages_id = source
        .catalog()
        .map_err(|err| lopdf_error(limits, err))?
        .get(b"Pages")
        .map_err(|err| lopdf_error(limits, err))?
        .as_reference()
        .map_err(|err| lopdf_error(limits, err))?;
    pages(
        &source,
        pages_id,
        BTreeMap::new(),
        &mut seen,
        &mut input,
        0,
        limits,
    )?;
    if input.is_empty() {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
    }
    let mut geometries: Vec<PageGeometry> = Vec::new();
    for page in &input {
        let geometry = page_geometry(&source, page, limits)?;
        push(limits.ledger, &mut geometries, geometry)?;
    }
    Ok(geometries)
}

/// The most kids one page-tree node carries: the array bound of ISO 32000-1
/// Annex C, Table C.1 (8,191 elements). A longer document is not refused; its
/// page tree nests (ISO 32000-1 section 7.7.3.2).
const PAGE_TREE_FANOUT: usize = 8191;

/// Hangs `kids` (every page, in order, each made with `root` as its parent)
/// under `root`, nesting intermediate nodes when they outgrow one node, as
/// the engine's `page_tree` (`E/render.rs:423-452`). Every fresh node,
/// `Parent` update, and vector growth is admitted first.
fn page_tree(
    out: &mut Document,
    root: ObjectId,
    kids: Vec<Object>,
    limits: &WorkLimits<'_>,
) -> Result<(), WorkError> {
    let total = kids.len() as i64;
    let mut level: Vec<(Object, i64)> = Vec::new();
    reserve(limits.ledger, &mut level, kids.len())?;
    for kid in kids {
        push(limits.ledger, &mut level, (kid, 1))?;
    }
    while level.len() > PAGE_TREE_FANOUT {
        let mut next: Vec<(Object, i64)> = Vec::new();
        reserve(
            limits.ledger,
            &mut next,
            level.len().div_ceil(PAGE_TREE_FANOUT),
        )?;
        for group in level.chunks(PAGE_TREE_FANOUT) {
            let node = out.new_object_id();
            let mut count = 0;
            let mut node_kids: Vec<Object> = Vec::new();
            reserve(limits.ledger, &mut node_kids, group.len())?;
            for (kid, leaves) in group {
                let id = kid.as_reference().map_err(|err| lopdf_error(limits, err))?;
                // The `Parent` key already exists; the set clones 6 key bytes then drops them.
                limits
                    .ledger
                    .admit_len::<u8>(6)
                    .map_err(WorkError::Memory)?;
                out.get_object_mut(id)
                    .map_err(|err| lopdf_error(limits, err))?
                    .as_dict_mut()
                    .map_err(|err| lopdf_error(limits, err))?
                    .set("Parent", node);
                limits.ledger.release_admitted(wide(6));
                count += leaves;
                push(limits.ledger, &mut node_kids, kid.clone())?;
            }
            dictionary_built(limits.ledger, 3, 15, 5)?;
            let mut tree = dictionary! { "Type" => "Pages", "Parent" => root, "Count" => count };
            dictionary_insert(limits.ledger, 4)?;
            tree.set("Kids", node_kids);
            object_insert(limits.ledger)?;
            out.objects.insert(node, tree.into());
            push(limits.ledger, &mut next, (Object::Reference(node), count))?;
        }
        level = next;
    }
    let mut ordered: Vec<Object> = Vec::new();
    reserve(limits.ledger, &mut ordered, level.len())?;
    for (kid, _) in level {
        push(limits.ledger, &mut ordered, kid)?;
    }
    dictionary_built(limits.ledger, 3, 13, 5)?;
    object_insert(limits.ledger)?;
    out.objects.insert(
        root,
        dictionary! { "Type" => "Pages", "Count" => total, "Kids" => ordered }.into(),
    );
    Ok(())
}

/// The prepared PDF as it is written, held to [`PDF_FORMAT_BYTES`], the
/// writer's offset width, as the engine's `BoundedOutput`
/// (`E/render.rs:455-471`): the output buffer growth is admitted on the
/// call's operation ledger as it extends.
struct BoundedOutput<'a> {
    buf: Vec<u8>,
    limits: &'a WorkLimits<'a>,
    failed: Option<WorkError>,
}

impl<'a> BoundedOutput<'a> {
    fn new(limits: &'a WorkLimits<'a>) -> Self {
        Self {
            buf: Vec::new(),
            limits,
            failed: None,
        }
    }

    fn failure(&self) -> Option<WorkError> {
        self.failed
    }

    fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

impl std::io::Write for BoundedOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > PDF_FORMAT_BYTES.saturating_sub(self.buf.len()) {
            self.failed = Some(WorkError::Invalid(InputInvalidCode::TooLarge));
            return Err(std::io::Error::other("PDF offset width"));
        }
        let needed = self.buf.len() + bytes.len();
        if needed > self.buf.capacity() {
            let grown = self.buf.capacity().saturating_mul(2).max(needed);
            if let Err(refusal) = self.limits.ledger.admit_len::<u8>(grown) {
                self.failed = Some(WorkError::Memory(refusal));
                return Err(std::io::Error::other("memory"));
            }
            let old_capacity = self.buf.capacity();
            let held = layout_bytes::<u8>(grown).unwrap_or(usize::MAX);
            if self.buf.try_reserve_exact(grown - self.buf.len()).is_err() {
                self.failed = Some(WorkError::Memory(floor(held)));
                return Err(std::io::Error::other("memory"));
            }
            let old_bytes = layout_bytes::<u8>(old_capacity).unwrap_or(0);
            self.limits
                .ledger
                .release_admitted(u64::try_from(old_bytes).unwrap_or(u64::MAX));
        }
        self.buf.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A lopdf read failure as the organ reads it: a kept memory refusal as
/// itself, anything else as a malformed PDF, never the reverse.
fn lopdf_error(limits: &WorkLimits<'_>, err: lopdf::Error) -> WorkError {
    limits.ledger.refusal_of(&err).map_or(
        WorkError::Invalid(InputInvalidCode::MalformedPdf),
        WorkError::Memory,
    )
}

/// A length as the ledger counts bytes.
fn wide(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
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
fn reserve<T>(
    ledger: &MemoryLedger,
    output: &mut Vec<T>,
    additional: usize,
) -> Result<(), WorkError> {
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

fn push<T>(ledger: &MemoryLedger, output: &mut Vec<T>, value: T) -> Result<(), WorkError> {
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

/// One fresh `Dictionary` entry: key bytes plus a BTree entry share.
fn dictionary_insert(ledger: &MemoryLedger, key_len: usize) -> Result<(), WorkError> {
    let bytes = btree_entry_bytes::<Vec<u8>, Object>()
        .checked_add(key_len)
        .ok_or_else(|| WorkError::Memory(floor(usize::MAX)))?;
    ledger.admit_len::<u8>(bytes).map_err(WorkError::Memory)
}

/// One fresh `Document` object: the objects-map entry share. The object's
/// heap (stream bytes, dictionaries) is admitted where it is built.
fn object_insert(ledger: &MemoryLedger) -> Result<(), WorkError> {
    ledger
        .admit_len::<u8>(btree_entry_bytes::<ObjectId, Object>())
        .map_err(WorkError::Memory)
}

/// One fresh dictionary built whole via `dictionary!`: `entries` shares plus
/// the map node and the key and inline-name heap bytes it holds (pattern:
/// `work_burn`'s image-dict admission).
fn dictionary_built(
    ledger: &MemoryLedger,
    entries: usize,
    key_bytes: usize,
    name_bytes: usize,
) -> Result<(), WorkError> {
    let bytes = btree_entry_bytes::<Vec<u8>, Object>()
        .checked_mul(entries)
        .and_then(|shares| shares.checked_add(btree_node_bytes::<Vec<u8>, Object>()))
        .and_then(|shares| shares.checked_add(key_bytes))
        .and_then(|shares| shares.checked_add(name_bytes))
        .ok_or_else(|| WorkError::Memory(floor(usize::MAX)))?;
    ledger.admit_len::<u8>(bytes).map_err(WorkError::Memory)
}
