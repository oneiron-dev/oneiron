//! Lossless PDF preparation and shared field presentation.
//! Unsafe dynamic or ambiguous visual constructs fail closed. Only the native
//! seal engine signs these bytes; ordinary compressed PDF structures are retained.
//! No document size, page count or object count refuses a preparation (Rule
//! 5): the bounds left are the codec's and the format's, below.
use super::model::*;
use crate::limit_ask::EngineLimit;
use lopdf::content::{Content, Operation};
use lopdf::{Dictionary, Document, LoadOptions, Object, ObjectId, Stream, dictionary};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

mod appearance;
mod presentation;
pub use presentation::{
    FieldControl, FieldLayout, FieldMark, FieldPresentation, PageGeometry, layout_field,
    present_field,
};
mod admitted;
pub use admitted::InspectionMemory;
pub use lopdf::DecodeAdmissionError;
mod evidence;
mod fields;
mod preflight;
mod source;
mod streams;

pub(crate) use streams::decode_stream;

use evidence::{certificate, evidence};
use fields::burn_fields;
use source::{PageContents, VisualCopy, pages, pdf_box, reject_signatures};

/// The most one filtered PDF stream decodes to in one preparation: the
/// `[limits] esign_stream_decode_bytes` row (FIX 6287), a decompression-bomb
/// guard held per stream and never summed over a page or a document (Rule
/// 5). An unfiltered stream runs no codec and is read whole.
#[derive(Clone, Copy)]
struct StreamBound(usize);
impl StreamBound {
    fn of(bytes: u64) -> Self {
        Self(usize::try_from(bytes).unwrap_or(usize::MAX))
    }
}
impl crate::Vault {
    /// This vault's `[limits] esign_stream_decode_bytes` row: the bound a
    /// host passes the render and inspection paths it runs (FIX 6287).
    #[must_use]
    pub fn esign_stream_decode_bytes(&self) -> u64 {
        self.limit_watch()
            .bound(EngineLimit::EsignStreamDecodeBytes)
    }
}
/// A decode refused past the bound, as its typed reason: the row it crossed.
fn past_stream_bound(error: PdfPreparationError) -> PdfPreparationError {
    match error {
        PdfPreparationError::Limit => {
            PdfPreparationError::StreamPastCodecBound(EngineLimit::EsignStreamDecodeBytes)
        }
        other => other,
    }
}
// The name the render tests size an expansion bomb by: one stream past the
// per-stream bound, at the row's default.
#[cfg(test)]
const MAX_INPUT: usize = 64 * 1024 * 1024;
/// The most indirect objects one PDF file holds: ISO 32000-1 Annex C,
/// section C.2, Table C.1 (8,388,607).
const MAX_INDIRECT_OBJECTS: usize = 8_388_607;
/// The most bytes a prepared PDF spans: lopdf's writer records each object's
/// byte offset as a `u32` (its xref entry), so an object past 4 GiB could not
/// be addressed. The classic xref table's ten-digit offset (ISO 32000-1
/// section 7.5.4) reaches further, so the codec's width binds.
const MAX_PDF_BYTES: usize = u32::MAX as usize;
type Result<T> = std::result::Result<T, PdfPreparationError>;

/// Refusals are preparation failures, never a successful unsigned seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PdfPreparationError {
    /// Past a codec or format bound: a stream's decode bound, the format's
    /// object count or the writer's offset width.
    #[error("PDF past a codec or format bound")]
    Limit,
    /// One stream decodes past a host codec bound: the named `[limits]` row.
    #[error("a PDF stream decodes past the [limits] {} codec bound", .0.key())]
    StreamPastCodecBound(EngineLimit),
    #[error("malformed PDF")]
    MalformedPdf,
    #[error("encrypted PDF cannot be rewritten")]
    EncryptedPdf,
    #[error("signed PDF cannot be rewritten")]
    AlreadySigned,
    #[error("PDF construct cannot be safely flattened")]
    UnsupportedPdf,
    #[error("invalid field geometry")]
    InvalidGeometry,
    #[error("invalid document evidence")]
    InvalidEvidence,
    #[error("invalid field value")]
    InvalidField,
    #[error("signature raster is missing or invalid")]
    InvalidSignatureImage,
    #[error("field text requires an unsupported font")]
    UnsupportedText,
    #[error("field text does not fit")]
    FieldOverflow,
    #[error("invalid canonical HTTPS capability URL")]
    InvalidCanonicalUrl,
    #[error("PDF encoding failed")]
    Encoding,
}
impl From<lopdf::Error> for PdfPreparationError {
    fn from(error: lopdf::Error) -> Self {
        match error {
            lopdf::Error::Decompress(lopdf::DecompressError::MemoryLimitExceeded { .. }) => {
                Self::Limit
            }
            lopdf::Error::AlreadyEncrypted
            | lopdf::Error::Decryption(_)
            | lopdf::Error::InvalidPassword
            | lopdf::Error::UnsupportedSecurityHandler(_) => Self::EncryptedPdf,
            _ => Self::MalformedPdf,
        }
    }
}

/// Caller-decoded, straight-alpha RGBA pixels, in top-to-bottom row order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureRaster {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}
/// The host resolves image references and supplies a stable, already-issued URL.
pub struct PdfPreparation<'a> {
    pub document_ref: &'a str,
    pub item: u32,
    pub state: &'a EsignState,
    pub audit: &'a [EsignEventRow],
    pub canonical_url: &'a str,
    pub signature_images: &'a BTreeMap<String, SignatureRaster>,
}
#[derive(Debug)]
pub struct PreparedEsignPdf {
    pub bytes: Vec<u8>,
    pub original_sha256: [u8; 32],
    pub audit_chain_sha256: [u8; 32],
    pub original_pages: u32,
    pub appendix_pages: u32,
}
/// PDF user-space rectangle, with a bottom-left origin.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfFieldRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}
/// Shared geometry for editor, ceremony and export. Page numbers are one-based.
/// Use `PageGeometry` to convert rotated/scaled page displays before placement.
pub fn render_field_geometry(g: &FieldGeometry, crop: [f64; 4]) -> Result<PdfFieldRect> {
    let [left, bottom, right, top] = crop;
    if g.page == 0
        || crop.iter().any(|v| !v.is_finite() || v.abs() > 1_000_000.0)
        || right <= left
        || top <= bottom
        || [g.x_percent, g.y_percent, g.width_percent, g.height_percent]
            .iter()
            .any(|v| !v.is_finite() || !(0.0..=100.0).contains(v))
        || g.width_percent == 0.0
        || g.height_percent == 0.0
        || g.x_percent + g.width_percent > 100.0
        || g.y_percent + g.height_percent > 100.0
    {
        return Err(PdfPreparationError::InvalidGeometry);
    }
    Ok(PdfFieldRect {
        x: left + (right - left) * g.x_percent / 100.0,
        y: top - (top - bottom) * (g.y_percent + g.height_percent) / 100.0,
        width: (right - left) * g.width_percent / 100.0,
        height: (top - bottom) * g.height_percent / 100.0,
    })
}
/// [`prepare_esign_pdf_within`] at the `[limits] esign_stream_decode_bytes`
/// row's default, for a caller holding no vault.
pub fn prepare_esign_pdf(original: &[u8], request: PdfPreparation<'_>) -> Result<PreparedEsignPdf> {
    prepare_esign_pdf_within(
        original,
        request,
        EngineLimit::EsignStreamDecodeBytes.default_bound(),
    )
}
/// Rewrite immutable original bytes and flatten all recorded fields. The audit
/// chain is checked and replayed; its projection must equal the supplied state.
/// No I/O, clock, network, key custody or PAdES signing occurs here. Each
/// filtered stream decodes within `stream_decode_bytes`, the host's
/// `[limits] esign_stream_decode_bytes` row, or the preparation is refused
/// with [`PdfPreparationError::StreamPastCodecBound`].
pub fn prepare_esign_pdf_within(
    original: &[u8],
    request: PdfPreparation<'_>,
    stream_decode_bytes: u64,
) -> Result<PreparedEsignPdf> {
    if !original.starts_with(b"%PDF-") {
        return Err(PdfPreparationError::MalformedPdf);
    }
    let bound = StreamBound::of(stream_decode_bytes);
    let source = preflight::load(original, bound, &admitted::Stage::UNADMITTED)?;
    reject_signatures(&source)?;
    let catalog = source.catalog()?;
    if [b"OCProperties".as_slice(), b"AlternatePresentations"]
        .iter()
        .any(|key| catalog.has(key))
    {
        return Err(PdfPreparationError::UnsupportedPdf);
    }
    if let Ok(form) = catalog.get(b"AcroForm") {
        let form = source::resolved(&source, form)?.as_dict()?;
        if form.has(b"XFA")
            || form
                .get(b"NeedAppearances")
                .ok()
                .is_some_and(|v| v.as_bool().ok() != Some(false))
        {
            return Err(PdfPreparationError::UnsupportedPdf);
        }
    }
    let mut input_pages = Vec::new();
    pages(
        &source,
        catalog.get(b"Pages")?.as_reference()?,
        BTreeMap::new(),
        &mut BTreeSet::new(),
        &mut input_pages,
        0,
    )?;
    if input_pages.is_empty() {
        return Err(PdfPreparationError::MalformedPdf);
    }
    let (audit_chain_sha256, trail) = evidence(&request)?;
    if request
        .state
        .document
        .fields
        .iter()
        .any(|f| f.item == request.item && f.geometry.page as usize > input_pages.len())
    {
        return Err(PdfPreparationError::InvalidGeometry);
    }
    let original_sha256 = Sha256::digest(original).into();
    let mut out = Document::with_version("1.7");
    out.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceTable;
    let parent = out.new_object_id();
    let font = out.add_object(dictionary! { "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Courier", "Encoding" => "WinAnsiEncoding" });
    let mut copier = VisualCopy {
        source: &source,
        ids: BTreeMap::new(),
        active: BTreeSet::new(),
        bound,
        copied_resources: BTreeMap::new(),
    };
    // This item's fields by page, in document order: each page burns its own
    // without reading every other page's (FIX 3810).
    let mut page_fields: BTreeMap<u32, Vec<&EsignField>> = BTreeMap::new();
    for field in request
        .state
        .document
        .fields
        .iter()
        .filter(|f| f.item == request.item)
    {
        page_fields
            .entry(field.geometry.page)
            .or_default()
            .push(field);
    }
    let mut kids = Vec::new();
    let mut images = fields::BurnImages::default();
    let mut contents = PageContents::default();
    // Every page's content opens inside this one shared stream; the page's
    // own streams follow it by reference, and its closing stream ends it.
    let open = out.add_object(Stream::new(Dictionary::new(), b"q\n".to_vec()));
    for (index, page) in input_pages.iter().enumerate() {
        let media = pdf_box(
            &source,
            page.get(b"MediaBox".as_slice())
                .ok_or(PdfPreparationError::MalformedPdf)?,
        )?;
        let geometry = source::page_geometry(&source, page)?;
        let crop = geometry.crop;
        let streams = match page.get(b"Contents".as_slice()) {
            Some(value) => contents.admit(&source, value, bound)?,
            None => Vec::new(),
        };
        let mut resources = match page.get(b"Resources".as_slice()) {
            Some(v) => copier.resources(&mut out, v, 0)?,
            None => Dictionary::new(),
        };
        let mut ops = appearance::flatten(
            &source,
            page.get(b"Annots".as_slice()),
            &mut copier,
            &mut out,
            &mut resources,
        )?;
        fields::op(&mut ops, "q", &[]);
        fields::op(&mut ops, "cm", &geometry.to_pdf()?);
        ops.extend(burn_fields(
            &mut out,
            &mut resources,
            geometry.display_box()?,
            page_fields
                .get(&(index as u32 + 1))
                .map_or(&[][..], Vec::as_slice),
            &request,
            font,
            &mut images,
        )?);
        fields::op(&mut ops, "Q", &[]);
        // The page's own streams are copied as they are, compression kept, and
        // named in order: content shared by many pages is written once
        // (ISO 32000-1 section 7.8.2 reads the array as one stream).
        let mut page_streams = vec![Object::Reference(open)];
        for id in streams {
            page_streams.push(copier.copy(&mut out, &Object::Reference(id), 0)?);
        }
        let mut close = b"\nQ\nn\n".to_vec();
        close.extend(Content { operations: ops }.encode()?);
        page_streams.push(out.add_object(Stream::new(Dictionary::new(), close)).into());
        let mut new_page = dictionary! { "Type" => "Page", "Parent" => parent,
        "MediaBox" => media.iter().map(|v| Object::Real(*v as f32)).collect::<Vec<_>>(),
        "CropBox" => crop.iter().map(|v| Object::Real(*v as f32)).collect::<Vec<_>>(), "Resources" => resources, "Contents" => page_streams };
        new_page.set("Rotate", i64::from(geometry.rotation));
        new_page.set("UserUnit", Object::Real(geometry.user_unit as f32));
        for key in [b"Group".as_slice(), b"TrimBox", b"BleedBox", b"ArtBox"] {
            if let Some(value) = page.get(key) {
                new_page.set(key, copier.copy(&mut out, value, 0)?);
            }
        }
        kids.push(out.add_object(new_page).into());
    }
    let original_pages = kids.len() as u32;
    certificate(
        &mut out,
        parent,
        font,
        &request,
        (original_sha256, audit_chain_sha256, trail),
        &mut kids,
    )?;
    let appendix_pages = kids.len() as u32 - original_pages;
    page_tree(&mut out, parent, kids)?;
    let mut catalog_out = dictionary! { "Type" => "Catalog", "Pages" => parent };
    if let Ok(intents) = catalog.get(b"OutputIntents") {
        catalog_out.set("OutputIntents", copier.copy(&mut out, intents, 0)?);
    }
    let root = out.add_object(catalog_out);
    out.trailer.set("Root", root);
    if out.objects.len() > MAX_INDIRECT_OBJECTS {
        return Err(PdfPreparationError::Limit);
    }
    let mut writer = BoundedOutput(Vec::new());
    out.save_to(&mut writer)
        .map_err(|_| PdfPreparationError::Limit)?;
    Ok(PreparedEsignPdf {
        bytes: writer.0,
        original_sha256,
        audit_chain_sha256,
        original_pages,
        appendix_pages,
    })
}
/// [`inspect_pdf_pages_within`] at the `[limits] esign_stream_decode_bytes`
/// row's default, for a caller holding no vault.
pub fn inspect_pdf_pages(bytes: &[u8]) -> Result<Vec<PageGeometry>> {
    inspect_pdf_pages_within(bytes, EngineLimit::EsignStreamDecodeBytes.default_bound())
}
/// Read actual inherited page boxes/rotation for editor and signing overlays,
/// each filtered stream decoded within `stream_decode_bytes`, the host's
/// `[limits] esign_stream_decode_bytes` row.
pub fn inspect_pdf_pages_within(
    bytes: &[u8],
    stream_decode_bytes: u64,
) -> Result<Vec<PageGeometry>> {
    inspect_in(bytes, stream_decode_bytes, &admitted::Stage::UNADMITTED)
}
/// [`inspect_pdf_pages_within`] with its parse's memory admitted by its host
/// before it is allocated (FIX 8065): lopdf's object tables, stream copies
/// and decodes, and the preflight's xref tables, decodes and revision
/// snapshots, each asked of `memory` first; a finished stage gives its
/// memory back ([`InspectionMemory::release`]). A refused admission ends the
/// inspection as a malformed PDF; the host reads its own refusal.
pub fn inspect_pdf_pages_admitted(
    bytes: &[u8],
    stream_decode_bytes: u64,
    memory: std::sync::Arc<dyn InspectionMemory>,
) -> Result<Vec<PageGeometry>> {
    inspect_in(bytes, stream_decode_bytes, &admitted::Stage::on(memory))
}
/// The inspection of `bytes` on `stage`, which outlives the parsed document.
fn inspect_in(
    bytes: &[u8],
    stream_decode_bytes: u64,
    stage: &admitted::Stage,
) -> Result<Vec<PageGeometry>> {
    let source = preflight::load(bytes, StreamBound::of(stream_decode_bytes), stage)?;
    reject_signatures(&source)?;
    let mut input = Vec::new();
    pages(
        &source,
        source.catalog()?.get(b"Pages")?.as_reference()?,
        BTreeMap::new(),
        &mut BTreeSet::new(),
        &mut input,
        0,
    )?;
    if input.is_empty() {
        return Err(PdfPreparationError::MalformedPdf);
    }
    input
        .iter()
        .map(|page| source::page_geometry(&source, page))
        .collect()
}
/// The most kids one page-tree node carries: the array bound of ISO 32000-1
/// Annex C, Table C.1 (8,191 elements). A longer document is not refused; its
/// page tree nests (ISO 32000-1 section 7.7.3.2).
const PAGE_TREE_FANOUT: usize = 8191;
/// Hangs `kids` (every page, in order, each made with `root` as its parent)
/// under `root`, nesting intermediate nodes when they outgrow one node. The
/// template layout hangs its pages here too.
pub(super) fn page_tree(out: &mut Document, root: ObjectId, kids: Vec<Object>) -> Result<()> {
    let total = kids.len() as i64;
    let mut level: Vec<(Object, i64)> = kids.into_iter().map(|kid| (kid, 1)).collect();
    while level.len() > PAGE_TREE_FANOUT {
        let mut next = Vec::with_capacity(level.len().div_ceil(PAGE_TREE_FANOUT));
        for group in level.chunks(PAGE_TREE_FANOUT) {
            let node = out.new_object_id();
            let mut count = 0;
            let mut node_kids = Vec::with_capacity(group.len());
            for (kid, leaves) in group {
                out.get_object_mut(kid.as_reference()?)?
                    .as_dict_mut()?
                    .set("Parent", node);
                count += leaves;
                node_kids.push(kid.clone());
            }
            let mut tree = dictionary! { "Type" => "Pages", "Parent" => root, "Count" => count };
            tree.set("Kids", node_kids);
            out.objects.insert(node, tree.into());
            next.push((Object::Reference(node), count));
        }
        level = next;
    }
    let kids: Vec<Object> = level.into_iter().map(|(kid, _)| kid).collect();
    out.objects.insert(
        root,
        dictionary! { "Type" => "Pages", "Count" => total, "Kids" => kids }.into(),
    );
    Ok(())
}
/// The prepared PDF as it is written, held to [`MAX_PDF_BYTES`], the
/// writer's offset width.
struct BoundedOutput(Vec<u8>);
impl std::io::Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_PDF_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("PDF offset width"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "render_tests.rs"]
mod tests;
