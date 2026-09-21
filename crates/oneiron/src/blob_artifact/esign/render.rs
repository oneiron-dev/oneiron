//! Lossless bounded PDF preparation and shared field presentation.
//! Unsafe dynamic or ambiguous visual constructs fail closed. Only the native
//! seal engine signs these bytes; ordinary compressed PDF structures are retained.
use super::model::*;
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
mod evidence;
mod fields;
mod preflight;
mod source;
mod streams;

use evidence::{certificate, evidence};
use fields::burn_fields;
use source::{VisualCopy, check_content, page_content, pages, pdf_box, reject_signatures};

const MAX_INPUT: usize = 16 * 1024 * 1024;
const MAX_OUTPUT: usize = 64 * 1024 * 1024;
const MAX_OBJECTS: usize = 50_000;
const MAX_PAGES: usize = 1000;
const MAX_NODES: usize = 500_000;
type Result<T> = std::result::Result<T, PdfPreparationError>;

/// Refusals are preparation failures, never a successful unsigned seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PdfPreparationError {
    #[error("PDF preparation resource limit")]
    Limit,
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
/// Rewrite immutable original bytes and flatten all recorded fields. The audit
/// chain is checked and replayed; its projection must equal the supplied state.
/// No I/O, clock, network, key custody or PAdES signing occurs here.
pub fn prepare_esign_pdf(original: &[u8], request: PdfPreparation<'_>) -> Result<PreparedEsignPdf> {
    if original.is_empty() || original.len() > MAX_INPUT {
        return Err(PdfPreparationError::Limit);
    }
    if !original.starts_with(b"%PDF-") {
        return Err(PdfPreparationError::MalformedPdf);
    }
    let source = preflight::load(original)?;
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
        nodes: 0,
        bytes: 0,
    };
    let mut kids = Vec::new();
    let mut images = fields::BurnImages::default();
    let mut total_content = 0;
    for (index, page) in input_pages.iter().enumerate() {
        let media = pdf_box(
            &source,
            page.get(b"MediaBox".as_slice())
                .ok_or(PdfPreparationError::MalformedPdf)?,
        )?;
        let geometry = source::page_geometry(&source, page)?;
        let crop = geometry.crop;
        let mut content = Vec::new();
        if let Some(value) = page.get(b"Contents".as_slice()) {
            page_content(&source, value, &mut content, 0, &mut 0)?;
        }
        total_content += content.len();
        if total_content > MAX_INPUT {
            return Err(PdfPreparationError::Limit);
        }
        check_content(&content)?;
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
            index as u32 + 1,
            &request,
            font,
            &mut images,
        )?);
        fields::op(&mut ops, "Q", &[]);
        let mut flattened = b"q\n".to_vec();
        flattened.extend(content);
        flattened.extend(b"\nQ\nn\n");
        flattened.extend(Content { operations: ops }.encode()?);
        let stream = out.add_object(Stream::new(Dictionary::new(), flattened));
        let mut new_page = dictionary! { "Type" => "Page", "Parent" => parent,
        "MediaBox" => media.iter().map(|v| Object::Real(*v as f32)).collect::<Vec<_>>(),
        "CropBox" => crop.iter().map(|v| Object::Real(*v as f32)).collect::<Vec<_>>(), "Resources" => resources, "Contents" => stream };
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
    out.objects.insert(
        parent,
        dictionary! { "Type" => "Pages", "Count" => kids.len() as i64, "Kids" => kids }.into(),
    );
    let mut catalog_out = dictionary! { "Type" => "Catalog", "Pages" => parent };
    if let Ok(intents) = catalog.get(b"OutputIntents") {
        catalog_out.set("OutputIntents", copier.copy(&mut out, intents, 0)?);
    }
    let root = out.add_object(catalog_out);
    out.trailer.set("Root", root);
    if out.objects.len() > MAX_OBJECTS {
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
/// Read actual inherited page boxes/rotation for editor and signing overlays.
pub fn inspect_pdf_pages(bytes: &[u8]) -> Result<Vec<PageGeometry>> {
    if bytes.is_empty() || bytes.len() > MAX_INPUT {
        return Err(PdfPreparationError::Limit);
    }
    let source = preflight::load(bytes)?;
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
struct BoundedOutput(Vec<u8>);
impl std::io::Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_OUTPUT.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("PDF output limit"));
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
