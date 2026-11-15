//! Door for `oneiron-seal`'s `tests/burn_parity.rs`, declared inside the
//! e-sign render module so it can reach the engine's field burn-in
//! (`fields::burn_fields`) without changing its visibility. Reached as
//! `oneiron::blob_artifact::esign::render::esign_burn`, not re-exported by
//! `test_doors`; compiled only under `oneiron_test_support`.
//!
//! It burns one page's fields exactly as `prepare_in` does (one shared font,
//! the page's resource dictionary, the document's raster cache) into a fresh
//! document, so the seal organ's door can burn the same rows into its own
//! fresh document and the test compares the two byte for byte.

use super::fields::{BurnImages, burn_fields};
use super::*;

/// One page's burned fields: the encoded content stream, and the whole
/// one-page document (font, rasters, content and resources) as saved.
pub struct BurnedPage {
    pub content: Vec<u8>,
    pub pdf: Vec<u8>,
}

/// Burns the fields of `fields` on `page` (one-based) inside `crop`, with
/// `values` as the current signature rows and `rasters` as the decoded
/// signature images, through the engine port. `rejected` stamps the page as
/// a rejected document's is. Every field is the request item's (item 1).
///
/// # Errors
/// The burn's own: a field or value the presentation contract refuses, a
/// box outside the page, a missing or malformed raster, unencodable text.
pub fn burn_page_fields(
    crop: [f64; 4],
    page: u32,
    fields: &[EsignField],
    values: &BTreeMap<String, FieldValue>,
    rasters: &BTreeMap<String, SignatureRaster>,
    rejected: bool,
) -> Result<BurnedPage> {
    let signatures = fields
        .iter()
        .filter_map(|field| {
            values.get(&field.id).map(|value| {
                (
                    field.id.clone(),
                    SignatureRow {
                        field: field.id.clone(),
                        recipient: field.recipient.clone(),
                        value: value.clone(),
                        at: 0,
                    },
                )
            })
        })
        .collect();
    let state = EsignState {
        document: EsignDocument {
            schema_version: 1,
            kind: DocumentKind::Document,
            title: "burn parity".to_owned(),
            sequential: false,
            expires_at: u64::MAX,
            token_expires_at: None,
            items: Vec::new(),
            recipients: Vec::new(),
            fields: fields.to_vec(),
            full_trail_appendix: false,
            lifecycle: None,
            project: None,
            commitments: Vec::new(),
        },
        status: DocumentStatus::Pending,
        recipients: BTreeMap::new(),
        signatures,
        rejection: rejected.then(|| "rejected".to_owned()),
        sealed_sha256: Vec::new(),
        reseal_pending: false,
        reminders: BTreeSet::new(),
        sent_at: None,
        reminder_at: BTreeMap::new(),
    };
    let request = PdfPreparation {
        document_ref: "burn-parity",
        item: 1,
        state: &state,
        audit: &[],
        canonical_url: "https://sign.example.test/cap/burn-parity",
        signature_images: rasters,
        pinned_buffer_bytes: 0,
    };
    let mut out = Document::with_version("1.7");
    out.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceTable;
    let font = out.add_object(dictionary! { "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Courier", "Encoding" => "WinAnsiEncoding" });
    let mut resources = Dictionary::new();
    let mut images = BurnImages::default();
    // The page's fields of the item, in document order, as `prepare_in`
    // groups them.
    let page_fields: Vec<&EsignField> = fields
        .iter()
        .filter(|field| field.item == request.item && field.geometry.page == page)
        .collect();
    let ops = burn_fields(
        &mut out,
        &mut resources,
        crop,
        &page_fields,
        &request,
        font,
        &mut images,
    )?;
    let content = Content { operations: ops }.encode()?;
    out.add_object(Stream::new(Dictionary::new(), content.clone()));
    out.add_object(resources);
    let mut pdf = Vec::new();
    out.save_to(&mut pdf)?;
    Ok(BurnedPage { content, pdf })
}
