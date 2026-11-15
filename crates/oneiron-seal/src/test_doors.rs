//! Doors for this crate's integration tests to crate-private items, as the
//! engine's `test_doors`. Compiled only under `--cfg oneiron_test_support`,
//! which only the test command sets (`RUSTFLAGS="--cfg oneiron_test_support"
//! cargo test ... --test <stem>`); never behind a cargo feature, so no
//! `--all-features` build and no organ binary a host runs reaches them.
//! Hidden; never API.
//!
//! `burn_page_fields` serves `tests/burn_parity.rs`: it burns one page's
//! fields through the organ's ported burn-in (`work_burn::burn_fields`) into
//! a fresh document, as `work_prepare::prepare_in` does, so the test can
//! compare the bytes with the engine port's door
//! (`oneiron::blob_artifact::esign::render::esign_burn`).

use std::collections::BTreeMap;
use std::sync::Arc;

use lopdf::content::Content;
use lopdf::{Dictionary, Document, Stream, dictionary};

use crate::native::pdf::{
    BurnField, BurnImages, BurnValue, FieldGeometry, WorkLimits, WorkRaster, burn_fields,
};
use crate::{
    SealMemory, SealMemoryProvider, SealMemoryRefusal, SealObservations, SealResourceLimits,
    SealStage,
};

/// One field as the host lends it: its id and its box, in percent of the
/// one-based page it sits on (the engine's `FieldGeometry`).
pub struct LentField {
    pub id: String,
    pub page: u32,
    pub x_percent: f64,
    pub y_percent: f64,
    pub width_percent: f64,
    pub height_percent: f64,
}

/// One field's lent value, as the engine's `FieldValue`. A field absent
/// from the value map is unfilled.
pub enum LentValue {
    Text(String),
    Checked(bool),
    Signature { image_ref: String },
}

/// One decoded signature raster: straight-alpha RGBA, top-to-bottom rows.
pub struct LentRaster {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

/// One page's burned fields: the encoded content stream, and the whole
/// one-page document (font, rasters, content and resources) as saved.
pub struct BurnedPage {
    pub content: Vec<u8>,
    pub pdf: Vec<u8>,
}

/// Grants every reservation and holds nothing: the burn's admissions are
/// counted, never refused.
struct GrantAllMemory;

impl SealMemory for GrantAllMemory {
    fn reserve(&self, _bytes: u64) -> Result<Box<dyn Send>, SealMemoryRefusal> {
        Ok(Box::new(()))
    }
}

/// Burns the fields of `fields` on `page` (one-based) inside `crop`, with
/// `values` and `rasters` as the host lends them, through the organ port,
/// under one operation's ledger over memory that grants every reservation.
/// `rejected` stamps the page as a rejected document's is.
///
/// # Errors
/// The burn's own, as its debug text: an invalid code (a box outside the
/// page, a missing or malformed raster, unencodable text), or the ledger's.
pub fn burn_page_fields(
    crop: [f64; 4],
    page: u32,
    fields: &[LentField],
    values: &BTreeMap<String, LentValue>,
    rasters: &BTreeMap<String, LentRaster>,
    rejected: bool,
) -> Result<BurnedPage, String> {
    let operation = SealResourceLimits {
        memory: SealMemoryProvider::new(Arc::new(GrantAllMemory)),
        ..SealResourceLimits::default()
    }
    .operation(SealStage::InputValidation)
    .map_err(|err| format!("{err:?}"))?;
    let ledger = operation
        .memory
        .ledger()
        .map_err(|err| format!("{err:?}"))?;
    let observed = SealObservations::default();
    let limits = WorkLimits {
        ledger: &ledger,
        observed: &observed,
        stream_decode_bytes: None,
    };
    let fields: Vec<BurnField> = fields
        .iter()
        .map(|field| BurnField {
            id: field.id.clone(),
            geometry: FieldGeometry {
                page: field.page,
                x_percent: field.x_percent,
                y_percent: field.y_percent,
                width_percent: field.width_percent,
                height_percent: field.height_percent,
            },
        })
        .collect();
    let values: BTreeMap<String, BurnValue> = values
        .iter()
        .map(|(id, value)| {
            let value = match value {
                LentValue::Text(text) => BurnValue::Text(text.clone()),
                LentValue::Checked(checked) => BurnValue::Checked(*checked),
                LentValue::Signature { image_ref } => BurnValue::Signature {
                    image_ref: image_ref.clone(),
                },
            };
            (id.clone(), value)
        })
        .collect();
    let rasters: BTreeMap<String, WorkRaster<'_>> = rasters
        .iter()
        .map(|(image_ref, raster)| {
            (
                image_ref.clone(),
                WorkRaster {
                    width: raster.width,
                    height: raster.height,
                    rgba: &raster.rgba,
                },
            )
        })
        .collect();
    let mut out = Document::with_version("1.7");
    out.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceTable;
    let font = out.add_object(dictionary! { "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Courier", "Encoding" => "WinAnsiEncoding" });
    let mut resources = Dictionary::new();
    let mut images = BurnImages::default();
    let ops = burn_fields(
        &mut out,
        &mut resources,
        crop,
        page,
        &fields,
        &values,
        &rasters,
        rejected,
        font,
        &mut images,
        &limits,
    )
    .map_err(|err| format!("{err:?}"))?;
    let content = Content { operations: ops }
        .encode()
        .map_err(|err| format!("{err:?}"))?;
    out.add_object(Stream::new(Dictionary::new(), content.clone()));
    out.add_object(resources);
    let mut pdf = Vec::new();
    out.save_to(&mut pdf).map_err(|err| format!("{err:?}"))?;
    Ok(BurnedPage { content, pdf })
}
