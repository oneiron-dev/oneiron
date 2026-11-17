//! Ported field burn-in and annotation-appearance flattening (FIX 7980/8157).
//!
//! Thin delegation over the shared e-sign field renderer: each item keeps
//! its path, name and signature, and the drawing program runs in the leaf
//! against the call's operation ledger. Raster dimensions must be nonzero,
//! the RGBA length exact, and alpha nonblank.
//!
//! The organ's projection rows ([`BurnField`], [`BurnValue`], [`WorkRaster`])
//! stay here: the handler admits them outside the leaf.

use std::collections::BTreeMap;

use lopdf::content::Operation;
use lopdf::{Dictionary, Document, Object, ObjectId};
use oneiron_esign_render as leaf;

use super::work::{LedgerAdmission, WorkError, WorkLimits, map_leaf};
use super::work_present::FieldGeometry;

/// One signature raster's decoded pixels, as the engine's `SignatureRaster`
/// but borrowed: rasters cross PNG-decoded and the handler slices the lent
/// blob, so no copy crosses here. Straight-alpha RGBA, top-to-bottom rows.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct WorkRaster<'a> {
    pub width: u32,
    pub height: u32,
    pub rgba: &'a [u8],
}

impl leaf::RasterView for WorkRaster<'_> {
    fn width(&self) -> u32 {
        self.width
    }
    fn height(&self) -> u32 {
        self.height
    }
    fn rgba(&self) -> &[u8] {
        self.rgba
    }
}

/// One field's lent identity and box, as the engine's `EsignField` row
/// already filtered to this item: the host validates the row engine-side.
/// `geometry.page` (one-based) selects the page this burn targets.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BurnField {
    pub id: String,
    pub geometry: FieldGeometry,
}

/// One field's lent value, as the engine's `FieldValue` row: the host
/// validates the shape engine-side. Absent from the map means unfilled.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum BurnValue {
    Text(String),
    Checked(bool),
    Signature { image_ref: String },
}

/// The rasters already written, each once however many fields show it, as
/// the engine's `BurnImages`. No raster budget refuses a document: each
/// raster is held to its decoder's bounds at upload.
pub(crate) type BurnImages = leaf::ImageCache;

/// One operation appended, as the engine's `fields::op`. Operator bytes,
/// operand vector, and `ops` growth are admitted first.
pub(super) fn op(
    ops: &mut Vec<Operation>,
    operator: &str,
    numbers: &[f64],
    limits: &WorkLimits<'_>,
) -> Result<(), WorkError> {
    let admit = LedgerAdmission {
        ledger: limits.ledger,
    };
    leaf::op(ops, operator, numbers, &admit).map_err(WorkError::Memory)
}

/// One labeled text draw, as the engine's `fields::text`.
pub(super) fn text(
    ops: &mut Vec<Operation>,
    font: &[u8],
    value: &str,
    x: f64,
    y: f64,
    size: f64,
    limits: &WorkLimits<'_>,
) -> Result<(), WorkError> {
    let admit = LedgerAdmission {
        ledger: limits.ledger,
    };
    leaf::text(ops, font, value, x, y, size, &admit).map_err(WorkError::Memory)
}

/// The resource name for `id` under `kind`, as the engine's `fields::resource`:
/// category maps are direct dictionaries, mutated in place (cloning per
/// field is quadratic). A missing category, name bytes, and entry are admitted.
pub(super) fn resource(
    resources: &mut Dictionary,
    kind: &[u8],
    id: ObjectId,
    limits: &WorkLimits<'_>,
) -> Result<Vec<u8>, WorkError> {
    let admit = LedgerAdmission {
        ledger: limits.ledger,
    };
    leaf::resource(resources, kind, id, &admit).map_err(|err| map_leaf(Some(limits), err))
}

/// One page's field burn-in, as the engine's `fields::burn_fields` but over
/// lent rows: `fields` is already item-filtered by the host, `values` and
/// `rasters` hold checked shapes, `rejected` carries the flag. Unfilled
/// fields draw nothing. Every `ops` push is admitted.
#[allow(clippy::too_many_arguments)]
pub(crate) fn burn_fields(
    out: &mut Document,
    resources: &mut Dictionary,
    crop: [f64; 4],
    page: u32,
    // organ: lent by the host, checked engine-side
    fields: &[BurnField],
    // organ: lent by the host, checked engine-side
    values: &BTreeMap<String, BurnValue>,
    // organ: lent by the host, checked engine-side
    rasters: &BTreeMap<String, WorkRaster<'_>>,
    // organ: lent by the host, checked engine-side
    rejected: bool,
    font: ObjectId,
    images: &mut BurnImages,
    limits: &WorkLimits<'_>,
) -> Result<Vec<Operation>, WorkError> {
    let admit = LedgerAdmission {
        ledger: limits.ledger,
    };
    let font_name = resource(resources, b"Font", font, limits)?;
    let mut ops = Vec::new();
    for field in fields.iter().filter(|f| f.geometry.page == page) {
        let value = match values.get(&field.id) {
            None => None,
            Some(BurnValue::Text(value)) => Some(leaf::LeafValue::Text(value.as_str())),
            Some(BurnValue::Checked(checked)) => Some(leaf::LeafValue::Checked(*checked)),
            Some(BurnValue::Signature { image_ref }) => Some(leaf::LeafValue::Signature {
                image_ref: image_ref.as_str(),
            }),
        };
        let geometry = leaf::FieldGeometry {
            page: field.geometry.page,
            x_percent: field.geometry.x_percent,
            y_percent: field.geometry.y_percent,
            width_percent: field.geometry.width_percent,
            height_percent: field.geometry.height_percent,
        };
        leaf::burn_field(
            &mut ops, out, resources, crop, &font_name, &geometry, value, rasters, images, &admit,
        )
        .map_err(|err| map_leaf(Some(limits), err))?;
    }
    if rejected {
        leaf::stamp_rejected(&mut ops, &font_name, crop, &admit).map_err(WorkError::Memory)?;
    }
    Ok(ops)
}

/// One page's `/Annots` flattened, as the engine's `appearance::flatten`:
/// every annotation, however many. A shared indirect array is flattened per
/// page into that page's resources and operations, as a reader draws it; the
/// source array is only read. `copy` is the visual copy `work_source` owns;
/// it crosses as a closure so this file does not name its unfinished type.
pub(crate) fn flatten(
    source: &Document,
    annotations: Option<&&Object>,
    copy: &mut impl FnMut(&mut Document, &Object, usize) -> Result<Object, WorkError>,
    out: &mut Document,
    resources: &mut Dictionary,
    limits: &WorkLimits<'_>,
) -> Result<Vec<Operation>, WorkError> {
    let admit = LedgerAdmission {
        ledger: limits.ledger,
    };
    leaf::flatten(source, annotations, copy, out, resources, &admit)
        .map_err(|err| map_leaf(Some(limits), err))
}
