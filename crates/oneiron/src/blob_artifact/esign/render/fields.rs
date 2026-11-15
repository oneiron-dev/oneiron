//! Flattened e-sign field text, marks and signature pixels.
use super::*;
use oneiron_esign_render::{self as leaf, NoAdmission};

pub(super) fn op(ops: &mut Vec<Operation>, operator: &str, numbers: &[f64]) {
    let Ok(()) = leaf::op(ops, operator, numbers, &NoAdmission);
}
pub(super) fn text(ops: &mut Vec<Operation>, font: &[u8], value: &str, x: f64, y: f64, size: f64) {
    let Ok(()) = leaf::text(ops, font, value, x, y, size, &NoAdmission);
}
pub(super) fn resource(resources: &mut Dictionary, kind: &[u8], id: ObjectId) -> Result<Vec<u8>> {
    leaf::resource(resources, kind, id, &NoAdmission).map_err(map_leaf)
}
/// The signature rasters already written, each once however many fields
/// show it. No raster budget refuses a document (Rule 5): each raster is held
/// to its decoder's bounds at upload.
pub(super) type BurnImages = leaf::ImageCache;
impl leaf::RasterView for SignatureRaster {
    fn width(&self) -> u32 {
        self.width
    }
    fn height(&self) -> u32 {
        self.height
    }
    fn rgba(&self) -> &[u8] {
        &self.rgba
    }
}
/// A copier failure as the engine reads it: the preparation error itself, or
/// nothing for a copier-free call.
pub(super) trait MapExternal {
    /// The preparation error for this copier failure.
    fn map_external(self) -> PdfPreparationError;
}
impl MapExternal for std::convert::Infallible {
    fn map_external(self) -> PdfPreparationError {
        match self {}
    }
}
impl MapExternal for PdfPreparationError {
    fn map_external(self) -> PdfPreparationError {
        self
    }
}
/// A shared-renderer failure as the engine reads it, exactly as each burn
/// site reads it today: the display-size refusal as the codec-or-format
/// limit, the unreachable raster-size refusal as an invalid image, a lopdf
/// failure through the existing conversion, and each logic failure 1:1.
pub(super) fn map_leaf<X: MapExternal>(
    err: leaf::BurnError<std::convert::Infallible, X>,
) -> PdfPreparationError {
    match err {
        leaf::BurnError::Admit(refusal) => match refusal {},
        leaf::BurnError::External(external) => external.map_external(),
        leaf::BurnError::Lopdf(err) => PdfPreparationError::from(err),
        leaf::BurnError::DisplayTooLarge => PdfPreparationError::Limit,
        leaf::BurnError::TooLarge => PdfPreparationError::InvalidSignatureImage,
        leaf::BurnError::MalformedPdf => PdfPreparationError::MalformedPdf,
        leaf::BurnError::UnsupportedPdf => PdfPreparationError::UnsupportedPdf,
        leaf::BurnError::InvalidGeometry => PdfPreparationError::InvalidGeometry,
        leaf::BurnError::InvalidSignatureImage => PdfPreparationError::InvalidSignatureImage,
        leaf::BurnError::UnsupportedText => PdfPreparationError::UnsupportedText,
        leaf::BurnError::FieldOverflow => PdfPreparationError::FieldOverflow,
    }
}
/// Burns `fields`, the request item's fields on one page in document order.
pub(super) fn burn_fields(
    out: &mut Document,
    resources: &mut Dictionary,
    crop: [f64; 4],
    fields: &[&EsignField],
    request: &PdfPreparation<'_>,
    font: ObjectId,
    images: &mut BurnImages,
) -> Result<Vec<Operation>> {
    let font_name = resource(resources, b"Font", font)?;
    let mut ops = Vec::new();
    for &field in fields {
        let presentation = present_field(
            field,
            request.state.signatures.get(&field.id).map(|s| &s.value),
        )?;
        let geometry = leaf::FieldGeometry {
            page: presentation.geometry.page,
            x_percent: presentation.geometry.x_percent,
            y_percent: presentation.geometry.y_percent,
            width_percent: presentation.geometry.width_percent,
            height_percent: presentation.geometry.height_percent,
        };
        let value = match &presentation.value {
            None => None,
            Some(FieldValue::Text(value)) => Some(leaf::LeafValue::Text(value.as_str())),
            Some(FieldValue::Checked(checked)) => Some(leaf::LeafValue::Checked(*checked)),
            Some(FieldValue::Signature { image_ref }) => Some(leaf::LeafValue::Signature {
                image_ref: image_ref.as_str(),
            }),
        };
        leaf::burn_field(
            &mut ops,
            out,
            resources,
            crop,
            &font_name,
            &geometry,
            value,
            request.signature_images,
            images,
            &NoAdmission,
        )
        .map_err(map_leaf)?;
    }
    if request.state.rejection.is_some() {
        let Ok(()) = leaf::stamp_rejected(&mut ops, &font_name, crop, &NoAdmission);
    }
    Ok(ops)
}
