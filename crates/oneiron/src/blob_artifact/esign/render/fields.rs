//! Flattened e-sign field text, marks and signature pixels.
use super::*;

pub(super) fn op(ops: &mut Vec<Operation>, operator: &str, numbers: &[f64]) {
    ops.push(Operation::new(
        operator,
        numbers.iter().map(|n| Object::Real(*n as f32)).collect(),
    ));
}
pub(super) fn text(ops: &mut Vec<Operation>, font: &[u8], value: &str, x: f64, y: f64, size: f64) {
    op(ops, "BT", &[]);
    ops.push(Operation::new(
        "Tf",
        vec![Object::Name(font.to_vec()), Object::Real(size as f32)],
    ));
    op(ops, "Tm", &[1.0, 0.0, 0.0, 1.0, x, y]);
    ops.push(Operation::new("Tj", vec![Object::string_literal(value)]));
    op(ops, "ET", &[]);
}
fn resource(resources: &mut Dictionary, kind: &[u8], id: ObjectId) -> Result<Vec<u8>> {
    // Resource category maps are already copied into direct dictionaries.
    // Mutate them in place: cloning the entire map for every field is quadratic.
    if !resources.has(kind) {
        resources.set(kind, Dictionary::new());
    }
    let members = resources.get_mut(kind)?.as_dict_mut()?;
    let base = format!("ESign{}", id.0);
    let mut name = base.as_bytes().to_vec();
    let mut counter = 0;
    while members.has(&name) {
        if members.get(&name)?.as_reference().ok() == Some(id) {
            return Ok(name);
        }
        counter += 1;
        name = format!("{base}_{counter}").into_bytes();
    }
    members.set(name.clone(), id);
    Ok(name)
}
fn raster(doc: &mut Document, image: &SignatureRaster) -> Result<ObjectId> {
    let pixels = u64::from(image.width) * u64::from(image.height);
    if image.width == 0
        || image.height == 0
        || image.width > 2048
        || image.height > 2048
        || pixels * 4 != image.rgba.len() as u64
        || image.rgba.chunks_exact(4).all(|p| p[3] == 0)
    {
        return Err(PdfPreparationError::InvalidSignatureImage);
    }
    let alpha = doc.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Image", "Width" => image.width,
            "Height" => image.height, "ColorSpace" => "DeviceGray", "BitsPerComponent" => 8,
        },
        image.rgba.chunks_exact(4).map(|p| p[3]).collect(),
    ));
    Ok(doc.add_object(Stream::new(dictionary! {
        "Type" => "XObject", "Subtype" => "Image", "Width" => image.width,
        "Height" => image.height, "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8, "SMask" => alpha,
    }, image.rgba.chunks_exact(4).flat_map(|p| p[..3].iter().copied()).collect())))
}
fn burn_text(ops: &mut Vec<Operation>, font: &[u8], value: &str, rect: PdfFieldRect) -> Result<()> {
    if value
        .bytes()
        .any(|b| !(b == b'\n' || (32..=126).contains(&b)))
    {
        return Err(PdfPreparationError::UnsupportedText);
    }
    let lines: Vec<_> = value.split('\n').collect();
    let columns = lines.iter().map(|l| l.len()).max().unwrap_or(0).max(1);
    let size = 12.0f64
        .min((rect.width - 4.0) / (columns as f64 * 0.6))
        .min((rect.height - 4.0) / (lines.len() as f64 * 1.2));
    if size < 6.0 {
        return Err(PdfPreparationError::FieldOverflow);
    }
    for (i, line) in lines.iter().enumerate() {
        text(
            ops,
            font,
            line,
            rect.x + 2.0,
            rect.y + rect.height - 2.0 - size * (1.0 + i as f64 * 1.2),
            size,
        );
    }
    Ok(())
}
#[derive(Default)]
pub(super) struct BurnImages {
    ids: BTreeMap<String, ObjectId>,
    bytes: usize,
}
pub(super) fn burn_fields(
    out: &mut Document,
    resources: &mut Dictionary,
    crop: [f64; 4],
    page: u32,
    request: &PdfPreparation<'_>,
    font: ObjectId,
    images: &mut BurnImages,
) -> Result<Vec<Operation>> {
    let font_name = resource(resources, b"Font", font)?;
    let mut ops = Vec::new();
    for field in request
        .state
        .document
        .fields
        .iter()
        .filter(|f| f.item == request.item && f.geometry.page == page)
    {
        let rect = render_field_geometry(&field.geometry, crop)?;
        let Some(signature) = request.state.signatures.get(&field.id) else {
            continue;
        };
        crate::blob_artifact::esign::fold::validate_value(field, &signature.value)
            .map_err(|_| PdfPreparationError::InvalidField)?;
        op(&mut ops, "q", &[]);
        op(&mut ops, "re", &[rect.x, rect.y, rect.width, rect.height]);
        op(&mut ops, "W", &[]);
        op(&mut ops, "n", &[]);
        op(&mut ops, "g", &[0.0]);
        match &signature.value {
            FieldValue::Text(value) => burn_text(&mut ops, &font_name, value, rect)?,
            FieldValue::Checked(checked) => {
                let side = rect.width.min(rect.height) - 2.0;
                if side < 2.0 {
                    return Err(PdfPreparationError::InvalidGeometry);
                }
                op(&mut ops, "w", &[1.0]);
                op(&mut ops, "re", &[rect.x + 1.0, rect.y + 1.0, side, side]);
                op(&mut ops, "S", &[]);
                if *checked {
                    op(&mut ops, "m", &[rect.x + 1.0, rect.y + 1.0]);
                    op(&mut ops, "l", &[rect.x + 1.0 + side, rect.y + 1.0 + side]);
                    op(&mut ops, "m", &[rect.x + 1.0, rect.y + 1.0 + side]);
                    op(&mut ops, "l", &[rect.x + 1.0 + side, rect.y + 1.0]);
                    op(&mut ops, "S", &[]);
                }
            }
            FieldValue::Signature { image_ref } => {
                let image = request
                    .signature_images
                    .get(image_ref)
                    .ok_or(PdfPreparationError::InvalidSignatureImage)?;
                let id = if let Some(id) = images.ids.get(image_ref) {
                    *id
                } else {
                    images.bytes = images
                        .bytes
                        .checked_add(image.rgba.len())
                        .ok_or(PdfPreparationError::Limit)?;
                    if images.bytes > MAX_OUTPUT {
                        return Err(PdfPreparationError::Limit);
                    }
                    let id = raster(out, image)?;
                    images.ids.insert(image_ref.clone(), id);
                    id
                };
                let name = resource(resources, b"XObject", id)?;
                let scale = (rect.width / f64::from(image.width))
                    .min(rect.height / f64::from(image.height));
                let (w, h) = (
                    f64::from(image.width) * scale,
                    f64::from(image.height) * scale,
                );
                op(
                    &mut ops,
                    "cm",
                    &[
                        w,
                        0.0,
                        0.0,
                        h,
                        rect.x + (rect.width - w) / 2.0,
                        rect.y + (rect.height - h) / 2.0,
                    ],
                );
                ops.push(Operation::new("Do", vec![Object::Name(name)]));
            }
        }
        op(&mut ops, "Q", &[]);
    }
    if request.state.rejection.is_some() {
        op(&mut ops, "q", &[]);
        op(&mut ops, "rg", &[1.0, 0.0, 0.0]);
        text(
            &mut ops,
            &font_name,
            "REJECTED",
            crop[0] + 8.0,
            crop[3] - 22.0,
            16.0,
        );
        op(&mut ops, "Q", &[]);
    }
    Ok(ops)
}
