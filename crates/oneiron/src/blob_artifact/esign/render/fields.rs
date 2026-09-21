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
pub(super) fn resource(resources: &mut Dictionary, kind: &[u8], id: ObjectId) -> Result<Vec<u8>> {
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
        let presentation = present_field(
            field,
            request.state.signatures.get(&field.id).map(|s| &s.value),
        )?;
        let rect = render_field_geometry(&presentation.geometry, crop)?;
        if presentation.value.is_none() {
            continue;
        }
        op(&mut ops, "q", &[]);
        op(&mut ops, "re", &[rect.x, rect.y, rect.width, rect.height]);
        op(&mut ops, "W", &[]);
        op(&mut ops, "n", &[]);
        op(&mut ops, "g", &[0.0]);
        op(&mut ops, "w", &[1.0]);
        for mark in presentation.marks(PageGeometry {
            crop,
            rotation: 0,
            user_unit: 1.,
        })? {
            match mark {
                FieldMark::Text { value, x, y, size } => {
                    op(&mut ops, "BT", &[]);
                    ops.push(Operation::new(
                        "Tf",
                        vec![Object::Name(font_name.clone()), Object::Real(size as f32)],
                    ));
                    op(&mut ops, "Tm", &[1., 0., 0., 1., x, y]);
                    ops.push(Operation::new(
                        "Tj",
                        vec![Object::String(
                            presentation::encoded_text(&value)?,
                            lopdf::StringFormat::Literal,
                        )],
                    ));
                    op(&mut ops, "ET", &[]);
                }
                FieldMark::Rectangle {
                    x,
                    y,
                    width,
                    height,
                } => {
                    op(&mut ops, "re", &[x, y, width, height]);
                    op(&mut ops, "S", &[]);
                }
                FieldMark::Line { x1, y1, x2, y2 } => {
                    op(&mut ops, "m", &[x1, y1]);
                    op(&mut ops, "l", &[x2, y2]);
                    op(&mut ops, "S", &[]);
                }
                FieldMark::Signature { image_ref, rect } => {
                    let image = request
                        .signature_images
                        .get(&image_ref)
                        .ok_or(PdfPreparationError::InvalidSignatureImage)?;
                    let id = if let Some(id) = images.ids.get(&image_ref) {
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
