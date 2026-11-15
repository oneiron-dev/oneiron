//! Shared field burn-in: operations, resources, rasters, and one field.
//!
//! The drawing program for the pre-seal burn-in: content-stream operations,
//! resource names, signature image objects, and the per-field burn that each
//! side's loop calls once per field. Every `ops` push and every fresh object
//! is admitted through the admission first.

use std::collections::BTreeMap;

use lopdf::content::Operation;
use lopdf::{Dictionary, Document, Object, ObjectId, Stream, dictionary};

use crate::admit::Admission;
use crate::error::BurnError;
use crate::present::{
    FieldGeometry, FieldMark, ImageCache, LeafValue, PageGeometry, RasterView, encoded_text, marks,
    render_field_geometry,
};

/// One operation appended. Operator bytes, operand vector, and `ops` growth
/// are admitted first.
pub fn op<A: Admission>(
    ops: &mut Vec<Operation>,
    operator: &str,
    numbers: &[f64],
    admit: &A,
) -> Result<(), A::Error> {
    admit.admit_len::<u8>(operator.len())?;
    admit.admit_len::<Object>(numbers.len())?;
    let operands = numbers.iter().map(|n| Object::Real(*n as f32)).collect();
    admit.push(ops, Operation::new(operator, operands))
}

/// One labeled text draw.
pub fn text<A: Admission>(
    ops: &mut Vec<Operation>,
    font: &[u8],
    value: &str,
    x: f64,
    y: f64,
    size: f64,
    admit: &A,
) -> Result<(), A::Error> {
    op(ops, "BT", &[], admit)?;
    admit.admit_len::<u8>(font.len())?;
    admit.admit_len::<Object>(2)?;
    admit.admit_len::<u8>(2)?; // "Tf"
    admit.push(
        ops,
        Operation::new(
            "Tf",
            vec![Object::Name(font.to_vec()), Object::Real(size as f32)],
        ),
    )?;
    op(ops, "Tm", &[1.0, 0.0, 0.0, 1.0, x, y], admit)?;
    admit.admit_len::<u8>(value.len())?;
    admit.admit_len::<Object>(1)?;
    admit.admit_len::<u8>(2)?; // "Tj"
    admit.push(
        ops,
        Operation::new("Tj", vec![Object::string_literal(value)]),
    )?;
    op(ops, "ET", &[], admit)
}

/// The resource name for `id` under `kind`: category maps are direct
/// dictionaries, mutated in place (cloning per field is quadratic). A
/// missing category, name bytes, and entry are admitted.
pub fn resource<A: Admission>(
    resources: &mut Dictionary,
    kind: &[u8],
    id: ObjectId,
    admit: &A,
) -> Result<Vec<u8>, BurnError<A::Error>> {
    if !resources.has(kind) {
        admit
            .admit_dict_entry(kind.len())
            .map_err(BurnError::Admit)?;
        resources.set(kind, Dictionary::new());
    }
    let members = resources
        .get_mut(kind)
        .map_err(BurnError::Lopdf)?
        .as_dict_mut()
        .map_err(BurnError::Lopdf)?;
    let base = format!("ESign{}", id.0);
    admit
        .admit_len::<u8>(base.len())
        .map_err(BurnError::Admit)?;
    admit
        .admit_len::<u8>(base.len())
        .map_err(BurnError::Admit)?;
    let mut name = base.as_bytes().to_vec();
    let mut counter = 0;
    while members.has(&name) {
        if members
            .get(&name)
            .map_err(BurnError::Lopdf)?
            .as_reference()
            .ok()
            == Some(id)
        {
            return Ok(name);
        }
        counter += 1;
        let next = format!("{base}_{counter}").into_bytes();
        admit
            .admit_len::<u8>(next.len())
            .map_err(BurnError::Admit)?;
        let old_len = name.len();
        name = next;
        admit.release_admitted(wide(old_len));
    }
    admit
        .admit_dict_entry(name.len())
        .map_err(BurnError::Admit)?;
    members.set(name.clone(), id);
    Ok(name)
}

/// The image XObjects for one raster: a DeviceGray smask plus a DeviceRGB
/// image. Nonzero dimensions, exact RGBA length, and non-blank alpha remain
/// required. Pixel buffers, dictionaries, and fresh objects are admitted
/// first.
fn raster<A: Admission, R: RasterView>(
    out: &mut Document,
    image: &R,
    admit: &A,
) -> Result<ObjectId, BurnError<A::Error>> {
    let pixels = u64::from(image.width()) * u64::from(image.height());
    if image.width() == 0
        || image.height() == 0
        || pixels.checked_mul(4) != Some(image.rgba().len() as u64)
        || image.rgba().chunks_exact(4).all(|p| p[3] == 0)
    {
        return Err(BurnError::InvalidSignatureImage);
    }
    let px = usize::try_from(pixels).map_err(|_| BurnError::TooLarge)?;
    let rgb_len = px.checked_mul(3).ok_or(BurnError::TooLarge)?;
    admit.admit_len::<u8>(px).map_err(BurnError::Admit)?;
    let alpha_bytes: Vec<u8> = image.rgba().chunks_exact(4).map(|p| p[3]).collect();
    admit
        .admit_image_dict(6, 48, 22)
        .map_err(BurnError::Admit)?; // Type/Subtype/Width/Height/ColorSpace/BitsPerComponent
    let alpha = {
        admit.admit_object().map_err(BurnError::Admit)?;
        out.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image", "Width" => image.width(),
                "Height" => image.height(), "ColorSpace" => "DeviceGray", "BitsPerComponent" => 8,
            },
            alpha_bytes,
        ))
    };
    admit.admit_len::<u8>(rgb_len).map_err(BurnError::Admit)?;
    let rgb_bytes: Vec<u8> = image
        .rgba()
        .chunks_exact(4)
        .flat_map(|p| p[..3].iter().copied())
        .collect();
    admit
        .admit_image_dict(7, 53, 21)
        .map_err(BurnError::Admit)?; // alpha keys plus SMask (a reference, no heap)
    admit.admit_object().map_err(BurnError::Admit)?;
    Ok(out.add_object(Stream::new(dictionary! {
        "Type" => "XObject", "Subtype" => "Image", "Width" => image.width(),
        "Height" => image.height(), "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8, "SMask" => alpha,
    }, rgb_bytes)))
}

/// One field's burn-in over `ops`: the rectangle the percent box projects
/// to, then the clip, the marks, and their arms. Unfilled fields draw
/// nothing. Each side's loop calls this once per field with its projected
/// geometry and value, so the per-field error order stays exactly as today.
#[allow(clippy::too_many_arguments)]
pub fn burn_field<A: Admission, R: RasterView>(
    ops: &mut Vec<Operation>,
    out: &mut Document,
    resources: &mut Dictionary,
    crop: [f64; 4],
    font_name: &[u8],
    geometry: &FieldGeometry,
    value: Option<LeafValue<'_>>,
    rasters: &BTreeMap<String, R>,
    images: &mut ImageCache,
    admit: &A,
) -> Result<(), BurnError<A::Error>> {
    let rect = render_field_geometry(geometry, crop).map_err(BurnError::into_burn)?;
    if value.is_none() {
        return Ok(());
    }
    op(ops, "q", &[], admit).map_err(BurnError::Admit)?;
    op(ops, "re", &[rect.x, rect.y, rect.width, rect.height], admit).map_err(BurnError::Admit)?;
    op(ops, "W", &[], admit).map_err(BurnError::Admit)?;
    op(ops, "n", &[], admit).map_err(BurnError::Admit)?;
    op(ops, "g", &[0.0], admit).map_err(BurnError::Admit)?;
    op(ops, "w", &[1.0], admit).map_err(BurnError::Admit)?;
    for mark in marks(
        geometry,
        PageGeometry {
            crop,
            rotation: 0,
            user_unit: 1.,
        },
        value,
        admit,
    )? {
        match mark {
            FieldMark::Text { value, x, y, size } => {
                op(ops, "BT", &[], admit).map_err(BurnError::Admit)?;
                admit
                    .admit_len::<u8>(font_name.len())
                    .map_err(BurnError::Admit)?;
                admit.admit_len::<Object>(2).map_err(BurnError::Admit)?;
                admit.admit_len::<u8>(2).map_err(BurnError::Admit)?; // "Tf"
                admit
                    .push(
                        ops,
                        Operation::new(
                            "Tf",
                            vec![Object::Name(font_name.to_vec()), Object::Real(size as f32)],
                        ),
                    )
                    .map_err(BurnError::Admit)?;
                op(ops, "Tm", &[1., 0., 0., 1., x, y], admit).map_err(BurnError::Admit)?;
                let encoded = encoded_text(&value, admit)?;
                admit.admit_len::<Object>(1).map_err(BurnError::Admit)?;
                admit.admit_len::<u8>(2).map_err(BurnError::Admit)?; // "Tj"
                admit
                    .push(
                        ops,
                        Operation::new(
                            "Tj",
                            vec![Object::String(encoded, lopdf::StringFormat::Literal)],
                        ),
                    )
                    .map_err(BurnError::Admit)?;
                op(ops, "ET", &[], admit).map_err(BurnError::Admit)?;
            }
            FieldMark::Rectangle {
                x,
                y,
                width,
                height,
            } => {
                op(ops, "re", &[x, y, width, height], admit).map_err(BurnError::Admit)?;
                op(ops, "S", &[], admit).map_err(BurnError::Admit)?;
            }
            FieldMark::Line { x1, y1, x2, y2 } => {
                op(ops, "m", &[x1, y1], admit).map_err(BurnError::Admit)?;
                op(ops, "l", &[x2, y2], admit).map_err(BurnError::Admit)?;
                op(ops, "S", &[], admit).map_err(BurnError::Admit)?;
            }
            FieldMark::Signature { image_ref, rect } => {
                let image = rasters
                    .get(&image_ref)
                    .ok_or(BurnError::InvalidSignatureImage)?;
                let id = if let Some(id) = images.ids.get(&image_ref) {
                    *id
                } else {
                    let id = raster(out, image, admit)?;
                    admit
                        .admit_image_entry(image_ref.len())
                        .map_err(BurnError::Admit)?;
                    images.ids.insert(image_ref.clone(), id);
                    id
                };
                let name = resource(resources, b"XObject", id, admit)?;
                let scale = (rect.width / f64::from(image.width()))
                    .min(rect.height / f64::from(image.height()));
                let (w, h) = (
                    f64::from(image.width()) * scale,
                    f64::from(image.height()) * scale,
                );
                op(
                    ops,
                    "cm",
                    &[
                        w,
                        0.0,
                        0.0,
                        h,
                        rect.x + (rect.width - w) / 2.0,
                        rect.y + (rect.height - h) / 2.0,
                    ],
                    admit,
                )
                .map_err(BurnError::Admit)?;
                admit.admit_len::<Object>(1).map_err(BurnError::Admit)?;
                admit.admit_len::<u8>(2).map_err(BurnError::Admit)?; // "Do"
                admit
                    .push(ops, Operation::new("Do", vec![Object::Name(name)]))
                    .map_err(BurnError::Admit)?;
            }
        }
    }
    op(ops, "Q", &[], admit).map_err(BurnError::Admit)
}

/// The rejected stamp: red `REJECTED` over the page's crop.
pub fn stamp_rejected<A: Admission>(
    ops: &mut Vec<Operation>,
    font_name: &[u8],
    crop: [f64; 4],
    admit: &A,
) -> Result<(), A::Error> {
    op(ops, "q", &[], admit)?;
    op(ops, "rg", &[1.0, 0.0, 0.0], admit)?;
    text(
        ops,
        font_name,
        "REJECTED",
        crop[0] + 8.0,
        crop[3] - 22.0,
        16.0,
        admit,
    )?;
    op(ops, "Q", &[], admit)
}

/// A length as the admission counts bytes.
fn wide(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}
