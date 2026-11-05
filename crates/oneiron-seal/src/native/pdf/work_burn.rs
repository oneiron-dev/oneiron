//! Ported field burn-in and annotation-appearance flattening (FIX 7980/8157).
//!
//! Ports the engine's `render/fields` (`op`/`text`/`resource`/`raster`/
//! `BurnImages`/`burn_fields`) and `render/appearance` (`flatten`/
//! `nonvisual_link`) into the organ admission model.
//!
//! Behavior-identical except admission and bounds: every vector, string
//! clone, pixel buffer, dictionary entry, and fresh-document object is
//! admitted against the call's operation ledger first (via [`WorkLimits`]),
//! never the engine `Stage` (the row sources take no `Stage`; the ledger is
//! added for the organ's buffers). The raster 2048px/alpha checks are
//! verbatim decoder bounds ([`InputInvalidCode::InvalidSignatureImage`]).
//! No per-stream codec bound exists here, so no refusal is dropped to an
//! admission (contrast `work_streams`): value-shape refusals stay
//! engine-side and their checked scalars are lent in, marked below.
//!
//! Reuses [`super::work_present`] for geometry, marks, and Win1252 text
//! rather than duplicating them. The small `source` readers are duplicated
//! locally so this file does not depend on `work_source`'s unfinished API;
//! the visual copy crosses as a caller-supplied `copy` closure that `work_prepare.rs`
//! wires to `work_source`'s copier.

use std::collections::BTreeMap;
use std::mem::size_of;

use lopdf::content::Operation;
use lopdf::{Dictionary, Document, Object, ObjectId, Stream, dictionary};

use super::work::{WorkError, WorkLimits};
use super::work_present::{
    FieldGeometry, FieldMark, MarkValue, PageGeometry, encoded_text, marks, render_field_geometry,
};
use crate::error::InputInvalidCode;
use crate::memory::{MemoryLedger, SealMemoryRefusal};

/// One signature raster's decoded pixels, as the engine's `SignatureRaster`
/// but borrowed: rasters cross PNG-decoded and the handler slices the lent
/// blob, so no copy crosses here. Straight-alpha RGBA, top-to-bottom rows.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct WorkRaster<'a> {
    pub width: u32,
    pub height: u32,
    pub rgba: &'a [u8],
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
#[derive(Default)]
pub(crate) struct BurnImages {
    ids: BTreeMap<String, ObjectId>,
}

/// One operation appended, as the engine's `fields::op`. Operator bytes,
/// operand vector, and `ops` growth are admitted first.
pub(super) fn op(
    ops: &mut Vec<Operation>,
    operator: &str,
    numbers: &[f64],
    limits: &WorkLimits<'_>,
) -> Result<(), WorkError> {
    limits
        .ledger
        .admit_len::<u8>(operator.len())
        .map_err(WorkError::Memory)?;
    limits
        .ledger
        .admit_len::<Object>(numbers.len())
        .map_err(WorkError::Memory)?;
    let operands = numbers.iter().map(|n| Object::Real(*n as f32)).collect();
    push(limits.ledger, ops, Operation::new(operator, operands))
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
    op(ops, "BT", &[], limits)?;
    limits
        .ledger
        .admit_len::<u8>(font.len())
        .map_err(WorkError::Memory)?;
    limits
        .ledger
        .admit_len::<Object>(2)
        .map_err(WorkError::Memory)?;
    limits
        .ledger
        .admit_len::<u8>(2)
        .map_err(WorkError::Memory)?; // "Tf"
    push(
        limits.ledger,
        ops,
        Operation::new(
            "Tf",
            vec![Object::Name(font.to_vec()), Object::Real(size as f32)],
        ),
    )?;
    op(ops, "Tm", &[1.0, 0.0, 0.0, 1.0, x, y], limits)?;
    limits
        .ledger
        .admit_len::<u8>(value.len())
        .map_err(WorkError::Memory)?;
    limits
        .ledger
        .admit_len::<Object>(1)
        .map_err(WorkError::Memory)?;
    limits
        .ledger
        .admit_len::<u8>(2)
        .map_err(WorkError::Memory)?; // "Tj"
    push(
        limits.ledger,
        ops,
        Operation::new("Tj", vec![Object::string_literal(value)]),
    )?;
    op(ops, "ET", &[], limits)
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
    if !resources.has(kind) {
        dictionary_insert(limits.ledger, kind.len())?;
        resources.set(kind, Dictionary::new());
    }
    let members = resources
        .get_mut(kind)
        .map_err(|err| lopdf_error(limits, err))?
        .as_dict_mut()
        .map_err(|err| lopdf_error(limits, err))?;
    let base = format!("ESign{}", id.0);
    limits
        .ledger
        .admit_len::<u8>(base.len())
        .map_err(WorkError::Memory)?;
    limits
        .ledger
        .admit_len::<u8>(base.len())
        .map_err(WorkError::Memory)?;
    let mut name = base.as_bytes().to_vec();
    let mut counter = 0;
    while members.has(&name) {
        if members
            .get(&name)
            .map_err(|err| lopdf_error(limits, err))?
            .as_reference()
            .ok()
            == Some(id)
        {
            return Ok(name);
        }
        counter += 1;
        let next = format!("{base}_{counter}").into_bytes();
        limits
            .ledger
            .admit_len::<u8>(next.len())
            .map_err(WorkError::Memory)?;
        let old_len = name.len();
        name = next;
        limits.ledger.release_admitted(wide(old_len));
    }
    dictionary_insert(limits.ledger, name.len())?;
    members.set(name.clone(), id);
    Ok(name)
}

/// The image XObjects for one raster, as the engine's `fields::raster`: a
/// DeviceGray smask plus a DeviceRGB image. The 2048px, row-length, and
/// non-blank-alpha checks are verbatim decoder bounds. Pixel buffers,
/// dictionaries, and fresh objects are admitted first.
fn raster(
    out: &mut Document,
    image: &WorkRaster<'_>,
    limits: &WorkLimits<'_>,
) -> Result<ObjectId, WorkError> {
    let pixels = u64::from(image.width) * u64::from(image.height);
    if image.width == 0
        || image.height == 0
        || image.width > 2048
        || image.height > 2048
        || pixels * 4 != image.rgba.len() as u64
        || image.rgba.chunks_exact(4).all(|p| p[3] == 0)
    {
        return Err(WorkError::Invalid(InputInvalidCode::InvalidSignatureImage));
    }
    let px = usize::try_from(pixels).map_err(|_| WorkError::Invalid(InputInvalidCode::TooLarge))?;
    let rgb_len = px
        .checked_mul(3)
        .ok_or(WorkError::Invalid(InputInvalidCode::TooLarge))?;
    limits
        .ledger
        .admit_len::<u8>(px)
        .map_err(WorkError::Memory)?;
    let alpha_bytes: Vec<u8> = image.rgba.chunks_exact(4).map(|p| p[3]).collect();
    image_dict_insert(limits.ledger, 6, 48, 22)?; // Type/Subtype/Width/Height/ColorSpace/BitsPerComponent
    let alpha = {
        object_insert(limits.ledger)?;
        out.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image", "Width" => image.width,
                "Height" => image.height, "ColorSpace" => "DeviceGray", "BitsPerComponent" => 8,
            },
            alpha_bytes,
        ))
    };
    limits
        .ledger
        .admit_len::<u8>(rgb_len)
        .map_err(WorkError::Memory)?;
    let rgb_bytes: Vec<u8> = image
        .rgba
        .chunks_exact(4)
        .flat_map(|p| p[..3].iter().copied())
        .collect();
    image_dict_insert(limits.ledger, 7, 53, 21)?; // alpha keys plus SMask (a reference, no heap)
    object_insert(limits.ledger)?;
    Ok(out.add_object(Stream::new(dictionary! {
        "Type" => "XObject", "Subtype" => "Image", "Width" => image.width,
        "Height" => image.height, "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8, "SMask" => alpha,
    }, rgb_bytes)))
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
    let font_name = resource(resources, b"Font", font, limits)?;
    let mut ops = Vec::new();
    for field in fields.iter().filter(|f| f.geometry.page == page) {
        let value = match values.get(&field.id) {
            None => None,
            Some(BurnValue::Text(value)) => Some(MarkValue::Text(value.as_str())),
            Some(BurnValue::Checked(checked)) => Some(MarkValue::Checked(*checked)),
            Some(BurnValue::Signature { image_ref }) => Some(MarkValue::Signature {
                image_ref: image_ref.as_str(),
            }),
        };
        let rect = render_field_geometry(&field.geometry, crop)?;
        if value.is_none() {
            continue;
        }
        op(&mut ops, "q", &[], limits)?;
        op(
            &mut ops,
            "re",
            &[rect.x, rect.y, rect.width, rect.height],
            limits,
        )?;
        op(&mut ops, "W", &[], limits)?;
        op(&mut ops, "n", &[], limits)?;
        op(&mut ops, "g", &[0.0], limits)?;
        op(&mut ops, "w", &[1.0], limits)?;
        for mark in marks(
            &field.geometry,
            PageGeometry {
                crop,
                rotation: 0,
                user_unit: 1.,
            },
            value,
            limits,
        )? {
            match mark {
                FieldMark::Text { value, x, y, size } => {
                    op(&mut ops, "BT", &[], limits)?;
                    limits
                        .ledger
                        .admit_len::<u8>(font_name.len())
                        .map_err(WorkError::Memory)?;
                    limits
                        .ledger
                        .admit_len::<Object>(2)
                        .map_err(WorkError::Memory)?;
                    limits
                        .ledger
                        .admit_len::<u8>(2)
                        .map_err(WorkError::Memory)?; // "Tf"
                    push(
                        limits.ledger,
                        &mut ops,
                        Operation::new(
                            "Tf",
                            vec![Object::Name(font_name.clone()), Object::Real(size as f32)],
                        ),
                    )?;
                    op(&mut ops, "Tm", &[1., 0., 0., 1., x, y], limits)?;
                    let encoded = encoded_text(&value, limits)?;
                    limits
                        .ledger
                        .admit_len::<Object>(1)
                        .map_err(WorkError::Memory)?;
                    limits
                        .ledger
                        .admit_len::<u8>(2)
                        .map_err(WorkError::Memory)?; // "Tj"
                    push(
                        limits.ledger,
                        &mut ops,
                        Operation::new(
                            "Tj",
                            vec![Object::String(encoded, lopdf::StringFormat::Literal)],
                        ),
                    )?;
                    op(&mut ops, "ET", &[], limits)?;
                }
                FieldMark::Rectangle {
                    x,
                    y,
                    width,
                    height,
                } => {
                    op(&mut ops, "re", &[x, y, width, height], limits)?;
                    op(&mut ops, "S", &[], limits)?;
                }
                FieldMark::Line { x1, y1, x2, y2 } => {
                    op(&mut ops, "m", &[x1, y1], limits)?;
                    op(&mut ops, "l", &[x2, y2], limits)?;
                    op(&mut ops, "S", &[], limits)?;
                }
                FieldMark::Signature { image_ref, rect } => {
                    let image = rasters
                        .get(&image_ref)
                        .ok_or(WorkError::Invalid(InputInvalidCode::InvalidSignatureImage))?;
                    let id = if let Some(id) = images.ids.get(&image_ref) {
                        *id
                    } else {
                        let id = raster(out, image, limits)?;
                        burn_image_insert(limits.ledger, image_ref.len())?;
                        images.ids.insert(image_ref.clone(), id);
                        id
                    };
                    let name = resource(resources, b"XObject", id, limits)?;
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
                        limits,
                    )?;
                    limits
                        .ledger
                        .admit_len::<Object>(1)
                        .map_err(WorkError::Memory)?;
                    limits
                        .ledger
                        .admit_len::<u8>(2)
                        .map_err(WorkError::Memory)?; // "Do"
                    push(
                        limits.ledger,
                        &mut ops,
                        Operation::new("Do", vec![Object::Name(name)]),
                    )?;
                }
            }
        }
        op(&mut ops, "Q", &[], limits)?;
    }
    if rejected {
        op(&mut ops, "q", &[], limits)?;
        op(&mut ops, "rg", &[1.0, 0.0, 0.0], limits)?;
        text(
            &mut ops,
            &font_name,
            "REJECTED",
            crop[0] + 8.0,
            crop[3] - 22.0,
            16.0,
            limits,
        )?;
        op(&mut ops, "Q", &[], limits)?;
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
    let mut ops = Vec::new();
    let Some(annotations) = annotations else {
        return Ok(ops);
    };
    let (_, annotations) = source
        .dereference(annotations)
        .map_err(|err| lopdf_error(limits, err))?;
    for annotation in annotations
        .as_array()
        .map_err(|err| lopdf_error(limits, err))?
    {
        let annotation = resolved(source, annotation, limits)?
            .as_dict()
            .map_err(|err| lopdf_error(limits, err))?;
        let flags = annotation
            .get(b"F")
            .ok()
            .map(|v| {
                resolved(source, v, limits)?
                    .as_i64()
                    .map_err(|err| lopdf_error(limits, err))
            })
            .transpose()?
            .unwrap_or(0);
        if flags & 3 != 0 {
            continue;
        } // Invisible / Hidden.
        if flags & (8 | 16 | 32) != 0 || annotation.has(b"OC") {
            return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf));
        }
        let appearance = match annotation.get(b"AP") {
            Ok(ap) => resolved(source, ap, limits)?
                .as_dict()
                .map_err(|err| lopdf_error(limits, err))?,
            // A link without a border or appearance is genuinely nonvisual.
            Err(_) if nonvisual_link(source, annotation, limits)? => continue,
            Err(_) => return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf)),
        };
        let normal = resolved(
            source,
            appearance
                .get(b"N")
                .map_err(|err| lopdf_error(limits, err))?,
            limits,
        )?;
        let normal = if let Object::Dictionary(states) = normal {
            let state = resolved(
                source,
                annotation
                    .get(b"AS")
                    .map_err(|err| lopdf_error(limits, err))?,
                limits,
            )?
            .as_name()
            .map_err(|err| lopdf_error(limits, err))?;
            states.get(state).map_err(|err| lopdf_error(limits, err))?
        } else {
            normal
        };
        let stream = resolved(source, normal, limits)?
            .as_stream()
            .map_err(|err| lopdf_error(limits, err))?;
        if !stream.dict.has_type(b"XObject")
            || stream
                .dict
                .get(b"Subtype")
                .map_err(|err| lopdf_error(limits, err))?
                .as_name()
                .map_err(|err| lopdf_error(limits, err))?
                != b"Form"
        {
            return Err(WorkError::Invalid(InputInvalidCode::UnsupportedPdf));
        }
        let rect = pdf_box(
            source,
            annotation
                .get(b"Rect")
                .map_err(|err| lopdf_error(limits, err))?,
            limits,
        )?;
        let bbox = pdf_box(
            source,
            stream
                .dict
                .get(b"BBox")
                .map_err(|err| lopdf_error(limits, err))?,
            limits,
        )?;
        let matrix = if let Ok(matrix) = stream.dict.get(b"Matrix") {
            let values = resolved(source, matrix, limits)?
                .as_array()
                .map_err(|err| lopdf_error(limits, err))?;
            if values.len() != 6 {
                return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
            }
            let mut matrix = [0.; 6];
            for (slot, value) in matrix.iter_mut().zip(values) {
                *slot = number(source, value, limits)?;
            }
            matrix
        } else {
            [1., 0., 0., 1., 0., 0.]
        };
        let [a, b, c, d, e, f] = matrix;
        if (a * d - b * c).abs() < 1e-12 {
            return Err(WorkError::Invalid(InputInvalidCode::InvalidGeometry));
        }
        let corners = [
            (bbox[0], bbox[1]),
            (bbox[0], bbox[3]),
            (bbox[2], bbox[1]),
            (bbox[2], bbox[3]),
        ];
        let mut bounds = [
            f64::INFINITY,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NEG_INFINITY,
        ];
        for (x, y) in corners {
            let (x, y) = (a * x + c * y + e, b * x + d * y + f);
            bounds[0] = bounds[0].min(x);
            bounds[1] = bounds[1].min(y);
            bounds[2] = bounds[2].max(x);
            bounds[3] = bounds[3].max(y);
        }
        let sx = (rect[2] - rect[0]) / (bounds[2] - bounds[0]);
        let sy = (rect[3] - rect[1]) / (bounds[3] - bounds[1]);
        if !sx.is_finite() || !sy.is_finite() {
            return Err(WorkError::Invalid(InputInvalidCode::InvalidGeometry));
        }
        let object = copy(out, normal, 0)?;
        let id = match object {
            Object::Reference(id) => id,
            other => {
                object_insert(limits.ledger)?;
                out.add_object(other)
            }
        };
        let name = resource(resources, b"XObject", id, limits)?;
        op(&mut ops, "q", &[], limits)?;
        op(
            &mut ops,
            "re",
            &[rect[0], rect[1], rect[2] - rect[0], rect[3] - rect[1]],
            limits,
        )?;
        op(&mut ops, "W", &[], limits)?;
        op(&mut ops, "n", &[], limits)?;
        op(
            &mut ops,
            "cm",
            &[
                sx,
                0.,
                0.,
                sy,
                rect[0] - sx * bounds[0],
                rect[1] - sy * bounds[1],
            ],
            limits,
        )?;
        limits
            .ledger
            .admit_len::<Object>(1)
            .map_err(WorkError::Memory)?;
        limits
            .ledger
            .admit_len::<u8>(2)
            .map_err(WorkError::Memory)?; // "Do"
        push(
            limits.ledger,
            &mut ops,
            Operation::new("Do", vec![Object::Name(name)]),
        )?;
        op(&mut ops, "Q", &[], limits)?;
    }
    Ok(ops)
}

// Border style overrides the legacy Border array in PDF. Never discard a
// visible link merely because its older Border entry says zero width.
fn nonvisual_link(
    source: &Document,
    annotation: &Dictionary,
    limits: &WorkLimits<'_>,
) -> Result<bool, WorkError> {
    if resolved(
        source,
        annotation
            .get(b"Subtype")
            .map_err(|err| lopdf_error(limits, err))?,
        limits,
    )?
    .as_name()
    .map_err(|err| lopdf_error(limits, err))?
        != b"Link"
    {
        return Ok(false);
    }
    let width = if let Ok(style) = annotation.get(b"BS") {
        let style = resolved(source, style, limits)?
            .as_dict()
            .map_err(|err| lopdf_error(limits, err))?;
        match style.get(b"W") {
            Ok(width) => number(source, width, limits)?,
            Err(_) => 1.0,
        }
    } else if let Ok(border) = annotation.get(b"Border") {
        let border = resolved(source, border, limits)?
            .as_array()
            .map_err(|err| lopdf_error(limits, err))?;
        if !(3..=4).contains(&border.len()) {
            return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
        }
        number(source, &border[2], limits)?
    } else {
        1.0
    };
    Ok(width == 0.0)
}

/// The terminal object `object` names, as the engine's `source::resolved`.
fn resolved<'a>(
    doc: &'a Document,
    object: &'a Object,
    limits: &WorkLimits<'_>,
) -> Result<&'a Object, WorkError> {
    doc.dereference(object)
        .map(|(_, object)| object)
        .map_err(|err| lopdf_error(limits, err))
}

/// The number `value` names, as the engine's `source::number`.
fn number(doc: &Document, value: &Object, limits: &WorkLimits<'_>) -> Result<f64, WorkError> {
    match resolved(doc, value, limits)? {
        Object::Integer(v) => Ok(*v as f64),
        Object::Real(v) if v.is_finite() => Ok(f64::from(*v)),
        _ => Err(WorkError::Invalid(InputInvalidCode::MalformedPdf)),
    }
}

/// The four-number box `value` names, as the engine's `source::pdf_box`.
fn pdf_box(doc: &Document, value: &Object, limits: &WorkLimits<'_>) -> Result<[f64; 4], WorkError> {
    let values = resolved(doc, value, limits)?
        .as_array()
        .map_err(|err| lopdf_error(limits, err))?;
    if values.len() != 4 {
        return Err(WorkError::Invalid(InputInvalidCode::InvalidGeometry));
    }
    let result = [
        number(doc, &values[0], limits)?,
        number(doc, &values[1], limits)?,
        number(doc, &values[2], limits)?,
        number(doc, &values[3], limits)?,
    ];
    render_field_geometry(
        &FieldGeometry {
            page: 1,
            x_percent: 0.0,
            y_percent: 0.0,
            width_percent: 100.0,
            height_percent: 100.0,
        },
        result,
    )?;
    Ok(result)
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

/// One `BurnImages` entry: the map share plus the cloned key's heap bytes.
fn burn_image_insert(ledger: &MemoryLedger, key_len: usize) -> Result<(), WorkError> {
    let bytes = btree_entry_bytes::<String, ObjectId>()
        .checked_add(key_len)
        .ok_or_else(|| WorkError::Memory(floor(usize::MAX)))?;
    ledger.admit_len::<u8>(bytes).map_err(WorkError::Memory)
}

/// One raster image dictionary built whole: `entries` shares plus the key
/// and inline-name heap bytes the `dictionary!` map holds.
fn image_dict_insert(
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
