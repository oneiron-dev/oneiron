//! Shared annotation-appearance flattening.
//!
//! One page's `/Annots` flattened: every annotation of it, however many. An
//! indirect `/Annots` array that several pages name is flattened again for
//! each of them, into that page's own resources and operations, as a reader
//! draws it on each: the shared source array is only read, never changed.
//! The visual copy crosses as a caller-supplied closure; its failures cross
//! as the caller's own error, never named here.

use lopdf::content::Operation;
use lopdf::{Dictionary, Document, Object};

use crate::admit::Admission;
use crate::burn::{op, resource};
use crate::error::BurnError;
use crate::present::{FieldGeometry, render_field_geometry};

/// One page's `/Annots` flattened. `copy` is the visual copy the caller
/// owns; it crosses as a closure so this file does not name its type.
pub fn flatten<A: Admission, X>(
    source: &Document,
    annotations: Option<&&Object>,
    copy: &mut impl FnMut(&mut Document, &Object, usize) -> Result<Object, X>,
    out: &mut Document,
    resources: &mut Dictionary,
    admit: &A,
) -> Result<Vec<Operation>, BurnError<A::Error, X>> {
    let mut ops = Vec::new();
    let Some(annotations) = annotations else {
        return Ok(ops);
    };
    let (_, annotations) = source.dereference(annotations).map_err(BurnError::Lopdf)?;
    for annotation in annotations.as_array().map_err(BurnError::Lopdf)? {
        let annotation = resolved(source, annotation, admit)?
            .as_dict()
            .map_err(BurnError::Lopdf)?;
        let flags = annotation
            .get(b"F")
            .ok()
            .map(|v| {
                resolved(source, v, admit)?
                    .as_i64()
                    .map_err(BurnError::Lopdf)
            })
            .transpose()?
            .unwrap_or(0);
        if flags & 3 != 0 {
            continue;
        } // Invisible / Hidden.
        if flags & (8 | 16 | 32) != 0 || annotation.has(b"OC") {
            return Err(BurnError::UnsupportedPdf);
        }
        let appearance = match annotation.get(b"AP") {
            Ok(ap) => resolved(source, ap, admit)?
                .as_dict()
                .map_err(BurnError::Lopdf)?,
            // A link without a border or appearance is genuinely nonvisual.
            Err(_) if nonvisual_link(source, annotation, admit)? => continue,
            Err(_) => return Err(BurnError::UnsupportedPdf),
        };
        let normal = resolved(
            source,
            appearance.get(b"N").map_err(BurnError::Lopdf)?,
            admit,
        )?;
        let normal = if let Object::Dictionary(states) = normal {
            let state = resolved(
                source,
                annotation.get(b"AS").map_err(BurnError::Lopdf)?,
                admit,
            )?
            .as_name()
            .map_err(BurnError::Lopdf)?;
            states.get(state).map_err(BurnError::Lopdf)?
        } else {
            normal
        };
        let stream = resolved(source, normal, admit)?
            .as_stream()
            .map_err(BurnError::Lopdf)?;
        if !stream.dict.has_type(b"XObject")
            || stream
                .dict
                .get(b"Subtype")
                .map_err(BurnError::Lopdf)?
                .as_name()
                .map_err(BurnError::Lopdf)?
                != b"Form"
        {
            return Err(BurnError::UnsupportedPdf);
        }
        let rect = pdf_box(
            source,
            annotation.get(b"Rect").map_err(BurnError::Lopdf)?,
            admit,
        )?;
        let bbox = pdf_box(
            source,
            stream.dict.get(b"BBox").map_err(BurnError::Lopdf)?,
            admit,
        )?;
        let matrix = if let Ok(matrix) = stream.dict.get(b"Matrix") {
            let values = resolved(source, matrix, admit)?
                .as_array()
                .map_err(BurnError::Lopdf)?;
            if values.len() != 6 {
                return Err(BurnError::MalformedPdf);
            }
            let mut matrix = [0.; 6];
            for (slot, value) in matrix.iter_mut().zip(values) {
                *slot = number(source, value, admit)?;
            }
            matrix
        } else {
            [1., 0., 0., 1., 0., 0.]
        };
        let [a, b, c, d, e, f] = matrix;
        if (a * d - b * c).abs() < 1e-12 {
            return Err(BurnError::InvalidGeometry);
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
            return Err(BurnError::InvalidGeometry);
        }
        let object = copy(out, normal, 0).map_err(BurnError::External)?;
        let id = match object {
            Object::Reference(id) => id,
            other => {
                admit.admit_object().map_err(BurnError::Admit)?;
                out.add_object(other)
            }
        };
        let name = resource(resources, b"XObject", id, admit).map_err(BurnError::into_external)?;
        op(&mut ops, "q", &[], admit).map_err(BurnError::Admit)?;
        op(
            &mut ops,
            "re",
            &[rect[0], rect[1], rect[2] - rect[0], rect[3] - rect[1]],
            admit,
        )
        .map_err(BurnError::Admit)?;
        op(&mut ops, "W", &[], admit).map_err(BurnError::Admit)?;
        op(&mut ops, "n", &[], admit).map_err(BurnError::Admit)?;
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
            admit,
        )
        .map_err(BurnError::Admit)?;
        admit.admit_len::<Object>(1).map_err(BurnError::Admit)?;
        admit.admit_len::<u8>(2).map_err(BurnError::Admit)?; // "Do"
        admit
            .push(&mut ops, Operation::new("Do", vec![Object::Name(name)]))
            .map_err(BurnError::Admit)?;
        op(&mut ops, "Q", &[], admit).map_err(BurnError::Admit)?;
    }
    Ok(ops)
}

// Border style overrides the legacy Border array in PDF. Never discard a
// visible link merely because its older Border entry says zero width.
fn nonvisual_link<A: Admission, X>(
    source: &Document,
    annotation: &Dictionary,
    admit: &A,
) -> Result<bool, BurnError<A::Error, X>> {
    if resolved(
        source,
        annotation.get(b"Subtype").map_err(BurnError::Lopdf)?,
        admit,
    )?
    .as_name()
    .map_err(BurnError::Lopdf)?
        != b"Link"
    {
        return Ok(false);
    }
    let width = if let Ok(style) = annotation.get(b"BS") {
        let style = resolved(source, style, admit)?
            .as_dict()
            .map_err(BurnError::Lopdf)?;
        match style.get(b"W") {
            Ok(width) => number(source, width, admit)?,
            Err(_) => 1.0,
        }
    } else if let Ok(border) = annotation.get(b"Border") {
        let border = resolved(source, border, admit)?
            .as_array()
            .map_err(BurnError::Lopdf)?;
        if !(3..=4).contains(&border.len()) {
            return Err(BurnError::MalformedPdf);
        }
        number(source, &border[2], admit)?
    } else {
        1.0
    };
    Ok(width == 0.0)
}

/// The terminal object `object` names.
fn resolved<'a, A: Admission, X>(
    doc: &'a Document,
    object: &'a Object,
    _admit: &A,
) -> Result<&'a Object, BurnError<A::Error, X>> {
    doc.dereference(object)
        .map(|(_, object)| object)
        .map_err(BurnError::Lopdf)
}

/// The number `value` names.
fn number<A: Admission, X>(
    doc: &Document,
    value: &Object,
    admit: &A,
) -> Result<f64, BurnError<A::Error, X>> {
    match resolved(doc, value, admit)? {
        Object::Integer(v) => Ok(*v as f64),
        Object::Real(v) if v.is_finite() => Ok(f64::from(*v)),
        _ => Err(BurnError::MalformedPdf),
    }
}

/// The four-number box `value` names.
fn pdf_box<A: Admission, X>(
    doc: &Document,
    value: &Object,
    admit: &A,
) -> Result<[f64; 4], BurnError<A::Error, X>> {
    let values = resolved(doc, value, admit)?
        .as_array()
        .map_err(BurnError::Lopdf)?;
    if values.len() != 4 {
        return Err(BurnError::InvalidGeometry);
    }
    let result = [
        number(doc, &values[0], admit)?,
        number(doc, &values[1], admit)?,
        number(doc, &values[2], admit)?,
        number(doc, &values[3], admit)?,
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
    )
    .map_err(BurnError::into_burn)?;
    Ok(result)
}
