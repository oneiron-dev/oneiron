//! Flatten explicit static annotation appearances; never invent missing glyphs.
use super::source::{number, resolved};
use super::*;

pub(super) fn flatten(
    source: &Document,
    annotations: Option<&&Object>,
    copier: &mut VisualCopy<'_>,
    out: &mut Document,
    resources: &mut Dictionary,
) -> Result<Vec<Operation>> {
    let mut ops = Vec::new();
    let Some(annotations) = annotations else {
        return Ok(ops);
    };
    let annotations = resolved(source, annotations)?.as_array()?;
    if annotations.len() > 10_000 {
        return Err(PdfPreparationError::Limit);
    }
    for annotation in annotations {
        let annotation = resolved(source, annotation)?.as_dict()?;
        let flags = annotation
            .get(b"F")
            .ok()
            .map(|v| {
                resolved(source, v)?
                    .as_i64()
                    .map_err(PdfPreparationError::from)
            })
            .transpose()?
            .unwrap_or(0);
        if flags & 3 != 0 {
            continue;
        } // Invisible / Hidden.
        if flags & (8 | 16 | 32) != 0 || annotation.has(b"OC") {
            return Err(PdfPreparationError::UnsupportedPdf);
        }
        let appearance = match annotation.get(b"AP") {
            Ok(ap) => resolved(source, ap)?.as_dict()?,
            // A link without a border or appearance is genuinely nonvisual.
            Err(_) if nonvisual_link(source, annotation)? => continue,
            Err(_) => return Err(PdfPreparationError::UnsupportedPdf),
        };
        let normal = resolved(source, appearance.get(b"N")?)?;
        let normal = if let Object::Dictionary(states) = normal {
            let state = resolved(source, annotation.get(b"AS")?)?.as_name()?;
            states.get(state)?
        } else {
            normal
        };
        let stream = resolved(source, normal)?.as_stream()?;
        if !stream.dict.has_type(b"XObject") || stream.dict.get(b"Subtype")?.as_name()? != b"Form" {
            return Err(PdfPreparationError::UnsupportedPdf);
        }
        let rect = pdf_box(source, annotation.get(b"Rect")?)?;
        let bbox = pdf_box(source, stream.dict.get(b"BBox")?)?;
        let matrix = if let Ok(matrix) = stream.dict.get(b"Matrix") {
            let values = resolved(source, matrix)?.as_array()?;
            if values.len() != 6 {
                return Err(PdfPreparationError::MalformedPdf);
            }
            let mut matrix = [0.; 6];
            for (out, value) in matrix.iter_mut().zip(values) {
                *out = number(source, value)?;
            }
            matrix
        } else {
            [1., 0., 0., 1., 0., 0.]
        };
        let [a, b, c, d, e, f] = matrix;
        if (a * d - b * c).abs() < 1e-12 {
            return Err(PdfPreparationError::InvalidGeometry);
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
            return Err(PdfPreparationError::InvalidGeometry);
        }
        let object = copier.copy(out, normal, 0)?;
        let id = match object {
            Object::Reference(id) => id,
            other => out.add_object(other),
        };
        let name = fields::resource(resources, b"XObject", id)?;
        fields::op(&mut ops, "q", &[]);
        fields::op(
            &mut ops,
            "re",
            &[rect[0], rect[1], rect[2] - rect[0], rect[3] - rect[1]],
        );
        fields::op(&mut ops, "W", &[]);
        fields::op(&mut ops, "n", &[]);
        fields::op(
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
        );
        ops.push(Operation::new("Do", vec![Object::Name(name)]));
        fields::op(&mut ops, "Q", &[]);
    }
    Ok(ops)
}

// Border style overrides the legacy Border array in PDF. Never discard a
// visible link merely because its older Border entry says zero width.
fn nonvisual_link(source: &Document, annotation: &Dictionary) -> Result<bool> {
    if resolved(source, annotation.get(b"Subtype")?)?.as_name()? != b"Link" {
        return Ok(false);
    }
    let width = if let Ok(style) = annotation.get(b"BS") {
        let style = resolved(source, style)?.as_dict()?;
        match style.get(b"W") { Ok(width) => number(source, width)?, Err(_) => 1.0 }
    } else if let Ok(border) = annotation.get(b"Border") {
        let border = resolved(source, border)?.as_array()?;
        if !(3..=4).contains(&border.len()) { return Err(PdfPreparationError::MalformedPdf); }
        number(source, &border[2])?
    } else { 1.0 };
    Ok(width == 0.0)
}
