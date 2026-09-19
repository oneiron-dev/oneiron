//! The field presentation contract consumed by editor, ceremony, and PDF export.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageGeometry {
    pub crop: [f64; 4],
    /// Clockwise PDF rotation, normalized to 0/90/180/270.
    pub rotation: u16,
    pub user_unit: f64,
}
impl PageGeometry {
    pub fn display_box(self) -> Result<[f64; 4]> {
        let [l, b, r, t] = self.crop;
        render_field_geometry(
            &FieldGeometry {
                page: 1,
                x_percent: 0.,
                y_percent: 0.,
                width_percent: 100.,
                height_percent: 100.,
            },
            self.crop,
        )?;
        if !matches!(self.rotation, 0 | 90 | 180 | 270)
            || !self.user_unit.is_finite()
            || !(0.01..=75000.).contains(&self.user_unit)
        {
            return Err(PdfPreparationError::InvalidGeometry);
        }
        if self.rotation == 0 && self.user_unit == 1. {
            return Ok(self.crop);
        }
        let (w, h) = if matches!(self.rotation, 90 | 270) {
            (t - b, r - l)
        } else {
            (r - l, t - b)
        };
        if w * self.user_unit > 1_000_000. || h * self.user_unit > 1_000_000. {
            return Err(PdfPreparationError::Limit);
        }
        Ok([0., 0., w * self.user_unit, h * self.user_unit])
    }
    pub(super) fn to_pdf(self) -> Result<[f64; 6]> {
        self.display_box()?;
        if self.rotation == 0 && self.user_unit == 1. {
            return Ok([1., 0., 0., 1., 0., 0.]);
        }
        let [l, b, r, t] = self.crop;
        let s = 1. / self.user_unit;
        Ok(match self.rotation {
            0 => [s, 0., 0., s, l, b],
            90 => [0., s, -s, 0., r, b],
            180 => [-s, 0., 0., -s, r, t],
            270 => [0., -s, s, 0., l, t],
            _ => return Err(PdfPreparationError::InvalidGeometry),
        })
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FieldControl {
    Text {
        max_bytes: u32,
        server_computed: bool,
    },
    Checkbox,
    Select {
        options: Vec<String>,
    },
    Signature,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldPresentation {
    pub id: String,
    pub item: u32,
    pub geometry: FieldGeometry,
    pub required: bool,
    pub control: FieldControl,
    pub value: Option<FieldValue>,
}
/// No HTML or styling from callers crosses this typed field boundary.
pub fn present_field(field: &EsignField, value: Option<&FieldValue>) -> Result<FieldPresentation> {
    render_field_geometry(&field.geometry, [0., 0., 100., 100.])?;
    if let Some(value) = value {
        super::super::fold::validate_value(field, value)
            .map_err(|_| PdfPreparationError::InvalidField)?;
    }
    let control = match &field.meta {
        FieldMeta::Signature | FieldMeta::Initials => FieldControl::Signature,
        FieldMeta::Checkbox => FieldControl::Checkbox,
        FieldMeta::Select { options } => FieldControl::Select {
            options: options.clone(),
        },
        FieldMeta::Date => FieldControl::Text {
            max_bytes: 10,
            server_computed: true,
        },
        FieldMeta::Text { max_bytes } => FieldControl::Text {
            max_bytes: *max_bytes,
            server_computed: false,
        },
        FieldMeta::Name => FieldControl::Text {
            max_bytes: 4096,
            server_computed: false,
        },
        FieldMeta::Email => FieldControl::Text {
            max_bytes: 320,
            server_computed: false,
        },
    };
    Ok(FieldPresentation {
        id: field.id.clone(),
        item: field.item,
        geometry: field.geometry.clone(),
        required: field.required,
        control,
        value: value.cloned(),
    })
}
impl FieldPresentation {
    pub fn rectangle(&self, page: PageGeometry) -> Result<PdfFieldRect> {
        render_field_geometry(&self.geometry, page.display_box()?)
    }
}

/// Device-independent marks in PDF-point coordinates. This is the drawing
/// program for both browser SVG overlays and the sealed PDF, not a screenshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FieldMark {
    Text {
        value: String,
        x: f64,
        y: f64,
        size: f64,
    },
    Rectangle {
        x: f64,
        y: f64,
        width: f64,
        height: f64,
    },
    Line {
        x1: f64,
        y1: f64,
        x2: f64,
        y2: f64,
    },
    Signature {
        image_ref: String,
        rect: PdfFieldRect,
    },
}
impl FieldPresentation {
    pub fn marks(&self, page: PageGeometry) -> Result<Vec<FieldMark>> {
        let r = self.rectangle(page)?;
        let mut marks = Vec::new();
        match &self.value {
            None => {}
            Some(FieldValue::Text(value)) => {
                let lines: Vec<_> = value.split('\n').collect();
                let mut columns = 1;
                for line in &lines {
                    columns = columns.max(encoded_text(line)?.len());
                }
                let size = 12f64
                    .min((r.width - 4.) / (columns as f64 * 0.6))
                    .min((r.height - 4.) / (lines.len() as f64 * 1.2));
                if size < 6. {
                    return Err(PdfPreparationError::FieldOverflow);
                }
                for (i, line) in lines.iter().enumerate() {
                    marks.push(FieldMark::Text {
                        value: (*line).to_owned(),
                        x: r.x + 2.,
                        y: r.y + r.height - 2. - size * (1. + i as f64 * 1.2),
                        size,
                    });
                }
            }
            Some(FieldValue::Checked(checked)) => {
                let side = r.width.min(r.height) - 2.;
                if side < 2. {
                    return Err(PdfPreparationError::InvalidGeometry);
                }
                marks.push(FieldMark::Rectangle {
                    x: r.x + 1.,
                    y: r.y + 1.,
                    width: side,
                    height: side,
                });
                if *checked {
                    marks.push(FieldMark::Line {
                        x1: r.x + 1.,
                        y1: r.y + 1.,
                        x2: r.x + 1. + side,
                        y2: r.y + 1. + side,
                    });
                    marks.push(FieldMark::Line {
                        x1: r.x + 1.,
                        y1: r.y + 1. + side,
                        x2: r.x + 1. + side,
                        y2: r.y + 1.,
                    });
                }
            }
            Some(FieldValue::Signature { image_ref }) => marks.push(FieldMark::Signature {
                image_ref: image_ref.clone(),
                rect: r,
            }),
        }
        Ok(marks)
    }
}
pub(super) fn encoded_text(value: &str) -> Result<Vec<u8>> {
    if value.chars().any(char::is_control) {
        return Err(PdfPreparationError::UnsupportedText);
    }
    let (bytes, _, unmappable) = encoding_rs::WINDOWS_1252.encode(value);
    if unmappable {
        return Err(PdfPreparationError::UnsupportedText);
    }
    Ok(bytes.into_owned())
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FieldLayout {
    pub presentation: FieldPresentation,
    pub rect: PdfFieldRect,
    pub marks: Vec<FieldMark>,
}
pub fn layout_field(
    field: &EsignField,
    value: Option<&FieldValue>,
    page: PageGeometry,
) -> Result<FieldLayout> {
    let presentation = present_field(field, value)?;
    Ok(FieldLayout {
        rect: presentation.rectangle(page)?,
        marks: presentation.marks(page)?,
        presentation,
    })
}
