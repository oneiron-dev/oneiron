//! Shared page geometry, field marks, and Win1252 text encoding.
//!
//! The drawing program's geometry: the page's display box, the percent-box
//! projection, the device-independent marks, and the text encoding. The
//! editor and ceremony doors stay with their callers; this file takes only
//! checked scalars and admits every vector and string clone through its
//! admission.

use std::collections::BTreeMap;
use std::convert::Infallible;

use lopdf::ObjectId;

use crate::admit::Admission;
use crate::error::BurnError;

/// A page's crop box, rotation, and user-unit scale: clockwise PDF rotation,
/// normalized to 0/90/180/270.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PageGeometry {
    pub crop: [f64; 4],
    pub rotation: u16,
    pub user_unit: f64,
}

impl PageGeometry {
    /// The page's display box in PDF points: the crop once its full-page
    /// percent box checks out, rotated and scaled by `rotation`/`user_unit`.
    pub fn display_box(self) -> Result<[f64; 4], BurnError<Infallible>> {
        let [left, bottom, right, top] = self.crop;
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
            return Err(BurnError::InvalidGeometry);
        }
        if self.rotation == 0 && self.user_unit == 1. {
            return Ok(self.crop);
        }
        let (width, height) = if matches!(self.rotation, 90 | 270) {
            (top - bottom, right - left)
        } else {
            (right - left, top - bottom)
        };
        if width * self.user_unit > 1_000_000. || height * self.user_unit > 1_000_000. {
            return Err(BurnError::DisplayTooLarge);
        }
        Ok([0., 0., width * self.user_unit, height * self.user_unit])
    }

    /// The content-stream matrix that undoes `rotation`/`user_unit`.
    pub fn to_pdf(self) -> Result<[f64; 6], BurnError<Infallible>> {
        self.display_box()?;
        if self.rotation == 0 && self.user_unit == 1. {
            return Ok([1., 0., 0., 1., 0., 0.]);
        }
        let [left, bottom, right, top] = self.crop;
        let scale = 1. / self.user_unit;
        Ok(match self.rotation {
            0 => [scale, 0., 0., scale, left, bottom],
            90 => [0., scale, -scale, 0., right, bottom],
            180 => [-scale, 0., 0., -scale, right, top],
            270 => [0., -scale, scale, 0., left, top],
            _ => return Err(BurnError::InvalidGeometry),
        })
    }
}

/// One field's box in page-percent coordinates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FieldGeometry {
    pub page: u32,
    pub x_percent: f64,
    pub y_percent: f64,
    pub width_percent: f64,
    pub height_percent: f64,
}

/// PDF user-space rectangle, with a bottom-left origin.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PdfFieldRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// Shared geometry for editor, ceremony and export: page numbers are
/// one-based, and the crop must already be a finite positive box within a
/// million points.
pub fn render_field_geometry(
    geometry: &FieldGeometry,
    crop: [f64; 4],
) -> Result<PdfFieldRect, BurnError<Infallible>> {
    let [left, bottom, right, top] = crop;
    if geometry.page == 0
        || crop.iter().any(|v| !v.is_finite() || v.abs() > 1_000_000.0)
        || right <= left
        || top <= bottom
        || [
            geometry.x_percent,
            geometry.y_percent,
            geometry.width_percent,
            geometry.height_percent,
        ]
        .iter()
        .any(|v| !v.is_finite() || !(0.0..=100.0).contains(v))
        || geometry.width_percent == 0.0
        || geometry.height_percent == 0.0
        || geometry.x_percent + geometry.width_percent > 100.0
        || geometry.y_percent + geometry.height_percent > 100.0
    {
        return Err(BurnError::InvalidGeometry);
    }
    Ok(PdfFieldRect {
        x: left + (right - left) * geometry.x_percent / 100.0,
        y: top - (top - bottom) * (geometry.y_percent + geometry.height_percent) / 100.0,
        width: (right - left) * geometry.width_percent / 100.0,
        height: (top - bottom) * geometry.height_percent / 100.0,
    })
}

/// Device-independent marks in PDF-point coordinates: the drawing program
/// for the sealed PDF, not a screenshot.
#[derive(Debug, Clone, PartialEq)]
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

/// One field's checked value: text, checkbox state, or signature image
/// reference. Each side projects its own value row onto this borrow.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LeafValue<'a> {
    Text(&'a str),
    Checked(bool),
    Signature { image_ref: &'a str },
}

/// One signature raster's decoded pixels as the drawing program reads them:
/// straight-alpha RGBA, top-to-bottom rows. Each side implements this for
/// its own raster row; the bytes are borrowed, never copied.
pub trait RasterView {
    /// The raster's width in pixels.
    fn width(&self) -> u32;
    /// The raster's height in pixels.
    fn height(&self) -> u32;
    /// The raster's straight-alpha RGBA bytes, top-to-bottom rows.
    fn rgba(&self) -> &[u8];
}

/// The signature rasters already written, each once however many fields
/// show it. No raster budget refuses a document: each raster is held to its
/// decoder's bounds at upload.
#[derive(Default)]
pub struct ImageCache {
    pub(crate) ids: BTreeMap<String, ObjectId>,
}

/// The field's marks over `page`: the rectangle the percent box projects
/// to, then one text mark per line, the checkbox square and its cross, or
/// the signature placement.
pub fn marks<A: Admission>(
    geometry: &FieldGeometry,
    page: PageGeometry,
    value: Option<LeafValue<'_>>,
    admit: &A,
) -> Result<Vec<FieldMark>, BurnError<A::Error>> {
    let rect = render_field_geometry(geometry, page.display_box().map_err(BurnError::into_burn)?)
        .map_err(BurnError::into_burn)?;
    let mut marks = Vec::new();
    match value {
        None => {}
        Some(LeafValue::Text(value)) => {
            let mut lines: Vec<&str> = Vec::new();
            admit
                .reserve(&mut lines, value.split('\n').count())
                .map_err(BurnError::Admit)?;
            lines.extend(value.split('\n'));
            let mut columns = 1;
            for line in &lines {
                columns = columns.max(encoded_text(line, admit)?.len());
            }
            let size = 12f64
                .min((rect.width - 4.) / (columns as f64 * 0.6))
                .min((rect.height - 4.) / (lines.len() as f64 * 1.2));
            if size < 6. {
                return Err(BurnError::FieldOverflow);
            }
            admit
                .reserve(&mut marks, lines.len())
                .map_err(BurnError::Admit)?;
            for (index, line) in lines.iter().enumerate() {
                admit
                    .admit_len::<u8>(line.len())
                    .map_err(BurnError::Admit)?;
                admit
                    .push(
                        &mut marks,
                        FieldMark::Text {
                            value: (*line).to_owned(),
                            x: rect.x + 2.,
                            y: rect.y + rect.height - 2. - size * (1. + index as f64 * 1.2),
                            size,
                        },
                    )
                    .map_err(BurnError::Admit)?;
            }
        }
        Some(LeafValue::Checked(checked)) => {
            let side = rect.width.min(rect.height) - 2.;
            if side < 2. {
                return Err(BurnError::InvalidGeometry);
            }
            admit.reserve(&mut marks, 3).map_err(BurnError::Admit)?;
            admit
                .push(
                    &mut marks,
                    FieldMark::Rectangle {
                        x: rect.x + 1.,
                        y: rect.y + 1.,
                        width: side,
                        height: side,
                    },
                )
                .map_err(BurnError::Admit)?;
            if checked {
                admit
                    .push(
                        &mut marks,
                        FieldMark::Line {
                            x1: rect.x + 1.,
                            y1: rect.y + 1.,
                            x2: rect.x + 1. + side,
                            y2: rect.y + 1. + side,
                        },
                    )
                    .map_err(BurnError::Admit)?;
                admit
                    .push(
                        &mut marks,
                        FieldMark::Line {
                            x1: rect.x + 1.,
                            y1: rect.y + 1. + side,
                            x2: rect.x + 1. + side,
                            y2: rect.y + 1.,
                        },
                    )
                    .map_err(BurnError::Admit)?;
            }
        }
        Some(LeafValue::Signature { image_ref }) => {
            admit
                .admit_len::<u8>(image_ref.len())
                .map_err(BurnError::Admit)?;
            admit
                .push(
                    &mut marks,
                    FieldMark::Signature {
                        image_ref: image_ref.to_owned(),
                        rect,
                    },
                )
                .map_err(BurnError::Admit)?;
        }
    }
    Ok(marks)
}

/// The Win1252 bytes of one text line: control characters and unmappable
/// text are unsupported.
pub fn encoded_text<A: Admission>(value: &str, admit: &A) -> Result<Vec<u8>, BurnError<A::Error>> {
    if value.chars().any(char::is_control) {
        return Err(BurnError::UnsupportedText);
    }
    let (bytes, _, unmappable) = encoding_rs::WINDOWS_1252.encode(value);
    if unmappable {
        return Err(BurnError::UnsupportedText);
    }
    admit
        .admit_len::<u8>(bytes.len())
        .map_err(BurnError::Admit)?;
    Ok(bytes.into_owned())
}
