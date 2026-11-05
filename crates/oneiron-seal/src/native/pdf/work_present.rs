//! Ported page geometry, field marks, and Win1252 text encoding (FIX 7980/8157).
//!
//! Ports the geometry part of the engine's `render/presentation` only:
//! [`PageGeometry`] (`display_box`/`to_pdf`), the percent-box projection
//! ([`render_field_geometry`], which `display_box` checks the crop with),
//! the [`FieldMark`] drawing program ([`marks`]), and [`encoded_text`].
//! The editor/ceremony door (`FieldControl`, `FieldPresentation`,
//! `present_field`, `layout_field`) stays engine-side: the host validates
//! each field row there and lents the checked scalars this file takes as
//! explicit parameters.
//!
//! Behavior-identical to the engine except admission and bounds: every
//! vector and string clone is admitted against the call's operation ledger
//! first, and value-shape failures surface as [`WorkError::Invalid`] while
//! memory refusals surface as [`WorkError::Memory`]. The engine's 1M-point
//! display-size refusal is a page-box bound here
//! ([`InputInvalidCode::InvalidGeometry`]).

use std::mem::size_of;

use super::work::{WorkError, WorkLimits};
use crate::error::InputInvalidCode;
use crate::memory::{MemoryLedger, SealMemoryRefusal};

/// A page's crop box, rotation, and user-unit scale, as the engine's
/// `PageGeometry`: clockwise PDF rotation, normalized to 0/90/180/270.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct PageGeometry {
    pub crop: [f64; 4],
    pub rotation: u16,
    pub user_unit: f64,
}

impl PageGeometry {
    /// The page's display box in PDF points, exactly as the engine's
    /// `display_box`: the crop once its full-page percent box checks out,
    /// rotated and scaled by `rotation`/`user_unit`.
    pub(crate) fn display_box(self) -> Result<[f64; 4], WorkError> {
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
            return Err(WorkError::Invalid(InputInvalidCode::InvalidGeometry));
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
            return Err(WorkError::Invalid(InputInvalidCode::InvalidGeometry));
        }
        Ok([0., 0., width * self.user_unit, height * self.user_unit])
    }

    /// The content-stream matrix that undoes `rotation`/`user_unit`,
    /// exactly as the engine's `to_pdf`.
    pub(crate) fn to_pdf(self) -> Result<[f64; 6], WorkError> {
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
            _ => return Err(WorkError::Invalid(InputInvalidCode::InvalidGeometry)),
        })
    }
}

/// One field's box in page-percent coordinates, as the engine's
/// `FieldGeometry` row.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct FieldGeometry {
    pub page: u32,
    pub x_percent: f64,
    pub y_percent: f64,
    pub width_percent: f64,
    pub height_percent: f64,
}

/// PDF user-space rectangle, with a bottom-left origin, as the engine's
/// `PdfFieldRect`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct PdfFieldRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// Shared geometry for editor, ceremony and export, exactly as the
/// engine's `render_field_geometry`: page numbers are one-based, and the
/// crop must already be a finite positive box within a million points.
pub(crate) fn render_field_geometry(
    // organ: lent by the host, checked engine-side
    geometry: &FieldGeometry,
    crop: [f64; 4],
) -> Result<PdfFieldRect, WorkError> {
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
        return Err(WorkError::Invalid(InputInvalidCode::InvalidGeometry));
    }
    Ok(PdfFieldRect {
        x: left + (right - left) * geometry.x_percent / 100.0,
        y: top - (top - bottom) * (geometry.y_percent + geometry.height_percent) / 100.0,
        width: (right - left) * geometry.width_percent / 100.0,
        height: (top - bottom) * geometry.height_percent / 100.0,
    })
}

/// Device-independent marks in PDF-point coordinates, as the engine's
/// `FieldMark`: the drawing program for the sealed PDF, not a screenshot.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum FieldMark {
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

/// One field's checked value, as the engine's `FieldValue` row: text,
/// checkbox state, or signature image reference.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum MarkValue<'a> {
    Text(&'a str),
    Checked(bool),
    Signature { image_ref: &'a str },
}

/// The field's marks over `page`, exactly as the engine's `marks`: the
/// rectangle the percent box projects to, then one text mark per line, the
/// checkbox square and its cross, or the signature placement.
pub(crate) fn marks(
    // organ: lent by the host, checked engine-side
    geometry: &FieldGeometry,
    page: PageGeometry,
    // organ: lent by the host, checked engine-side
    value: Option<MarkValue<'_>>,
    limits: &WorkLimits<'_>,
) -> Result<Vec<FieldMark>, WorkError> {
    let rect = render_field_geometry(geometry, page.display_box()?)?;
    let mut marks = Vec::new();
    match value {
        None => {}
        Some(MarkValue::Text(value)) => {
            let mut lines: Vec<&str> = Vec::new();
            reserve(limits.ledger, &mut lines, value.split('\n').count())?;
            lines.extend(value.split('\n'));
            let mut columns = 1;
            for line in &lines {
                columns = columns.max(encoded_text(line, limits)?.len());
            }
            let size = 12f64
                .min((rect.width - 4.) / (columns as f64 * 0.6))
                .min((rect.height - 4.) / (lines.len() as f64 * 1.2));
            if size < 6. {
                return Err(WorkError::Invalid(InputInvalidCode::FieldOverflow));
            }
            reserve(limits.ledger, &mut marks, lines.len())?;
            for (index, line) in lines.iter().enumerate() {
                limits
                    .ledger
                    .admit_len::<u8>(line.len())
                    .map_err(WorkError::Memory)?;
                push(
                    limits.ledger,
                    &mut marks,
                    FieldMark::Text {
                        value: (*line).to_owned(),
                        x: rect.x + 2.,
                        y: rect.y + rect.height - 2. - size * (1. + index as f64 * 1.2),
                        size,
                    },
                )?;
            }
        }
        Some(MarkValue::Checked(checked)) => {
            let side = rect.width.min(rect.height) - 2.;
            if side < 2. {
                return Err(WorkError::Invalid(InputInvalidCode::InvalidGeometry));
            }
            reserve(limits.ledger, &mut marks, 3)?;
            push(
                limits.ledger,
                &mut marks,
                FieldMark::Rectangle {
                    x: rect.x + 1.,
                    y: rect.y + 1.,
                    width: side,
                    height: side,
                },
            )?;
            if checked {
                push(
                    limits.ledger,
                    &mut marks,
                    FieldMark::Line {
                        x1: rect.x + 1.,
                        y1: rect.y + 1.,
                        x2: rect.x + 1. + side,
                        y2: rect.y + 1. + side,
                    },
                )?;
                push(
                    limits.ledger,
                    &mut marks,
                    FieldMark::Line {
                        x1: rect.x + 1.,
                        y1: rect.y + 1. + side,
                        x2: rect.x + 1. + side,
                        y2: rect.y + 1.,
                    },
                )?;
            }
        }
        Some(MarkValue::Signature { image_ref }) => {
            limits
                .ledger
                .admit_len::<u8>(image_ref.len())
                .map_err(WorkError::Memory)?;
            push(
                limits.ledger,
                &mut marks,
                FieldMark::Signature {
                    image_ref: image_ref.to_owned(),
                    rect,
                },
            )?;
        }
    }
    Ok(marks)
}

/// The Win1252 bytes of one text line, exactly as the engine's
/// `encoded_text`: control characters and unmappable text are unsupported.
pub(crate) fn encoded_text(
    // organ: lent by the host, checked engine-side
    value: &str,
    limits: &WorkLimits<'_>,
) -> Result<Vec<u8>, WorkError> {
    if value.chars().any(char::is_control) {
        return Err(WorkError::Invalid(InputInvalidCode::UnsupportedText));
    }
    let (bytes, _, unmappable) = encoding_rs::WINDOWS_1252.encode(value);
    if unmappable {
        return Err(WorkError::Invalid(InputInvalidCode::UnsupportedText));
    }
    limits
        .ledger
        .admit_len::<u8>(bytes.len())
        .map_err(WorkError::Memory)?;
    Ok(bytes.into_owned())
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
