//! Ported page geometry over the shared renderer (FIX 7980/8157).
//!
//! Thin delegation over the shared e-sign field renderer's geometry: each
//! item keeps its path, name and signature, and the checks run in the leaf.
//! The editor/ceremony door (`FieldControl`, `FieldPresentation`,
//! `present_field`, `layout_field`) stays engine-side: the host validates
//! each field row there and lents the checked scalars this file takes as
//! explicit parameters.
//!
//! The engine's 1M-point display-size refusal is a page-box bound here
//! (invalid geometry).

use oneiron_esign_render as leaf;

use super::work::{WorkError, map_leaf};

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
        leaf::PageGeometry {
            crop: self.crop,
            rotation: self.rotation,
            user_unit: self.user_unit,
        }
        .display_box()
        .map_err(|err| map_leaf(None, err))
    }

    /// The content-stream matrix that undoes `rotation`/`user_unit`,
    /// exactly as the engine's `to_pdf`.
    pub(crate) fn to_pdf(self) -> Result<[f64; 6], WorkError> {
        leaf::PageGeometry {
            crop: self.crop,
            rotation: self.rotation,
            user_unit: self.user_unit,
        }
        .to_pdf()
        .map_err(|err| map_leaf(None, err))
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
/// `PdfFieldRect`: the shared renderer's rectangle, which no organ caller
/// reads field by field.
pub(crate) type PdfFieldRect = leaf::PdfFieldRect;

/// Shared geometry for editor, ceremony and export, exactly as the
/// engine's `render_field_geometry`: page numbers are one-based, and the
/// crop must already be a finite positive box within a million points.
pub(crate) fn render_field_geometry(
    // organ: lent by the host, checked engine-side
    geometry: &FieldGeometry,
    crop: [f64; 4],
) -> Result<PdfFieldRect, WorkError> {
    let geometry = leaf::FieldGeometry {
        page: geometry.page,
        x_percent: geometry.x_percent,
        y_percent: geometry.y_percent,
        width_percent: geometry.width_percent,
        height_percent: geometry.height_percent,
    };
    leaf::render_field_geometry(&geometry, crop).map_err(|err| map_leaf(None, err))
}
