//! Moved from `crates/oneiron/src/blob_artifact/esign/render/presentation.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::blob_artifact::esign::render::*;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PageGeometry {
    pub crop: [f64; 4],
    /// Clockwise PDF rotation, normalized to 0/90/180/270.
    pub rotation: u16,
    pub user_unit: f64,
}

impl PageGeometry {
    pub fn display_box(self) -> Result<[f64; 4]> {
        leaf::PageGeometry {
            crop: self.crop,
            rotation: self.rotation,
            user_unit: self.user_unit,
        }
        .display_box()
        .map_err(map_leaf)
    }

    pub fn to_pdf(self) -> Result<[f64; 6]> {
        leaf::PageGeometry {
            crop: self.crop,
            rotation: self.rotation,
            user_unit: self.user_unit,
        }
        .to_pdf()
        .map_err(map_leaf)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FieldControl {
    Text {
        max_bytes: Option<u32>,
        server_computed: bool,
    },
    Checkbox,
    Select {
        options: Vec<String>,
    },
    Signature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FieldPresentation {
    pub id: String,
    pub item: u32,
    pub geometry: FieldGeometry,
    pub required: bool,
    pub control: FieldControl,
    pub value: Option<FieldValue>,
}

impl FieldPresentation {
    pub fn rectangle(&self, page: PageGeometry) -> Result<PdfFieldRect> {
        render_field_geometry(&self.geometry, page.display_box()?)
    }
}

/// Device-independent marks in PDF-point coordinates. This is the drawing
/// program for both browser SVG overlays and the sealed PDF, not a screenshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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
        let geometry = leaf::FieldGeometry {
            page: self.geometry.page,
            x_percent: self.geometry.x_percent,
            y_percent: self.geometry.y_percent,
            width_percent: self.geometry.width_percent,
            height_percent: self.geometry.height_percent,
        };
        let leaf_page = leaf::PageGeometry {
            crop: page.crop,
            rotation: page.rotation,
            user_unit: page.user_unit,
        };
        let value = match &self.value {
            None => None,
            Some(FieldValue::Text(value)) => Some(leaf::LeafValue::Text(value.as_str())),
            Some(FieldValue::Checked(checked)) => Some(leaf::LeafValue::Checked(*checked)),
            Some(FieldValue::Signature { image_ref }) => Some(leaf::LeafValue::Signature {
                image_ref: image_ref.as_str(),
            }),
        };
        let marks =
            leaf::marks(&geometry, leaf_page, value, &leaf::NoAdmission).map_err(map_leaf)?;
        Ok(marks
            .into_iter()
            .map(|mark| match mark {
                leaf::FieldMark::Text { value, x, y, size } => {
                    FieldMark::Text { value, x, y, size }
                }
                leaf::FieldMark::Rectangle {
                    x,
                    y,
                    width,
                    height,
                } => FieldMark::Rectangle {
                    x,
                    y,
                    width,
                    height,
                },
                leaf::FieldMark::Line { x1, y1, x2, y2 } => FieldMark::Line { x1, y1, x2, y2 },
                leaf::FieldMark::Signature { image_ref, rect } => FieldMark::Signature {
                    image_ref,
                    rect: PdfFieldRect {
                        x: rect.x,
                        y: rect.y,
                        width: rect.width,
                        height: rect.height,
                    },
                },
            })
            .collect())
    }
}

pub fn encoded_text(value: &str) -> Result<Vec<u8>> {
    leaf::encoded_text(value, &leaf::NoAdmission).map_err(map_leaf)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FieldLayout {
    pub presentation: FieldPresentation,
    pub rect: PdfFieldRect,
    pub marks: Vec<FieldMark>,
}
