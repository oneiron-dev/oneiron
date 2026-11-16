//! The field presentation contract consumed by editor, ceremony, and PDF export.
use super::*;

#[doc(hidden)]
pub(super) use oneiron_verb_wire::blob_artifact::esign::render::presentation::encoded_text;
#[doc(hidden)]
pub use oneiron_verb_wire::blob_artifact::esign::render::presentation::{
    FieldControl, FieldLayout, FieldMark, FieldPresentation, PageGeometry,
};

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
            max_bytes: None,
            server_computed: true,
        },
        FieldMeta::Text { max_bytes } => FieldControl::Text {
            max_bytes: Some(*max_bytes),
            server_computed: false,
        },
        // A name has no engine cap (Rule 5); the field's box bounds what fits.
        FieldMeta::Name => FieldControl::Text {
            max_bytes: None,
            server_computed: false,
        },
        FieldMeta::Email => FieldControl::Text {
            max_bytes: None,
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
