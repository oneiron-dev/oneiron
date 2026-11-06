//! Core half of `blob_artifact::esign::template`: its store-layer items live in `oneiron_store::blob_artifact::esign::template` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::blob_artifact::esign::template::*;

use super::{EsignField, render};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod html;
mod layout;
#[cfg(test)]
#[path = "template_tests.rs"]
mod tests;

type Result<T> = std::result::Result<T, ContentTemplateError>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContentTemplateError {
    /// Past a structural or codec bound: markup nested deeper than the
    /// renderer's recursion takes, or a PDF past the writer's offset width.
    #[error("template nesting or codec limit")]
    Limit,
    #[error("missing or invalid repo merge field")]
    MergeField,
    #[error("unsafe or unsupported HTML/CSS")]
    UnsupportedHtml,
    #[error("invalid page or field geography pack")]
    Geometry,
    #[error("template text is not representable by the selected font")]
    Font,
    #[error("template content does not fit")]
    Overflow,
    #[error("PDF preparation failed: {0}")]
    Pdf(#[from] render::PdfPreparationError),
}

#[derive(Debug)]
pub struct PreparedContent {
    pub bytes: Vec<u8>,
    pub pages: Vec<render::PageGeometry>,
    pub fields: Vec<EsignField>,
    pub generated_from_template: bool,
}

/// [`prepare_content_within`] at the `[limits] esign_stream_decode_bytes`
/// row's default, for a caller holding no vault.
pub fn prepare_content(
    source: ContentSource<'_>,
    pack: &FieldGeographyPack,
    item: u32,
) -> Result<PreparedContent> {
    let stream_decode_bytes = crate::limit_ask::EngineLimit::EsignStreamDecodeBytes.default_bound();
    prepare_content_within(source, pack, item, stream_decode_bytes)
}

/// The output is a pristine original. Store it as an immutable artifact version,
/// then use the ordinary ceremony and verified seal path. The pack is not HTML.
/// A host passes its `[limits] esign_stream_decode_bytes` row as
/// `stream_decode_bytes` ([`crate::Vault::esign_stream_decode_bytes`]).
pub fn prepare_content_within(
    source: ContentSource<'_>,
    pack: &FieldGeographyPack,
    item: u32,
    stream_decode_bytes: u64,
) -> Result<PreparedContent> {
    // An upload of any size is inspected whole (Rule 5); only the PDF codec's
    // and format's bounds refuse it.
    let (bytes, generated_from_template) = match source {
        ContentSource::Upload(bytes) => (bytes.to_vec(), false),
        ContentSource::Template {
            template,
            merge_fields,
        } => (render_html_template(template, merge_fields)?, true),
    };
    let pages = render::inspect_pdf_pages_within(&bytes, stream_decode_bytes)?;
    if pack.schema_version != 1 {
        return Err(ContentTemplateError::Geometry);
    }
    let mut ids = BTreeSet::new();
    for field in &pack.fields {
        if !ids.insert(&field.id)
            || super::model::reference(&field.id).is_err()
            || super::model::reference(&field.recipient).is_err()
        {
            return Err(ContentTemplateError::Geometry);
        }
        let presentation = render::present_field(field, None)?;
        if field.item == item {
            let page = pages
                .get(field.geometry.page.saturating_sub(1) as usize)
                .ok_or(ContentTemplateError::Geometry)?;
            presentation.rectangle(*page)?;
        }
    }
    Ok(PreparedContent {
        bytes,
        pages,
        fields: pack.fields.clone(),
        generated_from_template,
    })
}

/// Deterministic native HTML typesetting. Merge syntax is `{{repo.key}}` in
/// text nodes only. Values are inserted as DOM text, never interpreted as HTML.
pub fn render_html_template(
    template: &HtmlContentTemplate,
    values: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let p = template.page;
    if [p.width, p.height, p.margin].iter().any(|v| !v.is_finite())
        || p.width < 72.
        || p.height < 72.
        || p.width > 14400.
        || p.height > 14400.
        || p.margin < 0.
        || p.margin * 2. + 36. >= p.width.min(p.height)
    {
        return Err(ContentTemplateError::Geometry);
    }
    let document = html::parse(&template.html, values)?;
    let mut flow = layout::Flow::new(p);
    html::render(&document, &mut flow)?;
    flow.finish()
}
