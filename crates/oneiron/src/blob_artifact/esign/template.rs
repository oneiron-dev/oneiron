//! Regenerable repo HTML content plus an independent data-only field geography.
//! No scripts, network, filesystem, clock, or host font discovery participates.
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
    #[error("template resource limit")]
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
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplatePage {
    pub width: f64,
    pub height: f64,
    pub margin: f64,
}
impl Default for TemplatePage {
    fn default() -> Self {
        Self {
            width: 595.28,
            height: 841.89,
            margin: 48.,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HtmlContentTemplate {
    pub html: String,
    pub page: TemplatePage,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldGeographyPack {
    pub schema_version: u8,
    pub fields: Vec<EsignField>,
}
/// Uploads never enter the merge or HTML layer, even when a template exists.
pub enum ContentSource<'a> {
    Upload(&'a [u8]),
    Template {
        template: &'a HtmlContentTemplate,
        merge_fields: &'a BTreeMap<String, String>,
    },
}
#[derive(Debug)]
pub struct PreparedContent {
    pub bytes: Vec<u8>,
    pub pages: Vec<render::PageGeometry>,
    pub fields: Vec<EsignField>,
    pub generated_from_template: bool,
}
/// The output is a pristine original. Store it as an immutable artifact version,
/// then use the ordinary ceremony and verified seal path. The pack is not HTML.
pub fn prepare_content(
    source: ContentSource<'_>,
    pack: &FieldGeographyPack,
    item: u32,
) -> Result<PreparedContent> {
    let (bytes, generated_from_template) = match source {
        ContentSource::Upload(bytes) => {
            if bytes.len() > 16 * 1024 * 1024 {
                return Err(ContentTemplateError::Limit);
            }
            (bytes.to_vec(), false)
        }
        ContentSource::Template {
            template,
            merge_fields,
        } => (render_html_template(template, merge_fields)?, true),
    };
    let pages = render::inspect_pdf_pages(&bytes)?;
    if pack.schema_version != 1 || pack.fields.len() > 10000 {
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
