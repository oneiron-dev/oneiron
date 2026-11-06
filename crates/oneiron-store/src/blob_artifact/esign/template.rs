//! Regenerable repo HTML content plus an independent data-only field geography.
//! No scripts, network, filesystem, clock, or host font discovery participates.
use crate::blob_artifact::esign::model::EsignField;
use crate::blob_artifact::esign::render;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
