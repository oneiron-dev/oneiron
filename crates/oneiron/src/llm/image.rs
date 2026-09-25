//! Provider-neutral image generation and reference-edit intent. Vendor shims stay in adapters.
use super::{BudgetLease, LlmResult, ModelId};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageIntent {
    pub model: ModelId,
    pub instruction: String,
    pub width: u32,
    pub height: u32,
    pub params: BTreeMap<String, serde_json::Value>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageBytes {
    pub bytes: Vec<u8>,
    pub media_type: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageResponse {
    pub image: ImageBytes,
    pub model: ModelId,
    pub metadata: BTreeMap<String, serde_json::Value>,
}
pub type ImageFuture<'a> = Pin<Box<dyn Future<Output = LlmResult<ImageResponse>> + Send + 'a>>;
pub trait ImageBackend: Send + Sync {
    fn generate<'a>(&'a self, intent: ImageIntent, lease: &'a BudgetLease) -> ImageFuture<'a>;
    fn reference_edit<'a>(
        &'a self,
        intent: ImageIntent,
        references: Vec<ImageBytes>,
        lease: &'a BudgetLease,
    ) -> ImageFuture<'a>;
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageCatalogRow {
    pub model: ModelId,
    pub adapter: String,
    pub generate: bool,
    pub reference_edit: bool,
    pub max_pixels: u64,
}
#[derive(Default)]
pub struct ImageCatalog {
    rows: BTreeMap<ModelId, ImageCatalogRow>,
    adapters: BTreeMap<String, Arc<dyn ImageBackend>>,
}
impl ImageCatalog {
    pub fn new(
        rows: Vec<ImageCatalogRow>,
        adapters: BTreeMap<String, Arc<dyn ImageBackend>>,
    ) -> LlmResult<Self> {
        let mut map = BTreeMap::new();
        for row in rows {
            if row.max_pixels == 0
                || !adapters.contains_key(&row.adapter)
                || map.contains_key(&row.model)
            {
                return Err(super::FatalLlmError::InvalidRequest.into());
            }
            map.insert(row.model.clone(), row);
        }
        Ok(Self {
            rows: map,
            adapters,
        })
    }
    pub async fn render(
        &self,
        intent: ImageIntent,
        references: Option<Vec<ImageBytes>>,
        lease: &BudgetLease,
    ) -> LlmResult<ImageResponse> {
        let row = self
            .rows
            .get(&intent.model)
            .ok_or(super::FatalLlmError::InvalidRequest)?;
        if intent.instruction.trim().is_empty()
            || intent.width == 0
            || intent.height == 0
            || u64::from(intent.width) * u64::from(intent.height) > row.max_pixels
        {
            return Err(super::FatalLlmError::InvalidRequest.into());
        }
        let adapter = self
            .adapters
            .get(&row.adapter)
            .ok_or(super::FatalLlmError::InvalidRequest)?;
        let model = intent.model.clone();
        let response = match references {
            None if row.generate => adapter.generate(intent, lease).await?,
            Some(refs)
                if row.reference_edit
                    && !refs.is_empty()
                    && refs
                        .iter()
                        .all(|r| !r.bytes.is_empty() && r.media_type.starts_with("image/")) =>
            {
                adapter.reference_edit(intent, refs, lease).await?
            }
            _ => return Err(super::FatalLlmError::InvalidRequest.into()),
        };
        if response.model != model
            || response.image.bytes.is_empty()
            || !response.image.media_type.starts_with("image/")
        {
            return Err(super::FatalLlmError::EmptyResponse.into());
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests;
