//! An owned wire view of a validated plan. Only the engine compiler makes the plan.
use serde::{Deserialize, Serialize};
use oneiron_docedit::design_plan as plan;
use super::outline::OutlineDataset;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckPlanView {
    pub version: String,
    pub content_hash: [u8; 32],
    pub template_hash: [u8; 32],
    pub visual: DeckVisualChoices,
    pub slides: Vec<DeckPlannedSlide>,
    pub data: Vec<OutlineDataset>,
    pub assets: Vec<DeckAssetBinding>,
    pub package: DeckPackagePlan,
    pub trace: Vec<DeckTraceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckVisualChoices {
    pub master: String,
    pub theme: Option<String>,
    pub major_font: Option<String>,
    pub minor_font: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckPlannedSlide {
    pub page: String,
    pub part: String,
    pub layout: String,
    pub fallback: Option<DeckFallback>,
    pub split: Option<(usize, usize)>,
    pub placements: Vec<DeckPlacement>,
    pub fit: DeckFit,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeckFallback { OrdinaryShapes, Split, Rows, Ask }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckPlacement {
    pub block: String,
    pub content: DeckPlannedContent,
    pub destination: DeckDestination,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeckPlannedContent {
    Title(String), Text(Vec<String>), Table(String), Chart(String), Share(String),
    Picture(String), Figure(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeckDestination {
    Placeholder {
        role: String,
        idx: u32,
        part: String,
        element: usize,
        bounds: DeckRect,
    },
    Shape { bounds: DeckRect },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckRect { pub x: i64, pub y: i64, pub cx: i64, pub cy: i64 }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckFit {
    pub policy: DeckFitPolicy,
    pub estimates: Vec<crate::edit_roundtrip::deck_create::CreatedEstimate>,
    pub alternatives: Vec<DeckFallback>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeckFitPolicy { NoShrink }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckAssetBinding { pub asset: String, pub handle: String, pub media: DeckAssetMedia }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeckAssetMedia { Png, Jpeg, Svg }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckPackagePlan {
    pub new_parts: Vec<DeckNewPart>,
    pub changed_parts: Vec<String>,
    pub relationships: Vec<DeckPlannedRelationship>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckNewPart { pub part: String, pub content_type: String }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckPlannedRelationship { pub source: String, pub kind: String, pub target: String }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckTraceEntry {
    pub block: String,
    pub page: String,
    pub outcome: DeckTraceOutcome,
    pub drifted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeckTraceOutcome { Placed(Vec<(usize, usize)>), Omitted }

impl From<plan::Rect> for DeckRect {
    fn from(rect: plan::Rect) -> Self {
        Self { x: rect.x, y: rect.y, cx: rect.cx, cy: rect.cy }
    }
}

fn fallback(value: plan::Fallback) -> DeckFallback {
    match value {
        plan::Fallback::OrdinaryShapes => DeckFallback::OrdinaryShapes,
        plan::Fallback::Split => DeckFallback::Split,
        plan::Fallback::Composition(plan::Composition::Rows) => DeckFallback::Rows,
        plan::Fallback::Ask => DeckFallback::Ask,
    }
}

impl DeckPlanView {
    pub(super) fn of(value: &plan::DesignPlan, datasets: &[OutlineDataset]) -> Self {
        let visual = value.visual();
        Self {
            version: value.approved().version.clone(),
            content_hash: value.approved().content_hash,
            template_hash: *value.template(),
            visual: DeckVisualChoices {
                master: visual.master.clone(), theme: visual.theme.clone(),
                major_font: visual.major_font.clone(), minor_font: visual.minor_font.clone(),
            },
            slides: value.slides().iter().map(|slide| DeckPlannedSlide {
                page: slide.page.clone(), part: slide.part.clone(), layout: slide.layout.clone(),
                fallback: slide.fallback.map(fallback), split: slide.split,
                placements: slide.placements.iter().map(|placed| DeckPlacement {
                    block: placed.block.clone(),
                    content: match &placed.content {
                        plan::Content::Title(text) => DeckPlannedContent::Title(text.clone()),
                        plan::Content::Text(text) => DeckPlannedContent::Text(text.clone()),
                        plan::Content::Table(id) => DeckPlannedContent::Table(id.clone()),
                        plan::Content::Chart(id) => DeckPlannedContent::Chart(id.clone()),
                        plan::Content::Share(id) => DeckPlannedContent::Share(id.clone()),
                        plan::Content::Picture(id) => DeckPlannedContent::Picture(id.clone()),
                        plan::Content::Figure(id) => DeckPlannedContent::Figure(id.clone()),
                    },
                    destination: match &placed.destination {
                        plan::Destination::Placeholder { placeholder, shape, bounds } => DeckDestination::Placeholder {
                            role: placeholder.kind.clone(), idx: placeholder.idx,
                            part: shape.part.clone(), element: shape.index, bounds: (*bounds).into(),
                        },
                        plan::Destination::Shape { bounds } => DeckDestination::Shape { bounds: (*bounds).into() },
                    },
                }).collect(),
                fit: DeckFit {
                    policy: DeckFitPolicy::NoShrink,
                    estimates: slide.fit.estimates.iter().map(|e| crate::edit_roundtrip::deck_create::CreatedEstimate {
                        block: e.block.clone(), need: e.need, room: e.room, font: e.font.clone(),
                    }).collect(),
                    alternatives: slide.fit.alternatives.iter().copied().map(fallback).collect(),
                },
            }).collect(),
            data: datasets.iter().filter(|data| value.data().iter().any(|held| held.id == data.id)).cloned().collect(),
            assets: value.assets().iter().map(|(asset, binding)| DeckAssetBinding {
                asset: asset.clone(), handle: binding.handle.clone(), media: match binding.media {
                    plan::MediaType::Png => DeckAssetMedia::Png,
                    plan::MediaType::Jpeg => DeckAssetMedia::Jpeg,
                    plan::MediaType::Svg => DeckAssetMedia::Svg,
                },
            }).collect(),
            package: DeckPackagePlan {
                new_parts: value.package().new_parts.iter().map(|part| DeckNewPart {
                    part: part.part.clone(), content_type: part.content_type.to_owned(),
                }).collect(),
                changed_parts: value.package().changed_parts.clone(),
                relationships: value.package().relationships.iter().map(|rel| DeckPlannedRelationship {
                    source: rel.source.clone(), kind: rel.kind.to_owned(), target: rel.target.clone(),
                }).collect(),
            },
            trace: value.trace().iter().map(|trace| DeckTraceEntry {
                block: trace.block.clone(), page: trace.page.clone(), drifted: trace.drifted,
                outcome: match &trace.outcome {
                    plan::TraceOutcome::Placed(at) => DeckTraceOutcome::Placed(at.clone()),
                    plan::TraceOutcome::Omitted => DeckTraceOutcome::Omitted,
                },
            }).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckDesignDecision {
    pub page: String,
    pub options: Vec<DeckDesignOption>,
    pub shortfalls: Vec<DeckDesignShortfall>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeckDesignOption { OtherTemplate, DesignChange }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckDesignShortfall { pub block: String, pub reason: DeckShortfallReason }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeckShortfallReason { NoSuitableSlot, Overflow, Crowded }

impl From<&plan::Decision> for DeckDesignDecision {
    fn from(decision: &plan::Decision) -> Self {
        Self {
            page: decision.page.clone(),
            options: decision.options.iter().map(|option| match option {
                plan::DecisionOption::OtherTemplate => DeckDesignOption::OtherTemplate,
                plan::DecisionOption::DesignChange => DeckDesignOption::DesignChange,
            }).collect(),
            shortfalls: decision.shortfalls.iter().map(|shortfall| DeckDesignShortfall {
                block: shortfall.block.clone(),
                reason: match shortfall.reason {
                    plan::ShortfallReason::NoSuitableSlot => DeckShortfallReason::NoSuitableSlot,
                    plan::ShortfallReason::Overflow => DeckShortfallReason::Overflow,
                    plan::ShortfallReason::Crowded => DeckShortfallReason::Crowded,
                },
            }).collect(),
        }
    }
}
