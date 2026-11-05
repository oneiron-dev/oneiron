//! On-demand review explainers over the exact pending fork set. Outputs are never stored.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::{LlmUsage, ModelId, ReasoningEffort};

/// Skill-authored complexity, not a heuristic derived from fork count or size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewComplexity {
    Easy,
    Middling,
    VeryComplex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewForkExplanation {
    pub fork: String,
    pub line: String,
    pub complexity: ReviewComplexity,
    pub removed_public_names: Vec<String>,
}

/// Renderer-neutral generated UI data. No markup, executable code or fixed layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewDiagram {
    pub nodes: Vec<ReviewDiagramNode>,
    pub edges: Vec<ReviewDiagramEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewDiagramNode {
    pub id: String,
    pub label: String,
    /// Every node names the reviewed forks that support it.
    pub forks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewDiagramEdge {
    pub from: String,
    pub to: String,
    pub label: String,
}

pub fn one_line(text: &str) -> bool {
    !text.trim().is_empty() && !text.contains(['\n', '\r'])
}

/// A call's exact route, effort and budget charge, without retaining generated text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewExplainerCallReceipt {
    pub model: ModelId,
    pub effort: ReasoningEffort,
    pub lease: String,
    pub usage: LlmUsage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewExplainerEscalation {
    NotNeeded,
    Completed,
    RouteUnavailable,
    BudgetLimited,
}

/// A derived receipt naming every fork read and the exact input and skill revision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewExplainerReceipt {
    pub proposal: String,
    pub forks: Vec<String>,
    pub input_hash: String,
    pub skill: EntityId,
    pub skill_version: String,
    pub skill_content_hash: String,
    pub calls: Vec<ReviewExplainerCallReceipt>,
    pub escalation: ReviewExplainerEscalation,
    pub at: u64,
}

