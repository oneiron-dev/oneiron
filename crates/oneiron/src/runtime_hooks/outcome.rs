//! The one outcome a hook body returns (ARCH-0080 §4 Outcomes). The verb-hook
//! kinds parse too; a fact hook returning one is refused.

use serde::{Deserialize, Serialize};

use crate::skill_hub::pack_catalog::HookOutcomeKind;
use crate::{EntityId, OutboundDraftInput};

use super::block::HookBlockLifetime;

const MAX_TEXT: usize = 256;
const MAX_BODY: usize = 16 * 1024;
const MAX_REFS: usize = 32;
const MAX_DELIVERIES: u32 = 64;
pub(super) const MAX_TOKEN_CAP: u32 = 4_096;

/// One outcome, as the body emits it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HookOutcome {
    Nothing,
    /// Exactly one of `claim`, `edge` or `note`.
    Propose {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        claim: Option<ProposedClaim>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        edge: Option<ProposedEdge>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<ProposedNote>,
    },
    /// Exactly one of `task` or `dreamer`.
    Enqueue {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        task: Option<EnqueuedTask>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dreamer: Option<EnqueuedDreamer>,
    },
    /// The draft fields `schedule_outbound` takes.
    Effect {
        outbound: Box<OutboundDraftInput>,
    },
    AddBlock {
        block: BlockRequest,
    },
    Continue,
    Rewrite {
        #[serde(default)]
        args: serde_json::Value,
    },
    Skip {
        #[serde(default)]
        reason: String,
    },
    Ask {
        #[serde(default)]
        question: String,
    },
    Annotate {
        #[serde(default)]
        note: String,
    },
    Redact {
        #[serde(default)]
        paths: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposedClaim {
    pub subject: String,
    pub predicate: String,
    pub value: serde_json::Value,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedEdge {
    pub from: String,
    pub to: String,
    pub edge: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedNote {
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub about: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnqueuedTask {
    pub title: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub assignee: Option<String>,
    /// Unix seconds.
    #[serde(default)]
    pub due_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnqueuedDreamer {
    pub reason: String,
    #[serde(default)]
    pub about: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRequest {
    pub refs: Vec<String>,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub lifetime: Option<HookBlockLifetime>,
    #[serde(default)]
    pub token_cap: Option<u32>,
}

impl HookOutcome {
    /// The kind the binding's `outcomes` list names.
    #[must_use]
    pub const fn kind(&self) -> HookOutcomeKind {
        match self {
            Self::Nothing => HookOutcomeKind::Nothing,
            Self::Propose { .. } => HookOutcomeKind::Propose,
            Self::Enqueue { .. } => HookOutcomeKind::Enqueue,
            Self::Effect { .. } => HookOutcomeKind::Effect,
            Self::AddBlock { .. } => HookOutcomeKind::AddBlock,
            Self::Continue => HookOutcomeKind::Continue,
            Self::Rewrite { .. } => HookOutcomeKind::Rewrite,
            Self::Skip { .. } => HookOutcomeKind::Skip,
            Self::Ask { .. } => HookOutcomeKind::Ask,
            Self::Annotate { .. } => HookOutcomeKind::Annotate,
            Self::Redact { .. } => HookOutcomeKind::Redact,
        }
    }

    /// Whether the outcome lands later, as a saved intent, rather than in
    /// the run's own transaction.
    pub(super) const fn is_queued(&self) -> bool {
        matches!(
            self,
            Self::Propose { .. } | Self::Enqueue { .. } | Self::Effect { .. }
        )
    }

    /// Checks the shape a fact outcome must have; the reason is the refusal.
    pub(super) fn validate(&self) -> std::result::Result<(), String> {
        match self {
            Self::Propose { claim, edge, note } => {
                match (claim, edge, note) {
                    (Some(claim), None, None) => {
                        entity(&claim.subject)?;
                        text(&claim.predicate, MAX_TEXT)?;
                        if !(0.0..=1.0).contains(&claim.confidence) {
                            return Err("confidence is outside [0, 1]".to_owned());
                        }
                    }
                    (None, Some(edge), None) => {
                        entity(&edge.from)?;
                        entity(&edge.to)?;
                        if crate::EdgeKind::from_name(&edge.edge).is_none() {
                            return Err("unknown edge kind".to_owned());
                        }
                    }
                    (None, None, Some(note)) => {
                        text(&note.title, MAX_TEXT)?;
                        text(&note.body, MAX_BODY)?;
                        entities(&note.about)?;
                    }
                    _ => return Err("propose names exactly one claim, edge or note".to_owned()),
                }
                Ok(())
            }
            Self::Enqueue { task, dreamer } => match (task, dreamer) {
                (Some(task), None) => {
                    text(&task.title, MAX_TEXT)?;
                    if task.body.len() > MAX_BODY {
                        return Err("task body exceeds its bound".to_owned());
                    }
                    task.assignee.as_deref().map(entity).transpose()?;
                    Ok(())
                }
                (None, Some(dreamer)) => {
                    text(&dreamer.reason, MAX_TEXT)?;
                    entities(&dreamer.about)
                }
                _ => Err("enqueue names exactly one task or dreamer".to_owned()),
            },
            Self::AddBlock { block } => validate_block(block),
            _ => Ok(()),
        }
    }
}

fn validate_block(block: &BlockRequest) -> std::result::Result<(), String> {
    if block.refs.is_empty() {
        return Err("a block names one or more rows".to_owned());
    }
    entities(&block.refs)?;
    for id in [&block.session, &block.branch].into_iter().flatten() {
        text(id, MAX_TEXT)?;
    }
    match &block.lifetime {
        Some(HookBlockLifetime::Deliveries(count)) if *count == 0 || *count > MAX_DELIVERIES => {
            return Err("block deliveries are out of bounds".to_owned());
        }
        Some(HookBlockLifetime::UntilPredicate(glob)) => text(glob, MAX_TEXT)?,
        _ => {}
    }
    if block
        .token_cap
        .is_some_and(|cap| cap == 0 || cap > MAX_TOKEN_CAP)
    {
        return Err("block token cap is out of bounds".to_owned());
    }
    Ok(())
}

fn text(value: &str, max: usize) -> std::result::Result<(), String> {
    if value.trim().is_empty() || value.len() > max {
        return Err("a text field is empty or too long".to_owned());
    }
    Ok(())
}

fn entity(value: &str) -> std::result::Result<EntityId, String> {
    EntityId::from_hex(value).map_err(|_| "an entity ref is not 32 hex".to_owned())
}

fn entities(values: &[String]) -> std::result::Result<(), String> {
    if values.len() > MAX_REFS {
        return Err("too many entity refs".to_owned());
    }
    for value in values {
        entity(value)?;
    }
    Ok(())
}

/// The token a receipt and the memo carry for an outcome kind.
pub(super) const fn kind_token(kind: HookOutcomeKind) -> &'static str {
    match kind {
        HookOutcomeKind::Continue => "continue",
        HookOutcomeKind::Rewrite => "rewrite",
        HookOutcomeKind::Skip => "skip",
        HookOutcomeKind::Ask => "ask",
        HookOutcomeKind::AddBlock => "add_block",
        HookOutcomeKind::Annotate => "annotate",
        HookOutcomeKind::Redact => "redact",
        HookOutcomeKind::Propose => "propose",
        HookOutcomeKind::Enqueue => "enqueue",
        HookOutcomeKind::Effect => "effect",
        HookOutcomeKind::Nothing => "nothing",
    }
}
