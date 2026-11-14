//! The one outcome a hook body returns (ARCH-0080 §4 Outcomes). The verb-hook
//! kinds parse too; a fact hook returning one is refused.

use serde::{Deserialize, Serialize};

use crate::skill_hub::pack_catalog::HookOutcomeKind;
use crate::{EntityId, OutboundDraftInput};

use super::block::HookBlockLifetime;

#[doc(hidden)]
pub(super) use oneiron_records::runtime_hooks::outcome::MAX_TOKEN_CAP;
#[doc(hidden)]
pub use oneiron_records::runtime_hooks::outcome::{
    BlockRequest, EnqueuedDreamer, EnqueuedTask, ProposedClaim, ProposedEdge, ProposedNote,
};
#[doc(hidden)]
use oneiron_records::runtime_hooks::outcome::{
    MAX_BODY, MAX_TEXT, entities, entity, text, validate_block,
};

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
