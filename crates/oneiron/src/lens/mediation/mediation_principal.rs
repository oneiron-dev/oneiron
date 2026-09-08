//! Principal identity and validated-action outcome types.

use serde::{Deserialize, Serialize};

use crate::claim::ScopedReadActorKey;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::lens::generated_ui::GeneratedUiStateSnapshot;
use crate::lens::wire_ids::{LensAtomId, LensRenderId, SelfUiActionId};

use super::{LensApprovedAction, LensApprovedActionArg, LensReadHandle};

/// Host-side outcome of `LensRenderFrame::validate_action_event`. Every variant carries
/// the emitter stamped from the frame's principal binding; none is a wire type, and
/// none is self-executing.
#[derive(Debug, Clone, PartialEq)]
pub enum GeneratedUiValidatedAction {
    Local {
        emitter: LensPrincipalBinding,
        state: GeneratedUiStateSnapshot,
    },
    DeterministicTool {
        emitter: LensPrincipalBinding,
        action: LensApprovedAction,
    },
    ModelRoundTrip {
        emitter: LensPrincipalBinding,
        callback: GeneratedUiAgentCallback,
    },
}

impl GeneratedUiValidatedAction {
    #[must_use]
    pub fn emitter(&self) -> &LensPrincipalBinding {
        match self {
            Self::Local { emitter, .. }
            | Self::DeterministicTool { emitter, .. }
            | Self::ModelRoundTrip { emitter, .. } => emitter,
        }
    }
}

/// Data handed to the next agent turn. It is not a tool call and is never
/// auto-forwarded. It is an engine-to-agent output and has no `Deserialize`, so no
/// client can submit one.
#[derive(Debug, Clone, PartialEq)]
pub struct GeneratedUiAgentCallback {
    pub action_name: SelfUiActionId,
    pub resolved_params: Vec<LensApprovedActionArg>,
    pub source_card_id: LensRenderId,
    pub source_element_id: LensAtomId,
    /// Read reach the acting principal selected, carried as context only. Populate it
    /// through [`LensRenderFrame::with_selected_context`], which re-proves every handle.
    pub selected_context: Vec<LensReadHandle>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensActingPrincipalKind {
    HumanView,
    AgentTask,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensPrincipalBinding {
    principal_ref: String,
    kind: LensActingPrincipalKind,
    selected_read_key: ScopedReadActorKey,
    held_read_keys: Vec<ScopedReadActorKey>,
}

impl LensPrincipalBinding {
    pub fn human_view(
        principal_ref: impl Into<String>,
        selected_read_key: ScopedReadActorKey,
        held_read_keys: Vec<ScopedReadActorKey>,
    ) -> Result<Self> {
        Self::new(
            principal_ref,
            LensActingPrincipalKind::HumanView,
            selected_read_key,
            held_read_keys,
        )
    }

    pub fn agent_task(
        principal_ref: impl Into<String>,
        selected_read_key: ScopedReadActorKey,
        held_read_keys: Vec<ScopedReadActorKey>,
    ) -> Result<Self> {
        Self::new(
            principal_ref,
            LensActingPrincipalKind::AgentTask,
            selected_read_key,
            held_read_keys,
        )
    }

    fn new(
        principal_ref: impl Into<String>,
        kind: LensActingPrincipalKind,
        selected_read_key: ScopedReadActorKey,
        held_read_keys: Vec<ScopedReadActorKey>,
    ) -> Result<Self> {
        let principal_ref = principal_ref.into();
        let principal_ref = principal_ref.trim();
        if principal_ref.is_empty() {
            return Err(Error::InvalidConfig(
                "lens acting principal must not be empty".to_string(),
            ));
        }
        if held_read_keys.is_empty() {
            return Err(Error::InvalidConfig(
                "lens acting principal must hold at least one read key".to_string(),
            ));
        }
        if principal_ref != selected_read_key.actor_ref() {
            return Err(Error::InvalidConfig(
                "lens acting principal ref must match the selected read key actor".to_string(),
            ));
        }
        if held_read_keys
            .iter()
            .any(|key| key.actor_ref() != principal_ref)
        {
            return Err(Error::InvalidConfig(
                "lens acting principal held read keys must belong to the same actor".to_string(),
            ));
        }
        if !held_read_keys.iter().any(|key| key == &selected_read_key) {
            return Err(Error::InvalidConfig(
                "lens render read key must be held by the acting principal".to_string(),
            ));
        }
        match kind {
            LensActingPrincipalKind::HumanView => {
                if selected_read_key
                    .actor_class()
                    .is_some_and(|class| class != EdgeActorClass::Human.gate_actor_class())
                {
                    return Err(Error::InvalidConfig(
                        "lens human-view principal must use a human read key".to_string(),
                    ));
                }
            }
            LensActingPrincipalKind::AgentTask => {
                if selected_read_key.actor_class() != Some(EdgeActorClass::Agent.gate_actor_class())
                {
                    return Err(Error::InvalidConfig(
                        "lens agent-task principal must use an agent read key".to_string(),
                    ));
                }
            }
        }

        Ok(Self {
            principal_ref: principal_ref.to_owned(),
            kind,
            selected_read_key,
            held_read_keys,
        })
    }

    #[must_use]
    pub fn principal_ref(&self) -> &str {
        &self.principal_ref
    }

    #[must_use]
    pub fn kind(&self) -> LensActingPrincipalKind {
        self.kind
    }

    #[must_use]
    pub fn selected_read_key(&self) -> &ScopedReadActorKey {
        &self.selected_read_key
    }

    #[must_use]
    pub fn held_read_keys(&self) -> &[ScopedReadActorKey] {
        &self.held_read_keys
    }
}
