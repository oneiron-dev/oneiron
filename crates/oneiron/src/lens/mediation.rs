//! Host mediation — the lens security chokepoint.
//!
//! Principal binding, host-minted backing refs, engine-issued read reach, and
//! the [`LensRenderFrame`] that turns a client interaction event from
//! [`super::generated_ui`] into an approved, host-stamped write. Selection is
//! not approval and nothing here is self-executing.

use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    claim::{ScopedRead, ScopedReadActorKey},
    edge::EdgeActorClass,
    entity_id::EntityId,
    registry::ENTITY_TYPE_CLAIM,
};

use super::atom::{FiniteF64, LensAtom, LensText};
use super::generated_ui::{
    GeneratedUiActionEvent, GeneratedUiActionTier, GeneratedUiCardPhase, GeneratedUiRender,
    GeneratedUiStateSnapshot, LensElementRef, apply_generated_ui_state_patch,
    validate_generated_ui_state_bindings,
};
use super::self_ui::{SelfUiAction, SelfUiValue};
use super::validate::{validate_lens_collection_len, validate_lens_token};
use super::wire_ids::{
    LensAtomId, LensBackingRefId, LensHandleName, LensHandleRole, LensRenderId, SelfUiActionId,
    SelfUiOptionValue,
};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensBackingTargetKind {
    Entity,
    Claim,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensBackingTarget {
    kind: LensBackingTargetKind,
    pub(super) entity_id: EntityId,
    short_id: String,
    content_hash: u8,
}

impl LensBackingTarget {
    pub fn entity(
        entity_id: EntityId,
        short_id: impl Into<String>,
        content_hash: u8,
    ) -> Result<Self> {
        Self::new(
            LensBackingTargetKind::Entity,
            entity_id,
            short_id,
            content_hash,
        )
    }

    pub fn claim(
        entity_id: EntityId,
        short_id: impl Into<String>,
        content_hash: u8,
    ) -> Result<Self> {
        Self::new(
            LensBackingTargetKind::Claim,
            entity_id,
            short_id,
            content_hash,
        )
    }

    fn new(
        kind: LensBackingTargetKind,
        entity_id: EntityId,
        short_id: impl Into<String>,
        content_hash: u8,
    ) -> Result<Self> {
        let short_id = short_id.into();
        validate_lens_token("lens backing short id", &short_id)?;
        Ok(Self {
            kind,
            entity_id,
            short_id,
            content_hash,
        })
    }

    #[must_use]
    pub fn kind(&self) -> LensBackingTargetKind {
        self.kind
    }

    #[must_use]
    pub fn entity_id(&self) -> &EntityId {
        &self.entity_id
    }

    #[must_use]
    pub fn short_id(&self) -> &str {
        &self.short_id
    }

    #[must_use]
    pub fn content_hash(&self) -> u8 {
        self.content_hash
    }

    #[must_use]
    pub fn short_ref(&self) -> String {
        format!("{}:{:02x}", self.short_id, self.content_hash)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LensBackingRefToken {
    pub(super) render_id: LensRenderId,
    pub(super) ref_id: LensBackingRefId,
}

impl LensBackingRefToken {
    #[must_use]
    pub fn render_id(&self) -> &LensRenderId {
        &self.render_id
    }

    #[must_use]
    pub fn ref_id(&self) -> &LensBackingRefId {
        &self.ref_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensHostBackingRef {
    token: LensBackingRefToken,
    handle: LensHandleName,
    role: LensHandleRole,
    target: LensBackingTarget,
}

impl LensHostBackingRef {
    #[must_use]
    pub fn token(&self) -> &LensBackingRefToken {
        &self.token
    }

    #[must_use]
    pub fn handle(&self) -> &LensHandleName {
        &self.handle
    }

    #[must_use]
    pub fn role(&self) -> LensHandleRole {
        self.role
    }

    #[must_use]
    pub fn target(&self) -> &LensBackingTarget {
        &self.target
    }
}

/// Client-authored atom selection. It names *what was pointed at* and nothing else:
/// no entity id, body text, screenshot, write token, authority, or query string is
/// expressible here. The engine looks the node up in the exact render it emitted and
/// takes the target from its own backing table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensAtomSelectionRequest {
    pub card_id: LensRenderId,
    pub atom_id: LensAtomId,
    pub handle: LensHandleName,
}

/// The read reach a selection may carry: [`LensHandleRole`] minus
/// [`LensHandleRole::ActionTarget`]. An action-target binding is reach for the action
/// backchannel, so it can never be laundered into a selection handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensReadReach {
    ClaimSet,
    EntitySet,
    Timeline,
    QueryResult,
}

impl TryFrom<LensHandleRole> for LensReadReach {
    type Error = Error;

    fn try_from(role: LensHandleRole) -> Result<Self> {
        match role {
            LensHandleRole::ClaimSet => Ok(Self::ClaimSet),
            LensHandleRole::EntitySet => Ok(Self::EntitySet),
            LensHandleRole::Timeline => Ok(Self::Timeline),
            LensHandleRole::QueryResult => Ok(Self::QueryResult),
            LensHandleRole::ActionTarget => Err(Error::InvalidConfig(
                "lens action-target bindings are not selectable read reach".to_string(),
            )),
        }
    }
}

/// Engine-issued read reach over one selected atom. Serialize-only, with no public
/// constructor: the only way to hold one is to have passed
/// [`LensRenderFrame::select_atom`]. It carries an opaque backing token plus locator
/// metadata — never body text, screenshot bytes, a raw URL, authority, or a write
/// chokepoint — and has no conversion into [`LensApprovedAction`],
/// [`LensHostMediatedWrite`], or [`LensGateWriteChokepoint`]. Selection is not approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LensReadHandle {
    render_id: LensRenderId,
    atom_id: LensAtomId,
    reach: LensReadReach,
    target_kind: LensBackingTargetKind,
    /// A locator the acting principal already resolves under `ScopedRead`, so
    /// disclosing it widens nothing. The stored body it locates is never disclosed.
    short_ref: String,
    backing_token: LensBackingRefToken,
}

impl LensReadHandle {
    #[must_use]
    pub fn render_id(&self) -> &LensRenderId {
        &self.render_id
    }

    #[must_use]
    pub fn atom_id(&self) -> &LensAtomId {
        &self.atom_id
    }

    #[must_use]
    pub fn reach(&self) -> LensReadReach {
        self.reach
    }

    #[must_use]
    pub fn target_kind(&self) -> LensBackingTargetKind {
        self.target_kind
    }

    #[must_use]
    pub fn short_ref(&self) -> &str {
        &self.short_ref
    }
}

#[derive(Debug, Clone)]
pub struct LensRenderFrame {
    render_id: LensRenderId,
    principal: LensPrincipalBinding,
    backing_refs: Vec<LensHostBackingRef>,
}

impl LensRenderFrame {
    #[must_use]
    pub fn new(render_id: LensRenderId, principal: LensPrincipalBinding) -> Self {
        Self {
            render_id,
            principal,
            backing_refs: Vec::new(),
        }
    }

    #[must_use]
    pub fn render_id(&self) -> &LensRenderId {
        &self.render_id
    }

    #[must_use]
    pub fn principal(&self) -> &LensPrincipalBinding {
        &self.principal
    }

    #[must_use]
    pub fn backing_refs(&self) -> &[LensHostBackingRef] {
        &self.backing_refs
    }

    pub fn mint_backing_ref(
        &mut self,
        scoped_read: &ScopedRead<'_>,
        handle: LensHandleName,
        role: LensHandleRole,
        target: LensBackingTarget,
    ) -> Result<LensBackingRefToken> {
        self.ensure_scoped_read_actor(scoped_read)?;
        if self
            .backing_refs
            .iter()
            .any(|backing_ref| backing_ref.handle == handle)
        {
            return Err(Error::InvalidConfig(
                "lens backing handle must be host-bound at most once per render".to_string(),
            ));
        }
        Self::ensure_target_readable(scoped_read, &target)?;

        let ref_id = LensBackingRefId::new(format!("ref-{}", self.backing_refs.len()))?;
        let token = LensBackingRefToken {
            render_id: self.render_id.clone(),
            ref_id,
        };
        self.backing_refs.push(LensHostBackingRef {
            token: token.clone(),
            handle,
            role,
            target,
        });
        Ok(token)
    }

    pub fn resolve_backing_ref_token(
        &self,
        scoped_read: &ScopedRead<'_>,
        token: &LensBackingRefToken,
    ) -> Result<LensHostBackingRef> {
        self.ensure_scoped_read_actor(scoped_read)?;
        if token.render_id != self.render_id {
            return Err(Error::InvalidConfig(
                "lens backing ref token belongs to a different render".to_string(),
            ));
        }
        let backing_ref = self
            .backing_refs
            .iter()
            .find(|backing_ref| backing_ref.token.ref_id == token.ref_id)
            .ok_or_else(|| {
                Error::InvalidConfig("lens backing ref token was not host-minted".to_string())
            })?;
        Self::ensure_target_readable(scoped_read, &backing_ref.target)?;
        Ok(backing_ref.clone())
    }

    /// Turn a client atom selection into engine-issued read reach.
    ///
    /// The request names no target. The node is looked up in the exact render this
    /// frame emitted, the named handle must be one that node itself advertised, and the
    /// returned token is copied off this frame's host backing row — never synthesized
    /// from client data. The target is re-hydrated under the acting principal's
    /// selected read key before any handle is issued.
    pub fn select_atom(
        &self,
        scoped_read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        request: &LensAtomSelectionRequest,
    ) -> Result<LensReadHandle> {
        self.ensure_scoped_read_actor(scoped_read)?;
        self.ensure_render_is_ours(render)?;
        if request.card_id != render.card_id {
            return Err(Error::InvalidConfig(
                "lens atom selection must name the card it was rendered from".to_string(),
            ));
        }

        let row = self
            .backing_refs
            .iter()
            .find(|backing_ref| backing_ref.handle == request.handle)
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "lens selection handle was not host-bound for this render".to_string(),
                )
            })?;
        let resolved = self.resolve_backing_ref_token(scoped_read, &row.token)?;
        self.issue_read_handle(render, &request.atom_id, &resolved)
    }

    /// The handle that selecting `atom_id` onto `resolved` proves *right now*.
    ///
    /// Issuance and re-resolution share this one derivation, so every field a handle
    /// carries is engine-derived at both ends and none of them can drift apart. Reach
    /// is derived through [`LensReadReach`], which has no action-target variant: an
    /// action-target row yields no handle at all rather than a read handle over it.
    fn issue_read_handle(
        &self,
        render: &GeneratedUiRender,
        atom_id: &LensAtomId,
        resolved: &LensHostBackingRef,
    ) -> Result<LensReadHandle> {
        // The host row names the handle; the client's copy never gets a vote.
        let role = Self::declared_binding_role(render, atom_id, &resolved.handle)?;
        if role != resolved.role {
            return Err(Error::InvalidConfig(
                "lens selection handle role must match its host backing row".to_string(),
            ));
        }
        Ok(LensReadHandle {
            render_id: self.render_id.clone(),
            atom_id: atom_id.clone(),
            reach: LensReadReach::try_from(role)?,
            target_kind: resolved.target.kind(),
            short_ref: resolved.target.short_ref(),
            backing_token: resolved.token.clone(),
        })
    }

    /// Re-resolve an issued read handle at use time.
    ///
    /// An issued handle is honored only when re-deriving it against the *current*
    /// render, backing table, and scope reproduces it exactly: the presented handle is
    /// compared whole against a freshly issued one, so its recorded short ref, target
    /// kind, and reach are re-proved rather than trusted. A switched principal, a
    /// target that stopped hydrating, a render revision that no longer advertises the
    /// binding at the same role, and a same-named row that a later frame minted over a
    /// *different* target all fail here rather than letting an old handle widen — or
    /// silently relocate — what it reaches.
    pub fn resolve_read_handle(
        &self,
        scoped_read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        handle: &LensReadHandle,
    ) -> Result<LensHostBackingRef> {
        self.ensure_scoped_read_actor(scoped_read)?;
        self.ensure_render_is_ours(render)?;
        let resolved = self.resolve_backing_ref_token(scoped_read, &handle.backing_token)?;
        if self.issue_read_handle(render, &handle.atom_id, &resolved)? != *handle {
            return Err(Error::InvalidConfig(
                "lens read handle no longer matches the reach this render issues".to_string(),
            ));
        }
        Ok(resolved)
    }

    /// Carry proven selections into a model-round-trip callback as *context*.
    ///
    /// Every handle is re-resolved through this frame before it is attached, so a
    /// callback can never carry reach that selection no longer proves. Context is not
    /// approval: the callback still names no gated verb, and a later mutation resolves
    /// its own action target through the action backchannel.
    pub fn with_selected_context(
        &self,
        scoped_read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        callback: GeneratedUiAgentCallback,
        selected: Vec<LensReadHandle>,
    ) -> Result<GeneratedUiAgentCallback> {
        validate_lens_collection_len("lens selected read context", selected.len())?;
        if callback.source_card_id != self.render_id {
            return Err(Error::InvalidConfig(
                "lens selected context must ride a callback from this render frame".to_string(),
            ));
        }
        for handle in &selected {
            self.resolve_read_handle(scoped_read, render, handle)?;
        }
        Ok(GeneratedUiAgentCallback {
            selected_context: selected,
            ..callback
        })
    }

    /// The role a render node itself advertised for one handle name. A node must
    /// declare the handle exactly once: a duplicated binding is ambiguous about which
    /// reach was offered, so it resolves to nothing.
    fn declared_binding_role(
        render: &GeneratedUiRender,
        atom_id: &LensAtomId,
        handle: &LensHandleName,
    ) -> Result<LensHandleRole> {
        let node = render
            .nodes
            .iter()
            .find(|node| &node.id == atom_id)
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "lens atom selection must name an element of this render".to_string(),
                )
            })?;
        let mut declared = node
            .bindings
            .iter()
            .filter(|binding| &binding.name == handle);
        let binding = declared.next().ok_or_else(|| {
            Error::InvalidConfig(
                "lens atom selection must name a handle the element advertised".to_string(),
            )
        })?;
        if declared.next().is_some() {
            return Err(Error::InvalidConfig(
                "lens atom bindings must declare each handle at most once".to_string(),
            ));
        }
        Ok(binding.role)
    }

    pub fn approve_action(
        &self,
        scoped_read: &ScopedRead<'_>,
        action: &SelfUiAction,
    ) -> Result<LensApprovedAction> {
        self.ensure_scoped_read_actor(scoped_read)?;
        let mut args = Vec::with_capacity(action.args.len());
        for arg in &action.args {
            args.push(match arg {
                SelfUiValue::Bool(value) => LensApprovedActionArg::Bool(*value),
                SelfUiValue::Number(value) => LensApprovedActionArg::Number(*value),
                SelfUiValue::Text(value) => LensApprovedActionArg::Text(value.clone()),
                SelfUiValue::Token(value) => LensApprovedActionArg::Token(value.clone()),
                SelfUiValue::Handle(handle) => {
                    let backing_ref = self.resolve_handle(scoped_read, handle)?;
                    LensApprovedActionArg::BackingRef(backing_ref.clone())
                }
            });
        }
        Ok(LensApprovedAction {
            command: action.command.clone(),
            args,
        })
    }

    /// Resolve a client interaction event against the engine-authored manifest.
    ///
    /// `emitter` is the host's own [`LensRenderFrame::principal`]; it is never read
    /// from event JSON and must match this frame's binding. `render.state` is the
    /// declared `$state` schema; `state` is the current snapshot the patch applies to.
    pub fn validate_action_event(
        &self,
        scoped_read: &ScopedRead<'_>,
        emitter: &LensPrincipalBinding,
        render: &GeneratedUiRender,
        state: &GeneratedUiStateSnapshot,
        event: &GeneratedUiActionEvent,
    ) -> Result<GeneratedUiValidatedAction> {
        self.ensure_scoped_read_actor(scoped_read)?;
        if emitter != &self.principal {
            return Err(Error::InvalidConfig(
                "lens action emitter must be this render frame's acting principal".to_string(),
            ));
        }
        self.ensure_render_is_ours(render)?;
        if event.card_id != render.card_id {
            return Err(Error::InvalidConfig(
                "generated-ui action event card_id must match the render".to_string(),
            ));
        }
        if render.lifecycle.phase == GeneratedUiCardPhase::Archived {
            return Err(Error::InvalidConfig(
                "generated-ui archived cards must not accept action events".to_string(),
            ));
        }

        let node = render
            .nodes
            .iter()
            .find(|node| node.id == event.element_id)
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "generated-ui action event must name an element of this render".to_string(),
                )
            })?;

        let mut matches = render
            .actions
            .iter()
            .filter(|declaration| declaration.action_id == event.action_id);
        let declaration = matches.next().ok_or_else(|| {
            Error::InvalidConfig("generated-ui action event names an undeclared action".to_string())
        })?;
        if matches.next().is_some() {
            return Err(Error::InvalidConfig(
                "generated-ui action ids must be declared exactly once".to_string(),
            ));
        }
        if declaration.element_id != event.element_id {
            return Err(Error::InvalidConfig(
                "generated-ui action event element must match its declaration".to_string(),
            ));
        }
        let LensAtom::SelfUi(control) = &node.atom else {
            return Err(Error::InvalidConfig(
                "generated-ui action element must be a self.ui control".to_string(),
            ));
        };
        if control.action() != &declaration.action {
            return Err(Error::InvalidConfig(
                "generated-ui element action must match its manifest declaration".to_string(),
            ));
        }

        // Only the local tier carries client state; trigger tiers take their arguments
        // from the engine-authored declaration alone.
        if declaration.tier != GeneratedUiActionTier::Local && !event.patch.is_empty() {
            return Err(Error::InvalidConfig(
                "only local generated-ui actions may carry a $state patch".to_string(),
            ));
        }
        let next_state = apply_generated_ui_state_patch(&render.state, state, &event.patch)?;
        // Types alone do not describe a control's domain: the resulting snapshot has to
        // satisfy every `$bind` on the card, so a patch cannot select an option this
        // control never offered or move a slider off its declared grid.
        validate_generated_ui_state_bindings(
            &LensElementRef::collect_flat(&render.nodes),
            &next_state,
        )?;

        let emitter = self.principal.clone();
        Ok(match declaration.tier {
            GeneratedUiActionTier::Local => GeneratedUiValidatedAction::Local {
                emitter,
                state: next_state,
            },
            GeneratedUiActionTier::DeterministicTool => {
                GeneratedUiValidatedAction::DeterministicTool {
                    emitter,
                    action: self.approve_action(scoped_read, &declaration.action)?,
                }
            }
            GeneratedUiActionTier::ModelRoundTrip => {
                let approved = self.approve_action(scoped_read, &declaration.action)?;
                GeneratedUiValidatedAction::ModelRoundTrip {
                    emitter,
                    callback: GeneratedUiAgentCallback {
                        action_name: approved.command,
                        resolved_params: approved.args,
                        source_card_id: render.card_id.clone(),
                        source_element_id: event.element_id.clone(),
                        selected_context: Vec::new(),
                    },
                }
            }
        })
    }

    fn resolve_handle(
        &self,
        scoped_read: &ScopedRead<'_>,
        handle: &LensHandleName,
    ) -> Result<&LensHostBackingRef> {
        let backing_ref = self
            .backing_refs
            .iter()
            .find(|backing_ref| &backing_ref.handle == handle)
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "lens action handle was not host-bound for this render".to_string(),
                )
            })?;
        if backing_ref.role != LensHandleRole::ActionTarget {
            return Err(Error::InvalidConfig(
                "lens action handle must resolve to an action-target backing ref".to_string(),
            ));
        }
        Self::ensure_target_readable(scoped_read, &backing_ref.target)?;
        Ok(backing_ref)
    }

    fn ensure_render_is_ours(&self, render: &GeneratedUiRender) -> Result<()> {
        if render.card_id == self.render_id {
            return Ok(());
        }
        Err(Error::InvalidConfig(
            "generated-ui render must belong to this render frame".to_string(),
        ))
    }

    fn ensure_scoped_read_actor(&self, scoped_read: &ScopedRead<'_>) -> Result<()> {
        if scoped_read.actor_key() == self.principal.selected_read_key() {
            return Ok(());
        }
        Err(Error::InvalidConfig(
            "lens render must use the acting principal's selected read key".to_string(),
        ))
    }

    fn ensure_target_readable(
        scoped_read: &ScopedRead<'_>,
        target: &LensBackingTarget,
    ) -> Result<()> {
        let Some(hydrated) =
            scoped_read.hydrate_short_id(target.short_id(), target.content_hash())?
        else {
            return Err(Error::InvalidConfig(
                "lens backing short ref is not readable by the acting principal".to_string(),
            ));
        };
        if hydrated.id != *target.entity_id() || hydrated.body.is_none() {
            return Err(Error::InvalidConfig(
                "lens backing short ref does not resolve to the target entity".to_string(),
            ));
        }
        match (target.kind(), hydrated.entity_type) {
            (LensBackingTargetKind::Claim, ENTITY_TYPE_CLAIM) => {}
            (LensBackingTargetKind::Claim, _) => {
                return Err(Error::InvalidConfig(
                    "lens claim backing ref target must resolve to a claim entity".to_string(),
                ));
            }
            (LensBackingTargetKind::Entity, ENTITY_TYPE_CLAIM) => {
                return Err(Error::InvalidConfig(
                    "lens entity backing ref target must not resolve to a claim entity".to_string(),
                ));
            }
            (LensBackingTargetKind::Entity, _) => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LensApprovedAction {
    pub(super) command: SelfUiActionId,
    pub(super) args: Vec<LensApprovedActionArg>,
}

impl LensApprovedAction {
    #[must_use]
    pub fn command(&self) -> &SelfUiActionId {
        &self.command
    }

    #[must_use]
    pub fn args(&self) -> &[LensApprovedActionArg] {
        &self.args
    }

    #[must_use]
    pub fn into_host_mediated_write(
        self,
        chokepoint: LensGateWriteChokepoint,
    ) -> LensHostMediatedWrite {
        LensHostMediatedWrite {
            action: self,
            chokepoint,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum LensApprovedActionArg {
    Bool(bool),
    Number(FiniteF64),
    Text(LensText),
    Token(SelfUiOptionValue),
    BackingRef(LensHostBackingRef),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensGateWriteChokepoint {
    EvaluateGate,
    CheckClaimPolicyForWrite,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LensHostMediatedWrite {
    action: LensApprovedAction,
    chokepoint: LensGateWriteChokepoint,
}

impl LensHostMediatedWrite {
    #[must_use]
    pub fn action(&self) -> &LensApprovedAction {
        &self.action
    }

    #[must_use]
    pub fn chokepoint(&self) -> LensGateWriteChokepoint {
        self.chokepoint
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensHostImport {
    ScopedRead,
    ResolveBackingRef,
    EmitAtom,
    VaultWrite,
    BatchWrite,
    EvaluateGate,
    CheckClaimPolicyForWrite,
}

impl LensHostImport {
    #[must_use]
    pub fn is_write(self) -> bool {
        matches!(
            self,
            Self::VaultWrite
                | Self::BatchWrite
                | Self::EvaluateGate
                | Self::CheckClaimPolicyForWrite
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensExecutionBoundary {
    imports: Vec<LensHostImport>,
}

impl LensExecutionBoundary {
    pub fn read_only(imports: Vec<LensHostImport>) -> Result<Self> {
        if let Some(import) = imports.iter().copied().find(|import| import.is_write()) {
            return Err(Error::InvalidConfig(format!(
                "generated lens execution must not link write import {import:?}"
            )));
        }
        Ok(Self { imports })
    }

    #[must_use]
    pub fn imports(&self) -> &[LensHostImport] {
        &self.imports
    }
}
