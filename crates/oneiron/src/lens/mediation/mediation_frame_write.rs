//! Write phase of the render frame: action validation and result-set dispatch.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::claim::ScopedRead;
use crate::error::{Error, Result};
use crate::lens::atom::{
    FiniteF64, GeneratedUiResultSetActionEvent, GeneratedUiResultSetAtom,
    GeneratedUiResultSetSelectAll, GeneratedUiResultSetSelection, LensAtom, LensText,
};
use crate::lens::generated_ui::{
    GeneratedUiActionEvent, GeneratedUiActionTier, GeneratedUiCardPhase, GeneratedUiRender,
    GeneratedUiStateSnapshot, LensElementRef, apply_generated_ui_state_patch,
    validate_generated_ui_state_bindings,
};
use crate::lens::self_ui::{SelfUiAction, SelfUiValue};
use crate::lens::validate::{LensBudget, validate_lens_collection_len};
use crate::lens::wire_ids::{
    LensAtomId, LensHandleName, LensHandleRole, SelfUiActionId, SelfUiOptionValue,
};

use super::{
    GeneratedUiAgentCallback, GeneratedUiResultSetScope, GeneratedUiResultSetWritePlan,
    GeneratedUiValidatedAction, LensAtomSelectionRequest, LensBackingTargetKind,
    LensHostBackingRef, LensPrincipalBinding, LensReadReach, LensRenderFrame,
};

impl LensRenderFrame {
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

    /// Prove a result-set selection against the exact render this frame emitted.
    ///
    /// The action itself is validated by the landed ONE-1436 backchannel with this
    /// frame's own principal as emitter, so a client-supplied actor, command, authority,
    /// approval, verb, or source field has no field to arrive in. What this adds is the
    /// *scope*: which rendered rows were ticked, and what reach each one proves right
    /// now. Nothing is approved and no effect is produced — the returned plan is a plan.
    pub fn validate_result_set_action(
        &self,
        scoped_read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        event: &GeneratedUiResultSetActionEvent,
    ) -> Result<GeneratedUiResultSetWritePlan> {
        // (1) The landed action gate: emitter is the frame's principal, never event JSON.
        let validated = self.validate_action_event(
            scoped_read,
            self.principal(),
            render,
            &render.state,
            &event.action,
        )?;

        // (2) Only the deterministic Tier 2 write branch may carry a selection, and the
        // action id has to be allowlisted by exactly one rendered result set.
        if !matches!(
            validated,
            GeneratedUiValidatedAction::DeterministicTool { .. }
        ) {
            return Err(Error::InvalidConfig(
                "result set selections may only ride a deterministic-tool action".to_string(),
            ));
        }
        let (atom_id, result_set) = Self::result_set_for_action(render, &event.action.action_id)?;

        let scope = match &event.selection {
            // (3) Explicit: opaque row-id echoes, proved against this exact atom.
            GeneratedUiResultSetSelection::Explicit { row_ids } => {
                validate_lens_collection_len("result set selection row ids", row_ids.len())?;
                let mut budget = LensBudget::default();
                budget.add_collection("result set selection row ids", row_ids.len())?;
                if row_ids.is_empty() {
                    return Err(Error::InvalidConfig(
                        "result set explicit selections must name at least one row".to_string(),
                    ));
                }
                let mut selected_ids = BTreeSet::new();
                for row_id in row_ids {
                    if !result_set.rows.iter().any(|row| &row.id == row_id) {
                        return Err(Error::InvalidConfig(
                            "result set selections must name rows of this rendered atom"
                                .to_string(),
                        ));
                    }
                    if !selected_ids.insert(row_id.clone()) {
                        return Err(Error::InvalidConfig(
                            "result set selections must not repeat a row id".to_string(),
                        ));
                    }
                }

                // Rows are walked in *rendered* order, so the plan's reach is engine
                // ordered rather than client ordered.
                let mut selected = Vec::with_capacity(selected_ids.len());
                for row in &result_set.rows {
                    if !selected_ids.contains(&row.id) {
                        continue;
                    }
                    let handle = self.select_atom(
                        scoped_read,
                        render,
                        &LensAtomSelectionRequest {
                            card_id: render.card_id.clone(),
                            atom_id: atom_id.clone(),
                            handle: row.target_handle.clone(),
                        },
                    )?;
                    if !matches!(
                        handle.reach(),
                        LensReadReach::ClaimSet | LensReadReach::EntitySet
                    ) {
                        return Err(Error::InvalidConfig(
                            "result set rows must resolve to claim-set or entity-set reach"
                                .to_string(),
                        ));
                    }
                    selected.push(handle);
                }
                GeneratedUiResultSetScope::Explicit {
                    row_ids: selected_ids,
                    selected,
                }
            }
            // (4) Select-all: the predicate comes from the rendered atom, never the
            // event. `Disabled` has no predicate to take, so it rejects.
            GeneratedUiResultSetSelection::AllWithinFilter {} => {
                let GeneratedUiResultSetSelectAll::WithinFilter { predicate_handle } =
                    &result_set.select_all
                else {
                    return Err(Error::InvalidConfig(
                        "result set select-all is disabled on this rendered atom".to_string(),
                    ));
                };
                let predicate = self.select_atom(
                    scoped_read,
                    render,
                    &LensAtomSelectionRequest {
                        card_id: render.card_id.clone(),
                        atom_id: atom_id.clone(),
                        handle: predicate_handle.clone(),
                    },
                )?;
                if predicate.reach() != LensReadReach::QueryResult {
                    return Err(Error::InvalidConfig(
                        "result set select-all predicates must resolve to query-result reach"
                            .to_string(),
                    ));
                }
                GeneratedUiResultSetScope::Predicate { predicate }
            }
        };

        // (5) A plan, and only a plan: no receipt, no approved action, no effect.
        Ok(GeneratedUiResultSetWritePlan {
            emitter: self.principal.clone(),
            action: validated,
            scope,
        })
    }

    /// Turn a proved selection into one host-stamped write.
    ///
    /// Everything the plan recorded is re-proved against the *current* scope and render
    /// before a single backing ref is attached: a stale render, a switched principal, a
    /// removed row, a changed predicate, a cross-render handle, a wrong role, or a
    /// target that stopped hydrating all fail here. No dispatcher is called, no approval
    /// is persisted, and no effect is produced — the return value is the receipt.
    pub fn dispatch_result_set_action(
        &self,
        scoped_read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        event: &GeneratedUiResultSetActionEvent,
    ) -> Result<LensHostMediatedWrite> {
        // (6) Re-validate from scratch, then re-resolve every handle the plan holds.
        let plan = self.validate_result_set_action(scoped_read, render, event)?;
        self.ensure_scoped_read_actor(scoped_read)?;
        self.ensure_render_is_ours(render)?;
        if plan.emitter != self.principal {
            return Err(Error::InvalidConfig(
                "lens result set plan must carry this render frame's acting principal".to_string(),
            ));
        }
        let (atom_id, result_set) = Self::result_set_for_action(render, &event.action.action_id)?;

        let mut resolved = Vec::new();
        match plan.scope() {
            GeneratedUiResultSetScope::Explicit { row_ids, selected } => {
                for row_id in row_ids {
                    if !result_set.rows.iter().any(|row| &row.id == row_id) {
                        return Err(Error::InvalidConfig(
                            "result set selections must name rows of this rendered atom"
                                .to_string(),
                        ));
                    }
                }
                for handle in selected {
                    if handle.atom_id() != atom_id {
                        return Err(Error::InvalidConfig(
                            "result set reach must belong to the rendered result set".to_string(),
                        ));
                    }
                    if !matches!(
                        handle.reach(),
                        LensReadReach::ClaimSet | LensReadReach::EntitySet
                    ) {
                        return Err(Error::InvalidConfig(
                            "result set rows must resolve to claim-set or entity-set reach"
                                .to_string(),
                        ));
                    }
                    resolved.push(self.resolve_read_handle(scoped_read, render, handle)?);
                }
            }
            GeneratedUiResultSetScope::Predicate { predicate } => {
                if predicate.atom_id() != atom_id {
                    return Err(Error::InvalidConfig(
                        "result set reach must belong to the rendered result set".to_string(),
                    ));
                }
                if predicate.reach() != LensReadReach::QueryResult {
                    return Err(Error::InvalidConfig(
                        "result set select-all predicates must resolve to query-result reach"
                            .to_string(),
                    ));
                }
                resolved.push(self.resolve_read_handle(scoped_read, render, predicate)?);
            }
        }

        // (7) Chokepoint derivation over the *freshly* re-resolved targets: a claim
        // anywhere in scope routes through claim policy, otherwise the gate evaluator.
        let chokepoint = if resolved
            .iter()
            .any(|backing_ref| backing_ref.target().kind() == LensBackingTargetKind::Claim)
        {
            LensGateWriteChokepoint::CheckClaimPolicyForWrite
        } else {
            LensGateWriteChokepoint::EvaluateGate
        };
        let approved =
            Self::approve_result_set_write(render, &event.action.action_id, &plan, resolved)?;
        Ok(approved.into_host_mediated_write(chokepoint))
    }

    /// The one rendered result set that allowlists `action_id`. Absent or ambiguous
    /// allowlisting resolves to nothing rather than to a guess.
    fn result_set_for_action<'a>(
        render: &'a GeneratedUiRender,
        action_id: &SelfUiActionId,
    ) -> Result<(&'a LensAtomId, &'a GeneratedUiResultSetAtom)> {
        let mut hosting = render.nodes.iter().filter_map(|node| {
            let result_set = node.atom.result_set_payload()?;
            result_set
                .action_bar
                .contains(action_id)
                .then_some((&node.id, result_set))
        });
        let found = hosting.next().ok_or_else(|| {
            Error::InvalidConfig(
                "result set action must be allowlisted by a rendered result set".to_string(),
            )
        })?;
        if hosting.next().is_some() {
            return Err(Error::InvalidConfig(
                "result set action ids must be allowlisted by exactly one rendered atom"
                    .to_string(),
            ));
        }
        Ok(found)
    }

    /// Build the approved action a result-set write carries: the engine-authored action
    /// id as command, the declaration's frame-validated literal args, and one backing
    /// ref per freshly re-resolved target. Client data contributes no argument.
    fn approve_result_set_write(
        render: &GeneratedUiRender,
        action_id: &SelfUiActionId,
        plan: &GeneratedUiResultSetWritePlan,
        resolved: Vec<LensHostBackingRef>,
    ) -> Result<LensApprovedAction> {
        let GeneratedUiValidatedAction::DeterministicTool { action, .. } = plan.action() else {
            return Err(Error::InvalidConfig(
                "result set selections may only ride a deterministic-tool action".to_string(),
            ));
        };
        let mut declared = render
            .actions
            .iter()
            .filter(|declaration| &declaration.action_id == action_id);
        let declaration = declared.next().ok_or_else(|| {
            Error::InvalidConfig("result set action names an undeclared action".to_string())
        })?;
        if declared.next().is_some() {
            return Err(Error::InvalidConfig(
                "generated-ui action ids must be declared exactly once".to_string(),
            ));
        }

        let mut args = action.args.clone();
        args.extend(resolved.into_iter().map(LensApprovedActionArg::BackingRef));
        validate_lens_collection_len("result set approved action args", args.len())?;
        Ok(LensApprovedAction {
            command: declaration.action_id.clone(),
            args,
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
}

#[derive(Debug, Clone, PartialEq)]
pub struct LensApprovedAction {
    pub(crate) command: SelfUiActionId,
    pub(crate) args: Vec<LensApprovedActionArg>,
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
