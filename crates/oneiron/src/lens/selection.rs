//! Frame-bound selection doors. Read reach stays in the host's custody and
//! every use re-proves it against the caller's live read and exact render.

use serde::{Deserialize, Serialize};

use crate::claim::ClaimReadStatus;
#[cfg(feature = "sync")]
use crate::lens::LensSpanSelectionRequest;
use crate::lens::{
    GeneratedUiRender, GeneratedUiResultSetActionEvent, GeneratedUiResultSetScope,
    GeneratedUiStateSnapshot, GeneratedUiValidatedAction, InspectionResolved, LensAtomId,
    LensAtomSelectionRequest, LensBackingTargetKind, LensHandleName, LensReadHandle, LensReadReach,
    LensRenderFrame, LensRenderId,
};
use crate::memory::{Memory, MemoryError, MemoryResult};

/// Half-open Unicode scalar offsets. A supplied version is an echo to check,
/// never a version the engine is asked to trust or read instead of the live one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensSelectionRange {
    pub start: usize,
    pub end: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensSelectRequest {
    pub card_id: LensRenderId,
    pub atom_id: LensAtomId,
    pub handle: LensHandleName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<LensSelectionRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensSelectionResolveRequest {
    pub card_id: LensRenderId,
    pub selection_ref: String,
}

/// Cursor bytes, not a copy of the selected text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensSelectedSpan {
    pub start: usize,
    pub end: usize,
    pub version: Vec<u8>,
    pub start_cursor: Vec<u8>,
    pub end_cursor: Vec<u8>,
}

/// The wire view of a host-held selection. The ref is a locator, not authority;
/// the engine-issued LensReadHandle itself remains serialize-only and host-held.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensSelection {
    pub selection_ref: String,
    pub card_id: LensRenderId,
    pub atom_id: LensAtomId,
    pub reach: LensReadReach,
    pub target_kind: LensBackingTargetKind,
    pub short_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<LensSelectedSpan>,
}

impl LensSelection {
    #[must_use]
    pub fn of_handle(selection_ref: String, handle: &LensReadHandle) -> Self {
        Self {
            selection_ref,
            card_id: handle.render_id().clone(),
            atom_id: handle.atom_id().clone(),
            reach: handle.reach(),
            target_kind: handle.target_kind(),
            short_ref: handle.short_ref().to_owned(),
            span: handle.span().map(|span| {
                let (start, end) = span.range();
                let (start_cursor, end_cursor) = span.cursors();
                LensSelectedSpan {
                    start,
                    end,
                    version: span.frontier().to_vec(),
                    start_cursor: start_cursor.to_vec(),
                    end_cursor: end_cursor.to_vec(),
                }
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensSelectionResolved {
    pub selection: LensSelection,
    pub source: InspectionResolved,
}

/// Row ids are echoes of this rendered result set. Each selected ref must name
/// the corresponding engine-issued selection, in rendered order; select-all
/// instead names the rendered predicate's one QueryResult selection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensResultSetActionRequest {
    pub event: GeneratedUiResultSetActionEvent,
    #[serde(deserialize_with = "super::wire_limits::deserialize_limited_vec")]
    pub selected: Vec<String>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensResultSetActionResult {
    pub outcome: serde_json::Value,
    pub read_receipt: crate::claim::ScopedReadReceipt,
}

impl Memory<'_> {
    pub fn lens_frame_select(
        &self,
        frame: &LensRenderFrame,
        render: &GeneratedUiRender,
        input: &LensSelectRequest,
    ) -> MemoryResult<LensReadHandle> {
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        match &input.span {
            None => Ok(frame.select_atom(
                &read,
                render,
                &LensAtomSelectionRequest {
                    card_id: input.card_id.clone(),
                    atom_id: input.atom_id.clone(),
                    handle: input.handle.clone(),
                },
            )?),
            Some(span) => {
                #[cfg(feature = "sync")]
                {
                    let selected = frame.select_span(
                        &read,
                        render,
                        &LensSpanSelectionRequest {
                            card_id: input.card_id.clone(),
                            atom_id: input.atom_id.clone(),
                            handle: input.handle.clone(),
                            start: span.start,
                            end: span.end,
                        },
                    )?;
                    if let Some(version) = &span.version
                        && selected
                            .span()
                            .is_none_or(|current| current.frontier() != version.as_slice())
                    {
                        return Err(MemoryError::bad_request(
                            "selection version differs from the rendered document",
                        ));
                    }
                    Ok(selected)
                }
                #[cfg(not(feature = "sync"))]
                {
                    let _ = span;
                    Err(MemoryError::bad_request("span selection requires sync"))
                }
            }
        }
    }

    pub fn lens_frame_resolve_selection(
        &self,
        frame: &LensRenderFrame,
        render: &GeneratedUiRender,
        selected: &LensReadHandle,
    ) -> MemoryResult<InspectionResolved> {
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let state = frame.inspection_state(&read, render, selected)?;
        self.inspection_resolve_state(&read, state)
    }

    pub fn lens_frame_result_set_action(
        &self,
        frame: &LensRenderFrame,
        render: &GeneratedUiRender,
        state: &GeneratedUiStateSnapshot,
        event: &GeneratedUiResultSetActionEvent,
        selected: &[LensReadHandle],
    ) -> MemoryResult<GeneratedUiValidatedAction> {
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let plan = frame.validate_result_set_action_with_state(&read, render, state, event)?;
        let expected = match plan.scope() {
            GeneratedUiResultSetScope::Explicit { selected, .. } => selected.as_slice(),
            GeneratedUiResultSetScope::Predicate { predicate } => std::slice::from_ref(predicate),
        };
        if expected != selected {
            return Err(MemoryError::bad_request(
                "result-set selections must match exactly the ticked rows or rendered predicate",
            ));
        }
        for handle in selected {
            frame.resolve_read_handle(&read, render, handle)?;
        }
        let write = frame.dispatch_result_set_action_with_state(&read, render, state, event)?;
        Ok(GeneratedUiValidatedAction::DeterministicTool {
            emitter: frame.principal().clone(),
            action: write.action().clone(),
        })
    }
}
