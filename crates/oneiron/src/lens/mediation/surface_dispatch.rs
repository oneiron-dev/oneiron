//! Native SurfaceEvent adapter into the existing frame-validated write plan.

use super::{
    GeneratedUiValidatedAction, LensApprovedActionArg, LensBackingTargetKind,
    LensGateWriteChokepoint, LensHostMediatedWrite, LensPrincipalBinding, LensRenderFrame,
};
use crate::claim::ScopedRead;
use crate::lens::{
    GeneratedUiActionEvent, GeneratedUiRender, GeneratedUiStateSnapshot, LensHandleRole,
};
use crate::surface_event::{
    SurfaceCounterpartyStamp, SurfaceEvent, SurfaceEventAction, SurfaceSourceApp,
};
use crate::{Error, Result};

impl LensRenderFrame {
    /// The emitter is supplied by the authenticated host, never deserialized
    /// from an event. Provider observations remain claims, not instructions.
    /// `target_ref` echoes a host-issued backing-ref id from this exact frame.
    /// This produces a mediated plan, not a write capability or direct mutation.
    pub fn dispatch_surface_event(
        &self,
        read: &ScopedRead<'_>,
        emitter: &LensPrincipalBinding,
        render: &GeneratedUiRender,
        state: &GeneratedUiStateSnapshot,
        surface: &SurfaceEvent,
        action: &GeneratedUiActionEvent,
    ) -> Result<LensHostMediatedWrite> {
        let refuse = || {
            Error::InvalidConfig(
                "surface interaction is not bound to this native lens frame".into(),
            )
        };
        if surface.schema_version != crate::surface_event::SURFACE_EVENT_SCHEMA_VERSION
            || surface.foreign_inbound
            || surface.claims_not_instructions
            || surface.source.app != SurfaceSourceApp::Web
            || surface.channel != "web"
            || emitter != self.principal()
        {
            return Err(refuse());
        }
        match &surface.counterparty {
            SurfaceCounterpartyStamp::Known { counterparty_ref }
                if counterparty_ref == emitter.principal_ref() => {}
            _ => return Err(refuse()),
        }
        let SurfaceEventAction::Interaction {
            target_ref: Some(target),
            ..
        } = &surface.action
        else {
            return Err(refuse());
        };
        let backing = self
            .backing_refs()
            .iter()
            .find(|backing| backing.token().ref_id().as_str() == target)
            .ok_or_else(refuse)?;
        let backing = self.resolve_backing_ref_token(read, backing.token())?;
        if backing.role() != LensHandleRole::ActionTarget {
            return Err(refuse());
        }
        let GeneratedUiValidatedAction::DeterministicTool { action, .. } =
            self.validate_action_event(read, emitter, render, state, action)?
        else {
            return Err(refuse());
        };
        if !action
            .args()
            .iter()
            .any(|arg| matches!(arg, LensApprovedActionArg::BackingRef(arg) if arg == &backing))
        {
            return Err(refuse());
        }
        let claim_target = action.args().iter().any(|arg| matches!(arg, LensApprovedActionArg::BackingRef(arg) if arg.target().kind() == LensBackingTargetKind::Claim));
        Ok(action.into_host_mediated_write(if claim_target {
            LensGateWriteChokepoint::CheckClaimPolicyForWrite
        } else {
            LensGateWriteChokepoint::EvaluateGate
        }))
    }
}
