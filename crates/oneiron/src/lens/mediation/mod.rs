//! Host mediation — the lens security chokepoint.
//!
//! Principal binding, host-minted backing refs, engine-issued read reach, and
//! the [`LensRenderFrame`] that turns a client interaction event from
//! [`super::generated_ui`] into an approved, host-stamped write. Selection is
//! not approval and nothing here is self-executing.

mod mediation_backing;
mod mediation_frame_read;
mod mediation_frame_write;
mod mediation_principal;

pub use self::mediation_backing::{
    GeneratedUiResultSetScope, GeneratedUiResultSetWritePlan, LensAtomSelectionRequest,
    LensBackingRefToken, LensBackingTarget, LensBackingTargetKind, LensHostBackingRef,
    LensReadHandle, LensReadReach,
};
pub use self::mediation_frame_read::LensRenderFrame;
pub use self::mediation_frame_write::{
    LensApprovedAction, LensApprovedActionArg, LensExecutionBoundary, LensGateWriteChokepoint,
    LensHostImport, LensHostMediatedWrite,
};
pub use self::mediation_principal::{
    GeneratedUiAgentCallback, GeneratedUiValidatedAction, LensActingPrincipalKind,
    LensPrincipalBinding,
};
