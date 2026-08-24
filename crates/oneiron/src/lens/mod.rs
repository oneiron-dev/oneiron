//! Closed generated-lens atom vocabulary.
//!
//! Generated lenses are data that the trusted renderer interprets. This module
//! intentionally contains no raw script, URL/network, browser-storage, or eval
//! leaf types.
//!
//! Layout:
//!
//! - `wire_ids` — bounded newtype tokens and the shared collection budgets.
//! - `wire_limits` — generic bounded-collection serde plumbing.
//! - `atom` — the [`LensAtom`] vocabulary and [`LensNode`] tree.
//! - `self_ui` — the `self.ui` interactive control family.
//! - `generated_ui` — the Generated-UI card/segment/`$state` protocol.
//! - `mediation` — host mediation: principals, backing refs, [`LensRenderFrame`].
//! - `validate` — cross-cutting validators and the surface compiler.

mod atom;
mod generated_ui;
mod mediation;
mod self_ui;
mod validate;
mod wire_ids;
mod wire_limits;

#[cfg(test)]
mod tests;

pub use atom::{
    AnswerSheetAtom, AsofScrubberAtom, ClaimLineAtom, CollectionAtom, FiniteF64,
    GENERATED_LENS_ATOM_KINDS, GraphEdge, GraphNode, InspectorAtom, LENS_ATOM_KIT_VERSION,
    LedgerCell, LedgerRowAtom, LensAtom, LensNode, LensStatus, LensText, LensTextSpan, MediaAtom,
    MetaLineAtom, NeighborhoodGraphAtom, PackLineAtom, PostmarkAtom, QuickFilterAtom, ReceiptAtom,
    SealAtom, SealLevel, SectionAtom, StatusDotAtom, TextBlockAtom, ThreadEntryAtom, ThrobberAtom,
    TwoClocksAtom, VadBadge, VoiceLineAtom,
};
pub use generated_ui::{
    GENERATED_UI_SEGMENT_CONTENT_TYPE, GENERATED_UI_WIRE_VERSION, GeneratedLens,
    GeneratedUiActionDeclaration, GeneratedUiActionEvent, GeneratedUiActionTier,
    GeneratedUiArchiveReason, GeneratedUiCard, GeneratedUiCardElement, GeneratedUiCardLifecycle,
    GeneratedUiCardPhase, GeneratedUiCardStart, GeneratedUiCardStateUpdate, GeneratedUiCatalog,
    GeneratedUiDataModel, GeneratedUiNode, GeneratedUiPrebuilt, GeneratedUiPrimitive,
    GeneratedUiRender, GeneratedUiSegment, GeneratedUiStatePatch, GeneratedUiStateSnapshot,
    GeneratedUiSummaryCardPrebuilt, GeneratedUiSurfaceCapabilities, SelfUiBindableProperty,
    SelfUiBinding, SelfUiStateValue,
};
pub use mediation::{
    GeneratedUiAgentCallback, GeneratedUiValidatedAction, LensActingPrincipalKind,
    LensApprovedAction, LensApprovedActionArg, LensAtomSelectionRequest, LensBackingRefToken,
    LensBackingTarget, LensBackingTargetKind, LensExecutionBoundary, LensGateWriteChokepoint,
    LensHostBackingRef, LensHostImport, LensHostMediatedWrite, LensPrincipalBinding,
    LensReadHandle, LensReadReach, LensRenderFrame,
};
pub use self_ui::{
    ButtonControl, SegmentedControl, SelectControl, SelfUiAction, SelfUiControl, SelfUiOption,
    SelfUiValue, SliderControl, TextInputControl, ToggleControl,
};
pub use wire_ids::{
    LensAtomId, LensBackingRefId, LensHandleName, LensHandleRef, LensHandleRole, LensMediaHandle,
    LensRenderId, SelfUiActionId, SelfUiControlId, SelfUiOptionValue, SelfUiStateKey,
};
