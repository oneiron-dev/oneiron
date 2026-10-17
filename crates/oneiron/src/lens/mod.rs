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
//! - `proposal`, `activation` — pack lens proposals and the owner's slot
//!   selection (`vault.lenses.*`); `sdk` — the default vault projection verb.
//! - `record_ref` — OF-063 typed record refs and their scoped resolution.

mod activation;
mod atom;
mod default_vault;
pub use default_vault::{DefaultVaultInput, DefaultVaultItem, compose_default_vault};
mod guest;
mod inspection;
mod instrument;
mod intent;
pub use crate::claim::{
    WeaveItem, WeaveReader, WeaveReport, WeaveSection, WeaveSectionKind, WeaveSectionSpec,
};
pub use guest::LensExecutionRuntime;
pub use inspection::{
    INSPECTION_HANDLE_LEN, INSPECTION_HANDLE_VERSION, InspectionHandle, InspectionResolveRequest,
    InspectionResolved, InspectionState, decode_inspection_handle, encode_inspection_handle,
};
pub use instrument::{InstrumentAtoms, InstrumentView, render_instrument};
pub use intent::{LENS_INTENT_MAX_BYTES, LensIntentRecord};
mod generated_ui;
mod mediation;
mod mount;
pub use mount::LensMount;
mod proposal;
pub use activation::{
    LensActivateRequest, LensDeactivateRequest, activate_lens_embedded, deactivate_lens_embedded,
};
pub use proposal::{
    LENS_LIST_MAX_PAGE, LENS_LIST_NARROWED_CARRIES_COMPILED, LENS_PROPOSAL_MAX_BYTES, LensListPage,
    LensListRequest, LensListRow, LensProposalState, LensProposeRequest, LensSlot,
};
mod sdk;
pub use sdk::{LENS_DEFAULT_MAX_SOURCES, LensDefaultRequest, LensDossierSource};
mod record_ref;
pub use record_ref::{
    LinkedText, ProseSpan, RECORD_LINKS_TEXT_MAX_BYTES, RECORD_LINKS_TURN_PAGE_MAX,
    RECORD_REF_LABEL_MAX_CHARS, RECORD_REF_MAX_BYTES, RECORD_REF_SNIPPET_MAX_CHARS, RecordLinks,
    RecordLinksRequest, RecordRef, RecordRefPreview, ResolveRecordRefRequest,
};
mod self_ui;
mod validate;
mod wire_ids;
mod wire_limits;

#[cfg(test)]
mod tests;

pub use atom::{
    AnswerSheetAtom, AsofScrubberAtom, ClaimLineAtom, CollectionAtom, FiniteF64,
    GENERATED_LENS_ATOM_KINDS, GeneratedUiResultSetActionEvent, GeneratedUiResultSetAtom,
    GeneratedUiResultSetRow, GeneratedUiResultSetSelectAll, GeneratedUiResultSetSelection,
    GraphEdge, GraphNode, InspectorAtom, LENS_ATOM_KIT_VERSION, LENS_RESULT_SET_UNSUPPORTED,
    LedgerCell, LedgerRowAtom, LensAtom, LensNode, LensStatus, LensText, LensTextSpan, MediaAtom,
    MetaLineAtom, NeighborhoodGraphAtom, PackLineAtom, PostmarkAtom, QuickFilterAtom,
    RESULT_SET_ATOM_KIND, ReceiptAtom, SealAtom, SealLevel, SectionAtom, StatusDotAtom,
    TextBlockAtom, ThreadEntryAtom, ThrobberAtom, TwoClocksAtom, VadBadge, VoiceLineAtom,
};
pub use generated_ui::{
    GENERATED_UI_SEGMENT_CONTENT_TYPE, GENERATED_UI_WIRE_VERSION, GeneratedLens,
    GeneratedUiActionDeclaration, GeneratedUiActionEvent, GeneratedUiActionTier,
    GeneratedUiArchiveReason, GeneratedUiCard, GeneratedUiCardElement, GeneratedUiCardLifecycle,
    GeneratedUiCardPhase, GeneratedUiCardStart, GeneratedUiCardStateUpdate, GeneratedUiCatalog,
    GeneratedUiDataModel, GeneratedUiNode, GeneratedUiPrebuilt, GeneratedUiPrimitive,
    GeneratedUiRender, GeneratedUiSegment, GeneratedUiStatePatch, GeneratedUiStateSnapshot,
    GeneratedUiSummaryCardPrebuilt, GeneratedUiSurfaceCapabilities, LENS_APPS_CONTRACT_VERSION,
    LensAtomInventoryChange, LensBehaviorDiff, LensBehaviorFingerprint, LensBehaviorHandle,
    LensEvaluatedRevision, LensHandleRoleChange, LensLoadAction, LensRegenFailure,
    LensRegenFailurePhase, LensRegenOutcome, LensRegenRequest, LensRegenerator, LensVersionStamp,
    SelfUiBindableProperty, SelfUiBinding, SelfUiStateValue, lens_load_action, regenerate_lens,
};
pub use mediation::{
    GeneratedUiAgentCallback, GeneratedUiResultSetScope, GeneratedUiResultSetWritePlan,
    GeneratedUiValidatedAction, LensActingPrincipalKind, LensApprovedAction, LensApprovedActionArg,
    LensAtomSelectionRequest, LensBackingRefToken, LensBackingTarget, LensBackingTargetKind,
    LensExecutionBoundary, LensGateWriteChokepoint, LensHostBackingRef, LensHostImport,
    LensHostMediatedWrite, LensPrincipalBinding, LensQuoteHandle, LensQuoteRange, LensReadHandle,
    LensReadReach, LensRenderFrame, LensSpanCursor, LensSpanSelectionRequest,
};
pub use mediation::{HostedLensRender, LensFrameCard};
pub use self_ui::{
    ButtonControl, SegmentedControl, SelectControl, SelfUiAction, SelfUiControl, SelfUiOption,
    SelfUiValue, SliderControl, TextInputControl, ToggleControl,
};
pub use wire_ids::{
    LensAtomId, LensBackingRefId, LensHandleName, LensHandleRef, LensHandleRole, LensMediaHandle,
    LensRenderId, LensResultSetRowId, SelfUiActionId, SelfUiControlId, SelfUiOptionValue,
    SelfUiStateKey,
};
