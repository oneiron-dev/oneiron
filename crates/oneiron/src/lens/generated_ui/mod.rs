//! The Generated-UI protocol: the [`GeneratedLens`] envelope, catalog/primitive
//! negotiation and app-declared catalogs, the engine-authored action manifest,
//! the typed `$state` schema and its patch rules, card lifecycle, the
//! card/render/segment wire frames, the staged version boundary, and the
//! incremental stream reader.
//!
//! Everything here is data the trusted renderer interprets. Turning a client
//! action event into an approved host write is the job of [`super::mediation`].

mod genui_app_catalog;
mod genui_card;
mod genui_catalog;
mod genui_decode;
mod genui_envelope;
mod genui_fingerprint;
mod genui_heal;
mod genui_json_patch;
mod genui_regen;
mod genui_render;
mod genui_state;
mod genui_stream;

pub use self::genui_app_catalog::{
    GeneratedUiCatalog, GeneratedUiCatalogDescriptor, GeneratedUiCatalogVersion,
    GeneratedUiComponentAtom, GeneratedUiComponentSchema, LENS_ATOM_KIT_CATALOG_VERSION,
};
pub use self::genui_card::GeneratedUiCard;
pub use self::genui_catalog::{
    GeneratedUiPrebuilt, GeneratedUiPrimitive, GeneratedUiSummaryCardPrebuilt,
    GeneratedUiSurfaceCapabilities,
};
pub use self::genui_decode::{GeneratedUiDecoded, GeneratedUiFallback};
pub use self::genui_envelope::{
    GENERATED_UI_SEGMENT_CONTENT_TYPE, GENERATED_UI_WIRE_VERSION, GeneratedLens,
    LENS_APPS_CONTRACT_VERSION, LensLoadAction, LensVersionStamp, lens_load_action,
};
pub use self::genui_fingerprint::{
    LensAtomInventoryChange, LensBehaviorDiff, LensBehaviorFingerprint, LensBehaviorHandle,
    LensHandleRoleChange,
};
pub use self::genui_json_patch::GeneratedUiJsonPatchOperation;
pub use self::genui_regen::{
    LensEvaluatedRevision, LensRegenFailure, LensRegenFailurePhase, LensRegenOutcome,
    LensRegenRequest, LensRegenerator, regenerate_lens,
};
pub use self::genui_render::{
    GeneratedUiCardElement, GeneratedUiCardStart, GeneratedUiCardStateUpdate, GeneratedUiDataModel,
    GeneratedUiNode, GeneratedUiRender, GeneratedUiSegment,
};
pub use self::genui_state::{
    GeneratedUiActionDeclaration, GeneratedUiActionEvent, GeneratedUiActionTier,
    GeneratedUiArchiveReason, GeneratedUiCardLifecycle, GeneratedUiCardPhase,
    GeneratedUiStatePatch, GeneratedUiStateSnapshot, SelfUiBindableProperty, SelfUiBinding,
    SelfUiStateValue,
};
pub(in crate::lens) use self::genui_state::{
    LensElementRef, apply_generated_ui_state_patch, validate_generated_ui_state_bindings,
};
pub use self::genui_stream::{
    GeneratedUiCardReady, GeneratedUiCardStatePatch, GeneratedUiCardStateSnapshot,
    GeneratedUiPartialNode, GeneratedUiPartialTree, GeneratedUiStream, GeneratedUiStreamOutcome,
    GeneratedUiStreamProfile,
};
