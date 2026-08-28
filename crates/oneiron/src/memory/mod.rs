//! BRIDGE-01 (ONE-1454): transport-agnostic memory facade.
//!
//! The single write door for app-tier callers (ONE-WIRE-1 W1/W3, ONE-WIRE-2
//! S1/S3/S7/S8): every verb here rides EXISTING engine machinery — the gated
//! claim-candidate path, `BatchBuilder` structural puts, the named deletion
//! verbs, the blob-artifact store — and never bypasses
//! `check_claim_policy_for_write`. Bindings (napi, HTTP) lift this surface
//! verbatim; the facade is authored once, engine-side.
//!
//! Vocabulary (S1): short-id refs (`"ms3:a1"`) or 32-hex entity ids in,
//! typed DTOs out. No type bytes, no raw MessagePack on this surface.
//!
//! Approval policy (design §4.2): the facade REQUESTS `auto` only for
//! `user_stated`/`observed` claims whose scope carries no explicit
//! `sensitivity` key; everything else is submitted `proposed`. The gate
//! remains the enforcer: when it refuses an `auto` request
//! (`GateWriteRejected`), the facade resubmits the same claim `proposed`, so
//! writes park as pending consents instead of vanishing.
//!
//! One concern per file: `error` owns the error vocabulary, `support`
//! owns [`Memory`] itself plus the shared actor-verification and wire
//! plumbing, and each verb family lives in the file named for it. This
//! module re-exports the whole surface, so `crate::memory::X` paths are
//! unchanged from the flat-file era.

mod campaign;
mod chat;
mod claims;
mod dreamer;
mod error;
mod expression_preference;
mod outbound;
mod reads;
mod recall;
mod structural;
mod support;
mod witness;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_regressions;

pub use chat::{
    ChatComposeRequest, ChatComposer, ChatDepth, ChatDraft, ChatOptions, ComposedChatDraft,
};
pub use claims::{
    ClaimInput, CommitReceipt, DeleteReceipt, MULTI_CARDINALITY_PREDICATES, MemoryReceipt,
    PendingWrite, SafeDeleteReason,
};
pub use dreamer::{ConsolidationAttemptInput, DreamerAttemptRef, DreamerAttemptView};
pub use error::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_LEASE_REQUIRED, MEMORY_CODE_NOT_FOUND,
    MEMORY_CODE_OFF_RECORD_SESSION_DOOR, MemoryError, MemoryResult,
};
pub use expression_preference::{
    ExpressionPreferenceInput, ExpressionPreferenceReceipt, ExpressionPreferenceView,
};
pub use outbound::{
    BRIDGE_OUTBOUND_ATTEMPT_KIND, CALENDAR_INVITE_OUTBOUND_CHANNEL, CALENDAR_INVITE_OUTBOUND_VERB,
    CalendarFreebusyDto, CalendarFreebusyIntervalDto, CalendarInviteSurfaceInput,
    CalendarInviteSurfaceMethod, OutboundDraftInput, OutboundIntentReceipt,
    OutboundScheduleContext,
};
pub use reads::{ClaimListFilter, ClaimView, LexicalHit, NeighborHit, NeighborOpts};
pub use recall::{
    Effort, MEMORY_PACK_VERSION, MemoryItem, MemoryPack, MemoryProvenance, RecallScope,
    RetrievalMeta, ScopeHonesty,
};
pub use structural::{
    AdmitImportedClaimInput, BlobArtifactInput, BlobVersionView, CompanionRecordInput,
    EntityRefReceipt, EntityView, HabitCheckinInput, StructuralEdgeSpec, StructuralPutInput,
    TextIndexField,
};
pub use support::{Memory, parse_actor_key, resolve_entity_ref};
pub use witness::{WitnessAuthor, WitnessMessage, WitnessReceipt, WitnessTurn};

pub(crate) use support::{facade_provenance, verify_actor_binding};
